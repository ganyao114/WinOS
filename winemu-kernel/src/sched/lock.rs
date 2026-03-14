// sched/lock.rs — KSchedulerLock: yuzu-style deferred-update scheduler lock
//
// Mirrors the KAbstractSchedulerLock pattern:
//   - Outer spinlock guards all scheduler state.
//   - Lock count is per-vCPU (reentrant on same vCPU).
//   - On final unlock, runs deferred topology updates then checks reschedule.

use crate::sched::cpu::vcpu_id;
use crate::sched::types::MAX_VCPUS;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ── Raw spinlock ──────────────────────────────────────────────────────────────

pub struct SchedSpinlock {
    locked: AtomicBool,
}

impl SchedSpinlock {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    #[inline]
    pub fn acquire(&self) {
        loop {
            if self
                .locked
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
    }

    #[inline]
    pub fn release(&self) {
        self.locked.store(false, Ordering::Release);
    }

    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

// ── Global scheduler spinlock ─────────────────────────────────────────────────

pub static SCHED_LOCK: SchedSpinlock = SchedSpinlock::new();

// Per-vCPU lock depth (not in KCpuLocal to avoid circular dep at static init).
static LOCK_DEPTH: [AtomicU32; MAX_VCPUS] = [const { AtomicU32::new(0) }; MAX_VCPUS];

// ── KSchedulerLock RAII guard ─────────────────────────────────────────────────

/// RAII guard that holds the scheduler spinlock.
/// On drop, runs deferred topology updates and triggers reschedule if needed.
pub struct KSchedulerLock {
    vid: usize,
}

impl KSchedulerLock {
    /// Acquire the scheduler lock. Reentrant on the same vCPU.
    #[inline]
    pub fn lock() -> Self {
        let vid = vcpu_id() as usize;
        let depth = LOCK_DEPTH[vid].fetch_add(1, Ordering::Relaxed);
        if depth == 0 {
            SCHED_LOCK.acquire();
        }
        Self { vid }
    }

    /// Lock without going through cpu_local (safe during early init before
    /// the backend CPU-local register is set up — uses vid=0).
    #[inline]
    pub fn lock_vid0() -> Self {
        let depth = LOCK_DEPTH[0].fetch_add(1, Ordering::Relaxed);
        if depth == 0 {
            SCHED_LOCK.acquire();
        }
        Self { vid: 0 }
    }

    /// Returns true if the scheduler lock is currently held by this vCPU.
    #[inline]
    pub fn is_held() -> bool {
        let vid = vcpu_id() as usize;
        LOCK_DEPTH[vid].load(Ordering::Relaxed) > 0
    }

    /// Manually release without running deferred work (used in context switch
    /// paths where we transfer ownership to the new thread).
    #[inline]
    pub fn release_raw(vid: usize) {
        let depth = LOCK_DEPTH[vid].fetch_sub(1, Ordering::Relaxed);
        if depth == 1 {
            SCHED_LOCK.release();
        }
    }
}

/// Release scheduler lock for context-switch paths that may hold the lock
/// either through `KSchedulerLock` (depth > 0) or a raw `SCHED_LOCK.acquire()`.
#[inline]
pub fn unlock_after_raw_or_scoped(vid: usize) {
    if LOCK_DEPTH[vid].load(Ordering::Relaxed) > 0 {
        KSchedulerLock::release_raw(vid);
    } else {
        SCHED_LOCK.release();
    }
}

/// Raw scheduler spinlock guard that does not participate in unlock-edge
/// scheduling. Use only for bootstrap/pre-entry setup that must touch scheduler
/// state without committing a scheduling decision on drop.
pub struct RawSchedLockGuard;

impl RawSchedLockGuard {
    #[inline]
    pub fn lock() -> Self {
        SCHED_LOCK.acquire();
        Self
    }
}

impl Drop for RawSchedLockGuard {
    fn drop(&mut self) {
        SCHED_LOCK.release();
    }
}

impl Drop for KSchedulerLock {
    fn drop(&mut self) {
        let depth = LOCK_DEPTH[self.vid].fetch_sub(1, Ordering::Relaxed);
        if depth == 1 {
            // Final unlock — mirrors Atmosphere's KAbstractSchedulerLock::Unlock():
            //   1. build_unlock_edge_dispatch_locked: run scheduler core and build
            //      the unlock-edge dispatch object.
            //   2. Release the spinlock.
            //   3. dispatch.apply_after_unlock(): IPI other cores, then perform
            //      the local switch inline.
            let dispatch = crate::sched::schedule::build_unlock_edge_dispatch_locked(self.vid);
            SCHED_LOCK.release();
            dispatch.apply_after_unlock(self.vid);
        }
    }
}

// ── Scoped lock helper ────────────────────────────────────────────────────────

/// Run `f` with the scheduler lock held. Returns the result of `f`.
#[inline]
pub fn with_sched_lock<R>(f: impl FnOnce() -> R) -> R {
    let _guard = KSchedulerLock::lock();
    f()
}

/// Run `f` with the scheduler lock held (vid=0 variant for early init).
#[inline]
pub fn with_sched_lock_vid0<R>(f: impl FnOnce() -> R) -> R {
    let _guard = KSchedulerLock::lock_vid0();
    f()
}

/// Run `f` under the raw scheduler spinlock without triggering unlock-edge
/// scheduling on scope exit.
#[inline]
pub fn with_sched_raw_lock<R>(f: impl FnOnce() -> R) -> R {
    let _guard = RawSchedLockGuard::lock();
    f()
}

// ── SchedLockAndSleep ─────────────────────────────────────────────────────────

/// RAII equivalent of Atmosphere's KScopedSchedulerLockAndSleep.
///
/// Acquires the scheduler lock on construction.  On drop:
///   1. Any wait deadline is already registered via `block_thread_locked`'s
///      `wait.deadline` field — no extra action needed here.
///   2. The inner `KSchedulerLock` drops, triggering unlock-edge plan building
///      and local plan execution, which performs the actual context switch.
///
/// Usage pattern (syscall handler):
/// ```ignore
/// let result = {
///     let mut slp = SchedLockAndSleep::new(tid, deadline);
///     if obj.is_signaled() { slp.cancel(); STATUS_SUCCESS }
///     else if deadline == WaitDeadline::Immediate { slp.cancel(); STATUS_TIMEOUT }
///     else {
///         obj.enqueue_waiter(tid);
///         block_thread_locked(tid, deadline);
///         STATUS_PENDING   // slp drops here → unlock-edge → thread switches out
///     }
/// };
/// // Thread resumes here after being unblocked.
/// if result == STATUS_PENDING {
///     with_thread(tid, |t| t.wait.result).unwrap_or(STATUS_TIMEOUT)
/// } else { result }
/// ```
pub struct SchedLockAndSleep {
    _guard: KSchedulerLock,
}

impl SchedLockAndSleep {
    #[inline]
    pub fn new() -> Self {
        Self {
            _guard: KSchedulerLock::lock(),
        }
    }

    /// No-op compatibility helper for legacy wait paths that call `cancel()`
    /// before returning without changing thread state.
    #[inline]
    pub fn cancel(&mut self) {}
}

impl Drop for SchedLockAndSleep {
    fn drop(&mut self) {}
}
