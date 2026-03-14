// sched/wait.rs — Thread block/unblock/timeout logic
//
// block_thread_locked   — put current thread into Waiting state
// unblock_thread_locked — wake a waiting thread (set Ready)
// check_wait_timeout    — called from scheduler round to expire deadlines

use crate::sched::global::{with_thread, with_thread_mut, SCHED};
use crate::sched::resched::request_local_trap_reschedule;
use crate::sched::topology::set_thread_state_locked;
use crate::sched::types::{
    ThreadState, WaitDeadline, WAIT_KIND_DELAY, WAIT_KIND_MULTIPLE, WAIT_KIND_NONE,
    WAIT_KIND_SINGLE,
};

// ── NTSTATUS codes ────────────────────────────────────────────────────────────

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_TIMEOUT: u32 = 0x0000_0102;
pub const STATUS_ABANDONED_WAIT_0: u32 = 0x0000_0080;
pub const STATUS_USER_APC: u32 = 0x0000_00C0;

// ── block_thread_locked ───────────────────────────────────────────────────────

/// Block the current thread, transitioning it to Waiting.
/// `deadline` controls timeout behaviour.
/// Must be called with the scheduler lock held.
pub fn block_thread_locked(tid: u32, deadline: WaitDeadline) {
    let dl = deadline.to_ticks();
    with_thread_mut(tid, |t| {
        t.wait.deadline = dl;
        t.wait.result = STATUS_SUCCESS;
    });
    set_thread_state_locked(tid, ThreadState::Waiting);
}

/// Block the current thread for a pure delay (NtDelayExecution).
pub fn block_thread_delay_locked(tid: u32, deadline: WaitDeadline) {
    with_thread_mut(tid, |t| {
        t.wait.kind = WAIT_KIND_DELAY;
        t.wait.deadline = deadline.to_ticks();
        t.wait.result = STATUS_SUCCESS;
    });
    set_thread_state_locked(tid, ThreadState::Waiting);
}

// ── unblock_thread_locked ─────────────────────────────────────────────────────

/// Wake a waiting thread with the given result code.
/// No-op if the thread is not in Waiting state.
/// Must be called with the scheduler lock held.
pub fn unblock_thread_locked(tid: u32, result: u32) {
    let Some((state, wait_kind)) = with_thread(tid, |t| (t.state, t.wait.kind)) else {
        return;
    };
    if state != ThreadState::Waiting {
        // Defensive cleanup: a raced wake/timeout can leave stale sync wait-link
        // metadata behind even after state transitioned away from Waiting.
        if wait_kind == WAIT_KIND_SINGLE || wait_kind == WAIT_KIND_MULTIPLE {
            crate::sched::sync::detach_thread_sync_wait_links_locked(tid);
            with_thread_mut(tid, |t| {
                t.wait.kind = WAIT_KIND_NONE;
                t.wait.handle_count = 0;
                t.wait.wait_all = false;
                t.wait.signaled_mask = 0;
                t.wait.wait_next = 0;
            });
        }
        return;
    }
    crate::sched::sync::detach_thread_sync_wait_links_locked(tid);
    with_thread_mut(tid, |t| {
        t.wait.result = result;
        t.wait.kind = WAIT_KIND_NONE;
        t.wait.handle_count = 0;
        t.wait.wait_all = false;
        t.wait.signaled_mask = 0;
        t.wait.wait_next = 0;
    });
    set_thread_state_locked(tid, ThreadState::Ready);
    // Wake-up should be observed at the current unlock edge so syscall paths
    // can promptly hand off to newly readied peers.
    request_local_trap_reschedule();
}

/// Wake a waiting thread due to timeout.
pub fn timeout_thread_locked(tid: u32) {
    unblock_thread_locked(tid, STATUS_TIMEOUT);
}

// ── check_wait_timeout ────────────────────────────────────────────────────────

/// Scan all Waiting threads and expire those whose deadline has passed.
/// Returns the number of threads woken.
/// Must be called with the scheduler lock held.
pub fn check_wait_timeouts_locked() -> u32 {
    let now = current_ticks();
    let mut expired_tids = [0u32; 64];
    let mut count = 0usize;

    {
        let store = unsafe { SCHED.threads_raw() };
        store.for_each(|tid, t| {
            if t.state == ThreadState::Waiting
                && t.wait.deadline != u64::MAX
                && now >= t.wait.deadline
                && count < expired_tids.len()
            {
                expired_tids[count] = tid;
                count += 1;
            }
        });
    }

    for i in 0..count {
        timeout_thread_locked(expired_tids[i]);
    }
    count as u32
}

// ── Tick source ───────────────────────────────────────────────────────────────

/// Read the current monotonic tick counter (100ns units, from the backend timer counter).
#[inline]
pub fn current_ticks() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, cntvct_el0",
            out(reg) v,
            options(nostack, readonly),
        );
    }
    v
}

/// Convert a relative timeout in 100ns units to an absolute deadline tick.
/// Negative value = relative; positive = absolute (Windows convention).
pub fn timeout_to_deadline(timeout_100ns: i64) -> WaitDeadline {
    if timeout_100ns == 0 {
        return WaitDeadline::Immediate;
    }
    if timeout_100ns == i64::MIN {
        return WaitDeadline::Infinite;
    }
    if timeout_100ns < 0 {
        // Relative timeout: convert to absolute.
        let rel = (-timeout_100ns) as u64;
        let freq: u64;
        unsafe {
            core::arch::asm!(
                "mrs {0}, cntfrq_el0",
                out(reg) freq,
                options(nostack, readonly),
            );
        }
        // CNTVCT ticks at `freq` Hz; 100ns = freq/10_000_000 ticks.
        let ticks_per_100ns = freq / 10_000_000;
        let delta = rel.saturating_mul(ticks_per_100ns.max(1));
        WaitDeadline::DeadlineTicks(current_ticks().saturating_add(delta))
    } else {
        // Absolute timeout (Windows FILETIME-based) — treat as infinite for now.
        // TODO: convert Windows FILETIME to CNTVCT ticks.
        WaitDeadline::Infinite
    }
}
