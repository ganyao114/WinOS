// sched/global.rs — KGlobalScheduler: the single scheduler state singleton

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::sched::queue::KReadyQueue;
use crate::sched::thread_store::ThreadStore;
use crate::sched::types::{KThread, MAX_VCPUS};

// ── Per-vCPU state ────────────────────────────────────────────────────────────

pub struct KVcpuState {
    pub current_tid: u32,
    pub idle_tid: u32,
    pub needs_scheduling: bool,
    pub is_idle: bool,
    /// Next thread selected by flush_unlock_edge (0 = none/idle).
    pub highest_priority_tid: u32,
}

impl KVcpuState {
    const fn new() -> Self {
        Self {
            current_tid: 0,
            idle_tid: 0,
            needs_scheduling: false,
            is_idle: false,
            highest_priority_tid: 0,
        }
    }
}

// ── Deferred kstack reclaim ───────────────────────────────────────────────────

const MAX_DEFERRED_KSTACKS: usize = 16;

pub struct DeferredKstacks {
    bases: [u64; MAX_DEFERRED_KSTACKS],
    sizes: [usize; MAX_DEFERRED_KSTACKS],
    count: usize,
}

impl DeferredKstacks {
    const fn new() -> Self {
        Self {
            bases: [0u64; MAX_DEFERRED_KSTACKS],
            sizes: [0usize; MAX_DEFERRED_KSTACKS],
            count: 0,
        }
    }

    pub fn push(&mut self, base: u64, size: usize) -> bool {
        if self.count >= MAX_DEFERRED_KSTACKS {
            return false;
        }
        self.bases[self.count] = base;
        self.sizes[self.count] = size;
        self.count += 1;
        true
    }

    pub fn drain(&mut self, mut f: impl FnMut(u64, usize)) {
        let n = self.count;
        self.count = 0;
        for i in 0..n {
            f(self.bases[i], self.sizes[i]);
        }
    }
}

// ── KGlobalScheduler ─────────────────────────────────────────────────────────

pub struct KGlobalScheduler {
    /// Option<ThreadStore> — None until init() is called.
    threads: UnsafeCell<Option<ThreadStore>>,
    pub ready_queue: UnsafeCell<KReadyQueue>,
    pub vcpus: UnsafeCell<[KVcpuState; MAX_VCPUS]>,
    pub deferred_kstacks: UnsafeCell<DeferredKstacks>,
    /// bitmask of vCPUs that need a reschedule IPI
    pub reschedule_mask: AtomicU32,
    /// monotonic schedule-event counter (for debug)
    pub schedule_events: AtomicU32,
    /// Set when thread state changes; cleared by update_highest_priority_threads.
    /// Mirrors Atmosphere's s_scheduler_update_needed.
    pub scheduler_update_needed: AtomicBool,
    initialized: AtomicU32,
}

unsafe impl Sync for KGlobalScheduler {}
unsafe impl Send for KGlobalScheduler {}

impl KGlobalScheduler {
    const fn new_uninit() -> Self {
        Self {
            threads: UnsafeCell::new(None),
            ready_queue: UnsafeCell::new(KReadyQueue::new()),
            vcpus: UnsafeCell::new([
                KVcpuState::new(),
                KVcpuState::new(),
                KVcpuState::new(),
                KVcpuState::new(),
                KVcpuState::new(),
                KVcpuState::new(),
                KVcpuState::new(),
                KVcpuState::new(),
            ]),
            deferred_kstacks: UnsafeCell::new(DeferredKstacks::new()),
            reschedule_mask: AtomicU32::new(0),
            schedule_events: AtomicU32::new(0),
            scheduler_update_needed: AtomicBool::new(false),
            initialized: AtomicU32::new(0),
        }
    }

    pub fn init(&self) {
        if self.initialized.swap(1, Ordering::AcqRel) == 0 {
            unsafe { *self.threads.get() = Some(ThreadStore::new()) };
        }
    }

    // ── Raw accessors (caller must hold scheduler lock) ───────────────────

    #[inline]
    pub unsafe fn threads_raw(&self) -> &ThreadStore {
        (*self.threads.get())
            .as_ref()
            .expect("scheduler not initialized")
    }

    #[inline]
    pub unsafe fn threads_raw_mut(&self) -> &mut ThreadStore {
        (*self.threads.get())
            .as_mut()
            .expect("scheduler not initialized")
    }

    #[inline]
    pub unsafe fn queue_raw_mut(&self) -> &mut KReadyQueue {
        &mut *self.ready_queue.get()
    }

    #[inline]
    pub unsafe fn vcpu_raw_mut(&self, vid: usize) -> &mut KVcpuState {
        &mut (*self.vcpus.get())[vid]
    }

    #[inline]
    pub unsafe fn vcpu_raw(&self, vid: usize) -> &KVcpuState {
        &(*self.vcpus.get())[vid]
    }

    #[inline]
    pub unsafe fn deferred_kstacks_mut(&self) -> &mut DeferredKstacks {
        &mut *self.deferred_kstacks.get()
    }
}

// ── Global singleton ──────────────────────────────────────────────────────────

pub static SCHED: KGlobalScheduler = KGlobalScheduler::new_uninit();

pub fn init_scheduler() {
    SCHED.init();
}

// ── Convenience free-functions (require scheduler lock) ──────────────────────

#[inline]
pub fn with_thread<R>(tid: u32, f: impl FnOnce(&KThread) -> R) -> Option<R> {
    unsafe { SCHED.threads_raw() }.get(tid).map(f)
}

#[inline]
pub fn with_thread_mut<R>(tid: u32, f: impl FnOnce(&mut KThread) -> R) -> Option<R> {
    unsafe { SCHED.threads_raw_mut() }.get_mut(tid).map(f)
}

#[inline]
pub fn thread_exists(tid: u32) -> bool {
    if tid == 0 {
        return false;
    }
    unsafe { SCHED.threads_raw() }.contains(tid)
}
