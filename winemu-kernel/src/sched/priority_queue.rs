// sched/priority_queue.rs — Mesosphere-style shadow queue snapshot
//
// Phase A scope:
// - keep a lightweight Scheduled/Suggested view for diagnostics;
// - do not drive runtime scheduling decisions yet.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sched::global::SCHED;
use crate::sched::types::{ThreadState, MAX_VCPUS};

pub struct KPriorityQueue {
    scheduled_front: [u32; MAX_VCPUS],
    scheduled_prio: [u8; MAX_VCPUS],
    suggested_front: [u32; MAX_VCPUS],
    suggested_prio: [u8; MAX_VCPUS],
    runnable_count: u32,
}

impl KPriorityQueue {
    pub const fn new() -> Self {
        Self {
            scheduled_front: [0u32; MAX_VCPUS],
            scheduled_prio: [u8::MAX; MAX_VCPUS],
            suggested_front: [0u32; MAX_VCPUS],
            suggested_prio: [u8::MAX; MAX_VCPUS],
            runnable_count: 0,
        }
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }

    #[inline]
    pub fn get_scheduled_front(&self, core: usize) -> u32 {
        if core < MAX_VCPUS {
            self.scheduled_front[core]
        } else {
            0
        }
    }

    #[inline]
    pub fn get_suggested_front(&self, core: usize) -> u32 {
        if core < MAX_VCPUS {
            self.suggested_front[core]
        } else {
            0
        }
    }

    #[inline]
    pub fn runnable_count(&self) -> u32 {
        self.runnable_count
    }

    #[inline]
    fn pick_active_core_for_affinity(last_vcpu_hint: u8, affinity_mask: u32) -> i8 {
        let hint = last_vcpu_hint as usize;
        if hint < MAX_VCPUS && (affinity_mask & (1u32 << hint)) != 0 {
            return hint as i8;
        }
        for core in 0..MAX_VCPUS {
            if (affinity_mask & (1u32 << core)) != 0 {
                return core as i8;
            }
        }
        -1
    }

    #[inline]
    fn consider_scheduled_candidate(&mut self, core: usize, tid: u32, prio: u8) {
        let cur_tid = self.scheduled_front[core];
        let cur_prio = self.scheduled_prio[core];
        if cur_tid == 0 || prio < cur_prio || (prio == cur_prio && tid < cur_tid) {
            self.scheduled_front[core] = tid;
            self.scheduled_prio[core] = prio;
        }
    }

    #[inline]
    fn consider_suggested_candidate(&mut self, core: usize, tid: u32, prio: u8) {
        let cur_tid = self.suggested_front[core];
        let cur_prio = self.suggested_prio[core];
        if cur_tid == 0 || prio < cur_prio || (prio == cur_prio && tid < cur_tid) {
            self.suggested_front[core] = tid;
            self.suggested_prio[core] = prio;
        }
    }
}

struct ShadowQueueCell {
    inner: UnsafeCell<KPriorityQueue>,
}

unsafe impl Sync for ShadowQueueCell {}

impl ShadowQueueCell {
    const fn new() -> Self {
        Self {
            inner: UnsafeCell::new(KPriorityQueue::new()),
        }
    }

    #[inline]
    fn get(&self) -> *mut KPriorityQueue {
        self.inner.get()
    }
}

static SHADOW_PRIORITY_QUEUE: ShadowQueueCell = ShadowQueueCell::new();
static SHADOW_PRIORITY_QUEUE_DIRTY: AtomicBool = AtomicBool::new(true);

#[inline]
fn shadow_queue_mut() -> &'static mut KPriorityQueue {
    // SAFETY: callers hold scheduler lock when invoking rebuild/validate.
    unsafe { &mut *SHADOW_PRIORITY_QUEUE.get() }
}

#[inline]
pub fn mark_shadow_priority_queue_dirty_locked() {
    SHADOW_PRIORITY_QUEUE_DIRTY.store(true, Ordering::Relaxed);
}

pub fn rebuild_shadow_priority_queue_if_dirty_locked() {
    if !SHADOW_PRIORITY_QUEUE_DIRTY.swap(false, Ordering::AcqRel) {
        return;
    }
    rebuild_shadow_priority_queue_locked();
    validate_shadow_priority_queue_locked();
}

pub fn rebuild_shadow_priority_queue_locked() {
    let queue = shadow_queue_mut();
    queue.clear();

    let store = unsafe { SCHED.threads_raw() };
    store.for_each(|tid, t| {
        if t.is_idle_thread {
            return;
        }
        if t.state != ThreadState::Ready && t.state != ThreadState::Running {
            return;
        }
        if t.affinity_mask == 0 {
            return;
        }

        queue.runnable_count = queue.runnable_count.saturating_add(1);
        let prio = t.priority.min(31);
        let active_core =
            KPriorityQueue::pick_active_core_for_affinity(t.last_vcpu_hint, t.affinity_mask);

        if t.in_kernel {
            if active_core >= 0 {
                queue.consider_scheduled_candidate(active_core as usize, tid, prio);
            }
            return;
        }

        for core in 0..MAX_VCPUS {
            if (t.affinity_mask & (1u32 << core)) == 0 {
                continue;
            }
            if active_core >= 0 && core == active_core as usize {
                queue.consider_scheduled_candidate(core, tid, prio);
            } else {
                queue.consider_suggested_candidate(core, tid, prio);
            }
        }
    });
}

pub fn validate_shadow_priority_queue_locked() {
    let queue = shadow_queue_mut();
    let store = unsafe { SCHED.threads_raw() };

    let mut runnable_count = 0u32;
    store.for_each(|_, t| {
        if !t.is_idle_thread
            && t.affinity_mask != 0
            && (t.state == ThreadState::Ready || t.state == ThreadState::Running)
        {
            runnable_count = runnable_count.saturating_add(1);
        }
    });

    if runnable_count != queue.runnable_count() {
        crate::kerror!(
            "sched: shadow queue runnable mismatch shadow={} actual={}",
            queue.runnable_count(),
            runnable_count
        );
    }

    for core in 0..MAX_VCPUS {
        let check_front = |kind: &str, tid: u32| {
            if tid == 0 {
                return;
            }
            let Some(t) = store.get(tid) else {
                crate::kerror!(
                    "sched: shadow queue {} front invalid core={} tid={} (missing)",
                    kind,
                    core,
                    tid
                );
                return;
            };
            if t.is_idle_thread
                || (t.state != ThreadState::Ready && t.state != ThreadState::Running)
                || (t.affinity_mask & (1u32 << core)) == 0
            {
                crate::kerror!(
                    "sched: shadow queue {} front invalid core={} tid={} state={} affinity={:#x}",
                    kind,
                    core,
                    tid,
                    t.state as u8,
                    t.affinity_mask
                );
            }
        };

        check_front("scheduled", queue.get_scheduled_front(core));
        check_front("suggested", queue.get_suggested_front(core));
    }
}

pub fn shadow_pick_for_vcpu(vid: usize, idle_tid: u32) -> u32 {
    if vid >= MAX_VCPUS {
        return 0;
    }
    let queue = shadow_queue_mut();
    let scheduled = queue.get_scheduled_front(vid);
    if scheduled != 0 {
        return scheduled;
    }
    let suggested = queue.get_suggested_front(vid);
    if suggested != 0 {
        return suggested;
    }
    idle_tid
}
