// sched/ready.rs — Single-entry ready-queue mutations and selection helpers
//
// All functions require the scheduler lock to be held.

use core::sync::atomic::Ordering;

use crate::sched::cpu::current_tid;
use crate::sched::global::{with_thread, with_thread_mut, SCHED};
use crate::sched::queue::{ReadyQueueCandidate, ReadyQueueShape};
use crate::sched::resched::{
    request_local_trap_reschedule, request_remote_reschedule_for_ready_work_locked,
    request_remote_vcpu_reschedule_locked,
};
use crate::sched::types::CpuMask;

#[inline]
fn clear_ready_links_locked(tid: u32) {
    with_thread_mut(tid, |t| {
        t.in_ready_queue = false;
        t.scheduled_next = 0;
        t.suggested_next.fill(0);
    });
}

#[inline]
fn ready_queue_shape_for_thread(tid: u32) -> Option<ReadyQueueShape> {
    with_thread(tid, |t| {
        let effective_affinity = t.affinity_mask.intersection(online_cpu_mask_locked());
        ReadyQueueShape {
            home_core: t.ready_home_vcpu(),
            affinity_mask: effective_affinity,
            priority: t.priority,
            allow_migration: !t.in_kernel && effective_affinity.count() > 1,
        }
    })
}

#[inline]
pub fn ready_queue_shape_for_thread_locked(tid: u32) -> Option<ReadyQueueShape> {
    ready_queue_shape_for_thread(tid)
}

#[inline]
fn vcpu_is_idle_locked(vid: usize) -> bool {
    let vs = unsafe { SCHED.vcpu_raw(vid) };
    let cur = vs.current_tid;
    cur == 0 || cur == vs.idle_tid || with_thread(cur, |t| t.is_idle_thread).unwrap_or(true)
}

#[inline]
fn online_cpu_mask_locked() -> CpuMask {
    let mut mask = CpuMask::empty();
    for vid in 0..crate::sched::MAX_VCPUS {
        if unsafe { SCHED.vcpu_raw(vid) }.idle_tid != 0 {
            mask.insert(vid);
        }
    }
    if mask.is_empty() {
        CpuMask::from_cpu(0)
    } else {
        mask
    }
}

#[inline]
pub fn mark_scheduler_topology_changed_locked() {
    SCHED.scheduler_update_needed.store(true, Ordering::Relaxed);
}

pub fn notify_ready_thread_available_locked(tid: u32) {
    request_remote_reschedule_for_ready_work_locked(vcpu_is_idle_locked);
    if tid != current_tid() {
        request_local_trap_reschedule();
    }
}

/// Enqueue `tid` into the ready queue using the thread's current priority,
/// home core hint and affinity mask.
/// Returns `true` if a new ready link was created.
pub fn enqueue_ready_thread_locked(tid: u32) -> bool {
    if tid == 0 {
        return false;
    }
    if with_thread(tid, |t| t.in_ready_queue).unwrap_or(false) {
        return false;
    }

    let Some(shape) = ready_queue_shape_for_thread(tid) else {
        return false;
    };

    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw_mut() } as *mut crate::sched::thread_store::ThreadStore;
    queue.enqueue(tid, shape, &mut |id| {
        // SAFETY: caller holds the scheduler lock, so mutable access to the
        // thread store is exclusive for ready-queue link patching.
        unsafe { (*store).get_mut(id) }
    });
    with_thread_mut(tid, |t| {
        t.in_ready_queue = true;
    });
    true
}

fn remove_ready_thread_with_shape_locked(tid: u32, shape: ReadyQueueShape) -> bool {
    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw() };
    let removed = queue.remove(tid, shape, &|id| store.get_ptr(id));
    if removed {
        clear_ready_links_locked(tid);
    } else {
        crate::kerror!(
            "sched: ready dequeue miss tid={} home_core={} prio={} affinity={:#x} migrate={}",
            tid,
            shape.home_core,
            shape.priority,
            shape.affinity_mask.to_low_u64(),
            shape.allow_migration
        );
    }
    removed
}

/// Remove `tid` from the ready queue if it is currently linked there.
/// Returns `true` if queue unlink succeeded.
pub fn dequeue_ready_thread_locked(tid: u32) -> bool {
    if tid == 0 {
        return false;
    }

    let in_ready_queue = with_thread(tid, |t| t.in_ready_queue).unwrap_or(false);
    if !in_ready_queue {
        return false;
    }

    let Some(shape) = ready_queue_shape_for_thread(tid) else {
        return false;
    };

    remove_ready_thread_with_shape_locked(tid, shape)
}

fn change_ready_thread_shape_locked(tid: u32, old_shape: ReadyQueueShape) -> bool {
    if tid == 0 || !with_thread(tid, |t| t.in_ready_queue).unwrap_or(false) {
        return false;
    }

    let Some(new_shape) = ready_queue_shape_for_thread(tid) else {
        return false;
    };

    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw_mut() } as *mut crate::sched::thread_store::ThreadStore;
    queue.change_affinity(
        tid,
        old_shape,
        new_shape,
        &|id| {
            // SAFETY: caller holds the scheduler lock, so queue-link removal
            // can inspect stable thread pointers from the scheduler store.
            unsafe { (*store).get_ptr(id) }
        },
        &mut |id| {
            // SAFETY: caller holds the scheduler lock, so mutable access to the
            // thread store is exclusive for ready-queue relinking.
            unsafe { (*store).get_mut(id) }
        },
    )
}

/// Reorder a ready thread after its priority changed.
pub fn change_ready_thread_priority_locked(tid: u32, old_priority: u8) -> bool {
    if tid == 0 || !with_thread(tid, |t| t.in_ready_queue).unwrap_or(false) {
        return false;
    }

    let Some(new_shape) = ready_queue_shape_for_thread(tid) else {
        return false;
    };

    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw_mut() } as *mut crate::sched::thread_store::ThreadStore;
    queue.change_priority(
        tid,
        old_priority,
        new_shape,
        &|id| {
            // SAFETY: caller holds the scheduler lock, so queue-link removal
            // can inspect stable thread pointers from the scheduler store.
            unsafe { (*store).get_ptr(id) }
        },
        &mut |id| {
            // SAFETY: caller holds the scheduler lock, so mutable access to the
            // thread store is exclusive for ready-queue relinking.
            unsafe { (*store).get_mut(id) }
        },
    )
}

/// Reorder a ready thread after its affinity/home-core placement changed.
pub fn change_ready_thread_affinity_locked(tid: u32, old_shape: ReadyQueueShape) -> bool {
    change_ready_thread_shape_locked(tid, old_shape)
}

/// Peek at the highest-priority ready thread runnable on `vid` without
/// removing it from the queue.
pub fn peek_ready_candidate_for_vcpu_locked(vid: u32) -> Option<ReadyQueueCandidate> {
    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw() };
    queue.peek_candidate_for_core(vid as usize, &|id| store.get_ptr(id).map(|p| p as *const _))
}

/// Peek at the highest-priority ready thread runnable on `vid` without
/// removing it from the queue.
pub fn peek_next_ready_thread_for_vcpu_locked(vid: u32) -> u32 {
    peek_ready_candidate_for_vcpu_locked(vid)
        .map(|candidate| candidate.tid)
        .unwrap_or(0)
}

/// Commit a previously peeked ready candidate for execution on `vid`.
pub fn commit_ready_candidate_for_vcpu_locked(candidate: ReadyQueueCandidate, vid: u32) -> u32 {
    if candidate.requires_migration {
        let Some(mut shape) = ready_queue_shape_for_thread(candidate.tid) else {
            return 0;
        };
        shape.home_core = candidate.source_core;
        let removed = remove_ready_thread_with_shape_locked(candidate.tid, shape);
        debug_assert!(
            removed,
            "ready thread migration commit failed tid={} source_core={} vid={vid}",
            candidate.tid, candidate.source_core,
        );
        if removed {
            mark_scheduler_topology_changed_locked();
            request_remote_vcpu_reschedule_locked(candidate.source_core);
            return candidate.tid;
        }
        return 0;
    }
    if dequeue_ready_thread_locked(candidate.tid) {
        candidate.tid
    } else {
        0
    }
}
