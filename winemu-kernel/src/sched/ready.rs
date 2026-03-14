// sched/ready.rs — Single-entry ready-queue mutations and selection helpers
//
// All functions require the scheduler lock to be held.

use crate::sched::global::{with_thread, with_thread_mut, SCHED};

#[inline]
fn clear_ready_link_locked(tid: u32) {
    with_thread_mut(tid, |t| {
        t.in_ready_queue = false;
        t.sched_next = 0;
    });
}

/// Enqueue `tid` into the ready queue using its current priority.
/// Returns `true` if a new ready link was created.
pub fn enqueue_ready_thread_locked(tid: u32) -> bool {
    if tid == 0 {
        return false;
    }
    if with_thread(tid, |t| t.in_ready_queue).unwrap_or(false) {
        return false;
    }

    let priority = with_thread(tid, |t| t.priority).unwrap_or(8);
    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw_mut() } as *mut crate::sched::thread_store::ThreadStore;
    queue.push_with_store(tid, priority, &mut |id| {
        // SAFETY: caller holds the scheduler lock, so mutable access to the
        // thread store is exclusive for ready-queue link patching.
        unsafe { (*store).get_mut(id) }
    });
    with_thread_mut(tid, |t| {
        t.in_ready_queue = true;
    });
    true
}

/// Remove `tid` from the ready queue if it is currently linked there.
/// Returns `true` if queue unlink succeeded.
pub fn dequeue_ready_thread_locked(tid: u32) -> bool {
    let Some((priority, in_ready_queue)) = with_thread(tid, |t| (t.priority, t.in_ready_queue))
    else {
        return false;
    };
    if !in_ready_queue {
        return false;
    }

    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw() };
    let removed = queue.remove(tid, priority, &|id| store.get_ptr(id));
    clear_ready_link_locked(tid);
    removed
}

/// Reinsert a currently ready thread after its runnable ordering changed
/// (for example priority or affinity updates).
pub fn refresh_ready_thread_locked(tid: u32) -> bool {
    let was_ready = with_thread(tid, |t| t.in_ready_queue).unwrap_or(false);
    if !was_ready {
        return false;
    }
    let _ = dequeue_ready_thread_locked(tid);
    enqueue_ready_thread_locked(tid)
}

/// Peek at the highest-priority ready thread runnable on `vid` without
/// removing it from the queue.
pub fn peek_next_ready_thread_for_vcpu_locked(vid: u32) -> u32 {
    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw() };
    queue.peek_highest_matching(&|id| store.get_ptr(id).map(|p| p as *const _), &|t| {
        t.can_run_on_vcpu(vid)
    })
}

/// Remove and return the highest-priority ready thread runnable on `vid`.
pub fn take_next_ready_thread_for_vcpu_locked(vid: u32) -> u32 {
    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw() };
    let tid = queue.pop_highest_matching(&|id| store.get_ptr(id), &|t| t.can_run_on_vcpu(vid));
    if tid != 0 {
        clear_ready_link_locked(tid);
    }
    tid
}
