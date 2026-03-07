// sched/topology.rs — vCPU affinity, set_thread_state_locked, reschedule hints
//
// All functions require the scheduler lock to be held.

use core::sync::atomic::Ordering;
use crate::sched::cpu::{cpu_local, vcpu_id};
use crate::sched::global::{SCHED, with_thread, with_thread_mut};
use crate::sched::types::{KThread, ThreadState, MAX_VCPUS};

// ── set_thread_state_locked ───────────────────────────────────────────────────

/// Transition a thread's state and update the ready queue accordingly.
/// Must be called with the scheduler lock held.
pub fn set_thread_state_locked(tid: u32, new_state: ThreadState) {
    let (old_state, priority, is_idle) = match with_thread(tid, |t| {
        (t.state, t.priority, t.is_idle_thread)
    }) {
        Some(v) => v,
        None => return,
    };

    if old_state == new_state {
        return;
    }

    // Idle threads bypass the ready queue entirely.
    if is_idle {
        with_thread_mut(tid, |t| t.state = new_state);
        return;
    }

    // Remove from ready queue if was Ready.
    if old_state == ThreadState::Ready {
        let queue = unsafe { SCHED.queue_raw_mut() };
        let store = unsafe { SCHED.threads_raw() };
        queue.remove(tid, priority, &|id| {
            store.get_ptr(id)
        });
    }

    // Update state.
    with_thread_mut(tid, |t| t.state = new_state);

    // Push to ready queue if becoming Ready.
    if new_state == ThreadState::Ready {
        let priority = with_thread(tid, |t| t.priority).unwrap_or(8);
        let queue = unsafe { SCHED.queue_raw_mut() };
        let store = unsafe { SCHED.threads_raw_mut() } as *mut crate::sched::thread_store::ThreadStore;
        queue.push_with_store(tid, priority, &mut |id| unsafe { (*store).get_mut(id) });

        // Signal a vCPU that might be idle.
        hint_reschedule_any_idle();
    }

    // Notify flush_unlock_edge that a full re-scan is needed.
    SCHED.scheduler_update_needed.store(true, Ordering::Relaxed);
}

// ── Reschedule hints ──────────────────────────────────────────────────────────

/// Mark the current vCPU as needing a reschedule.
#[inline]
pub fn request_reschedule_self() {
    cpu_local().needs_reschedule = true;
}

/// Mark a specific vCPU as needing a reschedule.
pub fn request_reschedule_vcpu(vid: u32) {
    if (vid as usize) < MAX_VCPUS {
        unsafe { SCHED.vcpu_raw_mut(vid as usize) }.needs_scheduling = true;
    }
}

/// Find an idle vCPU and mark it for reschedule (to pick up a newly ready thread).
pub fn hint_reschedule_any_idle() {
    for vid in 0..MAX_VCPUS {
        let vs = unsafe { SCHED.vcpu_raw(vid) };
        if vs.is_idle {
            unsafe { SCHED.vcpu_raw_mut(vid) }.needs_scheduling = true;
            return;
        }
    }
    // No idle vCPU found — mark all for reschedule so preemption can occur.
    for vid in 0..MAX_VCPUS {
        unsafe { SCHED.vcpu_raw_mut(vid) }.needs_scheduling = true;
    }
}

// ── Affinity helpers ──────────────────────────────────────────────────────────

/// Returns true if `tid` can run on `vid`.
pub fn thread_can_run_on(tid: u32, vid: u32) -> bool {
    with_thread(tid, |t| {
        (t.affinity_mask & (1u32 << vid)) != 0
    }).unwrap_or(false)
}

/// Returns the best vCPU hint for a thread (last used or least loaded).
pub fn pick_vcpu_for_thread(tid: u32) -> u32 {
    let hint = with_thread(tid, |t| t.last_vcpu_hint as u32).unwrap_or(0);
    if hint < MAX_VCPUS as u32 {
        hint
    } else {
        0
    }
}

// ── vCPU current-thread tracking ─────────────────────────────────────────────

/// Record that `tid` is now running on `vid`.
pub fn set_vcpu_current_thread(vid: usize, tid: u32) {
    if vid < MAX_VCPUS {
        unsafe { SCHED.vcpu_raw_mut(vid) }.current_tid = tid;
    }
    // Also update the per-vCPU TLS if this is the current vCPU.
    if vid == vcpu_id() as usize {
        cpu_local().current_tid = tid;
    }
}

/// Get the TID currently running on `vid` (0 = idle).
pub fn get_vcpu_current_thread(vid: usize) -> u32 {
    if vid < MAX_VCPUS {
        unsafe { SCHED.vcpu_raw(vid) }.current_tid
    } else {
        0
    }
}

/// Returns true if any real (non-idle) thread is running on any vCPU.
pub fn any_thread_running() -> bool {
    for vid in 0..MAX_VCPUS {
        let cur = unsafe { SCHED.vcpu_raw(vid) }.current_tid;
        if cur != 0 {
            let is_idle = with_thread(cur, |t| t.is_idle_thread).unwrap_or(true);
            if !is_idle {
                return true;
            }
        }
    }
    false
}

/// Returns true if all threads are terminated (no Ready/Running/Waiting threads).
pub fn all_threads_done() -> bool {
    let store = unsafe { SCHED.threads_raw() };
    let mut found = false;
    store.for_each(|_tid, t| {
        if !t.is_idle_thread {
            match t.state {
                ThreadState::Ready | ThreadState::Running | ThreadState::Waiting => {
                    found = true;
                }
                _ => {}
            }
        }
    });
    !found
}
