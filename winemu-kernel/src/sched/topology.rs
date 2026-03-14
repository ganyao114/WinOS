// sched/topology.rs — vCPU affinity, state transitions, remote wake hints
//
// All functions require the scheduler lock to be held.

use crate::sched::cpu::{cpu_local, current_tid, vcpu_id};
use crate::sched::global::{with_thread, with_thread_mut, SCHED};
use crate::sched::ready::{dequeue_ready_thread_locked, enqueue_ready_thread_locked};
use crate::sched::resched::{
    request_local_trap_reschedule, request_remote_reschedule_for_ready_work_locked,
    request_remote_vcpu_reschedule_locked,
};
use crate::sched::types::{ThreadState, MAX_VCPUS};
use core::sync::atomic::Ordering;

// ── set_thread_state_locked ───────────────────────────────────────────────────

/// Transition a thread's state and update the ready queue accordingly.
/// Must be called with the scheduler lock held.
pub fn set_thread_state_locked(tid: u32, new_state: ThreadState) {
    let (old_state, is_idle) = match with_thread(tid, |t| (t.state, t.is_idle_thread)) {
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

    // State transition uses a single queue mutation path:
    // remove old Ready link (if any), then reinsert only when becoming Ready.
    if old_state == ThreadState::Ready {
        dequeue_ready_thread_locked(tid);
    }

    // Update state.
    with_thread_mut(tid, |t| t.state = new_state);

    // Push to ready queue if becoming Ready.
    if new_state == ThreadState::Ready {
        enqueue_ready_thread_locked(tid);

        // Signal a vCPU that might be idle.
        hint_reschedule_any_idle();
        // Also force local unlock-edge evaluation so same-priority wake/create
        // paths do not get stuck behind "continue current" policy.
        if tid != crate::sched::cpu::current_tid() {
            request_local_trap_reschedule();
        }
    }

    // Notify the unlock-edge planner that a full topology re-scan is needed.
    SCHED.scheduler_update_needed.store(true, Ordering::Relaxed);
}

// ── Reschedule hints ──────────────────────────────────────────────────────────

/// Mark a specific vCPU as needing a reschedule.
pub fn request_reschedule_vcpu(vid: u32) {
    if (vid as usize) < MAX_VCPUS {
        request_remote_vcpu_reschedule_locked(vid as usize);
    }
}

#[inline]
fn vcpu_is_idle_locked(vid: usize) -> bool {
    let vs = unsafe { SCHED.vcpu_raw(vid) };
    let cur = vs.current_tid;
    cur == 0 || cur == vs.idle_tid || with_thread(cur, |t| t.is_idle_thread).unwrap_or(true)
}

/// Find an idle vCPU and mark it for reschedule (to pick up a newly ready thread).
pub fn hint_reschedule_any_idle() {
    request_remote_reschedule_for_ready_work_locked(vcpu_is_idle_locked);
}

// ── Affinity helpers ──────────────────────────────────────────────────────────

/// Returns true if `tid` can run on `vid`.
pub fn thread_can_run_on(tid: u32, vid: u32) -> bool {
    with_thread(tid, |t| (t.affinity_mask & (1u32 << vid)) != 0).unwrap_or(false)
}

#[inline]
fn active_vcpu_mask_locked() -> u32 {
    let mut mask = 0u32;
    for vid in 0..MAX_VCPUS {
        if unsafe { SCHED.vcpu_raw(vid) }.idle_tid != 0 {
            mask |= 1u32 << vid;
        }
    }
    if mask == 0 {
        1
    } else {
        mask
    }
}

#[inline]
fn find_running_vcpu_for_tid_locked(tid: u32) -> Option<usize> {
    for vid in 0..MAX_VCPUS {
        if unsafe { SCHED.vcpu_raw(vid) }.current_tid == tid {
            return Some(vid);
        }
    }
    None
}

/// Update a thread's affinity mask (Windows KAFFINITY semantics, low bits used).
/// Returns false if mask is invalid after clamping to active vCPUs.
/// Requires scheduler lock to be held.
pub fn set_thread_affinity_mask_locked(tid: u32, requested_mask: u64) -> bool {
    let allowed = active_vcpu_mask_locked();
    let new_mask = (requested_mask as u32) & allowed;
    if new_mask == 0 {
        return false;
    }

    let (state, old_mask, is_idle) =
        match with_thread(tid, |t| (t.state, t.affinity_mask, t.is_idle_thread)) {
        Some(v) => v,
        None => return false,
    };

    if is_idle {
        return false;
    }
    if old_mask == new_mask {
        return true;
    }

    if state == ThreadState::Ready {
        dequeue_ready_thread_locked(tid);
    }

    with_thread_mut(tid, |t| t.affinity_mask = new_mask);

    if state == ThreadState::Ready {
        enqueue_ready_thread_locked(tid);
        hint_reschedule_any_idle();
        if tid != current_tid() {
            request_local_trap_reschedule();
        }
    } else if state == ThreadState::Running {
        if let Some(run_vid) = find_running_vcpu_for_tid_locked(tid) {
            if (new_mask & (1u32 << run_vid)) == 0 {
                if run_vid == vcpu_id() as usize {
                    request_local_trap_reschedule();
                } else {
                    request_reschedule_vcpu(run_vid as u32);
                }
            }
        }
    }

    SCHED.scheduler_update_needed.store(true, Ordering::Relaxed);
    true
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

/// Bind `tid` as the currently running thread on `vid` and refresh the thread's
/// running-state metadata.
pub fn bind_running_thread_to_vcpu(vid: usize, tid: u32) {
    set_vcpu_current_thread(vid, tid);
    with_thread_mut(tid, |t| {
        t.state = ThreadState::Running;
        t.last_vcpu_hint = vid as u8;
    });
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
