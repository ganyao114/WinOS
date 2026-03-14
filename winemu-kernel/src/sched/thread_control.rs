// sched/thread_control.rs — Priority, suspend/resume, terminate helpers
//
// All functions require the scheduler lock to be held.

use crate::sched::global::{with_thread, with_thread_mut};
use crate::sched::ready::{change_ready_thread_priority_locked, mark_scheduler_topology_changed_locked};
use crate::sched::request_local_unlock_edge_schedule;
use crate::sched::topology::set_thread_state_locked;
use crate::sched::types::ThreadState;
use crate::sched::wait::{unblock_thread_locked, STATUS_SUCCESS};
use crate::sched::ScheduleReason;

#[inline]
fn notify_priority_changed_locked() {
    mark_scheduler_topology_changed_locked();
}

// ── Priority ──────────────────────────────────────────────────────────────────

/// Set a thread's base priority (0=highest, 31=lowest, Windows convention).
/// Clamps to [0, 31]. Re-queues the thread if it was Ready.
pub fn set_thread_priority_locked(tid: u32, priority: u8) {
    let priority = priority.min(31);
    let (old_state, old_prio) = match with_thread(tid, |t| (t.state, t.priority)) {
        Some(v) => v,
        None => return,
    };

    if old_prio == priority {
        return;
    }

    with_thread_mut(tid, |t| {
        t.priority = priority;
        t.base_priority = priority;
    });
    if old_state == ThreadState::Ready && old_prio != priority {
        let changed = change_ready_thread_priority_locked(tid, old_prio);
        debug_assert!(changed, "ready thread priority enqueue failed tid={tid}");
    }
    notify_priority_changed_locked();
}

/// Apply a transient priority boost (e.g., after releasing a mutex).
/// Boost is clamped so it never exceeds base_priority.
pub fn boost_thread_priority_locked(tid: u32, boost: u8) {
    let (state, old_priority, boosted) = match with_thread(tid, |t| {
        (t.state, t.priority, t.base_priority.saturating_sub(boost))
    }) {
        Some(v) => v,
        None => return,
    };

    if boosted >= old_priority {
        return;
    }

    with_thread_mut(tid, |t| {
        t.priority = boosted;
        t.transient_boost = boost;
    });
    if state == ThreadState::Ready && boosted != old_priority {
        let changed = change_ready_thread_priority_locked(tid, old_priority);
        debug_assert!(changed, "ready thread boost enqueue failed tid={tid}");
    }
    notify_priority_changed_locked();
}

/// Decay a transient boost by one step. Called on each scheduler quantum.
pub fn decay_priority_boost_locked(tid: u32) {
    let (state, old_priority, had_boost, new_boost, new_priority) = match with_thread(tid, |t| {
        let had = t.transient_boost > 0;
        let nb = if had { t.transient_boost - 1 } else { 0 };
        let np = t.base_priority.saturating_sub(nb);
        (t.state, t.priority, had, nb, np)
    }) {
        Some(v) => v,
        None => return,
    };

    if !had_boost {
        return;
    }
    with_thread_mut(tid, |t| {
        t.transient_boost = new_boost;
        t.priority = new_priority;
    });
    if state == ThreadState::Ready && new_priority != old_priority {
        let changed = change_ready_thread_priority_locked(tid, old_priority);
        debug_assert!(changed, "ready thread decay enqueue failed tid={tid}");
    }
    if new_priority != old_priority {
        notify_priority_changed_locked();
    }
}

// ── Suspend / Resume ──────────────────────────────────────────────────────────

/// Increment suspend count. If count goes from 0→1, move thread to Suspended.
/// Returns the previous suspend count.
pub fn suspend_thread_locked(tid: u32) -> u32 {
    let (prev_count, state) = match with_thread(tid, |t| (t.suspend_count, t.state)) {
        Some(v) => v,
        None => return 0,
    };

    with_thread_mut(tid, |t| t.suspend_count += 1);

    if prev_count == 0 {
        match state {
            ThreadState::Ready | ThreadState::Running => {
                set_thread_state_locked(tid, ThreadState::Suspended);
            }
            _ => {}
        }
    }
    prev_count
}

/// Decrement suspend count. If count reaches 0, move thread back to Ready.
/// Returns the previous suspend count.
pub fn resume_thread_locked(tid: u32) -> u32 {
    let (prev_count, state) = match with_thread(tid, |t| (t.suspend_count, t.state)) {
        Some(v) => v,
        None => return 0,
    };

    if prev_count == 0 {
        return 0;
    }

    with_thread_mut(tid, |t| t.suspend_count -= 1);

    if prev_count == 1 {
        // Fully resumed.
        if state == ThreadState::Suspended {
            set_thread_state_locked(tid, ThreadState::Ready);
            request_local_unlock_edge_schedule(ScheduleReason::Wakeup);
        }
    }
    prev_count
}

// ── Terminate ─────────────────────────────────────────────────────────────────

/// Mark a thread as Terminated and remove it from the ready queue.
/// Does NOT free the KThread slot — that is done by the scheduler after
/// the context switch away from the thread completes.
pub fn terminate_thread_locked(tid: u32) {
    let (state, pid, is_idle) = match with_thread(tid, |t| (t.state, t.pid, t.is_idle_thread)) {
        Some(s) => s,
        None => return,
    };

    // Wake any threads waiting on this thread's termination.
    // (Handled by the sync layer via the thread's wait-queue.)

    match state {
        ThreadState::Terminated => return,
        ThreadState::Waiting => {
            // Force-unblock so it can be transitioned.
            unblock_thread_locked(tid, STATUS_SUCCESS);
        }
        _ => {}
    }

    set_thread_state_locked(tid, ThreadState::Terminated);
    if pid != 0 && !is_idle {
        crate::process::on_thread_terminated(pid, tid);
    }
}

// ── Quantum management ────────────────────────────────────────────────────────

/// Default quantum in 100ns units (15ms).
pub const DEFAULT_QUANTUM_100NS: u64 = crate::timer::DEFAULT_TIMESLICE_100NS;

/// Reset a thread's time slice to the default quantum.
pub fn reset_quantum_locked(tid: u32) {
    with_thread_mut(tid, |t| {
        t.slice_remaining_100ns = DEFAULT_QUANTUM_100NS;
    });
}

/// Consume `elapsed` 100ns from the thread's quantum.
/// Returns true if the quantum has expired.
pub fn consume_quantum_locked(tid: u32, elapsed_100ns: u64) -> bool {
    with_thread_mut(tid, |t| {
        if t.slice_remaining_100ns <= elapsed_100ns {
            t.slice_remaining_100ns = 0;
            true
        } else {
            t.slice_remaining_100ns -= elapsed_100ns;
            false
        }
    })
    .unwrap_or(false)
}
