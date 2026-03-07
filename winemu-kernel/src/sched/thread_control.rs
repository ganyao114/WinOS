// sched/thread_control.rs — Priority, suspend/resume, terminate helpers
//
// All functions require the scheduler lock to be held.

use crate::sched::global::{with_thread, with_thread_mut};
use crate::sched::topology::set_thread_state_locked;
use crate::sched::types::ThreadState;
use crate::sched::wait::{unblock_thread_locked, STATUS_SUCCESS};

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

    // If Ready, remove from queue, change priority, re-insert.
    if old_state == ThreadState::Ready {
        set_thread_state_locked(tid, ThreadState::Waiting); // temp remove
        with_thread_mut(tid, |t| {
            t.priority      = priority;
            t.base_priority = priority;
        });
        set_thread_state_locked(tid, ThreadState::Ready);
    } else {
        with_thread_mut(tid, |t| {
            t.priority      = priority;
            t.base_priority = priority;
        });
    }
}

/// Apply a transient priority boost (e.g., after releasing a mutex).
/// Boost is clamped so it never exceeds base_priority.
pub fn boost_thread_priority_locked(tid: u32, boost: u8) {
    with_thread_mut(tid, |t| {
        let boosted = t.base_priority.saturating_sub(boost);
        if boosted < t.priority {
            t.priority       = boosted;
            t.transient_boost = boost;
        }
    });
}

/// Decay a transient boost by one step. Called on each scheduler quantum.
pub fn decay_priority_boost_locked(tid: u32) {
    with_thread_mut(tid, |t| {
        if t.transient_boost > 0 {
            t.transient_boost -= 1;
            t.priority = t.base_priority.saturating_sub(t.transient_boost);
        }
    });
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
        }
    }
    prev_count
}

// ── Terminate ─────────────────────────────────────────────────────────────────

/// Mark a thread as Terminated and remove it from the ready queue.
/// Does NOT free the KThread slot — that is done by the scheduler after
/// the context switch away from the thread completes.
pub fn terminate_thread_locked(tid: u32) {
    let state = match with_thread(tid, |t| t.state) {
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
}

// ── Quantum management ────────────────────────────────────────────────────────

/// Default quantum in 100ns units (20ms).
pub const DEFAULT_QUANTUM_100NS: u64 = 200_000;

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
    }).unwrap_or(false)
}
