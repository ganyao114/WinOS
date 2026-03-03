use super::*;

pub(crate) fn set_wait_deadline_locked(tid: u32, deadline: u64) -> bool {
    crate::log::debug_u64(0xD101_0001);
    crate::log::debug_u64(tid as u64);
    crate::log::debug_u64(deadline);
    if tid == 0 || !thread_exists(tid) {
        crate::log::debug_u64(0xD101_E001);
        return false;
    }
    let old_handle = with_thread_mut(tid, |t| {
        let prev = TimerTaskHandle {
            id: t.wait_timer_task_id,
            generation: t.wait_timer_generation,
        };
        t.wait_deadline = deadline;
        t.wait_timer_task_id = 0;
        t.wait_timer_generation = 0;
        prev
    });
    if deadline == 0 {
        if old_handle.is_valid() {
            let _ = timer::cancel_task(old_handle);
        }
        crate::log::debug_u64(0xD101_0002);
        return true;
    }

    if old_handle.is_valid() {
        if let Some(handle) = timer::rearm_task(old_handle, deadline) {
            with_thread_mut(tid, |t| {
                t.wait_timer_task_id = handle.id;
                t.wait_timer_generation = handle.generation;
            });
            crate::log::debug_u64(0xD101_0003);
            crate::log::debug_u64(handle.id as u64);
            crate::log::debug_u64(handle.generation as u64);
            return true;
        }
        let _ = timer::cancel_task(old_handle);
    }

    if let Some(handle) = timer::register_task(TimerTaskKind::ThreadTimeout, tid, deadline) {
        with_thread_mut(tid, |t| {
            t.wait_timer_task_id = handle.id;
            t.wait_timer_generation = handle.generation;
        });
        crate::log::debug_u64(0xD101_0004);
        crate::log::debug_u64(handle.id as u64);
        crate::log::debug_u64(handle.generation as u64);
        return true;
    }

    with_thread_mut(tid, |t| {
        t.wait_deadline = 0;
        t.wait_timer_task_id = 0;
        t.wait_timer_generation = 0;
    });
    crate::log::debug_u64(0xD101_E002);
    false
}

pub(crate) fn clear_wait_deadline_locked(tid: u32) {
    let _ = set_wait_deadline_locked(tid, 0);
}

#[inline(always)]
fn clear_wait_tracking_fields(thread: &mut KThread) {
    thread.wait_kind = WAIT_KIND_NONE;
    thread.wait_count = 0;
    thread.wait_signaled = 0;
    thread.wait_handles.fill(0);
}

#[inline(always)]
fn set_wait_tracking_fields(thread: &mut KThread, wait_kind: u8, wait_handles: &[u64], pending_result: u32) {
    let handle_count = wait_handles.len().min(MAX_WAIT_HANDLES);
    thread.wait_result = pending_result;
    thread.wait_kind = wait_kind;
    thread.wait_count = handle_count as u8;
    thread.wait_signaled = 0;
    thread.wait_handles.fill(0);
    let mut i = 0usize;
    while i < handle_count {
        thread.wait_handles[i] = wait_handles[i];
        i += 1;
    }
}

pub(crate) fn clear_wait_tracking_locked(tid: u32) {
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    clear_wait_deadline_locked(tid);
    with_thread_mut(tid, clear_wait_tracking_fields);
    debug_assert!(
        with_thread(tid, |t| {
            t.wait_deadline == 0
                && t.wait_timer_task_id == 0
                && t.wait_timer_generation == 0
                && t.wait_kind == WAIT_KIND_NONE
                && t.wait_count == 0
        }),
        "clear_wait_tracking_locked must fully clear wait/timer metadata"
    );
}

// Prepare wait bookkeeping fields under scheduler lock, without changing
// runnable state or timer registration yet.
pub(crate) fn prepare_wait_tracking_locked(
    tid: u32,
    wait_kind: u8,
    wait_handles: &[u64],
    pending_result: u32,
) -> u32 {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "prepare_wait_tracking_locked requires sched lock"
    );
    if tid == 0 || !thread_exists(tid) {
        return status::INVALID_PARAMETER;
    }
    with_thread_mut(tid, |t| {
        set_wait_tracking_fields(t, wait_kind, wait_handles, pending_result);
    });
    status::SUCCESS
}

pub(crate) fn ensure_current_wait_continuation_locked(tid: u32) -> u32 {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "ensure_current_wait_continuation_locked requires sched lock"
    );
    if tid == 0 || !thread_exists(tid) {
        return status::INVALID_PARAMETER;
    }
    if tid != current_tid() {
        return status::SUCCESS;
    }
    let has = has_dispatch_continuation(tid);
    debug_assert!(
        has,
        "blocking current thread wait requires dispatch continuation"
    );
    if !has {
        return status::INVALID_PARAMETER;
    }
    status::SUCCESS
}

// Begin wait on current metadata: move thread to Waiting and arm timeout.
pub(crate) fn begin_wait_locked(tid: u32, wait_deadline: u64) -> u32 {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "begin_wait_locked requires sched lock"
    );
    if tid == 0 || !thread_exists(tid) {
        return status::INVALID_PARAMETER;
    }

    let old_state = with_thread(tid, |t| t.state);
    set_thread_state_locked(tid, ThreadState::Waiting);
    if !set_wait_deadline_locked(tid, wait_deadline) {
        set_thread_state_locked(tid, old_state);
        return status::NO_MEMORY;
    }
    status::SUCCESS
}

fn apply_dynamic_wake_boost_locked(tid: u32) {
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    with_thread_mut(tid, |t| {
        if t.base_priority >= 16 || t.priority != t.base_priority {
            return;
        }
        let boosted = t
            .base_priority
            .saturating_add(DYNAMIC_BOOST_DELTA)
            .min(DYNAMIC_BOOST_MAX);
        if boosted > t.priority {
            t.priority = boosted;
            t.transient_boost = boosted.saturating_sub(t.base_priority);
        }
    });
}

// End a waiting thread through scheduler-owned path:
// clear wait/timer metadata, publish x0 result, and transition to Ready/Suspended.
pub(crate) fn end_wait_locked(tid: u32, result: u32) -> bool {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "end_wait_locked requires sched lock"
    );
    if tid == 0 || !thread_exists(tid) {
        return false;
    }
    let state = with_thread(tid, |t| t.state);
    if state != ThreadState::Waiting {
        return false;
    }

    let should_boost = with_thread(tid, |t| {
        result == status::SUCCESS && t.wait_kind != WAIT_KIND_DELAY && t.base_priority < 16
    });
    if should_boost {
        apply_dynamic_wake_boost_locked(tid);
    }

    clear_wait_tracking_locked(tid);
    with_thread_mut(tid, |t| {
        t.wait_result = result;
        t.ctx.x[0] = result as u64;
    });
    let suspended = with_thread(tid, |t| t.suspend_count != 0);
    if suspended {
        set_thread_state_locked(tid, ThreadState::Suspended);
    } else {
        set_thread_state_locked(tid, ThreadState::Ready);
    }
    debug_assert!(
        with_thread(tid, |t| t.state != ThreadState::Waiting),
        "end_wait_locked must leave waiting state"
    );
    true
}

#[inline(always)]
pub(crate) fn cancel_wait_locked(tid: u32, result: u32) -> bool {
    end_wait_locked(tid, result)
}

// Enter waiting state through a single scheduler-owned path so all wait users
// (NtWait*, delay, hostcall wait) share the same invariants.
pub(crate) fn prepare_wait_locked(
    tid: u32,
    wait_kind: u8,
    wait_handles: &[u64],
    wait_deadline: u64,
    pending_result: u32,
) -> u32 {
    let gate = ensure_current_wait_continuation_locked(tid);
    if gate != status::SUCCESS {
        return gate;
    }
    let prep = prepare_wait_tracking_locked(tid, wait_kind, wait_handles, pending_result);
    if prep != status::SUCCESS {
        return prep;
    }
    let begin = begin_wait_locked(tid, wait_deadline);
    if begin != status::SUCCESS {
        with_thread_mut(tid, |t| {
            t.wait_result = 0;
            clear_wait_tracking_fields(t);
        });
        return begin;
    }
    status::SUCCESS
}

// Unified blocking primitive for "current thread waits for something".
// The actual context switch is still performed by trap-exit scheduling path.
pub fn block_current_and_resched(
    wait_kind: u8,
    wait_handles: &[u64],
    wait_deadline: u64,
    pending_result: u32,
) -> u32 {
    let tid = current_tid();
    if tid == 0 || !thread_exists(tid) {
        return status::INVALID_PARAMETER;
    }
    let _guard = ScopedSchedulerLock::new();
    let st = prepare_wait_locked(tid, wait_kind, wait_handles, wait_deadline, pending_result);
    if st != status::SUCCESS {
        return st;
    }
    status::SUCCESS
}

// Wait until current blocked kernel thread transitions out of Waiting and
// return the scheduler-owned wait result.
pub fn wait_current_pending_result() -> u32 {
    let cur = current_tid();
    if cur == 0 || !thread_exists(cur) {
        return status::INVALID_PARAMETER;
    }
    let has = has_dispatch_continuation(cur);
    debug_assert!(
        has,
        "wait_current_pending_result requires dispatch continuation"
    );
    if !has {
        return status::INVALID_PARAMETER;
    }
    loop {
        let (state, result) = {
            let _guard = ScopedSchedulerLock::new();
            with_thread(cur, |t| (t.state, t.wait_result))
        };
        if state != ThreadState::Waiting {
            return result;
        }
        let switched = reschedule_current_via_dispatch_continuation();
        debug_assert!(
            switched,
            "dispatch continuation switch failed while waiting"
        );
        if !switched {
            return status::INVALID_PARAMETER;
        }
    }
}

/// Timeout dispatch hot path.
/// Caller must hold scheduler lock.
pub fn check_timeouts(now_ticks: u64) -> bool {
    let mut woke_any = false;

    let mut timeout_now = |tid: u32| {
        if tid == 0 || !thread_exists(tid) {
            return;
        }
        let still_waiting = with_thread(tid, |t| t.state == ThreadState::Waiting);
        if !still_waiting {
            return;
        }
        let was_delay_wait = with_thread(tid, |t| t.wait_kind == WAIT_KIND_DELAY);
        let timeout_result = if was_delay_wait {
            status::SUCCESS
        } else {
            status::TIMEOUT
        };
        let ended = crate::sched::sync::cancel_wait_on_sync_objects_locked(tid, timeout_result);
        debug_assert!(
            ended,
            "timeout cancellation must finish waiting thread transition"
        );
        woke_any |= ended;
    };

    loop {
        let Some(fired) = timer::pop_expired_task_locked(now_ticks) else {
            break;
        };
        if fired.kind != TimerTaskKind::ThreadTimeout {
            continue;
        }
        let tid = fired.target_id;
        if tid == 0 || !thread_exists(tid) {
            continue;
        }

        let still_waiting = with_thread(tid, |t| {
            t.state == ThreadState::Waiting
                && t.wait_deadline == fired.deadline_100ns
                && t.wait_timer_task_id == fired.handle.id
                && t.wait_timer_generation == fired.handle.generation
        });
        if !still_waiting {
            continue;
        }

        timeout_now(tid);
    }

    woke_any
}

/// Return the earliest waiting deadline (100ns), 0 if none.
/// Caller must hold scheduler lock.
pub fn next_wait_deadline_locked() -> u64 {
    timer::next_deadline_locked()
}

/// Locking wrapper for callers that are not already in scheduler critical section.
pub fn next_wait_deadline() -> u64 {
    sched_lock_acquire();
    let d = next_wait_deadline_locked();
    sched_lock_release();
    d
}

#[inline(always)]
pub fn now_ticks() -> u64 {
    crate::hypercall::query_mono_time_100ns()
}

/// Convert a relative timeout (100ns units) to an absolute counter deadline.
pub fn deadline_after_100ns(timeout_100ns: u64) -> u64 {
    now_ticks().saturating_add(timeout_100ns)
}
