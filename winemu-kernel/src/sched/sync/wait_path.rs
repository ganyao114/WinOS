// ── 内部辅助 ──────────────────────────────────────────────────

fn deadline_ticks(timeout: WaitDeadline) -> u64 {
    match timeout {
        WaitDeadline::Infinite | WaitDeadline::Immediate => 0,
        WaitDeadline::DeadlineTicks(t) => t,
    }
}

fn clear_wait_metadata(tid: u32) {
    clear_wait_tracking_locked(tid);
}

fn end_wait_on_sync_objects_locked(tid: u32, result: u32) -> bool {
    cleanup_wait_registration_locked(tid);
    end_wait_locked(tid, result)
}

pub(crate) fn cancel_wait_on_sync_objects_locked(tid: u32, result: u32) -> bool {
    cleanup_wait_registration_locked(tid);
    cancel_wait_locked(tid, result)
}

fn validate_thread_target_tid(target_tid: u32) -> bool {
    if target_tid == 0 || !thread_exists(target_tid) {
        return false;
    }
    let state = with_thread(target_tid, |t| t.state);
    state != ThreadState::Free
}

fn waiter_owner_pid(waiter_tid: u32) -> u32 {
    if waiter_tid != 0 {
        if let Some(pid) = crate::sched::thread_pid(waiter_tid) {
            if pid != 0 {
                return pid;
            }
        }
    }
    current_handle_owner_pid()
}

struct WaitableObjectOps {
    validate: fn(obj_idx: u32) -> bool,
    is_signaled: fn(waiter_tid: u32, obj_idx: u32) -> bool,
    consume_signal: fn(waiter_tid: u32, obj_idx: u32) -> bool,
    register_waiter: fn(obj_idx: u32, waiter_tid: u32) -> bool,
    remove_waiter: fn(obj_idx: u32, waiter_tid: u32),
}

const EVENT_WAITABLE_OPS: WaitableObjectOps = WaitableObjectOps {
    validate: event_validate_waitable,
    is_signaled: event_is_signaled,
    consume_signal: event_consume_signal,
    register_waiter: event_register_waiter,
    remove_waiter: event_remove_waiter,
};

const MUTEX_WAITABLE_OPS: WaitableObjectOps = WaitableObjectOps {
    validate: mutex_validate_waitable,
    is_signaled: mutex_is_signaled,
    consume_signal: mutex_consume_signal,
    register_waiter: mutex_register_waiter,
    remove_waiter: mutex_remove_waiter,
};

const SEMAPHORE_WAITABLE_OPS: WaitableObjectOps = WaitableObjectOps {
    validate: semaphore_validate_waitable,
    is_signaled: semaphore_is_signaled,
    consume_signal: semaphore_consume_signal,
    register_waiter: semaphore_register_waiter,
    remove_waiter: semaphore_remove_waiter,
};

const THREAD_WAITABLE_OPS: WaitableObjectOps = WaitableObjectOps {
    validate: thread_validate_waitable,
    is_signaled: thread_is_signaled,
    consume_signal: thread_consume_signal,
    register_waiter: thread_register_waiter,
    remove_waiter: thread_remove_waiter,
};

const PROCESS_WAITABLE_OPS: WaitableObjectOps = WaitableObjectOps {
    validate: process_validate_waitable,
    is_signaled: process_is_signaled,
    consume_signal: process_consume_signal,
    register_waiter: process_register_waiter,
    remove_waiter: process_remove_waiter,
};

fn waitable_ops_for_type(htype: u64) -> Option<&'static WaitableObjectOps> {
    match htype {
        HANDLE_TYPE_EVENT => Some(&EVENT_WAITABLE_OPS),
        HANDLE_TYPE_MUTEX => Some(&MUTEX_WAITABLE_OPS),
        HANDLE_TYPE_SEMAPHORE => Some(&SEMAPHORE_WAITABLE_OPS),
        HANDLE_TYPE_THREAD => Some(&THREAD_WAITABLE_OPS),
        HANDLE_TYPE_PROCESS => Some(&PROCESS_WAITABLE_OPS),
        _ => None,
    }
}

fn resolve_waitable_target_for_waiter(
    waiter_tid: u32,
    h: u64,
) -> Option<(&'static WaitableObjectOps, u32)> {
    let owner_pid = waiter_owner_pid(waiter_tid);
    let htype = handle_type_for_pid(h, owner_pid);
    let obj_idx = handle_idx_for_pid(h, owner_pid);
    Some((waitable_ops_for_type(htype)?, obj_idx))
}

fn event_validate_waitable(idx: u32) -> bool {
    idx != 0 && !event_ptr(idx).is_null()
}

fn event_is_signaled(_waiter_tid: u32, idx: u32) -> bool {
    let ev = event_ptr(idx);
    if ev.is_null() {
        return false;
    }
    unsafe { (*ev).signaled }
}

fn event_consume_signal(_waiter_tid: u32, idx: u32) -> bool {
    let ev = event_ptr(idx);
    if ev.is_null() {
        return false;
    }
    unsafe {
        if !(*ev).signaled {
            return false;
        }
        if (*ev).ev_type == EventType::SynchronizationEvent {
            (*ev).signaled = false;
        }
    }
    true
}

fn event_register_waiter(idx: u32, waiter_tid: u32) -> bool {
    let ev = event_ptr(idx);
    if ev.is_null() {
        return false;
    }
    unsafe { (*ev).waiters.enqueue(waiter_tid) }
}

fn event_remove_waiter(idx: u32, waiter_tid: u32) {
    let ev = event_ptr(idx);
    if ev.is_null() {
        return;
    }
    unsafe { (*ev).waiters.remove(waiter_tid) };
}

fn mutex_validate_waitable(idx: u32) -> bool {
    idx != 0 && !mutex_ptr(idx).is_null()
}

fn mutex_is_signaled(waiter_tid: u32, idx: u32) -> bool {
    let m = mutex_ptr(idx);
    if m.is_null() {
        return false;
    }
    unsafe { (*m).owner_tid == 0 || (*m).owner_tid == waiter_tid }
}

fn mutex_consume_signal(waiter_tid: u32, idx: u32) -> bool {
    let m = mutex_ptr(idx);
    if m.is_null() {
        return false;
    }
    unsafe {
        if (*m).owner_tid == 0 {
            (*m).owner_tid = waiter_tid;
            (*m).recursion = 1;
            recompute_owned_mutex_priority_locked(waiter_tid);
            return true;
        }
        if (*m).owner_tid == waiter_tid {
            (*m).recursion = (*m).recursion.saturating_add(1);
            recompute_owned_mutex_priority_locked(waiter_tid);
            return true;
        }
    }
    false
}

fn mutex_register_waiter(idx: u32, waiter_tid: u32) -> bool {
    let m = mutex_ptr(idx);
    if m.is_null() {
        return false;
    }
    let queued = unsafe { (*m).waiters.enqueue(waiter_tid) };
    if !queued {
        return false;
    }
    unsafe {
        let owner_tid = (*m).owner_tid;
        if owner_tid != 0 && owner_tid != waiter_tid {
            let waiter_prio = with_thread(waiter_tid, |t| t.priority);
            boost_thread_priority_locked(owner_tid, waiter_prio);
        }
    }
    true
}

fn mutex_remove_waiter(idx: u32, waiter_tid: u32) {
    let m = mutex_ptr(idx);
    if m.is_null() {
        return;
    }
    unsafe { (*m).waiters.remove(waiter_tid) };
}

fn semaphore_validate_waitable(idx: u32) -> bool {
    idx != 0 && !semaphore_ptr(idx).is_null()
}

fn semaphore_is_signaled(_waiter_tid: u32, idx: u32) -> bool {
    let s = semaphore_ptr(idx);
    if s.is_null() {
        return false;
    }
    unsafe { (*s).count > 0 }
}

fn semaphore_consume_signal(_waiter_tid: u32, idx: u32) -> bool {
    let s = semaphore_ptr(idx);
    if s.is_null() {
        return false;
    }
    unsafe {
        if (*s).count <= 0 {
            return false;
        }
        (*s).count -= 1;
    }
    true
}

fn semaphore_register_waiter(idx: u32, waiter_tid: u32) -> bool {
    let s = semaphore_ptr(idx);
    if s.is_null() {
        return false;
    }
    unsafe { (*s).waiters.enqueue(waiter_tid) }
}

fn semaphore_remove_waiter(idx: u32, waiter_tid: u32) {
    let s = semaphore_ptr(idx);
    if s.is_null() {
        return;
    }
    unsafe { (*s).waiters.remove(waiter_tid) };
}

fn thread_validate_waitable(idx: u32) -> bool {
    validate_thread_target_tid(idx)
}

fn thread_is_signaled(_waiter_tid: u32, idx: u32) -> bool {
    let tid = idx;
    if tid == 0 || !thread_exists(tid) {
        return false;
    }
    let state = with_thread(tid, |t| t.state);
    state == ThreadState::Terminated || state == ThreadState::Free
}

fn thread_consume_signal(waiter_tid: u32, idx: u32) -> bool {
    thread_is_signaled(waiter_tid, idx)
}

fn thread_register_waiter(idx: u32, waiter_tid: u32) -> bool {
    if !validate_thread_target_tid(idx) {
        return false;
    }
    let q = thread_waiters_ptr(idx);
    if q.is_null() {
        return false;
    }
    unsafe { (*q).enqueue(waiter_tid) }
}

fn thread_remove_waiter(idx: u32, waiter_tid: u32) {
    let q = thread_waiters_ptr(idx);
    if q.is_null() {
        return;
    }
    unsafe { (*q).remove(waiter_tid) };
}

fn process_validate_waitable(idx: u32) -> bool {
    idx != 0 && crate::process::process_exists(idx)
}

fn process_is_signaled(_waiter_tid: u32, idx: u32) -> bool {
    idx != 0 && crate::process::process_signaled(idx)
}

fn process_consume_signal(waiter_tid: u32, idx: u32) -> bool {
    process_is_signaled(waiter_tid, idx)
}

fn process_register_waiter(idx: u32, waiter_tid: u32) -> bool {
    if idx == 0 || !crate::process::process_exists(idx) {
        return false;
    }
    let q = process_waiters_ptr(idx);
    if q.is_null() {
        return false;
    }
    unsafe { (*q).enqueue(waiter_tid) }
}

fn process_remove_waiter(idx: u32, waiter_tid: u32) {
    let q = process_waiters_ptr(idx);
    if q.is_null() {
        return;
    }
    unsafe { (*q).remove(waiter_tid) };
}

fn validate_waitable_handle_locked(h: u64) -> u32 {
    let Some((ops, idx)) = resolve_waitable_target_for_waiter(current_tid(), h) else {
        return STATUS_INVALID_HANDLE;
    };
    if (ops.validate)(idx) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_HANDLE
    }
}

fn is_handle_signaled_locked(waiter_tid: u32, h: u64) -> bool {
    let Some((ops, idx)) = resolve_waitable_target_for_waiter(waiter_tid, h) else {
        return false;
    };
    (ops.is_signaled)(waiter_tid, idx)
}

fn consume_handle_signal_locked(waiter_tid: u32, h: u64) -> bool {
    let Some((ops, idx)) = resolve_waitable_target_for_waiter(waiter_tid, h) else {
        return false;
    };
    (ops.consume_signal)(waiter_tid, idx)
}

fn copy_wait_handles_for_thread(tid: u32) -> ([u64; MAX_WAIT_HANDLES], usize) {
    let mut local = [0u64; MAX_WAIT_HANDLES];
    let mut count = 0usize;
    with_thread(tid, |t| {
        count = t.wait_count as usize;
        let mut i = 0usize;
        while i < count && i < MAX_WAIT_HANDLES {
            local[i] = t.wait_handles[i];
            i += 1;
        }
    });
    (local, count)
}

fn wait_all_handles_signaled_locked(tid: u32, handles: &[u64]) -> bool {
    let mut i = 0usize;
    while i < handles.len() {
        if !is_handle_signaled_locked(tid, handles[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn consume_wait_all_locked(tid: u32, handles: &[u64]) -> bool {
    if !wait_all_handles_signaled_locked(tid, handles) {
        return false;
    }
    let mut i = 0usize;
    while i < handles.len() {
        if !consume_handle_signal_locked(tid, handles[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn register_waiter_on_handle_locked(h: u64, tid: u32) -> bool {
    let Some((ops, idx)) = resolve_waitable_target_for_waiter(tid, h) else {
        return false;
    };
    if !(ops.validate)(idx) {
        return false;
    }
    (ops.register_waiter)(idx, tid)
}

fn remove_waiter_from_handle_locked(h: u64, tid: u32) {
    let Some((ops, idx)) = resolve_waitable_target_for_waiter(tid, h) else {
        return;
    };
    (ops.remove_waiter)(idx, tid);
}

pub(crate) fn cleanup_wait_registration_locked(tid: u32) {
    let (handles, count) = copy_wait_handles_for_thread(tid);
    let mut i = 0usize;
    while i < count {
        remove_waiter_from_handle_locked(handles[i], tid);
        i += 1;
    }
}

fn wait_index_for_handle_locked(tid: u32, h: u64) -> Option<usize> {
    let owner_pid = waiter_owner_pid(tid);
    with_thread(tid, |t| {
        let count = t.wait_count as usize;
        let mut i = 0usize;
        while i < count && i < MAX_WAIT_HANDLES {
            if handles_same_object_for_pid(t.wait_handles[i], h, owner_pid) {
                return Some(i);
            }
            i += 1;
        }
        None
    })
}

fn complete_wait_locked(tid: u32, result: u32) {
    let _ = end_wait_on_sync_objects_locked(tid, result);
}

fn try_complete_waiter_for_handle_locked(tid: u32, signaled_handle: u64) -> bool {
    let (state, kind) = with_thread(tid, |t| (t.state, t.wait_kind));
    if state != ThreadState::Waiting {
        return false;
    }

    match kind {
        WAIT_KIND_SINGLE => {
            let expected = with_thread(tid, |t| t.wait_handles[0]);
            let owner_pid = waiter_owner_pid(tid);
            if !handles_same_object_for_pid(expected, signaled_handle, owner_pid) {
                return false;
            }
            if !consume_handle_signal_locked(tid, expected) {
                return false;
            }
            complete_wait_locked(tid, STATUS_SUCCESS);
            true
        }
        WAIT_KIND_MULTI_ANY => {
            let Some(index) = wait_index_for_handle_locked(tid, signaled_handle) else {
                return false;
            };
            let expected = with_thread(tid, |t| t.wait_handles[index]);
            if !consume_handle_signal_locked(tid, expected) {
                return false;
            }
            complete_wait_locked(tid, STATUS_SUCCESS + index as u32);
            true
        }
        WAIT_KIND_MULTI_ALL => {
            if let Some(index) = wait_index_for_handle_locked(tid, signaled_handle) {
                with_thread_mut(tid, |t| t.wait_signaled |= 1u64 << (index as u64));
            }
            let (handles, count) = copy_wait_handles_for_thread(tid);
            let handles = &handles[..count];
            if !wait_all_handles_signaled_locked(tid, handles) {
                return false;
            }
            if !consume_wait_all_locked(tid, handles) {
                return false;
            }
            complete_wait_locked(tid, STATUS_SUCCESS);
            true
        }
        _ => false,
    }
}

fn wake_queue_one_for_handle_locked(queue: &mut WaitQueue, signaled_handle: u64) -> bool {
    let attempts = queue.len();
    let mut i = 0usize;
    while i < attempts {
        let tid = queue.dequeue_waiting();
        if tid == 0 {
            return false;
        }
        if try_complete_waiter_for_handle_locked(tid, signaled_handle) {
            return true;
        }
        if thread_exists(tid) && with_thread(tid, |t| t.state == ThreadState::Waiting) {
            let _ = queue.enqueue(tid);
        }
        i += 1;
    }
    false
}

fn wake_queue_all_for_handle_locked(queue: &mut WaitQueue, signaled_handle: u64) -> usize {
    let attempts = queue.len();
    let mut i = 0usize;
    let mut woke = 0usize;
    while i < attempts {
        let tid = queue.dequeue_waiting();
        if tid == 0 {
            break;
        }
        if try_complete_waiter_for_handle_locked(tid, signaled_handle) {
            woke += 1;
        } else if thread_exists(tid) && with_thread(tid, |t| t.state == ThreadState::Waiting) {
            let _ = queue.enqueue(tid);
        }
        i += 1;
    }
    woke
}

fn cancel_queue_all_locked(queue: &mut WaitQueue, result: u32) -> usize {
    let attempts = queue.len();
    let mut i = 0usize;
    let mut canceled = 0usize;
    while i < attempts {
        let tid = queue.dequeue_waiting();
        if tid == 0 {
            break;
        }
        if tid != 0
            && thread_exists(tid)
            && with_thread(tid, |t| t.state == ThreadState::Waiting)
            && cancel_wait_on_sync_objects_locked(tid, result)
        {
            canceled += 1;
        }
        i += 1;
    }
    canceled
}

fn wait_common_locked(handles: &[u64], wait_all: bool, timeout: WaitDeadline) -> u32 {
    if handles.is_empty() || handles.len() > MAX_WAIT_HANDLES {
        return STATUS_INVALID_PARAMETER;
    }

    let mut i = 0usize;
    while i < handles.len() {
        let st = validate_waitable_handle_locked(handles[i]);
        if st != STATUS_SUCCESS {
            return st;
        }
        i += 1;
    }

    if wait_all {
        let owner_pid = waiter_owner_pid(current_tid());
        let mut i = 0usize;
        while i < handles.len() {
            let mut j = i + 1;
            while j < handles.len() {
                if handles_same_object_for_pid(handles[i], handles[j], owner_pid) {
                    return STATUS_INVALID_PARAMETER;
                }
                j += 1;
            }
            i += 1;
        }
    }

    let cur = current_tid();

    if wait_all {
        if consume_wait_all_locked(cur, handles) {
            return STATUS_SUCCESS;
        }
    } else {
        let mut idx = 0usize;
        while idx < handles.len() {
            let h = handles[idx];
            if is_handle_signaled_locked(cur, h) && consume_handle_signal_locked(cur, h) {
                return STATUS_SUCCESS + idx as u32;
            }
            idx += 1;
        }
    }

    if timeout == WaitDeadline::Immediate {
        return STATUS_TIMEOUT;
    }

    let gate = ensure_current_wait_preconditions_locked(cur);
    if gate != STATUS_SUCCESS {
        return gate;
    }

    let kind = if handles.len() == 1 {
        WAIT_KIND_SINGLE
    } else if wait_all {
        WAIT_KIND_MULTI_ALL
    } else {
        WAIT_KIND_MULTI_ANY
    };
    let prepare = prepare_wait_tracking_locked(cur, kind, handles, STATUS_PENDING);
    if prepare != STATUS_SUCCESS {
        return prepare;
    }

    let old_state = with_thread(cur, |t| t.state);
    let wait_deadline = deadline_ticks(timeout);
    let begin = begin_wait_locked(cur, wait_deadline);
    if begin != STATUS_SUCCESS {
        clear_wait_metadata(cur);
        with_thread_mut(cur, |t| t.wait_result = 0);
        return begin;
    }

    let mut registered = 0usize;
    while registered < handles.len() {
        if !register_waiter_on_handle_locked(handles[registered], cur) {
            while registered > 0 {
                registered -= 1;
                remove_waiter_from_handle_locked(handles[registered], cur);
            }
            clear_wait_metadata(cur);
            with_thread_mut(cur, |t| t.wait_result = 0);
            set_thread_state_locked(cur, old_state);
            return STATUS_NO_MEMORY;
        }
        registered += 1;
    }

    STATUS_PENDING
}

// ── 对外接口：等待/清理/线程终止通知 ─────────────────────────

pub fn wait_handle_sync(h: u64, timeout: WaitDeadline) -> u32 {
    let st = {
        let _guard = ScopedSchedulerLock::new();
        wait_common_locked(core::slice::from_ref(&h), false, timeout)
    };
    if st != STATUS_PENDING {
        return st;
    }
    crate::sched::current_wait_result()
}

pub fn wait_multiple_sync(handles: &[u64], wait_all: bool, timeout: WaitDeadline) -> u32 {
    let st = {
        let _guard = ScopedSchedulerLock::new();
        wait_common_locked(handles, wait_all, timeout)
    };
    if st != STATUS_PENDING {
        return st;
    }
    crate::sched::current_wait_result()
}

pub fn delay_current_thread_sync(timeout: WaitDeadline) -> u32 {
    if timeout == WaitDeadline::Immediate {
        return STATUS_SUCCESS;
    }

    let st = {
        let _guard = ScopedSchedulerLock::new();
        let cur = current_tid();
        if cur == 0 || !thread_exists(cur) {
            STATUS_INVALID_PARAMETER
        } else {
            let gate = ensure_current_wait_preconditions_locked(cur);
            if gate != STATUS_SUCCESS {
                gate
            } else {
                let prepare = prepare_wait_tracking_locked(cur, WAIT_KIND_DELAY, &[], STATUS_PENDING);
                if prepare != STATUS_SUCCESS {
                    prepare
                } else {
                    let begin = begin_wait_locked(cur, deadline_ticks(timeout));
                    if begin != STATUS_SUCCESS {
                        clear_wait_metadata(cur);
                        with_thread_mut(cur, |t| t.wait_result = 0);
                        begin
                    } else {
                        STATUS_PENDING
                    }
                }
            }
        }
    };
    if st != STATUS_PENDING {
        return st;
    }
    crate::sched::current_wait_result()
}

/// Remove a waiting thread from all object wait queues.
/// Called on timeout/cancel/wake cleanup paths.
pub fn cleanup_wait_registration(tid: u32) {
    if tid == 0 {
        return;
    }
    sched_lock_acquire();
    cleanup_wait_registration_locked(tid);
    sched_lock_release();
}

/// Notify synchronization subsystem that a thread became terminated.
/// Wakes waiters blocked on this thread handle.
pub fn thread_notify_terminated(target_tid: u32) {
    if target_tid == 0 {
        return;
    }
    sched_lock_acquire();
    let h = make_handle(HANDLE_TYPE_THREAD, target_tid);
    let q = thread_waiters_ptr(target_tid);
    if !q.is_null() {
        unsafe {
            wake_queue_all_for_handle_locked(&mut *q, h);
        }
    }
    sched_lock_release();
}

/// Notify synchronization subsystem that a process became terminated.
/// Wakes waiters blocked on this process handle.
pub fn process_notify_terminated(target_pid: u32) {
    if target_pid == 0 {
        return;
    }
    sched_lock_acquire();
    let h = make_handle(HANDLE_TYPE_PROCESS, target_pid);
    let q = process_waiters_ptr(target_pid);
    if !q.is_null() {
        unsafe {
            wake_queue_all_for_handle_locked(&mut *q, h);
        }
    }
    sched_lock_release();
}
