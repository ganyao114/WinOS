// ── Event API ────────────────────────────────────────────────

pub fn create_event_handle(ev_type: EventType, initial_state: bool) -> Result<u64, u32> {
    let Some(idx) = event_alloc(ev_type, initial_state) else {
        return Err(status::NO_MEMORY);
    };
    let Some(h) = make_new_handle(HANDLE_TYPE_EVENT, idx) else {
        event_free(idx);
        return Err(status::NO_MEMORY);
    };
    Ok(h)
}

pub fn event_alloc(ev_type: EventType, initial_state: bool) -> Option<u32> {
    events_store_mut().alloc_with(|_| KEvent::new(ev_type, initial_state))
}

pub fn event_set(idx: u32) -> u32 {
    if idx == 0 {
        return STATUS_INVALID_HANDLE;
    }
    let ev_ptr = event_ptr(idx);
    if ev_ptr.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    sched_lock_acquire();
    unsafe { (*ev_ptr).set_locked(idx) };
    sched_lock_release();

    STATUS_SUCCESS
}

pub fn event_reset(idx: u32) -> u32 {
    if idx == 0 {
        return STATUS_INVALID_HANDLE;
    }
    let ev = event_ptr(idx);
    if ev.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    sched_lock_acquire();
    unsafe { (*ev).reset() };
    sched_lock_release();
    STATUS_SUCCESS
}

pub fn event_set_by_handle(h: u64) -> u32 {
    let Some(idx) = resolve_handle_idx_by_type(h, HANDLE_TYPE_EVENT) else {
        return STATUS_INVALID_HANDLE;
    };
    event_set(idx)
}

pub fn event_set_by_handle_for_pid(owner_pid: u32, h: u64) -> u32 {
    let Some(idx) = resolve_handle_idx_by_type_for_pid(h, owner_pid, HANDLE_TYPE_EVENT) else {
        return STATUS_INVALID_HANDLE;
    };
    event_set(idx)
}

pub fn event_reset_by_handle(h: u64) -> u32 {
    let Some(idx) = resolve_handle_idx_by_type(h, HANDLE_TYPE_EVENT) else {
        return STATUS_INVALID_HANDLE;
    };
    event_reset(idx)
}

pub fn event_free(idx: u32) {
    if idx == 0 {
        return;
    }
    let _guard = ScopedSchedulerLock::new();
    let ev = event_ptr(idx);
    if ev.is_null() {
        return;
    }
    unsafe {
        let _ = cancel_queue_all_locked(&mut (*ev).waiters, STATUS_INVALID_HANDLE);
        (*ev).signaled = false;
    }
    let _ = events_store_mut().free(idx);
}

// ── Mutex API ────────────────────────────────────────────────

pub fn create_mutex_handle(initial_owner: bool) -> Result<u64, u32> {
    let Some(idx) = mutex_alloc(initial_owner) else {
        return Err(status::NO_MEMORY);
    };
    let Some(h) = make_new_handle(HANDLE_TYPE_MUTEX, idx) else {
        mutex_free(idx);
        return Err(status::NO_MEMORY);
    };
    Ok(h)
}

pub fn mutex_alloc(initial_owner: bool) -> Option<u32> {
    mutexes_store_mut().alloc_with(|_| KMutex::new(initial_owner))
}

pub fn mutex_release(idx: u32) -> u32 {
    if idx == 0 {
        return STATUS_INVALID_HANDLE;
    }
    let m_ptr = mutex_ptr(idx);
    if m_ptr.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    sched_lock_acquire();
    let st = unsafe { (*m_ptr).release_locked(idx, current_tid()) };
    sched_lock_release();
    st
}

pub fn mutex_free(idx: u32) {
    if idx == 0 {
        return;
    }
    let _guard = ScopedSchedulerLock::new();
    let m = mutex_ptr(idx);
    if m.is_null() {
        return;
    }
    let owner_tid = unsafe { (*m).owner_tid };
    unsafe {
        let _ = cancel_queue_all_locked(&mut (*m).waiters, STATUS_INVALID_HANDLE);
        (*m).owner_tid = 0;
        (*m).recursion = 0;
    }
    if owner_tid != 0 && thread_exists(owner_tid) {
        recompute_owned_mutex_priority_locked(owner_tid);
    }
    let _ = mutexes_store_mut().free(idx);
}

pub fn mutex_release_by_handle(h: u64) -> u32 {
    let Some(idx) = resolve_handle_idx_by_type(h, HANDLE_TYPE_MUTEX) else {
        return STATUS_INVALID_HANDLE;
    };
    mutex_release(idx)
}

// ── Semaphore API ────────────────────────────────────────────

pub fn create_semaphore_handle(initial: i32, maximum: i32) -> Result<u64, u32> {
    if maximum <= 0 || initial < 0 || initial > maximum {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let Some(idx) = semaphore_alloc(initial, maximum) else {
        return Err(status::NO_MEMORY);
    };
    let Some(h) = make_new_handle(HANDLE_TYPE_SEMAPHORE, idx) else {
        semaphore_free(idx);
        return Err(status::NO_MEMORY);
    };
    Ok(h)
}

pub fn semaphore_alloc(initial: i32, maximum: i32) -> Option<u32> {
    if maximum <= 0 || initial < 0 || initial > maximum {
        return None;
    }
    semaphores_store_mut().alloc_with(|_| KSemaphore::new(initial, maximum))
}

/// Returns previous count, or STATUS_SEMAPHORE_LIMIT_EXCEEDED.
pub fn semaphore_release(idx: u32, count: i32) -> u32 {
    if idx == 0 {
        return STATUS_INVALID_HANDLE;
    }

    let s_ptr = semaphore_ptr(idx);
    if s_ptr.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    sched_lock_acquire();
    let st = unsafe {
        match (*s_ptr).release_locked(idx, count) {
            Ok(prev) => prev,
            Err(err) => err,
        }
    };
    sched_lock_release();
    st
}

pub fn semaphore_free(idx: u32) {
    if idx == 0 {
        return;
    }
    let _guard = ScopedSchedulerLock::new();
    let s = semaphore_ptr(idx);
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = cancel_queue_all_locked(&mut (*s).waiters, STATUS_INVALID_HANDLE);
        (*s).count = 0;
    }
    let _ = semaphores_store_mut().free(idx);
}

pub fn semaphore_release_by_handle(h: u64, count: i32) -> Result<u32, u32> {
    let Some(idx) = resolve_handle_idx_by_type(h, HANDLE_TYPE_SEMAPHORE) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    let prev_or_status = semaphore_release(idx, count);
    if (prev_or_status & NTSTATUS_ERROR_BIT) != 0 {
        Err(prev_or_status)
    } else {
        Ok(prev_or_status)
    }
}

// ── Handle wait / close ─────────────────────────────────────

pub fn close_handle(h: u64) -> u32 {
    let Some(info) = close_handle_info(h) else {
        return STATUS_INVALID_HANDLE;
    };
    if !info.destroy_object {
        return STATUS_SUCCESS;
    }
    destroy_object_by_type(info.htype, info.obj_idx)
}

pub fn destroy_object_by_type(htype: u64, obj_idx: u32) -> u32 {
    match htype {
        HANDLE_TYPE_EVENT => {
            event_free(obj_idx);
            STATUS_SUCCESS
        }
        HANDLE_TYPE_MUTEX => {
            mutex_free(obj_idx);
            STATUS_SUCCESS
        }
        HANDLE_TYPE_SEMAPHORE => {
            semaphore_free(obj_idx);
            STATUS_SUCCESS
        }
        HANDLE_TYPE_THREAD => STATUS_SUCCESS,
        HANDLE_TYPE_PROCESS => {
            crate::process::last_handle_closed(obj_idx);
            STATUS_SUCCESS
        }
        HANDLE_TYPE_TOKEN => STATUS_SUCCESS,
        _ => STATUS_INVALID_HANDLE,
    }
}
