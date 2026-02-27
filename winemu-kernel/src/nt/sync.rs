use crate::sched::sync::{
    self, event_alloc, event_reset, event_set, make_handle, mutex_alloc, mutex_release,
    semaphore_alloc, semaphore_release, wait_handle, EventType, STATUS_SUCCESS,
    HANDLE_TYPE_EVENT, HANDLE_TYPE_MUTEX, HANDLE_TYPE_SEMAPHORE,
};
use winemu_shared::status;

use super::SvcFrame;

// x0 = EventHandle* (out), x1 = DesiredAccess, x2 = ObjectAttributes*
// x3 = EventType (0=Notification, 1=Sync), x4 = InitialState
pub(crate) fn handle_create_event(frame: &mut SvcFrame) {
    let ev_type = if frame.x[3] == 1 {
        EventType::SynchronizationEvent
    } else {
        EventType::NotificationEvent
    };
    let initial = frame.x[4] != 0;
    match event_alloc(ev_type, initial) {
        Some(idx) => {
            let h = make_handle(HANDLE_TYPE_EVENT, idx);
            let out_ptr = frame.x[0] as *mut u64;
            unsafe { out_ptr.write_volatile(h) };
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        None => {
            frame.x[0] = 0xC000_0017u64;
        }
    }
}

pub(crate) fn handle_set_event(frame: &mut SvcFrame) {
    let h = frame.x[0];
    if sync::handle_type(h) != HANDLE_TYPE_EVENT {
        frame.x[0] = sync::STATUS_INVALID_HANDLE as u64;
        return;
    }
    frame.x[0] = event_set(sync::handle_idx(h)) as u64;
}

pub(crate) fn handle_reset_event(frame: &mut SvcFrame) {
    let h = frame.x[0];
    if sync::handle_type(h) != HANDLE_TYPE_EVENT {
        frame.x[0] = sync::STATUS_INVALID_HANDLE as u64;
        return;
    }
    frame.x[0] = event_reset(sync::handle_idx(h)) as u64;
}

// x0 = Handle, x1 = Alertable, x2 = Timeout* (LARGE_INTEGER*)
pub(crate) fn handle_wait_single(frame: &mut SvcFrame) {
    let h = frame.x[0];
    let timeout_ptr = frame.x[2] as *const i64;
    let deadline = if timeout_ptr.is_null() {
        0u64
    } else {
        let rel = unsafe { timeout_ptr.read_volatile() };
        if rel < 0 { (-rel) as u64 } else { rel as u64 }
    };

    frame.x[0] = wait_handle(h, deadline) as u64;
}

pub(crate) fn handle_wait_multiple(frame: &mut SvcFrame) {
    let count = frame.x[0] as usize;
    let arr = frame.x[1] as *const u64;
    if arr.is_null() || count == 0 || count > 64 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let first = unsafe { arr.read_volatile() };
    frame.x[0] = wait_handle(first, 0) as u64;
}

// x0 = MutantHandle* (out), x1 = DesiredAccess, x2 = ObjAttr*
// x3 = InitialOwner (bool)
pub(crate) fn handle_create_mutex(frame: &mut SvcFrame) {
    let initial_owner = frame.x[3] != 0;
    match mutex_alloc(initial_owner) {
        Some(idx) => {
            let h = make_handle(HANDLE_TYPE_MUTEX, idx);
            let out_ptr = frame.x[0] as *mut u64;
            unsafe { out_ptr.write_volatile(h) };
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        None => {
            frame.x[0] = 0xC000_0017u64;
        }
    }
}

// x0 = MutantHandle, x1 = PreviousCount* (optional)
pub(crate) fn handle_release_mutant(frame: &mut SvcFrame) {
    let h = frame.x[0];
    if sync::handle_type(h) != HANDLE_TYPE_MUTEX {
        frame.x[0] = sync::STATUS_INVALID_HANDLE as u64;
        return;
    }
    frame.x[0] = mutex_release(sync::handle_idx(h)) as u64;
}

// x0 = SemaphoreHandle* (out), x1 = DesiredAccess, x2 = ObjAttr*
// x3 = InitialCount, x4 = MaximumCount
pub(crate) fn handle_create_semaphore(frame: &mut SvcFrame) {
    let initial = frame.x[3] as i32;
    let maximum = frame.x[4] as i32;
    match semaphore_alloc(initial, maximum) {
        Some(idx) => {
            let h = make_handle(HANDLE_TYPE_SEMAPHORE, idx);
            let out_ptr = frame.x[0] as *mut u64;
            unsafe { out_ptr.write_volatile(h) };
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        None => {
            frame.x[0] = 0xC000_0017u64;
        }
    }
}

// x0 = SemaphoreHandle, x1 = ReleaseCount, x2 = PreviousCount* (opt)
pub(crate) fn handle_release_semaphore(frame: &mut SvcFrame) {
    let h = frame.x[0];
    let count = frame.x[1] as i32;
    if sync::handle_type(h) != HANDLE_TYPE_SEMAPHORE {
        frame.x[0] = sync::STATUS_INVALID_HANDLE as u64;
        return;
    }
    let prev = semaphore_release(sync::handle_idx(h), count);
    if let Some(ptr) = unsafe { (frame.x[2] as *mut u32).as_mut() } {
        unsafe { (ptr as *mut u32).write_volatile(prev) };
    }
    frame.x[0] = if prev & 0x8000_0000 != 0 {
        prev as u64
    } else {
        STATUS_SUCCESS as u64
    };
}
