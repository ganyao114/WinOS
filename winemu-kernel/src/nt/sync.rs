use crate::sched::sync::{
    create_event_handle, create_mutex_handle, create_semaphore_handle, event_reset_by_handle,
    event_set_by_handle, mutex_release_by_handle, semaphore_release_by_handle, wait_handle,
    wait_multiple, EventType, WaitDeadline, STATUS_SUCCESS,
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
    match create_event_handle(ev_type, initial) {
        Ok(h) => {
            write_out_handle(frame, h);
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        Err(st) => frame.x[0] = st as u64,
    }
}

pub(crate) fn handle_set_event(frame: &mut SvcFrame) {
    frame.x[0] = event_set_by_handle(frame.x[0]) as u64;
}

pub(crate) fn handle_reset_event_or_delay(frame: &mut SvcFrame) {
    if super::system::should_dispatch_delay_execution(frame) {
        super::system::handle_delay_execution(frame);
    } else {
        frame.x[0] = event_reset_by_handle(frame.x[0]) as u64;
    }
}

// x0 = Handle, x1 = Alertable, x2 = Timeout* (LARGE_INTEGER*)
pub(crate) fn handle_wait_single(frame: &mut SvcFrame) {
    let h = frame.x[0];
    let timeout = parse_timeout(frame.x[2] as *const i64);
    frame.x[0] = wait_handle(h, timeout) as u64;
}

pub(crate) fn handle_wait_multiple(frame: &mut SvcFrame) {
    let count = frame.x[0] as usize;
    let arr = frame.x[1] as *const u64;
    let wait_type = frame.x[2] as u32;
    let wait_all = match wait_type {
        0 => true,  // WaitAll
        1 => false, // WaitAny
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
    };
    if arr.is_null() || count == 0 || count > crate::sched::MAX_WAIT_HANDLES {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let timeout = parse_timeout(frame.x[4] as *const i64);
    let mut handles = [0u64; crate::sched::MAX_WAIT_HANDLES];
    let mut i = 0usize;
    while i < count {
        handles[i] = unsafe { arr.add(i).read_volatile() };
        i += 1;
    }
    frame.x[0] = wait_multiple(&handles[..count], wait_all, timeout) as u64;
}

// x0 = MutantHandle* (out), x1 = DesiredAccess, x2 = ObjAttr*
// x3 = InitialOwner (bool)
pub(crate) fn handle_create_mutex(frame: &mut SvcFrame) {
    let initial_owner = frame.x[3] != 0;
    match create_mutex_handle(initial_owner) {
        Ok(h) => {
            write_out_handle(frame, h);
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        Err(st) => frame.x[0] = st as u64,
    }
}

// `NtReleaseMutant` and `NtSetInformationProcess` share nr in current ABI profile.
pub(crate) fn handle_release_mutant_or_set_information_process(frame: &mut SvcFrame) {
    if super::process::should_dispatch_set_information_process(frame) {
        super::process::handle_set_information_process(frame);
        return;
    }
    frame.x[0] = mutex_release_by_handle(frame.x[0]) as u64;
}

// x0 = SemaphoreHandle* (out), x1 = DesiredAccess, x2 = ObjAttr*
// x3 = InitialCount, x4 = MaximumCount
pub(crate) fn handle_create_semaphore(frame: &mut SvcFrame) {
    let initial = frame.x[3] as i32;
    let maximum = frame.x[4] as i32;
    match create_semaphore_handle(initial, maximum) {
        Ok(h) => {
            write_out_handle(frame, h);
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        Err(st) => frame.x[0] = st as u64,
    }
}

// x0 = SemaphoreHandle, x1 = ReleaseCount, x2 = PreviousCount* (opt)
pub(crate) fn handle_release_semaphore(frame: &mut SvcFrame) {
    let h = frame.x[0];
    let count = frame.x[1] as i32;
    match semaphore_release_by_handle(h, count) {
        Ok(prev) => {
            if let Some(ptr) = unsafe { (frame.x[2] as *mut u32).as_mut() } {
                unsafe { (ptr as *mut u32).write_volatile(prev) };
            }
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        Err(st) => frame.x[0] = st as u64,
    }
}

fn write_out_handle(frame: &SvcFrame, handle: u64) {
    let out_ptr = frame.x[0] as *mut u64;
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(handle) };
    }
}

fn parse_timeout(timeout_ptr: *const i64) -> WaitDeadline {
    if timeout_ptr.is_null() {
        return WaitDeadline::Infinite;
    }
    let raw = unsafe { timeout_ptr.read_volatile() };
    if raw == 0 {
        return WaitDeadline::Immediate;
    }
    if raw < 0 {
        let rel_100ns = raw.unsigned_abs();
        return WaitDeadline::DeadlineTicks(crate::sched::deadline_after_100ns(rel_100ns));
    }
    // NT 语义里正值是绝对时间（FILETIME）。当前 guest 内还没有 FILETIME 时钟源，
    // 先按相对 100ns 处理，保证不会把调用误判成“立即超时”。
    WaitDeadline::DeadlineTicks(crate::sched::deadline_after_100ns(raw as u64))
}
