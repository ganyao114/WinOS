use crate::sched::sync::{
    create_event, set_event, reset_event,
    create_mutex, release_mutex,
    create_semaphore, release_semaphore,
    wait_for_single_object, wait_for_multiple_objects,
};
use crate::sched::types::WaitDeadline;
use crate::sched::wait::{timeout_to_deadline, STATUS_SUCCESS};
use winemu_shared::status;

use super::SvcFrame;

const MAX_WAIT_HANDLES: usize = 64;

const ACCESS_MASK_EVENT:     u32 = 0x001F_0003;
const ACCESS_MASK_MUTEX:     u32 = 0x001F_0001;
const ACCESS_MASK_SEMAPHORE: u32 = 0x001F_0003;

// x0 = EventHandle* (out), x1 = DesiredAccess, x2 = ObjectAttributes*
// x3 = EventType (0=Notification, 1=Sync), x4 = InitialState
pub(crate) fn handle_create_event(frame: &mut SvcFrame) {
    let desired_access = frame.x[1] as u32;
    if (desired_access & !ACCESS_MASK_EVENT) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    // x3: 0=NotificationEvent (manual-reset), 1=SynchronizationEvent (auto-reset)
    let auto_reset = frame.x[3] == 1;
    let initial    = frame.x[4] != 0;
    match create_event(auto_reset, initial) {
        Some(h) => {
            write_out_handle(frame, h);
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        None => frame.x[0] = status::NO_MEMORY as u64,
    }
}

pub(crate) fn handle_set_event(frame: &mut SvcFrame) {
    frame.x[0] = set_event(frame.x[0]) as u64;
}

pub(crate) fn handle_reset_event_or_delay(frame: &mut SvcFrame) {
    if super::system::should_dispatch_delay_execution(frame) {
        super::system::handle_delay_execution(frame);
    } else {
        frame.x[0] = reset_event(frame.x[0]) as u64;
    }
}

// x0 = Handle, x1 = Alertable, x2 = Timeout* (LARGE_INTEGER*)
pub(crate) fn handle_wait_single(frame: &mut SvcFrame) {
    let h       = frame.x[0];
    let timeout = parse_timeout(frame.x[2] as *const i64);
    frame.x[0]  = wait_for_single_object(h, timeout) as u64;
}

pub(crate) fn handle_wait_multiple(frame: &mut SvcFrame) {
    let count    = frame.x[0] as usize;
    let arr      = frame.x[1] as *const u64;
    let wait_type = frame.x[2] as u32;
    let wait_all = match wait_type {
        0 => true,  // WaitAll
        1 => false, // WaitAny
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
    };
    if arr.is_null() || count == 0 || count > MAX_WAIT_HANDLES {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let timeout = parse_timeout(frame.x[4] as *const i64);
    let mut handles = [0u64; MAX_WAIT_HANDLES];
    for i in 0..count {
        handles[i] = unsafe { arr.add(i).read_volatile() };
    }
    frame.x[0] = wait_for_multiple_objects(&handles[..count], wait_all, timeout) as u64;
}

// x0 = MutantHandle* (out), x1 = DesiredAccess, x2 = ObjAttr*, x3 = InitialOwner
pub(crate) fn handle_create_mutex(frame: &mut SvcFrame) {
    let desired_access = frame.x[1] as u32;
    if (desired_access & !ACCESS_MASK_MUTEX) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    let initial_owner = frame.x[3] != 0;
    match create_mutex(initial_owner) {
        Some(h) => {
            write_out_handle(frame, h);
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        None => frame.x[0] = status::NO_MEMORY as u64,
    }
}

// `NtReleaseMutant` and `NtSetInformationProcess` share nr in current ABI profile.
pub(crate) fn handle_release_mutant_or_set_information_process(frame: &mut SvcFrame) {
    if super::process::should_dispatch_set_information_process(frame) {
        super::process::handle_set_information_process(frame);
        return;
    }
    frame.x[0] = release_mutex(frame.x[0]) as u64;
}

// x0 = SemaphoreHandle* (out), x1 = DesiredAccess, x2 = ObjAttr*
// x3 = InitialCount, x4 = MaximumCount
pub(crate) fn handle_create_semaphore(frame: &mut SvcFrame) {
    let desired_access = frame.x[1] as u32;
    if (desired_access & !ACCESS_MASK_SEMAPHORE) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    let initial = frame.x[3] as i32;
    let maximum = frame.x[4] as i32;
    match create_semaphore(initial, maximum) {
        Some(h) => {
            write_out_handle(frame, h);
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        None => frame.x[0] = status::NO_MEMORY as u64,
    }
}

// x0 = SemaphoreHandle, x1 = ReleaseCount, x2 = PreviousCount* (opt)
pub(crate) fn handle_release_semaphore(frame: &mut SvcFrame) {
    let h     = frame.x[0];
    let count = frame.x[1] as i32;
    let (st, prev) = release_semaphore(h, count);
    if st == STATUS_SUCCESS {
        if let Some(ptr) = unsafe { (frame.x[2] as *mut u32).as_mut() } {
            unsafe { (ptr as *mut u32).write_volatile(prev as u32) };
        }
    }
    frame.x[0] = st as u64;
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
    timeout_to_deadline(raw)
}
