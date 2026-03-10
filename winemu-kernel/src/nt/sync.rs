use crate::sched::sync::{
    create_event, set_event, reset_event,
    create_mutex, release_mutex,
    create_semaphore, release_semaphore,
    wait_for_single_object, wait_for_multiple_objects,
    sync_alloc, SyncObject,
};
use crate::sched::sync::primitives_api::{KEvent, KMutex, KSemaphore};
use crate::process::{KObjectKind, KObjectRef, current_pid, with_process_mut};
use crate::sched::types::WaitDeadline;
use crate::sched::wait::{timeout_to_deadline, STATUS_SUCCESS};
use winemu_shared::status;

use super::named_objects as nobj;
use crate::mm::usercopy::{
    copy_from_current_user, read_current_user_value, write_current_user_value,
};
use super::SvcFrame;

const MAX_WAIT_HANDLES: usize = 64;

const ACCESS_MASK_EVENT:     u32 = 0x001F_0003;
const ACCESS_MASK_MUTEX:     u32 = 0x001F_0001;
const ACCESS_MASK_SEMAPHORE: u32 = 0x001F_0003;

const OBJ_OPENIF: u32 = 0x80;

// ── OA name helpers ───────────────────────────────────────────────────────────

/// Read and normalize the ObjectName from an ObjectAttributes pointer.
/// Returns (name_buf, name_len, attributes_u32).
fn read_oa_name(oa_ptr: u64) -> ([u8; 128], usize, u32) {
    let mut name = [0u8; 128];
    if oa_ptr == 0 {
        return (name, 0, 0);
    }
    let attrs = read_current_user_value((oa_ptr + 24) as *const u32).unwrap_or(0);
    let us_ptr = read_current_user_value((oa_ptr + 16) as *const u64).unwrap_or(0);
    if us_ptr == 0 {
        return (name, 0, attrs);
    }
    let byte_len = read_current_user_value(us_ptr as *const u16).unwrap_or(0) as usize;
    let buf_ptr = read_current_user_value((us_ptr + 8) as *const u64).unwrap_or(0);
    if byte_len == 0 || buf_ptr == 0 {
        return (name, 0, attrs);
    }
    let mut raw = [0u8; 128];
    let count = core::cmp::min(byte_len / 2, 128);
    for i in 0..count {
        let wc = read_current_user_value((buf_ptr + (i as u64 * 2)) as *const u16).unwrap_or(0);
        raw[i] = if wc < 0x80 { wc as u8 } else { b'?' };
    }
    let len = nobj::normalize_name(&raw[..count], &mut name);
    (name, len, attrs)
}

/// Open-by-name: look up named object, add a handle for current process.
fn open_named(kind: KObjectKind, name: &[u8; 128], name_len: usize) -> Option<u64> {
    let obj_idx = nobj::lookup(kind, name, name_len)?;
    let pid = current_pid();
    let kref = match kind {
        KObjectKind::Event     => KObjectRef::event(obj_idx),
        KObjectKind::Mutex     => KObjectRef::mutex(obj_idx),
        KObjectKind::Semaphore => KObjectRef::semaphore(obj_idx),
        _ => return None,
    };
    with_process_mut(pid, |p| p.handle_table.add(kref)).flatten().map(|h| h as u64)
}

// x0 = EventHandle* (out), x1 = DesiredAccess, x2 = ObjectAttributes*
// x3 = EventType (0=Notification, 1=Sync), x4 = InitialState
pub(crate) fn handle_create_event(frame: &mut SvcFrame) {
    let desired_access = frame.x[1] as u32;
    if (desired_access & !ACCESS_MASK_EVENT) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    let oa_ptr = frame.x[2];
    let auto_reset = frame.x[3] == 1;
    let initial    = frame.x[4] != 0;

    let (name, name_len, attrs) = read_oa_name(oa_ptr);

    if name_len > 0 {
        // Named object: check if already exists
        if let Some(h) = open_named(KObjectKind::Event, &name, name_len) {
            write_out_handle(frame, h);
            // STATUS_OBJECT_NAME_EXISTS when OBJ_OPENIF and object already existed
            frame.x[0] = if (attrs & OBJ_OPENIF) != 0 {
                status::OBJECT_NAME_EXISTS as u64
            } else {
                status::OBJECT_NAME_COLLISION as u64
            };
            return;
        }
        // Create new named event
        let _lock = crate::sched::lock::KSchedulerLock::lock();
        let obj_idx = match sync_alloc(SyncObject::Event(KEvent::new(auto_reset, initial))) {
            Some(idx) => idx as u32,
            None => { frame.x[0] = status::NO_MEMORY as u64; return; }
        };
        nobj::insert(KObjectKind::Event, obj_idx, &name, name_len);
        let pid = current_pid();
        match with_process_mut(pid, |p| p.handle_table.add(KObjectRef::event(obj_idx))).flatten() {
            Some(h) => { write_out_handle(frame, h as u64); frame.x[0] = STATUS_SUCCESS as u64; }
            None    => { frame.x[0] = status::NO_MEMORY as u64; }
        }
    } else {
        match create_event(auto_reset, initial) {
            Some(h) => { write_out_handle(frame, h); frame.x[0] = STATUS_SUCCESS as u64; }
            None    => { frame.x[0] = status::NO_MEMORY as u64; }
        }
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
    if !copy_from_current_user(arr.cast::<u8>(), handles.as_mut_ptr().cast::<u8>(), count * 8) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
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
    let oa_ptr = frame.x[2];
    let initial_owner = frame.x[3] != 0;
    let (name, name_len, attrs) = read_oa_name(oa_ptr);

    if name_len > 0 {
        if let Some(h) = open_named(KObjectKind::Mutex, &name, name_len) {
            write_out_handle(frame, h);
            frame.x[0] = if (attrs & OBJ_OPENIF) != 0 {
                status::OBJECT_NAME_EXISTS as u64
            } else {
                status::OBJECT_NAME_COLLISION as u64
            };
            return;
        }
        let _lock = crate::sched::lock::KSchedulerLock::lock();
        let mut m = KMutex::new();
        if initial_owner {
            m.owner_tid = crate::sched::current_tid();
            m.recursion = 1;
        }
        let obj_idx = match sync_alloc(SyncObject::Mutex(m)) {
            Some(idx) => idx as u32,
            None => { frame.x[0] = status::NO_MEMORY as u64; return; }
        };
        nobj::insert(KObjectKind::Mutex, obj_idx, &name, name_len);
        let pid = current_pid();
        match with_process_mut(pid, |p| p.handle_table.add(KObjectRef::mutex(obj_idx))).flatten() {
            Some(h) => { write_out_handle(frame, h as u64); frame.x[0] = STATUS_SUCCESS as u64; }
            None    => { frame.x[0] = status::NO_MEMORY as u64; }
        }
    } else {
        match create_mutex(initial_owner) {
            Some(h) => { write_out_handle(frame, h); frame.x[0] = STATUS_SUCCESS as u64; }
            None    => { frame.x[0] = status::NO_MEMORY as u64; }
        }
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
    let oa_ptr  = frame.x[2];
    let initial = frame.x[3] as i32;
    let maximum = frame.x[4] as i32;
    let (name, name_len, attrs) = read_oa_name(oa_ptr);

    if name_len > 0 {
        if let Some(h) = open_named(KObjectKind::Semaphore, &name, name_len) {
            write_out_handle(frame, h);
            frame.x[0] = if (attrs & OBJ_OPENIF) != 0 {
                status::OBJECT_NAME_EXISTS as u64
            } else {
                status::OBJECT_NAME_COLLISION as u64
            };
            return;
        }
        let _lock = crate::sched::lock::KSchedulerLock::lock();
        let obj_idx = match sync_alloc(SyncObject::Semaphore(KSemaphore::new(initial, maximum))) {
            Some(idx) => idx as u32,
            None => { frame.x[0] = status::NO_MEMORY as u64; return; }
        };
        nobj::insert(KObjectKind::Semaphore, obj_idx, &name, name_len);
        let pid = current_pid();
        match with_process_mut(pid, |p| p.handle_table.add(KObjectRef::semaphore(obj_idx))).flatten() {
            Some(h) => { write_out_handle(frame, h as u64); frame.x[0] = STATUS_SUCCESS as u64; }
            None    => { frame.x[0] = status::NO_MEMORY as u64; }
        }
    } else {
        match create_semaphore(initial, maximum) {
            Some(h) => { write_out_handle(frame, h); frame.x[0] = STATUS_SUCCESS as u64; }
            None    => { frame.x[0] = status::NO_MEMORY as u64; }
        }
    }
}

// x0 = SemaphoreHandle, x1 = ReleaseCount, x2 = PreviousCount* (opt)
pub(crate) fn handle_release_semaphore(frame: &mut SvcFrame) {
    let h     = frame.x[0];
    let count = frame.x[1] as i32;
    let (st, prev) = release_semaphore(h, count);
    if st == STATUS_SUCCESS {
        let ptr = frame.x[2] as *mut u32;
        if !ptr.is_null() && !write_current_user_value(ptr, prev as u32) {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
    }
    frame.x[0] = st as u64;
}

// x0 = EventHandle
pub(crate) fn handle_clear_event(frame: &mut SvcFrame) {
    use crate::sched::sync::reset_event;
    frame.x[0] = reset_event(frame.x[0]) as u64;
}

// x0 = EventHandle* (out), x1 = DesiredAccess, x2 = ObjectAttributes*
pub(crate) fn handle_open_event(frame: &mut SvcFrame) {
    let (name, name_len, _) = read_oa_name(frame.x[2]);
    if name_len == 0 {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    match open_named(KObjectKind::Event, &name, name_len) {
        Some(h) => { write_out_handle(frame, h); frame.x[0] = STATUS_SUCCESS as u64; }
        None    => { frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64; }
    }
}

// x0 = MutantHandle* (out), x1 = DesiredAccess, x2 = ObjectAttributes*
pub(crate) fn handle_open_mutex(frame: &mut SvcFrame) {
    let (name, name_len, _) = read_oa_name(frame.x[2]);
    if name_len == 0 {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    match open_named(KObjectKind::Mutex, &name, name_len) {
        Some(h) => { write_out_handle(frame, h); frame.x[0] = STATUS_SUCCESS as u64; }
        None    => { frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64; }
    }
}

// x0 = SemaphoreHandle* (out), x1 = DesiredAccess, x2 = ObjectAttributes*
pub(crate) fn handle_open_semaphore(frame: &mut SvcFrame) {
    let (name, name_len, _) = read_oa_name(frame.x[2]);
    if name_len == 0 {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    match open_named(KObjectKind::Semaphore, &name, name_len) {
        Some(h) => { write_out_handle(frame, h); frame.x[0] = STATUS_SUCCESS as u64; }
        None    => { frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64; }
    }
}

// x0 = EventHandle, x1 = EventInformationClass, x2 = buf, x3 = len, x4 = *ReturnLength
pub(crate) fn handle_query_event(frame: &mut SvcFrame) {
    use crate::sched::sync::query_event;
    let h = frame.x[0];
    let info_class = frame.x[1] as u32;
    let buf = frame.x[2] as *mut u8;
    let len = frame.x[3] as usize;
    let ret_len = frame.x[4] as *mut u32;

    // Only EventBasicInformation (class 0) supported: 8 bytes (EventType u32 + State u32)
    if info_class != 0 {
        frame.x[0] = winemu_shared::status::INVALID_PARAMETER as u64;
        return;
    }
    if buf.is_null() || len < 8 {
        if !ret_len.is_null() {
            let _ = write_current_user_value(ret_len, 8u32);
        }
        frame.x[0] = winemu_shared::status::BUFFER_TOO_SMALL as u64;
        return;
    }
    let (st, signaled) = query_event(h);
    if st != crate::sched::wait::STATUS_SUCCESS {
        frame.x[0] = st as u64;
        return;
    }
    // EventType: 0=NotificationEvent, 1=SynchronizationEvent — we don't track type, use 0
    if !write_current_user_value(buf as *mut u32, 0u32)
        || !write_current_user_value(unsafe { buf.add(4) } as *mut u32, signaled as u32)
    {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if !ret_len.is_null() {
        let _ = write_current_user_value(ret_len, 8u32);
    }
    frame.x[0] = winemu_shared::status::SUCCESS as u64;
}

fn write_out_handle(frame: &SvcFrame, handle: u64) {
    let out_ptr = frame.x[0] as *mut u64;
    if !out_ptr.is_null() {
        let _ = write_current_user_value(out_ptr, handle);
    }
}

fn parse_timeout(timeout_ptr: *const i64) -> WaitDeadline {
    if timeout_ptr.is_null() {
        return WaitDeadline::Infinite;
    }
    let Some(raw) = read_current_user_value(timeout_ptr) else {
        return WaitDeadline::Immediate;
    };
    timeout_to_deadline(raw)
}
