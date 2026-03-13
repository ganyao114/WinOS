use crate::process::{current_pid, KObjectKind, KObjectRef};
use crate::sched::sync::primitives_api::{KEvent, KMutex, KSemaphore};
use crate::sched::sync::{
    create_event, create_mutex, create_semaphore, release_mutex, release_semaphore, reset_event,
    set_event, sync_alloc, wait_for_multiple_objects, wait_for_single_object, SyncObject,
};
use crate::sched::types::WaitDeadline;
use crate::sched::wait::{timeout_to_deadline, STATUS_SUCCESS};
use core::sync::atomic::{AtomicU32, Ordering};
use winemu_shared::status;

use super::common::GuestWriter;
use super::named_objects as nobj;
use super::path::ObjectAttributesView;
use super::user_args::{UserInPtr, UserOutPtr};
use super::SvcFrame;
use crate::mm::usercopy::copy_from_current_user;

const MAX_WAIT_HANDLES: usize = 64;

const ACCESS_MASK_EVENT: u32 = 0x001F_0003;
const ACCESS_MASK_MUTEX: u32 = 0x001F_0001;
const ACCESS_MASK_SEMAPHORE: u32 = 0x001F_0003;

const OBJ_OPENIF: u32 = 0x80;
static WAIT_TRACE_BUDGET: AtomicU32 = AtomicU32::new(128);

// ── OA name helpers ───────────────────────────────────────────────────────────

/// Read and normalize the ObjectName from an ObjectAttributes pointer.
/// Returns (name_buf, name_len, attributes_u32).
fn read_oa_name(oa: Option<ObjectAttributesView>) -> ([u8; 128], usize, u32) {
    let mut name = [0u8; 128];
    let Some(oa) = oa else {
        return (name, 0, 0);
    };
    let attrs = oa.attributes();
    let mut raw = [0u8; 128];
    let raw_len = oa.read_name_ascii(&mut raw);
    if raw_len == 0 {
        return (name, 0, attrs);
    }
    let len = nobj::normalize_name(&raw[..raw_len], &mut name);
    (name, len, attrs)
}

fn sync_kref(kind: KObjectKind, obj_idx: u32) -> Option<KObjectRef> {
    match kind {
        KObjectKind::Event => Some(KObjectRef::event(obj_idx)),
        KObjectKind::Mutex => Some(KObjectRef::mutex(obj_idx)),
        KObjectKind::Semaphore => Some(KObjectRef::semaphore(obj_idx)),
        _ => None,
    }
}

fn lookup_named_live(kind: KObjectKind, name: &[u8; 128], name_len: usize) -> Option<u32> {
    let _lock = crate::sched::lock::KSchedulerLock::lock();
    let obj_idx = nobj::lookup(kind, name, name_len)?;
    if crate::sched::sync::state::sync_get_by_idx(obj_idx).is_some() {
        Some(obj_idx)
    } else {
        nobj::remove(kind, obj_idx);
        None
    }
}

fn open_named_handle(
    kind: KObjectKind,
    name: &[u8; 128],
    name_len: usize,
    out_ptr: UserOutPtr<u64>,
) -> Result<u64, u32> {
    let obj_idx = lookup_named_live(kind, name, name_len).ok_or(status::OBJECT_NAME_NOT_FOUND)?;
    let pid = current_pid();
    let kref = sync_kref(kind, obj_idx).ok_or(status::INVALID_PARAMETER)?;
    super::kobject::install_handle_for_pid(pid, kref, out_ptr)
}

fn alloc_named_sync_object(
    kind: KObjectKind,
    object: SyncObject,
    name: &[u8; 128],
    name_len: usize,
) -> Result<u32, u32> {
    let _lock = crate::sched::lock::KSchedulerLock::lock();
    let Some(obj_idx) = sync_alloc(object).map(|idx| idx as u32) else {
        return Err(status::NO_MEMORY);
    };
    if nobj::insert(kind, obj_idx, name, name_len) {
        Ok(obj_idx)
    } else {
        let _ = crate::sched::sync::sync_free_idx(obj_idx);
        Err(status::NO_MEMORY)
    }
}

fn rollback_named_sync_create(kind: KObjectKind, obj_idx: u32, install_status: u32) {
    if install_status != status::NO_MEMORY {
        return;
    }
    let _lock = crate::sched::lock::KSchedulerLock::lock();
    nobj::remove(kind, obj_idx);
    let _ = crate::sched::sync::sync_free_idx(obj_idx);
}

fn publish_created_handle(out_ptr: UserOutPtr<u64>, handle: u64) -> Result<(), u32> {
    if out_ptr.write_current(handle) {
        Ok(())
    } else {
        let _ = super::kobject::close_handle_for_current(handle);
        Err(status::INVALID_PARAMETER)
    }
}

fn trace_wait_single(handle: u64, deadline: WaitDeadline, result: u32) {
    if !crate::log::log_enabled(crate::log::LogLevel::Trace) {
        return;
    }
    if WAIT_TRACE_BUDGET
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1))
        .is_err()
    {
        return;
    }
    crate::log::debug_print("nt: WaitSingle tid=");
    crate::log::debug_u64(crate::sched::current_tid() as u64);
    crate::log::debug_print(" pid=");
    crate::log::debug_u64(current_pid() as u64);
    crate::log::debug_print(" handle=");
    crate::log::debug_u64(handle);
    crate::log::debug_print(" deadline=");
    crate::log::debug_u64(deadline.to_ticks());
    if let Some((kind, obj_idx)) = super::kobject::resolve_handle_target(handle) {
        crate::log::debug_print(" kind=");
        crate::log::debug_u64(kind as u64);
        crate::log::debug_print(" obj_idx=");
        crate::log::debug_u64(obj_idx as u64);
    } else {
        crate::log::debug_print(" kind=<unresolved>");
    }
    crate::log::debug_print(" result=");
    crate::log::debug_u64(result as u64);
    crate::log::debug_print("\n");
}

fn trace_wait_multiple(handles: &[u64], wait_all: bool, deadline: WaitDeadline, result: u32) {
    if !crate::log::log_enabled(crate::log::LogLevel::Trace) {
        return;
    }
    if WAIT_TRACE_BUDGET
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1))
        .is_err()
    {
        return;
    }
    crate::log::debug_print("nt: WaitMultiple tid=");
    crate::log::debug_u64(crate::sched::current_tid() as u64);
    crate::log::debug_print(" pid=");
    crate::log::debug_u64(current_pid() as u64);
    crate::log::debug_print(" count=");
    crate::log::debug_u64(handles.len() as u64);
    crate::log::debug_print(" wait_all=");
    crate::log::debug_u64(wait_all as u64);
    crate::log::debug_print(" deadline=");
    crate::log::debug_u64(deadline.to_ticks());
    crate::log::debug_print(" result=");
    crate::log::debug_u64(result as u64);
    let limit = core::cmp::min(handles.len(), 4);
    for (idx, handle) in handles.iter().take(limit).enumerate() {
        crate::log::debug_print(" h[");
        crate::log::debug_u64(idx as u64);
        crate::log::debug_print("]=");
        crate::log::debug_u64(*handle);
        if let Some((kind, obj_idx)) = super::kobject::resolve_handle_target(*handle) {
            crate::log::debug_print("(");
            crate::log::debug_u64(kind as u64);
            crate::log::debug_print(",");
            crate::log::debug_u64(obj_idx as u64);
            crate::log::debug_print(")");
        }
    }
    crate::log::debug_print("\n");
}

// x0 = EventHandle* (out), x1 = DesiredAccess, x2 = ObjectAttributes*
// x3 = EventType (0=Notification, 1=Sync), x4 = InitialState
pub(crate) fn handle_create_event(frame: &mut SvcFrame) {
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    if (desired_access & !ACCESS_MASK_EVENT) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let oa_ptr = frame.x[2];
    let auto_reset = frame.x[3] == 1;
    let initial = frame.x[4] != 0;

    let (name, name_len, attrs) = read_oa_name(ObjectAttributesView::from_ptr(oa_ptr));

    if name_len > 0 {
        // Named object: check if already exists
        if let Some(_obj_idx) = lookup_named_live(KObjectKind::Event, &name, name_len) {
            let st = match open_named_handle(KObjectKind::Event, &name, name_len, out_ptr) {
                Ok(_) => {
                    if (attrs & OBJ_OPENIF) != 0 {
                        status::OBJECT_NAME_EXISTS
                    } else {
                        status::OBJECT_NAME_COLLISION
                    }
                }
                Err(st) => st,
            };
            // STATUS_OBJECT_NAME_EXISTS when OBJ_OPENIF and object already existed
            frame.x[0] = st as u64;
            return;
        }
        // Create new named event
        let obj_idx = match alloc_named_sync_object(
            KObjectKind::Event,
            SyncObject::Event(KEvent::new(auto_reset, initial)),
            &name,
            name_len,
        ) {
            Ok(idx) => idx,
            Err(st) => {
                frame.x[0] = st as u64;
                return;
            }
        };
        let pid = current_pid();
        match super::kobject::install_handle_for_pid(pid, KObjectRef::event(obj_idx), out_ptr) {
            Ok(_) => {
                frame.x[0] = STATUS_SUCCESS as u64;
            }
            Err(st) => {
                rollback_named_sync_create(KObjectKind::Event, obj_idx, st);
                frame.x[0] = st as u64;
            }
        }
    } else {
        match create_event(auto_reset, initial) {
            Some(h) => {
                frame.x[0] = match publish_created_handle(out_ptr, h) {
                    Ok(()) => STATUS_SUCCESS,
                    Err(st) => st,
                } as u64;
            }
            None => {
                frame.x[0] = status::NO_MEMORY as u64;
            }
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
    let h = frame.x[0];
    let timeout = parse_timeout(UserInPtr::from_raw(frame.x[2] as *const i64));
    let st = wait_for_single_object(h, timeout);
    trace_wait_single(h, timeout, st);
    frame.x[0] = st as u64;
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
    if arr.is_null() || count == 0 || count > MAX_WAIT_HANDLES {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let timeout = parse_timeout(UserInPtr::from_raw(frame.x[4] as *const i64));
    let mut handles = [0u64; MAX_WAIT_HANDLES];
    if !copy_from_current_user(
        arr.cast::<u8>(),
        handles.as_mut_ptr().cast::<u8>(),
        count * 8,
    ) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let st = wait_for_multiple_objects(&handles[..count], wait_all, timeout);
    trace_wait_multiple(&handles[..count], wait_all, timeout, st);
    frame.x[0] = st as u64;
}

// x0 = MutantHandle* (out), x1 = DesiredAccess, x2 = ObjAttr*, x3 = InitialOwner
pub(crate) fn handle_create_mutex(frame: &mut SvcFrame) {
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    if (desired_access & !ACCESS_MASK_MUTEX) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let oa_ptr = frame.x[2];
    let initial_owner = frame.x[3] != 0;
    let (name, name_len, attrs) = read_oa_name(ObjectAttributesView::from_ptr(oa_ptr));

    if name_len > 0 {
        if let Some(_obj_idx) = lookup_named_live(KObjectKind::Mutex, &name, name_len) {
            frame.x[0] = match open_named_handle(KObjectKind::Mutex, &name, name_len, out_ptr) {
                Ok(_) => {
                    if (attrs & OBJ_OPENIF) != 0 {
                        status::OBJECT_NAME_EXISTS
                    } else {
                        status::OBJECT_NAME_COLLISION
                    }
                }
                Err(st) => st,
            } as u64;
            return;
        }
        let mut m = KMutex::new();
        if initial_owner {
            m.owner_tid = crate::sched::current_tid();
            m.recursion = 1;
        }
        let obj_idx =
            match alloc_named_sync_object(KObjectKind::Mutex, SyncObject::Mutex(m), &name, name_len)
            {
                Ok(idx) => idx,
                Err(st) => {
                    frame.x[0] = st as u64;
                    return;
                }
            };
        let pid = current_pid();
        match super::kobject::install_handle_for_pid(pid, KObjectRef::mutex(obj_idx), out_ptr) {
            Ok(_) => {
                frame.x[0] = STATUS_SUCCESS as u64;
            }
            Err(st) => {
                rollback_named_sync_create(KObjectKind::Mutex, obj_idx, st);
                frame.x[0] = st as u64;
            }
        }
    } else {
        match create_mutex(initial_owner) {
            Some(h) => {
                frame.x[0] = match publish_created_handle(out_ptr, h) {
                    Ok(()) => STATUS_SUCCESS,
                    Err(st) => st,
                } as u64;
            }
            None => {
                frame.x[0] = status::NO_MEMORY as u64;
            }
        }
    }
}

// `NtReleaseMutant` and `NtSetInformationProcess` share nr in current ABI profile.
pub(crate) fn handle_release_mutant_or_set_information_process(frame: &mut SvcFrame) {
    if super::process::should_dispatch_set_information_process(frame) {
        super::process::handle_set_information_process(frame);
        return;
    }
    let handle = frame.x[0];
    let st = release_mutex(handle);
    if st != status::SUCCESS
        && st != crate::sched::sync::primitives_api::STATUS_MUTANT_NOT_OWNED
    {
        crate::log::debug_print("nt: ReleaseMutant failed handle=");
        crate::log::debug_u64(handle);
        crate::log::debug_print(" st=");
        crate::log::debug_u64(st as u64);
        crate::log::debug_print(" current_tid=");
        crate::log::debug_u64(crate::sched::current_tid() as u64);
        if let Some((kind, obj_idx)) = super::kobject::resolve_handle_target(handle) {
            crate::log::debug_print(" kind=");
            crate::log::debug_u64(kind as u64);
            crate::log::debug_print(" obj_idx=");
            crate::log::debug_u64(obj_idx as u64);
            if kind == KObjectKind::Mutex {
                if let Some(SyncObject::Mutex(m)) = crate::sched::sync::state::sync_get_by_idx(obj_idx)
                {
                    crate::log::debug_print(" owner_tid=");
                    crate::log::debug_u64(m.owner_tid as u64);
                    crate::log::debug_print(" recursion=");
                    crate::log::debug_u64(m.recursion as u64);
                }
            }
        }
        crate::log::debug_print("\n");
    }
    frame.x[0] = st as u64;
}

// x0 = SemaphoreHandle* (out), x1 = DesiredAccess, x2 = ObjAttr*
// x3 = InitialCount, x4 = MaximumCount
pub(crate) fn handle_create_semaphore(frame: &mut SvcFrame) {
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    if (desired_access & !ACCESS_MASK_SEMAPHORE) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let oa_ptr = frame.x[2];
    let initial = frame.x[3] as i32;
    let maximum = frame.x[4] as i32;
    let (name, name_len, attrs) = read_oa_name(ObjectAttributesView::from_ptr(oa_ptr));

    if name_len > 0 {
        if let Some(_obj_idx) = lookup_named_live(KObjectKind::Semaphore, &name, name_len) {
            frame.x[0] = match open_named_handle(KObjectKind::Semaphore, &name, name_len, out_ptr) {
                Ok(_) => {
                    if (attrs & OBJ_OPENIF) != 0 {
                        status::OBJECT_NAME_EXISTS
                    } else {
                        status::OBJECT_NAME_COLLISION
                    }
                }
                Err(st) => st,
            } as u64;
            return;
        }
        let obj_idx = match alloc_named_sync_object(
            KObjectKind::Semaphore,
            SyncObject::Semaphore(KSemaphore::new(initial, maximum)),
            &name,
            name_len,
        ) {
            Ok(idx) => idx,
            Err(st) => {
                frame.x[0] = st as u64;
                return;
            }
        };
        let pid = current_pid();
        match super::kobject::install_handle_for_pid(pid, KObjectRef::semaphore(obj_idx), out_ptr)
        {
            Ok(_) => {
                frame.x[0] = STATUS_SUCCESS as u64;
            }
            Err(st) => {
                rollback_named_sync_create(KObjectKind::Semaphore, obj_idx, st);
                frame.x[0] = st as u64;
            }
        }
    } else {
        match create_semaphore(initial, maximum) {
            Some(h) => {
                frame.x[0] = match publish_created_handle(out_ptr, h) {
                    Ok(()) => STATUS_SUCCESS,
                    Err(st) => st,
                } as u64;
            }
            None => {
                frame.x[0] = status::NO_MEMORY as u64;
            }
        }
    }
}

// x0 = SemaphoreHandle, x1 = ReleaseCount, x2 = PreviousCount* (opt)
pub(crate) fn handle_release_semaphore(frame: &mut SvcFrame) {
    let h = frame.x[0];
    let count = frame.x[1] as i32;
    let (st, prev) = release_semaphore(h, count);
    if st == STATUS_SUCCESS {
        let ptr = UserOutPtr::from_raw(frame.x[2] as *mut u32);
        if !ptr.write_current_if_present(prev as u32) {
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
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    if (desired_access & !ACCESS_MASK_EVENT) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let (name, name_len, _) = read_oa_name(ObjectAttributesView::from_ptr(frame.x[2]));
    if name_len == 0 {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    frame.x[0] = match open_named_handle(KObjectKind::Event, &name, name_len, out_ptr) {
        Ok(_) => STATUS_SUCCESS,
        Err(st) => st,
    } as u64;
}

// x0 = MutantHandle* (out), x1 = DesiredAccess, x2 = ObjectAttributes*
pub(crate) fn handle_open_mutex(frame: &mut SvcFrame) {
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    if (desired_access & !ACCESS_MASK_MUTEX) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let (name, name_len, _) = read_oa_name(ObjectAttributesView::from_ptr(frame.x[2]));
    if name_len == 0 {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    frame.x[0] = match open_named_handle(KObjectKind::Mutex, &name, name_len, out_ptr) {
        Ok(_) => STATUS_SUCCESS,
        Err(st) => st,
    } as u64;
}

// x0 = SemaphoreHandle* (out), x1 = DesiredAccess, x2 = ObjectAttributes*
pub(crate) fn handle_open_semaphore(frame: &mut SvcFrame) {
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    if (desired_access & !ACCESS_MASK_SEMAPHORE) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let (name, name_len, _) = read_oa_name(ObjectAttributesView::from_ptr(frame.x[2]));
    if name_len == 0 {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    frame.x[0] = match open_named_handle(KObjectKind::Semaphore, &name, name_len, out_ptr) {
        Ok(_) => STATUS_SUCCESS,
        Err(st) => st,
    } as u64;
}

// x0 = EventHandle, x1 = EventInformationClass, x2 = buf, x3 = len, x4 = *ReturnLength
pub(crate) fn handle_query_event(frame: &mut SvcFrame) {
    use crate::sched::sync::query_event;
    let h = frame.x[0];
    let info_class = frame.x[1] as u32;
    let buf = frame.x[2] as *mut u8;
    let len = frame.x[3] as usize;
    let ret_len = UserOutPtr::from_raw(frame.x[4] as *mut u32);

    // Only EventBasicInformation (class 0) supported: 8 bytes (EventType u32 + State u32)
    if info_class != 0 {
        frame.x[0] = winemu_shared::status::INVALID_PARAMETER as u64;
        return;
    }
    if buf.is_null() || len < 8 {
        let _ = ret_len.write_current_if_present(8u32);
        frame.x[0] = winemu_shared::status::BUFFER_TOO_SMALL as u64;
        return;
    }
    let (st, signaled) = query_event(h);
    if st != crate::sched::wait::STATUS_SUCCESS {
        frame.x[0] = st as u64;
        return;
    }
    // EventType: 0=NotificationEvent, 1=SynchronizationEvent — we don't track type, use 0
    let Some(mut w) = GuestWriter::new(buf, len, 8) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    w.u32(0).u32(signaled as u32);
    let _ = ret_len.write_current_if_present(8u32);
    frame.x[0] = winemu_shared::status::SUCCESS as u64;
}

fn parse_timeout(timeout_ptr: UserInPtr<i64>) -> WaitDeadline {
    if timeout_ptr.is_null() {
        return WaitDeadline::Infinite;
    }
    let Some(raw) = timeout_ptr.read_current() else {
        return WaitDeadline::Immediate;
    };
    timeout_to_deadline(raw)
}
