use core::mem::size_of;
use winemu_shared::status;

use crate::mm::usercopy::write_current_user_value;
use super::SvcFrame;

// ── Guest-memory layout structs ───────────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone)]
struct TokenUser {
    sid_ptr:    u64,  // pointer to SID (follows immediately in same buffer)
    attributes: u32,
    _pad:       u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Sid1 {
    revision:           u8,
    sub_authority_count: u8,
    authority:          [u8; 6],
    sub_authority_0:    u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TokenUserBuffer {
    user: TokenUser,
    sid:  Sid1,
}

// ── Constants ─────────────────────────────────────────────────────────────────

const TOKEN_USER_CLASS: u32 = 1;
const TOKEN_TYPE_CLASS: u32 = 8;
const TOKEN_IMPERSONATION_LEVEL_CLASS: u32 = 9;
const TOKEN_SESSION_ID_CLASS: u32 = 12;
const TOKEN_ELEVATION_TYPE_CLASS: u32 = 18;
const TOKEN_LINKED_TOKEN_CLASS: u32 = 19;
const TOKEN_ELEVATION_CLASS: u32 = 20;
const TOKEN_VIRTUALIZATION_ENABLED_CLASS: u32 = 24;
const TOKEN_IS_APP_CONTAINER_CLASS: u32 = 29;

const TOKEN_TYPE_PRIMARY: u32 = 1;
const SECURITY_IMPERSONATION_LEVEL: u32 = 2;
const TOKEN_ELEVATION_TYPE_DEFAULT: u32 = 1;

const TOKEN_USER_ATTRIBUTES: u32 = 0;
const TOKEN_IS_ELEVATED: u32 = 0;
const TOKEN_VIRTUALIZATION_ENABLED: u32 = 0;
const TOKEN_IS_APP_CONTAINER: u32 = 0;

const SID_REVISION: u8 = 1;
const SECURITY_LOCAL_SYSTEM_RID: u32 = 18;
const SECURITY_NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

const PSEUDO_CURRENT_PROCESS_TOKEN: u64 = u64::MAX - 3;
const PSEUDO_CURRENT_THREAD_TOKEN: u64 = u64::MAX - 4;
const PSEUDO_CURRENT_THREAD_EFFECTIVE_TOKEN: u64 = u64::MAX - 5;

pub fn is_valid_token_handle(token_handle: u64) -> bool {
    resolve_token_owner_pid(token_handle).is_some()
}

// x0=ProcessHandle, x1=DesiredAccess, x2=*TokenHandle
pub(crate) fn handle_open_process_token(frame: &mut SvcFrame) {
    let process_handle = frame.x[0];
    let desired_access = frame.x[1] as u32;
    let out_ptr = frame.x[2] as *mut u64;

    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Some(pid) = crate::process::resolve_process_handle(process_handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let meta = super::kobject::object_type_meta_for_kind(crate::process::KObjectKind::Token);
    if (desired_access & !meta.valid_access_mask) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }

    let cur_pid = crate::process::current_pid();
    let Some(token_handle) = super::kobject::add_handle_for_pid(
        cur_pid,
        crate::process::KObjectRef::token(pid),
    ) else {
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };

    if !write_current_user_value(out_ptr, token_handle) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    frame.x[0] = status::SUCCESS as u64;
}

// x0=ProcessHandle, x1=DesiredAccess, x2=HandleAttributes, x3=*TokenHandle
pub(crate) fn handle_open_process_token_ex(frame: &mut SvcFrame) {
    // HandleAttributes (x2) ignored — delegate to base OpenProcessToken logic
    let process_handle = frame.x[0];
    let desired_access = frame.x[1] as u32;
    let out_ptr = frame.x[3] as *mut u64;

    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let Some(pid) = crate::process::resolve_process_handle(process_handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    let meta = super::kobject::object_type_meta_for_kind(crate::process::KObjectKind::Token);
    if (desired_access & !meta.valid_access_mask) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    let cur_pid = crate::process::current_pid();
    let Some(token_handle) = super::kobject::add_handle_for_pid(
        cur_pid,
        crate::process::KObjectRef::token(pid),
    ) else {
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };
    if !write_current_user_value(out_ptr, token_handle) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    frame.x[0] = status::SUCCESS as u64;
}

// x0=ThreadHandle, x1=OpenAsSelf, x2=DesiredAccess, x3=*TokenHandle
// x0=ThreadHandle, x1=OpenAsSelf, x2=HandleAttributes, x3=DesiredAccess, x4=*TokenHandle (Ex)
// We use the process token for the thread's owning process (no impersonation support).
pub(crate) fn handle_open_thread_token(frame: &mut SvcFrame) {
    let thread_handle = frame.x[0];
    let out_ptr = frame.x[3] as *mut u64;
    open_thread_token_inner(thread_handle, out_ptr, frame);
}

pub(crate) fn handle_open_thread_token_ex(frame: &mut SvcFrame) {
    let thread_handle = frame.x[0];
    let out_ptr = frame.x[4] as *mut u64;
    open_thread_token_inner(thread_handle, out_ptr, frame);
}

fn open_thread_token_inner(thread_handle: u64, out_ptr: *mut u64, frame: &mut SvcFrame) {
    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let tid = super::kobject::handle_to_tid(thread_handle);
    let pid = tid.map(|t| crate::sched::thread_pid(t)).unwrap_or(0);
    if pid == 0 {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
    let cur_pid = crate::process::current_pid();
    let Some(token_handle) = super::kobject::add_handle_for_pid(
        cur_pid,
        crate::process::KObjectRef::token(pid),
    ) else {
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };
    if !write_current_user_value(out_ptr, token_handle) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    frame.x[0] = status::SUCCESS as u64;
}

// x0=TokenHandle, x1=DisableAllPrivileges, x2=NewState*, x3=BufferLength,
// x4=PreviousState*, x5=ReturnLength*
// Stub: always succeed (we don't enforce privileges).
pub(crate) fn handle_adjust_privileges_token(frame: &mut SvcFrame) {
    frame.x[0] = status::SUCCESS as u64;
}

// x0=TokenHandle, x1=TokenInformationClass, x2=Buffer, x3=Length, x4=*ReturnLength
pub(crate) fn handle_query_information_token(frame: &mut SvcFrame) {
    let token_handle = frame.x[0];
    let info_class = frame.x[1] as u32;
    let buf = frame.x[2] as *mut u8;
    let len = frame.x[3] as usize;
    let ret_len = frame.x[4] as *mut u32;

    let Some(pid) = resolve_token_owner_pid(token_handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    frame.x[0] = match info_class {
        TOKEN_USER_CLASS => query_token_user(buf, len, ret_len),
        TOKEN_TYPE_CLASS => write_u32(buf, len, ret_len, TOKEN_TYPE_PRIMARY),
        TOKEN_IMPERSONATION_LEVEL_CLASS => {
            write_u32(buf, len, ret_len, SECURITY_IMPERSONATION_LEVEL)
        }
        TOKEN_SESSION_ID_CLASS => write_u32(buf, len, ret_len, 0),
        TOKEN_ELEVATION_TYPE_CLASS => write_u32(buf, len, ret_len, TOKEN_ELEVATION_TYPE_DEFAULT),
        TOKEN_LINKED_TOKEN_CLASS => query_token_linked_token(pid, buf, len, ret_len),
        TOKEN_ELEVATION_CLASS => write_u32(buf, len, ret_len, TOKEN_IS_ELEVATED),
        TOKEN_VIRTUALIZATION_ENABLED_CLASS => {
            write_u32(buf, len, ret_len, TOKEN_VIRTUALIZATION_ENABLED)
        }
        TOKEN_IS_APP_CONTAINER_CLASS => write_u32(buf, len, ret_len, TOKEN_IS_APP_CONTAINER),
        _ => status::INVALID_PARAMETER,
    } as u64;
}

fn resolve_token_owner_pid(token_handle: u64) -> Option<u32> {
    if token_handle == PSEUDO_CURRENT_PROCESS_TOKEN
        || token_handle == PSEUDO_CURRENT_THREAD_TOKEN
        || token_handle == PSEUDO_CURRENT_THREAD_EFFECTIVE_TOKEN
    {
        let pid = crate::process::current_pid();
        return if pid != 0 { Some(pid) } else { None };
    }

    let cur_pid = crate::process::current_pid();
    let obj = crate::process::with_process_mut(cur_pid, |p| {
        p.handle_table.get(token_handle as u32)
    }).flatten()?;
    if obj.kind != crate::process::KObjectKind::Token {
        return None;
    }
    let pid = obj.obj_idx;
    if pid == 0 || !crate::process::process_exists(pid) {
        return None;
    }
    Some(pid)
}

fn query_token_user(buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    use super::common::GuestWriter;
    let required = size_of::<TokenUserBuffer>();
    let Some(mut w) = GuestWriter::new(buf, len, required) else {
        write_ret_len(ret_len, required as u32);
        return status::BUFFER_TOO_SMALL;
    };
    let sid_addr = buf as u64 + size_of::<TokenUser>() as u64;
    w.write_struct(TokenUserBuffer {
        user: TokenUser { sid_ptr: sid_addr, attributes: TOKEN_USER_ATTRIBUTES, _pad: 0 },
        sid:  Sid1 {
            revision:            SID_REVISION,
            sub_authority_count: 1,
            authority:           SECURITY_NT_AUTHORITY,
            sub_authority_0:     SECURITY_LOCAL_SYSTEM_RID,
        },
    });
    write_ret_len(ret_len, required as u32);
    status::SUCCESS
}

fn query_token_linked_token(pid: u32, buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || len < size_of::<u64>() {
        write_ret_len(ret_len, size_of::<u64>() as u32);
        return status::BUFFER_TOO_SMALL;
    }

    let cur_pid = crate::process::current_pid();
    let Some(linked) = super::kobject::add_handle_for_pid(
        cur_pid,
        crate::process::KObjectRef::token(pid),
    ) else {
        return status::NO_MEMORY;
    };
    if !write_current_user_value(buf as *mut u64, linked) {
        return status::INVALID_PARAMETER;
    }
    write_ret_len(ret_len, size_of::<u64>() as u32);
    status::SUCCESS
}

fn write_u32(buf: *mut u8, len: usize, ret_len: *mut u32, value: u32) -> u32 {
    if buf.is_null() || len < size_of::<u32>() {
        write_ret_len(ret_len, size_of::<u32>() as u32);
        return status::BUFFER_TOO_SMALL;
    }

    if !write_current_user_value(buf as *mut u32, value) {
        return status::INVALID_PARAMETER;
    }
    write_ret_len(ret_len, size_of::<u32>() as u32);
    status::SUCCESS
}

fn write_ret_len(ptr: *mut u32, value: u32) {
    if !ptr.is_null() {
        let _ = write_current_user_value(ptr, value);
    }
}
