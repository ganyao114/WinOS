use core::mem::size_of;

use winemu_shared::status;

use crate::sched::sync::HANDLE_TYPE_TOKEN;

use super::SvcFrame;

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

const SID_SIZE: usize = 12;
const TOKEN_USER_SIZE: usize = 16;
const TOKEN_USER_TOTAL_SIZE: usize = TOKEN_USER_SIZE + SID_SIZE;

const PSEUDO_CURRENT_PROCESS_TOKEN: u64 = u64::MAX - 3;
const PSEUDO_CURRENT_THREAD_TOKEN: u64 = u64::MAX - 4;
const PSEUDO_CURRENT_THREAD_EFFECTIVE_TOKEN: u64 = u64::MAX - 5;

pub fn is_valid_token_handle(token_handle: u64) -> bool {
    resolve_token_owner_pid(token_handle).is_some()
}

// x0=ProcessHandle, x1=DesiredAccess, x2=*TokenHandle
pub(crate) fn handle_open_process_token(frame: &mut SvcFrame) {
    let process_handle = frame.x[0];
    let _desired_access = frame.x[1] as u32;
    let out_ptr = frame.x[2] as *mut u64;

    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Some(pid) = crate::process::resolve_process_handle(process_handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let Some(token_handle) = crate::sched::sync::make_new_handle(HANDLE_TYPE_TOKEN, pid) else {
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };

    unsafe { out_ptr.write_volatile(token_handle) };
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
        if pid != 0 {
            return Some(pid);
        }
        return None;
    }

    if crate::sched::sync::handle_type(token_handle) != HANDLE_TYPE_TOKEN {
        return None;
    }
    let pid = crate::sched::sync::handle_idx(token_handle);
    if pid == 0 || !crate::process::process_exists(pid) {
        return None;
    }
    Some(pid)
}

fn query_token_user(buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || len < TOKEN_USER_TOTAL_SIZE {
        write_ret_len(ret_len, TOKEN_USER_TOTAL_SIZE as u32);
        return status::BUFFER_TOO_SMALL;
    }

    let sid_ptr = unsafe { buf.add(TOKEN_USER_SIZE) };
    let sid_addr = sid_ptr as u64;

    unsafe {
        (buf as *mut u64).write_volatile(sid_addr);
        (buf.add(size_of::<u64>()) as *mut u32).write_volatile(TOKEN_USER_ATTRIBUTES);
        (buf.add(size_of::<u64>() + size_of::<u32>()) as *mut u32).write_volatile(0);
    }

    write_sid_local_system(sid_ptr);
    write_ret_len(ret_len, TOKEN_USER_TOTAL_SIZE as u32);
    status::SUCCESS
}

fn query_token_linked_token(pid: u32, buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || len < size_of::<u64>() {
        write_ret_len(ret_len, size_of::<u64>() as u32);
        return status::BUFFER_TOO_SMALL;
    }

    let Some(linked) = crate::sched::sync::make_new_handle(HANDLE_TYPE_TOKEN, pid) else {
        return status::NO_MEMORY;
    };
    unsafe {
        (buf as *mut u64).write_volatile(linked);
    }
    write_ret_len(ret_len, size_of::<u64>() as u32);
    status::SUCCESS
}

fn write_u32(buf: *mut u8, len: usize, ret_len: *mut u32, value: u32) -> u32 {
    if buf.is_null() || len < size_of::<u32>() {
        write_ret_len(ret_len, size_of::<u32>() as u32);
        return status::BUFFER_TOO_SMALL;
    }

    unsafe {
        (buf as *mut u32).write_volatile(value);
    }
    write_ret_len(ret_len, size_of::<u32>() as u32);
    status::SUCCESS
}

fn write_sid_local_system(dst: *mut u8) {
    unsafe {
        dst.add(0).write_volatile(SID_REVISION);
        dst.add(1).write_volatile(1);
        let mut i = 0usize;
        while i < SECURITY_NT_AUTHORITY.len() {
            dst.add(2 + i).write_volatile(SECURITY_NT_AUTHORITY[i]);
            i += 1;
        }
        (dst.add(8) as *mut u32).write_volatile(SECURITY_LOCAL_SYSTEM_RID);
    }
}

fn write_ret_len(ptr: *mut u32, value: u32) {
    if !ptr.is_null() {
        unsafe { ptr.write_volatile(value) };
    }
}
