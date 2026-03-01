use core::mem::size_of;

use crate::sched::sync::{
    close_handle_info, destroy_object_by_type, duplicate_handle_between, HANDLE_TYPE_EVENT,
    HANDLE_TYPE_FILE, HANDLE_TYPE_KEY, HANDLE_TYPE_MUTEX, HANDLE_TYPE_PROCESS, HANDLE_TYPE_SECTION,
    HANDLE_TYPE_SEMAPHORE, HANDLE_TYPE_THREAD, HANDLE_TYPE_TOKEN, STATUS_SUCCESS,
};
use winemu_shared::status;

use super::common::{STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use super::file;
use super::registry;
use super::section;
use super::SvcFrame;

const OBJECT_INFORMATION_CLASS_BASIC: u32 = 0;
const OBJECT_INFORMATION_CLASS_NAME: u32 = 1;
const OBJECT_INFORMATION_CLASS_TYPE: u32 = 2;
const OBJECT_BASIC_INFORMATION_SIZE: usize = 56;
const OBJECT_NAME_INFORMATION_SIZE: usize = 16;
const OBJECT_TYPE_INFORMATION_SIZE: usize = 104;

// x0=Handle, x1=ObjectInformationClass, x2=Buffer, x3=Length, x4=*ReturnLength
pub(crate) fn handle_query_object(frame: &mut SvcFrame) {
    let handle = frame.x[0];
    let info_class = frame.x[1] as u32;
    let buf = frame.x[2] as *mut u8;
    let len = frame.x[3] as usize;
    let ret_len = frame.x[4] as *mut u32;

    match info_class {
        OBJECT_INFORMATION_CLASS_BASIC => {
            frame.x[0] = query_object_basic(handle, buf, len, ret_len) as u64;
        }
        OBJECT_INFORMATION_CLASS_NAME => {
            frame.x[0] = query_object_name(buf, len, ret_len) as u64;
        }
        OBJECT_INFORMATION_CLASS_TYPE => {
            frame.x[0] = query_object_type(handle, buf, len, ret_len) as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

// x0=SourceProcessHandle, x1=SourceHandle, x2=TargetProcessHandle, x3=*TargetHandle
pub(crate) fn handle_duplicate_object(frame: &mut SvcFrame) {
    let source_process = frame.x[0];
    let src = frame.x[1];
    let target_process = frame.x[2];
    let out_ptr = frame.x[3] as *mut u64;

    let Some(source_pid) = crate::process::resolve_process_handle(source_process) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    let Some(target_pid) = crate::process::resolve_process_handle(target_process) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let dup = match duplicate_handle_between(source_pid, src, target_pid) {
        Ok(v) => v,
        Err(st) => {
            frame.x[0] = st as u64;
            return;
        }
    };
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(dup) };
    }
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_close(frame: &mut SvcFrame) -> bool {
    let h = frame.x[0];
    if h == STD_INPUT_HANDLE || h == STD_OUTPUT_HANDLE || h == STD_ERROR_HANDLE {
        frame.x[0] = STATUS_SUCCESS as u64;
        return true;
    }

    let Some(info) = close_handle_info(h) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return true;
    };

    if !info.destroy_object {
        frame.x[0] = STATUS_SUCCESS as u64;
        return true;
    }

    let htype = info.htype;
    if htype == HANDLE_TYPE_EVENT
        || htype == HANDLE_TYPE_MUTEX
        || htype == HANDLE_TYPE_SEMAPHORE
        || htype == HANDLE_TYPE_THREAD
        || htype == HANDLE_TYPE_PROCESS
        || htype == HANDLE_TYPE_TOKEN
    {
        frame.x[0] = destroy_object_by_type(htype, info.obj_idx) as u64;
        return true;
    }
    if htype == HANDLE_TYPE_FILE {
        file::close_file_idx(info.obj_idx);
        frame.x[0] = STATUS_SUCCESS as u64;
        return true;
    }
    if htype == HANDLE_TYPE_SECTION {
        section::close_section_idx(info.obj_idx);
        frame.x[0] = STATUS_SUCCESS as u64;
        return true;
    }
    if htype == HANDLE_TYPE_KEY {
        if registry::close_key_idx(info.obj_idx) {
            frame.x[0] = STATUS_SUCCESS as u64;
            return true;
        }
        frame.x[0] = status::INVALID_HANDLE as u64;
        return true;
    }

    frame.x[0] = status::INVALID_HANDLE as u64;
    true
}

fn query_object_basic(handle: u64, buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || len < OBJECT_BASIC_INFORMATION_SIZE {
        write_ret_len(ret_len, OBJECT_BASIC_INFORMATION_SIZE as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    let Some((htype, obj_idx)) = resolve_query_target(handle) else {
        return status::INVALID_HANDLE;
    };

    let refs = crate::sched::sync::object_ref_count(htype, obj_idx).max(1);
    let mut obi = [0u8; OBJECT_BASIC_INFORMATION_SIZE];
    obi[8..12].copy_from_slice(&refs.to_le_bytes()); // HandleCount
    obi[12..16].copy_from_slice(&refs.to_le_bytes()); // PointerCount

    unsafe {
        core::ptr::copy_nonoverlapping(obi.as_ptr(), buf, OBJECT_BASIC_INFORMATION_SIZE);
    }
    write_ret_len(ret_len, OBJECT_BASIC_INFORMATION_SIZE as u32);
    status::SUCCESS
}

fn query_object_name(buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || len < OBJECT_NAME_INFORMATION_SIZE {
        write_ret_len(ret_len, OBJECT_NAME_INFORMATION_SIZE as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    unsafe {
        core::ptr::write_bytes(buf, 0, OBJECT_NAME_INFORMATION_SIZE);
    }
    write_ret_len(ret_len, OBJECT_NAME_INFORMATION_SIZE as u32);
    status::SUCCESS
}

fn query_object_type(handle: u64, buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    let Some((htype, obj_idx)) = resolve_query_target(handle) else {
        return status::INVALID_HANDLE;
    };
    let Some(type_name_utf16) = object_type_name(htype) else {
        return status::INVALID_HANDLE;
    };

    let type_name_bytes = type_name_utf16.len() * size_of::<u16>();
    let required = OBJECT_TYPE_INFORMATION_SIZE + type_name_bytes;
    if buf.is_null() || len < required {
        write_ret_len(ret_len, required as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    unsafe {
        core::ptr::write_bytes(buf, 0, OBJECT_TYPE_INFORMATION_SIZE);
    }

    let refs = crate::sched::sync::object_ref_count(htype, obj_idx).max(1);
    let name_ptr = unsafe { buf.add(OBJECT_TYPE_INFORMATION_SIZE) };
    let name_addr = name_ptr as u64;

    unsafe {
        (buf as *mut u16).write_volatile(type_name_bytes as u16);
        (buf.add(2) as *mut u16).write_volatile(type_name_bytes as u16);
        (buf.add(8) as *mut u64).write_volatile(name_addr);

        (buf.add(16) as *mut u32).write_volatile(refs);
        (buf.add(20) as *mut u32).write_volatile(refs);
        (buf.add(40) as *mut u32).write_volatile(refs);
        (buf.add(44) as *mut u32).write_volatile(refs);

        (buf.add(84) as *mut u32).write_volatile(0x001F_FFFF);
        (buf.add(90) as *mut u8).write_volatile(htype as u8);

        let mut i = 0usize;
        while i < type_name_utf16.len() {
            (name_ptr.add(i * 2) as *mut u16).write_volatile(type_name_utf16[i]);
            i += 1;
        }
    }

    write_ret_len(ret_len, required as u32);
    status::SUCCESS
}

fn resolve_query_target(handle: u64) -> Option<(u64, u32)> {
    if let Some(pid) = crate::process::resolve_process_handle(handle) {
        return Some((HANDLE_TYPE_PROCESS, pid));
    }
    let htype = crate::sched::sync::handle_type(handle);
    if htype == 0 {
        return None;
    }
    let idx = crate::sched::sync::handle_idx(handle);
    if idx == 0 {
        return None;
    }
    Some((htype, idx))
}

fn object_type_name(htype: u64) -> Option<&'static [u16]> {
    const PROCESS: &[u16] = &[80, 114, 111, 99, 101, 115, 115];
    const THREAD: &[u16] = &[84, 104, 114, 101, 97, 100];
    const EVENT: &[u16] = &[69, 118, 101, 110, 116];
    const MUTANT: &[u16] = &[77, 117, 116, 97, 110, 116];
    const SEMAPHORE: &[u16] = &[83, 101, 109, 97, 112, 104, 111, 114, 101];
    const FILE: &[u16] = &[70, 105, 108, 101];
    const SECTION: &[u16] = &[83, 101, 99, 116, 105, 111, 110];
    const KEY: &[u16] = &[75, 101, 121];
    const TOKEN: &[u16] = &[84, 111, 107, 101, 110];

    match htype {
        HANDLE_TYPE_PROCESS => Some(PROCESS),
        HANDLE_TYPE_THREAD => Some(THREAD),
        HANDLE_TYPE_EVENT => Some(EVENT),
        HANDLE_TYPE_MUTEX => Some(MUTANT),
        HANDLE_TYPE_SEMAPHORE => Some(SEMAPHORE),
        HANDLE_TYPE_FILE => Some(FILE),
        HANDLE_TYPE_SECTION => Some(SECTION),
        HANDLE_TYPE_KEY => Some(KEY),
        HANDLE_TYPE_TOKEN => Some(TOKEN),
        _ => None,
    }
}

fn write_ret_len(ptr: *mut u32, value: u32) {
    if !ptr.is_null() {
        unsafe { ptr.write_volatile(value) };
    }
}
