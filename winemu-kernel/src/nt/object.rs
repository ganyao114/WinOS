use core::mem::size_of;

use crate::sched::wait::STATUS_SUCCESS;
use winemu_shared::status;

use super::common::{GuestWriter, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use super::kobject;
use super::user_args::UserOutPtr;
use super::SvcFrame;

const OBJECT_INFORMATION_CLASS_BASIC: u32 = 0;
const OBJECT_INFORMATION_CLASS_NAME: u32 = 1;
const OBJECT_INFORMATION_CLASS_TYPE: u32 = 2;
const OBJECT_BASIC_INFORMATION_SIZE: usize = 56;
const OBJECT_NAME_INFORMATION_SIZE: usize = 16;
const OBJECT_TYPE_INFORMATION_SIZE: usize = 104;
const DUPLICATE_CLOSE_SOURCE: u32 = 0x0000_0001;
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;
const DUPLICATE_SAME_ATTRIBUTES: u32 = 0x0000_0004;
const DUPLICATE_VALID_OPTIONS: u32 =
    DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES;

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
            frame.x[0] = query_object_name(handle, buf, len, ret_len) as u64;
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
// x4=DesiredAccess, x5=HandleAttributes, x6=Options
pub(crate) fn handle_duplicate_object(frame: &mut SvcFrame) {
    let source_process = frame.x[0];
    let src = frame.x[1];
    let target_process = frame.x[2];
    let out_ptr = UserOutPtr::from_raw(frame.x[3] as *mut u64);
    let desired_access = frame.x[4] as u32;
    let options = frame.x[6] as u32;

    if (options & !DUPLICATE_VALID_OPTIONS) != 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Some(source_pid) = crate::process::resolve_process_handle(source_process) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    let Some(target_pid) = crate::process::resolve_process_handle(target_process) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let Some((src_kind, _src_idx)) = kobject::resolve_handle_target_for_pid(source_pid, src) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    if (options & DUPLICATE_SAME_ACCESS) == 0 {
        let meta = kobject::object_type_meta_for_kind(src_kind);
        if (desired_access & !meta.valid_access_mask) != 0 {
            close_source_if_requested(options, source_pid, src);
            frame.x[0] = status::ACCESS_DENIED as u64;
            return;
        }
    }

    let dup = match kobject::duplicate_handle(source_pid, src, target_pid) {
        Some(v) => v,
        None => {
            close_source_if_requested(options, source_pid, src);
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };

    if !out_ptr.write_current_if_present(dup) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    close_source_if_requested(options, source_pid, src);
    frame.x[0] = status::SUCCESS as u64;
}

fn close_source_if_requested(options: u32, source_pid: u32, source_handle: u64) {
    if (options & DUPLICATE_CLOSE_SOURCE) == 0 {
        return;
    }
    kobject::close_handle_for_pid(source_pid, source_handle);
}

pub(crate) fn handle_close(frame: &mut SvcFrame) -> bool {
    let h = frame.x[0];
    if h == STD_INPUT_HANDLE || h == STD_OUTPUT_HANDLE || h == STD_ERROR_HANDLE {
        frame.x[0] = STATUS_SUCCESS as u64;
        return true;
    }
    frame.x[0] = kobject::close_handle_for_current(h) as u64;
    true
}

fn query_object_basic(handle: u64, buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || len < OBJECT_BASIC_INFORMATION_SIZE {
        write_ret_len(ret_len, OBJECT_BASIC_INFORMATION_SIZE as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    if kobject::resolve_handle_target(handle).is_none() {
        return status::INVALID_HANDLE;
    }

    let refs = 1u32;
    let Some(mut w) = GuestWriter::new(buf, len, OBJECT_BASIC_INFORMATION_SIZE) else {
        return status::INVALID_PARAMETER;
    };
    w.u64(0)
        .u32(refs)
        .u32(refs)
        .zeros(OBJECT_BASIC_INFORMATION_SIZE - 16);
    write_ret_len(ret_len, OBJECT_BASIC_INFORMATION_SIZE as u32);
    status::SUCCESS
}

fn query_object_name(handle: u64, buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    let Some((kind, obj_idx)) = kobject::resolve_handle_target(handle) else {
        return status::INVALID_HANDLE;
    };
    let name_utf16 = kobject::object_name_utf16_for_kind(kind, obj_idx);
    let name_len_bytes = name_utf16
        .as_ref()
        .map(|n| n.len().saturating_mul(size_of::<u16>()))
        .unwrap_or(0);
    let Some(required) = OBJECT_NAME_INFORMATION_SIZE.checked_add(name_len_bytes) else {
        return status::INVALID_PARAMETER;
    };

    if buf.is_null() || len < required {
        write_ret_len(ret_len, required as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    let Some(mut w) = GuestWriter::new(buf, len, required) else {
        return status::INVALID_PARAMETER;
    };
    let uni_len = core::cmp::min(name_len_bytes, u16::MAX as usize) as u16;
    let name_addr = if name_len_bytes != 0 {
        buf as u64 + OBJECT_NAME_INFORMATION_SIZE as u64
    } else {
        0
    };
    w.u16(uni_len).u16(uni_len).u32(0).u64(name_addr);
    if let Some(name) = name_utf16.as_ref() {
        for &ch in name {
            w.u16(ch);
        }
    }
    write_ret_len(ret_len, required as u32);
    status::SUCCESS
}

fn query_object_type(handle: u64, buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    let Some((kind, _obj_idx)) = kobject::resolve_handle_target(handle) else {
        return status::INVALID_HANDLE;
    };
    let type_name_utf16 = kobject::ops_for_kind(kind).type_name_utf16;

    let type_name_bytes = type_name_utf16.len() * size_of::<u16>();
    let required = OBJECT_TYPE_INFORMATION_SIZE + type_name_bytes;
    if buf.is_null() || len < required {
        write_ret_len(ret_len, required as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    let Some(mut w) = GuestWriter::new(buf, len, required) else {
        return status::INVALID_PARAMETER;
    };
    let type_meta = kobject::object_type_meta_for_kind(kind);
    let name_addr = buf as u64 + OBJECT_TYPE_INFORMATION_SIZE as u64;
    w.u16(type_name_bytes as u16)
        .u16(type_name_bytes as u16)
        .u32(0)
        .u64(name_addr)
        .zeros(68)
        .u32(type_meta.valid_access_mask)
        .u8(type_meta.security_required as u8)
        .u8(type_meta.maintain_handle_count as u8)
        .zeros(14);
    for &ch in type_name_utf16 {
        w.u16(ch);
    }

    write_ret_len(ret_len, required as u32);
    status::SUCCESS
}

fn write_ret_len(ptr: *mut u32, value: u32) {
    let _ = UserOutPtr::from_raw(ptr).write_current_if_present(value);
}
