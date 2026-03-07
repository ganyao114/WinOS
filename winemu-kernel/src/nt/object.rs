use core::mem::size_of;

use crate::sched::sync::{
    close_handle_info, close_handle_info_for_pid, duplicate_handle_between,
};
use crate::sched::wait::STATUS_SUCCESS;
use winemu_shared::status;

use super::common::{STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use super::kobject;
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
    let out_ptr = frame.x[3] as *mut u64;
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

    let Some((src_htype, _src_idx)) = kobject::resolve_handle_target_for_pid(source_pid, src)
    else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    if (options & DUPLICATE_SAME_ACCESS) == 0 {
        let Some(meta) = kobject::object_type_meta(src_htype) else {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        };
        if (desired_access & !meta.valid_access_mask) != 0 {
            close_source_if_requested(options, source_pid, src);
            frame.x[0] = status::ACCESS_DENIED as u64;
            return;
        }
    }

    let dup = match duplicate_handle_between(source_pid, src, target_pid) {
        Ok(v) => v,
        Err(st) => {
            close_source_if_requested(options, source_pid, src);
            frame.x[0] = st as u64;
            return;
        }
    };

    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(dup) };
    }
    close_source_if_requested(options, source_pid, src);
    frame.x[0] = status::SUCCESS as u64;
}

fn close_source_if_requested(options: u32, source_pid: u32, source_handle: u64) {
    if (options & DUPLICATE_CLOSE_SOURCE) == 0 {
        return;
    }
    let Some(info) = close_handle_info_for_pid(source_pid, source_handle) else {
        return;
    };
    if info.destroy_object {
        let _ = kobject::close_last_ref(info.htype, info.obj_idx);
    }
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

    frame.x[0] = kobject::close_last_ref(info.htype, info.obj_idx) as u64;
    true
}

fn query_object_basic(handle: u64, buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || len < OBJECT_BASIC_INFORMATION_SIZE {
        write_ret_len(ret_len, OBJECT_BASIC_INFORMATION_SIZE as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    let Some((htype, obj_idx)) = kobject::resolve_handle_target(handle) else {
        return status::INVALID_HANDLE;
    };

    let refs = kobject::object_ref_count(htype, obj_idx).max(1);
    let mut obi = [0u8; OBJECT_BASIC_INFORMATION_SIZE];
    obi[8..12].copy_from_slice(&refs.to_le_bytes()); // HandleCount
    obi[12..16].copy_from_slice(&refs.to_le_bytes()); // PointerCount

    unsafe {
        core::ptr::copy_nonoverlapping(obi.as_ptr(), buf, OBJECT_BASIC_INFORMATION_SIZE);
    }
    write_ret_len(ret_len, OBJECT_BASIC_INFORMATION_SIZE as u32);
    status::SUCCESS
}

fn query_object_name(handle: u64, buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    let Some((htype, obj_idx)) = kobject::resolve_handle_target(handle) else {
        return status::INVALID_HANDLE;
    };
    let name_utf16 = kobject::object_name_utf16(htype, obj_idx);
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

    unsafe {
        core::ptr::write_bytes(buf, 0, required);

        let uni_len = core::cmp::min(name_len_bytes, u16::MAX as usize) as u16;
        (buf as *mut u16).write_volatile(uni_len);
        (buf.add(2) as *mut u16).write_volatile(uni_len);

        if name_len_bytes != 0 {
            let name_ptr = buf.add(OBJECT_NAME_INFORMATION_SIZE);
            (buf.add(8) as *mut u64).write_volatile(name_ptr as u64);
            if let Some(name) = name_utf16.as_ref() {
                let mut i = 0usize;
                while i < name.len() {
                    (name_ptr.add(i * 2) as *mut u16).write_volatile(name[i]);
                    i += 1;
                }
            }
        }
    }
    write_ret_len(ret_len, required as u32);
    status::SUCCESS
}

fn query_object_type(handle: u64, buf: *mut u8, len: usize, ret_len: *mut u32) -> u32 {
    let Some((htype, obj_idx)) = kobject::resolve_handle_target(handle) else {
        return status::INVALID_HANDLE;
    };
    let Some(type_name_utf16) = kobject::object_type_name(htype) else {
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

    let refs = kobject::object_ref_count(htype, obj_idx).max(1);
    let type_stats = kobject::object_type_stats(htype);
    let total_objects = type_stats.object_count.max(1);
    let total_handles = type_stats.handle_count.max(refs);
    let type_meta = kobject::object_type_meta(htype).unwrap_or_default();
    let name_ptr = unsafe { buf.add(OBJECT_TYPE_INFORMATION_SIZE) };
    let name_addr = name_ptr as u64;

    unsafe {
        (buf as *mut u16).write_volatile(type_name_bytes as u16);
        (buf.add(2) as *mut u16).write_volatile(type_name_bytes as u16);
        (buf.add(8) as *mut u64).write_volatile(name_addr);

        // OBJECT_TYPE_INFORMATION counters:
        // TotalNumberOfObjects / TotalNumberOfHandles / HighWater*.
        (buf.add(16) as *mut u32).write_volatile(total_objects);
        (buf.add(20) as *mut u32).write_volatile(total_handles);
        (buf.add(40) as *mut u32).write_volatile(total_objects);
        (buf.add(44) as *mut u32).write_volatile(total_handles);

        (buf.add(84) as *mut u32).write_volatile(type_meta.valid_access_mask);
        (buf.add(88) as *mut u8).write_volatile(if type_meta.security_required { 1 } else { 0 });
        (buf.add(89) as *mut u8).write_volatile(if type_meta.maintain_handle_count {
            1
        } else {
            0
        });
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

fn write_ret_len(ptr: *mut u32, value: u32) {
    if !ptr.is_null() {
        unsafe { ptr.write_volatile(value) };
    }
}
