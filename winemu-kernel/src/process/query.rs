use winemu_shared::status;

use crate::mm::usercopy::write_current_user_value;

use super::with_process;
use crate::nt::common::GuestWriter;

const PROCESS_BASIC_INFORMATION_SIZE: usize = 48;
const PROCESS_DEFAULT_HARD_ERROR_MODE_SIZE: usize = 4;
const PROCESS_IMAGE_FILE_NAME_SIZE: usize = 16;
const PROCESS_VM_COUNTERS_SIZE: usize = 88;
const PROCESS_WOW64_INFORMATION_SIZE: usize = 8;

pub fn query_information_process(
    process_handle: u64,
    info_class: u32,
    buf: *mut u8,
    buf_len: usize,
    ret_len: *mut u32,
) -> u32 {
    let Some(pid) = super::resolve_process_handle(process_handle) else {
        crate::kwarn!(
            "nt: qip invalid handle={:#x} class={:#x}",
            process_handle,
            info_class
        );
        return status::INVALID_HANDLE;
    };

    match info_class {
        0 => query_basic(pid, buf, buf_len, ret_len),
        3 => query_vm_counters(buf, buf_len, ret_len),
        12 => query_default_hard_error_mode(pid, buf, buf_len, ret_len),
        26 => query_wow64_information(buf, buf_len, ret_len),
        27 => query_image_file_name(buf, buf_len, ret_len),
        _ => {
            crate::kwarn!("nt: qip unsupported class={:#x} pid={:#x}", info_class, pid);
            status::INVALID_PARAMETER
        }
    }
}

fn query_wow64_information(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || buf_len < PROCESS_WOW64_INFORMATION_SIZE {
        write_ret_len(ret_len, PROCESS_WOW64_INFORMATION_SIZE as u32);
        return status::INFO_LENGTH_MISMATCH;
    }
    let Some(mut w) = GuestWriter::new(buf, buf_len, PROCESS_WOW64_INFORMATION_SIZE) else {
        return status::INVALID_PARAMETER;
    };
    w.u64(0);
    write_ret_len(ret_len, PROCESS_WOW64_INFORMATION_SIZE as u32);
    status::SUCCESS
}

fn query_vm_counters(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || buf_len < PROCESS_VM_COUNTERS_SIZE {
        write_ret_len(ret_len, PROCESS_VM_COUNTERS_SIZE as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    let Some(mut w) = GuestWriter::new(buf, buf_len, PROCESS_VM_COUNTERS_SIZE) else {
        return status::INVALID_PARAMETER;
    };
    w.zeros(PROCESS_VM_COUNTERS_SIZE);
    write_ret_len(ret_len, PROCESS_VM_COUNTERS_SIZE as u32);
    status::SUCCESS
}

fn query_default_hard_error_mode(
    pid: u32,
    buf: *mut u8,
    buf_len: usize,
    ret_len: *mut u32,
) -> u32 {
    if buf.is_null() || buf_len != PROCESS_DEFAULT_HARD_ERROR_MODE_SIZE {
        write_ret_len(ret_len, PROCESS_DEFAULT_HARD_ERROR_MODE_SIZE as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    let Some(mode) = with_process(pid, |p| p.default_hard_error_mode) else {
        return status::INVALID_HANDLE;
    };
    let Some(mut w) = GuestWriter::new(buf, buf_len, PROCESS_DEFAULT_HARD_ERROR_MODE_SIZE) else {
        return status::INVALID_PARAMETER;
    };
    w.u32(mode);
    write_ret_len(ret_len, PROCESS_DEFAULT_HARD_ERROR_MODE_SIZE as u32);
    status::SUCCESS
}

fn query_basic(pid: u32, buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || buf_len < PROCESS_BASIC_INFORMATION_SIZE {
        write_ret_len(ret_len, PROCESS_BASIC_INFORMATION_SIZE as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    let Some((exit_status, peb_va, parent_pid)) =
        with_process(pid, |p| (p.exit_status, p.peb_va, p.parent_pid))
    else {
        return status::INVALID_HANDLE;
    };

    let mut pbi = [0u8; PROCESS_BASIC_INFORMATION_SIZE];
    pbi[0..4].copy_from_slice(&exit_status.to_le_bytes());
    pbi[8..16].copy_from_slice(&peb_va.to_le_bytes());
    pbi[16..24].copy_from_slice(&1u64.to_le_bytes());
    pbi[24..28].copy_from_slice(&8i32.to_le_bytes());
    pbi[32..40].copy_from_slice(&(pid as u64).to_le_bytes());
    pbi[40..48].copy_from_slice(&(parent_pid as u64).to_le_bytes());

    let Some(mut w) = GuestWriter::new(buf, buf_len, PROCESS_BASIC_INFORMATION_SIZE) else {
        return status::INVALID_PARAMETER;
    };
    w.bytes(&pbi);
    write_ret_len(ret_len, PROCESS_BASIC_INFORMATION_SIZE as u32);
    status::SUCCESS
}

fn query_image_file_name(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || buf_len < PROCESS_IMAGE_FILE_NAME_SIZE {
        write_ret_len(ret_len, PROCESS_IMAGE_FILE_NAME_SIZE as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    let Some(mut w) = GuestWriter::new(buf, buf_len, PROCESS_IMAGE_FILE_NAME_SIZE) else {
        return status::INVALID_PARAMETER;
    };
    w.zeros(PROCESS_IMAGE_FILE_NAME_SIZE);
    write_ret_len(ret_len, PROCESS_IMAGE_FILE_NAME_SIZE as u32);
    status::SUCCESS
}

fn write_ret_len(ptr: *mut u32, value: u32) {
    if !ptr.is_null() {
        let _ = write_current_user_value(ptr, value);
    }
}
