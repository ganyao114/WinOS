use winemu_shared::status;

use super::with_process;

const PROCESS_BASIC_INFORMATION_SIZE: usize = 48;
const PROCESS_IMAGE_FILE_NAME_SIZE: usize = 16;
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
        26 => query_wow64_information(buf, buf_len, ret_len),
        27 => query_image_file_name(buf, buf_len, ret_len),
        _ => {
            crate::kwarn!(
                "nt: qip unsupported class={:#x} pid={:#x}",
                info_class,
                pid
            );
            status::INVALID_PARAMETER
        }
    }
}

fn query_wow64_information(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || buf_len < PROCESS_WOW64_INFORMATION_SIZE {
        write_ret_len(ret_len, PROCESS_WOW64_INFORMATION_SIZE as u32);
        return status::INFO_LENGTH_MISMATCH;
    }
    unsafe {
        (buf as *mut u64).write_volatile(0);
    }
    write_ret_len(ret_len, PROCESS_WOW64_INFORMATION_SIZE as u32);
    status::SUCCESS
}

fn query_basic(pid: u32, buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || buf_len < PROCESS_BASIC_INFORMATION_SIZE {
        write_ret_len(ret_len, PROCESS_BASIC_INFORMATION_SIZE as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    let Some((exit_status, peb_va, parent_pid)) = with_process(pid, |p| {
        (p.exit_status, p.peb_va, p.parent_pid)
    }) else {
        return status::INVALID_HANDLE;
    };

    let mut pbi = [0u8; PROCESS_BASIC_INFORMATION_SIZE];
    pbi[0..4].copy_from_slice(&exit_status.to_le_bytes());
    pbi[8..16].copy_from_slice(&peb_va.to_le_bytes());
    pbi[16..24].copy_from_slice(&1u64.to_le_bytes());
    pbi[24..28].copy_from_slice(&8i32.to_le_bytes());
    pbi[32..40].copy_from_slice(&(pid as u64).to_le_bytes());
    pbi[40..48].copy_from_slice(&(parent_pid as u64).to_le_bytes());

    unsafe {
        core::ptr::copy_nonoverlapping(pbi.as_ptr(), buf, PROCESS_BASIC_INFORMATION_SIZE);
    }
    write_ret_len(ret_len, PROCESS_BASIC_INFORMATION_SIZE as u32);
    status::SUCCESS
}

fn query_image_file_name(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    if buf.is_null() || buf_len < PROCESS_IMAGE_FILE_NAME_SIZE {
        write_ret_len(ret_len, PROCESS_IMAGE_FILE_NAME_SIZE as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    unsafe {
        core::ptr::write_bytes(buf, 0, PROCESS_IMAGE_FILE_NAME_SIZE);
    }
    write_ret_len(ret_len, PROCESS_IMAGE_FILE_NAME_SIZE as u32);
    status::SUCCESS
}

fn write_ret_len(ptr: *mut u32, value: u32) {
    if !ptr.is_null() {
        unsafe {
            ptr.write_volatile(value);
        }
    }
}
