use crate::hypercall;
use crate::sched::sync::{make_new_handle, HANDLE_TYPE_FILE};
use winemu_shared::status;

use super::common::{file_handle_to_host_fd, map_open_flags, write_iosb, IoStatusBlock, FILE_OPEN};
use super::path::read_oa_path;
use super::state::{file_alloc, file_free};
use super::SvcFrame;

const FILE_FS_SIZE_INFORMATION: u32 = 3;
const FILE_FS_DEVICE_INFORMATION: u32 = 4;
const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 5;
const FILE_FS_SIZE_INFORMATION_SIZE: usize = 24;
const FILE_FS_DEVICE_INFORMATION_SIZE: usize = 8;
const FILE_FS_ATTRIBUTE_INFORMATION_SIZE: usize = 12;

const FILE_DEVICE_DISK: u32 = 0x0000_0007;
const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x0000_0001;
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;

// x0=*FileHandle, x1=DesiredAccess, x2=ObjectAttributes, x3=*IoStatusBlock
// x7=CreateDisposition
pub(crate) fn handle_create_file(frame: &mut SvcFrame) {
    let out_ptr = frame.x[0] as *mut u64;
    let access = frame.x[1] as u32;
    let oa_ptr = frame.x[2];
    let iosb_ptr = frame.x[3] as *mut IoStatusBlock;
    let disposition = frame.x[7] as u32;
    let mut path_buf = [0u8; 512];
    let path_len = read_oa_path(oa_ptr, &mut path_buf);
    if path_len == 0 {
        write_iosb(iosb_ptr, status::OBJECT_NAME_NOT_FOUND, 0);
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    let path = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => {
            write_iosb(iosb_ptr, status::INVALID_PARAMETER, 0);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
    };
    let fd = hypercall::host_open(path, map_open_flags(access, disposition));
    if fd == u64::MAX {
        write_iosb(iosb_ptr, status::OBJECT_NAME_NOT_FOUND, 0);
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    let owner_pid = crate::process::current_pid();
    let idx = match file_alloc(owner_pid, fd) {
        Some(v) => v,
        None => {
            hypercall::host_close(fd);
            write_iosb(iosb_ptr, status::NO_MEMORY, 0);
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };
    if !out_ptr.is_null() {
        let Some(h) = make_new_handle(HANDLE_TYPE_FILE, idx) else {
            file_free(idx);
            write_iosb(iosb_ptr, status::NO_MEMORY, 0);
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        };
        unsafe { out_ptr.write_volatile(h) };
    }
    write_iosb(iosb_ptr, status::SUCCESS, 0);
    frame.x[0] = status::SUCCESS as u64;
}

// x0=*FileHandle, x1=DesiredAccess, x2=ObjectAttributes, x3=*IoStatusBlock
pub(crate) fn handle_open_file(frame: &mut SvcFrame) {
    frame.x[7] = FILE_OPEN as u64;
    handle_create_file(frame);
}

// x0=FileHandle, x4=IoStatusBlock*, x5=Buffer, x6=Length, x7=ByteOffset*
pub(crate) fn handle_write_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    let buf = frame.x[5] as *const u8;
    let len = frame.x[6] as usize;
    let byte_offset_ptr = frame.x[7] as *const u64;

    let host_fd = match file_handle_to_host_fd(file_handle) {
        Some(fd) => fd,
        None => {
            write_iosb(iosb_ptr, status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let offset = if byte_offset_ptr.is_null() {
        u64::MAX
    } else {
        unsafe { byte_offset_ptr.read_volatile() }
    };

    let written = hypercall::host_write(host_fd, buf, len, offset) as u64;
    write_iosb(iosb_ptr, status::SUCCESS, written);
    frame.x[0] = status::SUCCESS as u64;
}

// x0=FileHandle, x4=IoStatusBlock*, x5=Buffer, x6=Length, x7=ByteOffset*
pub(crate) fn handle_read_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    let buf = frame.x[5] as *mut u8;
    let len = frame.x[6] as usize;
    let byte_offset_ptr = frame.x[7] as *const u64;

    let host_fd = match file_handle_to_host_fd(file_handle) {
        Some(fd) => fd,
        None => {
            write_iosb(iosb_ptr, status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let offset = if byte_offset_ptr.is_null() {
        u64::MAX
    } else {
        unsafe { byte_offset_ptr.read_volatile() }
    };
    let read = hypercall::host_read(host_fd, buf, len, offset) as u64;
    let st = if read == 0 && len != 0 {
        status::END_OF_FILE
    } else {
        status::SUCCESS
    };
    write_iosb(iosb_ptr, st, read);
    frame.x[0] = st as u64;
}

// x0=FileHandle, x1=*IoStatusBlock, x2=FileInformation, x3=Length, x4=Class
pub(crate) fn handle_query_information_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[1] as *mut IoStatusBlock;
    let out_ptr = frame.x[2] as *mut u8;
    let out_len = frame.x[3] as usize;
    let info_class = frame.x[4] as u32;
    let host_fd = match file_handle_to_host_fd(file_handle) {
        Some(fd) => fd,
        None => {
            write_iosb(iosb_ptr, status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };
    if info_class == 5 {
        if out_ptr.is_null() || out_len < 24 {
            write_iosb(iosb_ptr, status::INFO_LENGTH_MISMATCH, 0);
            frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
            return;
        }
        let size = if host_fd <= 2 { 0u64 } else { hypercall::host_stat(host_fd) };
        let mut info = [0u8; 24];
        info[0..8].copy_from_slice(&size.to_le_bytes());
        info[8..16].copy_from_slice(&size.to_le_bytes());
        info[16..20].copy_from_slice(&1u32.to_le_bytes());
        unsafe { core::ptr::copy_nonoverlapping(info.as_ptr(), out_ptr, 24) };
        write_iosb(iosb_ptr, status::SUCCESS, 24);
        frame.x[0] = status::SUCCESS as u64;
        return;
    }
    if !out_ptr.is_null() && out_len != 0 {
        unsafe { core::ptr::write_bytes(out_ptr, 0, out_len) };
    }
    write_iosb(iosb_ptr, status::SUCCESS, 0);
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_set_information_file(frame: &mut SvcFrame) {
    let iosb_ptr = frame.x[1] as *mut IoStatusBlock;
    write_iosb(iosb_ptr, status::SUCCESS, 0);
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_query_directory_file(frame: &mut SvcFrame) {
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    write_iosb(iosb_ptr, status::NO_MORE_FILES, 0);
    frame.x[0] = status::NO_MORE_FILES as u64;
}

// x0=FileHandle, x1=*IoStatusBlock, x2=FsInformation, x3=Length, x4=FsInformationClass
pub(crate) fn handle_query_volume_information_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[1] as *mut IoStatusBlock;
    let out_ptr = frame.x[2] as *mut u8;
    let out_len = frame.x[3] as usize;
    let info_class = frame.x[4] as u32;

    let host_fd = match file_handle_to_host_fd(file_handle) {
        Some(fd) => fd,
        None => {
            write_iosb(iosb_ptr, status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    unsafe {
        match info_class {
            FILE_FS_DEVICE_INFORMATION => {
                if out_ptr.is_null() || out_len < FILE_FS_DEVICE_INFORMATION_SIZE {
                    write_iosb(iosb_ptr, status::INFO_LENGTH_MISMATCH, 0);
                    frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(FILE_DEVICE_DISK);
                (out_ptr.add(4) as *mut u32).write_volatile(0);
                write_iosb(iosb_ptr, status::SUCCESS, FILE_FS_DEVICE_INFORMATION_SIZE as u64);
                frame.x[0] = status::SUCCESS as u64;
            }
            FILE_FS_ATTRIBUTE_INFORMATION => {
                const FS_NAME: &[u8] = b"WinEmuFS";
                let fs_name_bytes = FS_NAME.len() * 2;
                let need = FILE_FS_ATTRIBUTE_INFORMATION_SIZE + fs_name_bytes;
                if out_ptr.is_null() || out_len < need {
                    write_iosb(iosb_ptr, status::INFO_LENGTH_MISMATCH, 0);
                    frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(
                    FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK,
                );
                (out_ptr.add(4) as *mut u32).write_volatile(255);
                (out_ptr.add(8) as *mut u32).write_volatile(fs_name_bytes as u32);

                let mut i = 0usize;
                while i < FS_NAME.len() {
                    let ch = FS_NAME[i] as u16;
                    (out_ptr.add(FILE_FS_ATTRIBUTE_INFORMATION_SIZE + i * 2) as *mut u16)
                        .write_volatile(ch);
                    i += 1;
                }
                write_iosb(iosb_ptr, status::SUCCESS, need as u64);
                frame.x[0] = status::SUCCESS as u64;
            }
            FILE_FS_SIZE_INFORMATION => {
                if out_ptr.is_null() || out_len < FILE_FS_SIZE_INFORMATION_SIZE {
                    write_iosb(iosb_ptr, status::INFO_LENGTH_MISMATCH, 0);
                    frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                    return;
                }
                let bytes_per_sector: u64 = 4096;
                let sectors_per_alloc: u64 = 1;
                let file_bytes = if host_fd <= 2 {
                    0
                } else {
                    hypercall::host_stat(host_fd)
                };
                let total_bytes = core::cmp::max(file_bytes, 64 * 1024 * 1024);
                let total_units = core::cmp::max(total_bytes / bytes_per_sector, 1);
                let avail_units = total_units / 2;

                (out_ptr as *mut u64).write_volatile(total_units);
                (out_ptr.add(8) as *mut u64).write_volatile(avail_units);
                (out_ptr.add(16) as *mut u32).write_volatile(sectors_per_alloc as u32);
                (out_ptr.add(20) as *mut u32).write_volatile(bytes_per_sector as u32);
                write_iosb(iosb_ptr, status::SUCCESS, FILE_FS_SIZE_INFORMATION_SIZE as u64);
                frame.x[0] = status::SUCCESS as u64;
            }
            _ => {
                write_iosb(iosb_ptr, status::INVALID_PARAMETER, 0);
                frame.x[0] = status::INVALID_PARAMETER as u64;
            }
        }
    }
}

pub(crate) fn close_file_idx(idx: u32) {
    file_free(idx);
}
