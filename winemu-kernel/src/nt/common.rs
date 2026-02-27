use crate::sched::sync::{self, HANDLE_TYPE_FILE};

use super::state::file_host_fd;

pub(crate) const STD_INPUT_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFF6;
pub(crate) const STD_OUTPUT_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFF5;
pub(crate) const STD_ERROR_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFF4;

pub(crate) const FILE_OPEN: u32 = 1;

pub(crate) const HOST_OPEN_READ: u64 = 0;
pub(crate) const HOST_OPEN_WRITE: u64 = 1;
pub(crate) const HOST_OPEN_RW: u64 = 2;
pub(crate) const HOST_OPEN_CREATE: u64 = 3;

pub(crate) const MEM_COMMIT: u32 = 0x1000;

#[repr(C)]
pub(crate) struct IoStatusBlock {
    pub(crate) status: u64,
    pub(crate) info: u64,
}

#[inline(always)]
pub(crate) fn align_up_4k(v: u64) -> u64 {
    (v + 0xFFF) & !0xFFF
}

pub(crate) fn write_iosb(iosb_ptr: *mut IoStatusBlock, st: u32, info: u64) {
    if !iosb_ptr.is_null() {
        unsafe {
            iosb_ptr.write_volatile(IoStatusBlock {
                status: st as u64,
                info,
            });
        }
    }
}

fn normalize_nt_path(path: &mut [u8], len: usize) -> usize {
    let mut start = 0usize;
    if len >= 4
        && ((path[0] == b'/' && path[1] == b'?' && path[2] == b'?' && path[3] == b'/')
            || (path[0] == b'/' && path[1] == b'/' && path[2] == b'?' && path[3] == b'/')
            || (path[0] == b'/' && path[1] == b'/' && path[2] == b'.' && path[3] == b'/'))
    {
        start = 4;
    }
    while start < len && path[start] == b'/' {
        start += 1;
    }
    if start + 1 < len && path[start + 1] == b':' {
        start += 2;
        if start < len && path[start] == b'/' {
            start += 1;
        }
    }
    while start < len && path[start] == b'/' {
        start += 1;
    }
    let mut out = 0usize;
    for i in start..len {
        path[out] = path[i];
        out += 1;
    }
    out
}

pub(crate) fn read_oa_path(oa_ptr: u64, out: &mut [u8]) -> usize {
    if oa_ptr == 0 || out.is_empty() {
        return 0;
    }
    let us_ptr = unsafe { ((oa_ptr + 0x10) as *const u64).read_volatile() };
    if us_ptr == 0 {
        return 0;
    }
    let byte_len = unsafe { (us_ptr as *const u16).read_volatile() as usize };
    let buf_ptr = unsafe { ((us_ptr + 8) as *const u64).read_volatile() };
    if byte_len == 0 || buf_ptr == 0 {
        return 0;
    }
    let count = core::cmp::min(byte_len / 2, out.len());
    for i in 0..count {
        let wc = unsafe { ((buf_ptr + (i as u64 * 2)) as *const u16).read_volatile() };
        let mut ch = if wc < 0x80 { wc as u8 } else { b'?' };
        if ch == b'\\' {
            ch = b'/';
        }
        out[i] = ch;
    }
    normalize_nt_path(out, count)
}

pub(crate) fn read_unicode_direct(us_ptr: u64, out: &mut [u8]) -> usize {
    if us_ptr == 0 || out.is_empty() {
        return 0;
    }
    let byte_len = unsafe { (us_ptr as *const u16).read_volatile() as usize };
    let buf_ptr = unsafe { ((us_ptr + 8) as *const u64).read_volatile() };
    if byte_len == 0 || buf_ptr == 0 {
        return 0;
    }
    let count = core::cmp::min(byte_len / 2, out.len());
    for i in 0..count {
        let wc = unsafe { ((buf_ptr + (i as u64 * 2)) as *const u16).read_volatile() };
        let mut ch = if wc < 0x80 { wc as u8 } else { b'?' };
        if ch == b'\\' {
            ch = b'/';
        }
        out[i] = ch;
    }
    count
}

pub(crate) fn map_open_flags(access: u32, disposition: u32) -> u64 {
    let can_read = (access & (0x8000_0000 | 0x0001)) != 0;
    let can_write = (access & (0x4000_0000 | 0x0002)) != 0;
    if disposition != FILE_OPEN {
        return HOST_OPEN_CREATE;
    }
    match (can_read, can_write) {
        (true, true) => HOST_OPEN_RW,
        (false, true) => HOST_OPEN_WRITE,
        _ => HOST_OPEN_READ,
    }
}

pub(crate) fn file_handle_to_host_fd(file_handle: u64) -> Option<u64> {
    match file_handle {
        STD_INPUT_HANDLE => Some(0),
        STD_OUTPUT_HANDLE => Some(1),
        STD_ERROR_HANDLE => Some(2),
        _ => {
            if sync::handle_type(file_handle) == HANDLE_TYPE_FILE {
                file_host_fd(sync::handle_idx(file_handle))
            } else {
                None
            }
        }
    }
}
