use crate::process::{KObjectKind, with_process_mut};

use super::state::file_host_fd;

pub(crate) const STD_INPUT_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFF6;
pub(crate) const STD_OUTPUT_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFF5;
pub(crate) const STD_ERROR_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFF4;

pub(crate) const FILE_OPEN: u32 = 1;

pub(crate) const HOST_OPEN_READ: u64 = 0;
pub(crate) const HOST_OPEN_WRITE: u64 = 1;
pub(crate) const HOST_OPEN_RW: u64 = 2;
pub(crate) const HOST_OPEN_CREATE: u64 = 3;
pub(crate) const HOST_PSEUDO_FD_WINEMU_HOST: u64 = u64::MAX - 1;
pub(crate) const WINEMU_HOST_DEVICE_PATH: &str = "\\Device\\WinEmuHost";
pub(crate) const WINEMU_HOST_DEVICE_PATH_NORMALIZED: &str = "Device/WinEmuHost";

pub(crate) const MEM_COMMIT: u32 = 0x1000;
pub(crate) const MEM_RESERVE: u32 = 0x2000;
pub(crate) const MEM_DECOMMIT: u32 = 0x4000;
pub(crate) const MEM_RELEASE: u32 = 0x8000;

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
    file_handle_to_host_fd_for_pid(crate::process::current_pid(), file_handle)
}

pub(crate) fn file_handle_to_host_fd_for_pid(owner_pid: u32, file_handle: u64) -> Option<u64> {
    match file_handle {
        STD_INPUT_HANDLE => Some(0),
        STD_OUTPUT_HANDLE => Some(1),
        STD_ERROR_HANDLE => Some(2),
        _ => {
            let obj = with_process_mut(owner_pid, |p| p.handle_table.get(file_handle as u32)).flatten();
            match obj {
                Some(o) if o.kind == KObjectKind::File => file_host_fd(o.obj_idx),
                _ => None,
            }
        }
    }
}
