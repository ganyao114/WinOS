use crate::hypercall;
use crate::sched::sync::{self, make_new_handle, HANDLE_TYPE_FILE, HANDLE_TYPE_SECTION};
use winemu_shared::status;

use super::common::align_up_4k;
use super::constants::PAGE_SIZE_4K;
use super::state::{
    file_host_fd, section_alloc, section_free, section_get, view_alloc, view_free, vm_alloc_region,
    vm_free_region,
};
use super::SvcFrame;

// x0=*SectionHandle, x3=*MaximumSize, x4=Protection, x6=FileHandle
pub(crate) fn handle_create_section(frame: &mut SvcFrame) {
    let out_ptr = frame.x[0] as *mut u64;
    let max_size_ptr = frame.x[3] as *const u64;
    let prot = frame.x[4] as u32;
    let file_handle = frame.x[6];
    let size = if max_size_ptr.is_null() {
        PAGE_SIZE_4K
    } else {
        align_up_4k(unsafe { max_size_ptr.read_volatile().max(PAGE_SIZE_4K) })
    };
    let owner_pid = crate::process::current_pid();

    let idx = match section_alloc(owner_pid, size, prot, file_handle) {
        Some(i) => i,
        None => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };
    let Some(handle) = make_new_handle(HANDLE_TYPE_SECTION, idx) else {
        section_free(idx);
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(handle) };
    }
    frame.x[0] = status::SUCCESS as u64;
}

// x0=SectionHandle, x2=*BaseAddress, x5=*SectionOffset, x6=*ViewSize
// stack[0]=AllocationType, stack[1]=Win32Protect
pub(crate) fn handle_map_view_of_section(frame: &mut SvcFrame) {
    let h = frame.x[0];
    if sync::handle_type(h) != HANDLE_TYPE_SECTION {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
    let sec = match section_get(sync::handle_idx(h)) {
        Some(s) => s,
        None => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let base_ptr = frame.x[2] as *mut u64;
    let view_size_ptr = frame.x[6] as *mut u64;
    let _offset_ptr = frame.x[5] as *const u64;
    let win32_protect = unsafe { (frame.sp_el0 as *const u64).add(1).read_volatile() } as u32;

    let req_size = if view_size_ptr.is_null() {
        0
    } else {
        unsafe { view_size_ptr.read_volatile() }
    };
    let map_size = align_up_4k(if req_size == 0 { sec.size } else { req_size }.max(PAGE_SIZE_4K));
    let prot = if win32_protect == 0 {
        sec.prot
    } else {
        win32_protect
    };
    let owner_pid = crate::process::current_pid();

    let base = match vm_alloc_region(owner_pid, map_size, prot) {
        Some(v) => v,
        None => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };

    if sec.file_handle != 0 && sync::handle_type(sec.file_handle) == HANDLE_TYPE_FILE {
        if let Some(fd) = file_host_fd(sync::handle_idx(sec.file_handle)) {
            let _ = hypercall::host_read(fd, base as *mut u8, map_size as usize, 0);
        }
    }

    if !view_alloc(owner_pid, base, map_size) {
        let _ = vm_free_region(owner_pid, base);
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    }

    if !base_ptr.is_null() {
        unsafe { base_ptr.write_volatile(base) };
    }
    if !view_size_ptr.is_null() {
        unsafe { view_size_ptr.write_volatile(map_size) };
    }
    frame.x[0] = status::SUCCESS as u64;
}

// x1=BaseAddress
pub(crate) fn handle_unmap_view_of_section(frame: &mut SvcFrame) {
    let base = frame.x[1];
    let owner_pid = crate::process::current_pid();
    let _ = view_free(owner_pid, base);
    let _ = vm_free_region(owner_pid, base);
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn close_section_idx(idx: u32) {
    section_free(idx);
}
