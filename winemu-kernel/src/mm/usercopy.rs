use crate::rust_alloc::vec::Vec;

use crate::nt::constants::PAGE_MASK_4K;
use crate::nt::state::{VM_ACCESS_READ, VM_ACCESS_WRITE};

const PAGE_SIZE_4K: u64 = 0x1000;
const USER_ACCESS_BASE: u64 = crate::process::USER_ACCESS_BASE;
const USER_VA_BASE: u64 = crate::process::USER_VA_BASE;
const USER_VA_LIMIT: u64 = crate::process::USER_VA_LIMIT;

pub(crate) fn ensure_user_range_access(pid: u32, addr: u64, size: usize, access: u8) -> bool {
    if pid == 0 {
        return false;
    }
    if size == 0 {
        return true;
    }
    let Some(end_addr) = addr.checked_add((size as u64).saturating_sub(1)) else {
        return false;
    };
    let mut page = addr & PAGE_MASK_4K;
    let end_page = end_addr & PAGE_MASK_4K;
    loop {
        if page < USER_ACCESS_BASE || page >= USER_VA_LIMIT {
            return false;
        }
        if page >= USER_VA_BASE
            && !crate::nt::state::vm_handle_page_fault(pid, page, access)
        {
            return false;
        }
        if translate_user_va(pid, page, access).is_none() {
            return false;
        }
        if page == end_page {
            break;
        }
        let Some(next) = page.checked_add(PAGE_SIZE_4K) else {
            return false;
        };
        page = next;
    }
    true
}

pub(crate) fn translate_user_va(pid: u32, va: u64, access: u8) -> Option<u64> {
    crate::process::with_process(pid, |p| {
        p.address_space.translate_user_va_for_access(va, access)
    })
    .flatten()
}

pub(crate) fn copy_from_process_user(pid: u32, src_va: u64, dst: *mut u8, size: usize) -> bool {
    if size == 0 {
        return true;
    }
    if dst.is_null() || !ensure_user_range_access(pid, src_va, size, VM_ACCESS_READ) {
        return false;
    }
    if current_pid() == Some(pid) {
        // SAFETY: ensure_user_range_access() validated the full source range in
        // the current address space and faulted in any lazy mappings; `dst` is
        // a caller-provided kernel buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(src_va as *const u8, dst, size);
        }
        return true;
    }
    let mut done = 0usize;
    while done < size {
        let Some(cur_src_va) = src_va.checked_add(done as u64) else {
            return false;
        };
        let Some(src_gpa) = translate_user_va(pid, cur_src_va, VM_ACCESS_READ) else {
            return false;
        };
        let page_off = (cur_src_va as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let src_left = (PAGE_SIZE_4K as usize) - page_off;
        let chunk = core::cmp::min(size - done, src_left);
        let Some(cur_dst) = (dst as u64).checked_add(done as u64) else {
            return false;
        };
        if !crate::mm::physmap::copy_from_gpa(cur_dst as *mut u8, src_gpa, chunk) {
            return false;
        }
        done += chunk;
    }
    true
}

pub(crate) fn copy_to_process_user(pid: u32, dst_va: u64, src: *const u8, size: usize) -> bool {
    if size == 0 {
        return true;
    }
    if src.is_null() || !ensure_user_range_access(pid, dst_va, size, VM_ACCESS_WRITE) {
        return false;
    }
    if current_pid() == Some(pid) {
        // SAFETY: ensure_user_range_access() validated the full destination
        // range in the current address space and faulted in any lazy mappings;
        // `src` points to a caller-provided kernel buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst_va as *mut u8, size);
        }
        return true;
    }
    let mut done = 0usize;
    while done < size {
        let Some(cur_dst_va) = dst_va.checked_add(done as u64) else {
            return false;
        };
        let Some(dst_gpa) = translate_user_va(pid, cur_dst_va, VM_ACCESS_WRITE) else {
            return false;
        };
        let page_off = (cur_dst_va as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let dst_left = (PAGE_SIZE_4K as usize) - page_off;
        let chunk = core::cmp::min(size - done, dst_left);
        let Some(cur_src) = (src as u64).checked_add(done as u64) else {
            return false;
        };
        if !crate::mm::physmap::copy_to_gpa(dst_gpa, cur_src as *const u8, chunk) {
            return false;
        }
        done += chunk;
    }
    true
}

pub(crate) fn copy_between_process_users(
    src_pid: u32,
    src_va: u64,
    dst_pid: u32,
    dst_va: u64,
    size: usize,
) -> bool {
    if size == 0 {
        return true;
    }
    if !ensure_user_range_access(src_pid, src_va, size, VM_ACCESS_READ)
        || !ensure_user_range_access(dst_pid, dst_va, size, VM_ACCESS_WRITE)
    {
        return false;
    }
    let cur_pid = current_pid();
    if cur_pid == Some(src_pid) && cur_pid == Some(dst_pid) {
        // SAFETY: both user ranges were validated in the current address space.
        // Use overlap-safe semantics because source/destination may alias.
        unsafe {
            core::ptr::copy(src_va as *const u8, dst_va as *mut u8, size);
        }
        return true;
    }

    let mut done = 0usize;
    while done < size {
        let Some(cur_src_va) = src_va.checked_add(done as u64) else {
            return false;
        };
        let Some(cur_dst_va) = dst_va.checked_add(done as u64) else {
            return false;
        };
        let src_page_off = (cur_src_va as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let dst_page_off = (cur_dst_va as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let src_left = (PAGE_SIZE_4K as usize) - src_page_off;
        let dst_left = (PAGE_SIZE_4K as usize) - dst_page_off;
        let chunk = core::cmp::min(size - done, core::cmp::min(src_left, dst_left));
        if cur_pid == Some(src_pid) {
            let Some(dst_gpa) = translate_user_va(dst_pid, cur_dst_va, VM_ACCESS_WRITE) else {
                return false;
            };
            // SAFETY: source user range is validated and resident in the
            // current address space for this chunk.
            if !crate::mm::physmap::copy_to_gpa(dst_gpa, cur_src_va as *const u8, chunk) {
                return false;
            }
        } else if cur_pid == Some(dst_pid) {
            let Some(src_gpa) = translate_user_va(src_pid, cur_src_va, VM_ACCESS_READ) else {
                return false;
            };
            // SAFETY: destination user range is validated and resident in the
            // current address space for this chunk.
            if !crate::mm::physmap::copy_from_gpa(cur_dst_va as *mut u8, src_gpa, chunk) {
                return false;
            }
        } else {
            let Some(src_gpa) = translate_user_va(src_pid, cur_src_va, VM_ACCESS_READ) else {
                return false;
            };
            let Some(dst_gpa) = translate_user_va(dst_pid, cur_dst_va, VM_ACCESS_WRITE) else {
                return false;
            };
            if !crate::mm::physmap::copy_gpa(dst_gpa, src_gpa, chunk) {
                return false;
            }
        }
        done += chunk;
    }
    true
}

pub(crate) fn current_pid() -> Option<u32> {
    let pid = crate::process::current_pid();
    if pid == 0 { None } else { Some(pid) }
}

pub(crate) fn copy_from_current_user(src: *const u8, dst: *mut u8, size: usize) -> bool {
    let Some(pid) = current_pid() else {
        return false;
    };
    copy_from_process_user(pid, src as u64, dst, size)
}

pub(crate) fn copy_to_current_user(dst: *mut u8, src: *const u8, size: usize) -> bool {
    let Some(pid) = current_pid() else {
        return false;
    };
    copy_to_process_user(pid, dst as u64, src, size)
}

pub(crate) fn read_user_value<T: Copy>(pid: u32, user_ptr: *const T) -> Option<T> {
    if user_ptr.is_null() {
        return None;
    }
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    if !copy_from_process_user(
        pid,
        user_ptr as u64,
        value.as_mut_ptr().cast::<u8>(),
        core::mem::size_of::<T>(),
    ) {
        return None;
    }
    // SAFETY: the buffer has been fully initialized by copy_from_process_user.
    Some(unsafe { value.assume_init() })
}

pub(crate) fn write_user_value<T: Copy>(pid: u32, user_ptr: *mut T, value: T) -> bool {
    if user_ptr.is_null() {
        return false;
    }
    copy_to_process_user(
        pid,
        user_ptr as u64,
        (&value as *const T).cast::<u8>(),
        core::mem::size_of::<T>(),
    )
}

pub(crate) fn read_current_user_value<T: Copy>(user_ptr: *const T) -> Option<T> {
    let pid = current_pid()?;
    read_user_value(pid, user_ptr)
}

pub(crate) fn write_current_user_value<T: Copy>(user_ptr: *mut T, value: T) -> bool {
    let Some(pid) = current_pid() else {
        return false;
    };
    write_user_value(pid, user_ptr, value)
}

pub(crate) fn read_current_user_bytes(user_ptr: *const u8, len: usize) -> Option<Vec<u8>> {
    if user_ptr.is_null() {
        return None;
    }
    let mut out = Vec::new();
    if out.try_reserve(len).is_err() {
        return None;
    }
    out.resize(len, 0);
    if !copy_from_current_user(user_ptr, out.as_mut_ptr(), len) {
        return None;
    }
    Some(out)
}
