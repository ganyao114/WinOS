use crate::rust_alloc::vec::Vec;

use crate::mm::{PhysAddr, UserVa, VM_ACCESS_READ, VM_ACCESS_WRITE};
use crate::nt::constants::PAGE_MASK_4K;

const PAGE_SIZE_4K: u64 = 0x1000;
const USER_ACCESS_BASE: u64 = crate::process::USER_ACCESS_BASE;
const USER_VA_BASE: u64 = crate::process::USER_VA_BASE;
const USER_VA_LIMIT: u64 = crate::process::USER_VA_LIMIT;
const ENABLE_CURRENT_PROCESS_COPY_FASTPATH: bool = true;

#[inline]
fn can_use_current_process_fastpath(pid: u32) -> bool {
    ENABLE_CURRENT_PROCESS_COPY_FASTPATH && crate::process::current_process_context_matches(pid)
}

pub(crate) fn ensure_user_range_access(pid: u32, addr: UserVa, size: usize, access: u8) -> bool {
    if pid == 0 {
        return false;
    }
    if size == 0 {
        return true;
    }
    let Some(end_addr) = addr.get().checked_add((size as u64).saturating_sub(1)) else {
        return false;
    };
    let mut page = addr.get() & PAGE_MASK_4K;
    let end_page = end_addr & PAGE_MASK_4K;
    loop {
        if page < USER_ACCESS_BASE || page >= USER_VA_LIMIT {
            return false;
        }
        let page_va = UserVa::new(page);
        let current_fast = can_use_current_process_fastpath(pid);
        let translated = if current_fast {
            crate::mm::address_space::translate_current_user_va_for_access(page_va, access)
        } else {
            translate_user_va(pid, page_va, access)
        };
        if translated.is_none()
            && (page < USER_VA_BASE
                || !crate::mm::handle_process_page_fault(pid, page_va, access)
                || if current_fast {
                    crate::mm::address_space::translate_current_user_va_for_access(page_va, access)
                } else {
                    translate_user_va(pid, page_va, access)
                }
                .is_none())
        {
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

pub(crate) fn translate_user_va(pid: u32, va: UserVa, access: u8) -> Option<PhysAddr> {
    crate::process::with_process(pid, |p| {
        p.address_space.translate_user_va_for_access(va, access)
    })
    .flatten()
}

pub(crate) fn copy_from_process_user(pid: u32, src_va: UserVa, dst: *mut u8, size: usize) -> bool {
    if size == 0 {
        return true;
    }
    if dst.is_null() || !ensure_user_range_access(pid, src_va, size, VM_ACCESS_READ) {
        return false;
    }
    if can_use_current_process_fastpath(pid) {
        // SAFETY: ensure_user_range_access() validated the full source range in
        // the current address space and faulted in any lazy mappings; `dst` is
        // a caller-provided kernel buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(src_va.as_ptr::<u8>(), dst, size);
        }
        return true;
    }
    let mut done = 0usize;
    while done < size {
        let Some(cur_src_va) = src_va.checked_add(done as u64) else {
            return false;
        };
        let Some(src_pa) = translate_user_va(pid, cur_src_va, VM_ACCESS_READ) else {
            return false;
        };
        let page_off = (cur_src_va.get() as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let src_left = (PAGE_SIZE_4K as usize) - page_off;
        let chunk = core::cmp::min(size - done, src_left);
        let Some(cur_dst) = (dst as u64).checked_add(done as u64) else {
            return false;
        };
        if !crate::mm::linear_map::copy_from_phys(cur_dst as *mut u8, src_pa, chunk) {
            return false;
        }
        done += chunk;
    }
    true
}

pub(crate) fn copy_to_process_user(pid: u32, dst_va: UserVa, src: *const u8, size: usize) -> bool {
    if size == 0 {
        return true;
    }
    if src.is_null() || !ensure_user_range_access(pid, dst_va, size, VM_ACCESS_WRITE) {
        return false;
    }
    if can_use_current_process_fastpath(pid) {
        // SAFETY: ensure_user_range_access() validated the full destination
        // range in the current address space and faulted in any lazy mappings;
        // `src` points to a caller-provided kernel buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst_va.as_mut_ptr::<u8>(), size);
        }
        return true;
    }
    let mut done = 0usize;
    while done < size {
        let Some(cur_dst_va) = dst_va.checked_add(done as u64) else {
            return false;
        };
        let Some(dst_pa) = translate_user_va(pid, cur_dst_va, VM_ACCESS_WRITE) else {
            return false;
        };
        let page_off = (cur_dst_va.get() as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let dst_left = (PAGE_SIZE_4K as usize) - page_off;
        let chunk = core::cmp::min(size - done, dst_left);
        let Some(cur_src) = (src as u64).checked_add(done as u64) else {
            return false;
        };
        if !crate::mm::linear_map::copy_to_phys(dst_pa, cur_src as *const u8, chunk) {
            return false;
        }
        done += chunk;
    }
    true
}

pub(crate) fn copy_between_process_users(
    src_pid: u32,
    src_va: UserVa,
    dst_pid: u32,
    dst_va: UserVa,
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
    let src_fast = can_use_current_process_fastpath(src_pid);
    let dst_fast = can_use_current_process_fastpath(dst_pid);
    if src_fast && dst_fast {
        // SAFETY: both user ranges were validated in the current address space.
        // Use overlap-safe semantics because source/destination may alias.
        unsafe {
            core::ptr::copy(src_va.as_ptr::<u8>(), dst_va.as_mut_ptr::<u8>(), size);
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
        let src_page_off = (cur_src_va.get() as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let dst_page_off = (cur_dst_va.get() as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let src_left = (PAGE_SIZE_4K as usize) - src_page_off;
        let dst_left = (PAGE_SIZE_4K as usize) - dst_page_off;
        let chunk = core::cmp::min(size - done, core::cmp::min(src_left, dst_left));
        if src_fast {
            let Some(dst_pa) = translate_user_va(dst_pid, cur_dst_va, VM_ACCESS_WRITE) else {
                return false;
            };
            // SAFETY: source user range is validated and resident in the
            // current address space for this chunk.
            if !crate::mm::linear_map::copy_to_phys(dst_pa, cur_src_va.as_ptr::<u8>(), chunk) {
                return false;
            }
        } else if dst_fast {
            let Some(src_pa) = translate_user_va(src_pid, cur_src_va, VM_ACCESS_READ) else {
                return false;
            };
            // SAFETY: destination user range is validated and resident in the
            // current address space for this chunk.
            if !crate::mm::linear_map::copy_from_phys(cur_dst_va.as_mut_ptr::<u8>(), src_pa, chunk)
            {
                return false;
            }
        } else {
            let Some(src_pa) = translate_user_va(src_pid, cur_src_va, VM_ACCESS_READ) else {
                return false;
            };
            let Some(dst_pa) = translate_user_va(dst_pid, cur_dst_va, VM_ACCESS_WRITE) else {
                return false;
            };
            if !crate::mm::linear_map::copy_phys(dst_pa, src_pa, chunk) {
                return false;
            }
        }
        done += chunk;
    }
    true
}

pub(crate) fn copy_from_process_user_to_phys(
    pid: u32,
    src_va: UserVa,
    dst_pa: PhysAddr,
    size: usize,
) -> bool {
    if size == 0 {
        return true;
    }
    if !ensure_user_range_access(pid, src_va, size, VM_ACCESS_READ) {
        return false;
    }

    let mut done = 0usize;
    while done < size {
        let Some(cur_src_va) = src_va.checked_add(done as u64) else {
            return false;
        };
        let Some(cur_dst_pa) = dst_pa.checked_add(done as u64) else {
            return false;
        };
        let page_off = (cur_src_va.get() as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let src_left = (PAGE_SIZE_4K as usize) - page_off;
        let chunk = core::cmp::min(size - done, src_left);
        if can_use_current_process_fastpath(pid) {
            // SAFETY: source user range is validated in the current address
            // space for this chunk.
            if !crate::mm::linear_map::copy_to_phys(cur_dst_pa, cur_src_va.as_ptr::<u8>(), chunk) {
                return false;
            }
        } else {
            let Some(src_pa) = translate_user_va(pid, cur_src_va, VM_ACCESS_READ) else {
                return false;
            };
            if !crate::mm::linear_map::copy_phys(cur_dst_pa, src_pa, chunk) {
                return false;
            }
        }
        done += chunk;
    }
    true
}

pub(crate) fn copy_from_phys_to_process_user(
    pid: u32,
    dst_va: UserVa,
    src_pa: PhysAddr,
    size: usize,
) -> bool {
    if size == 0 {
        return true;
    }
    if !ensure_user_range_access(pid, dst_va, size, VM_ACCESS_WRITE) {
        return false;
    }

    let mut done = 0usize;
    while done < size {
        let Some(cur_dst_va) = dst_va.checked_add(done as u64) else {
            return false;
        };
        let Some(cur_src_pa) = src_pa.checked_add(done as u64) else {
            return false;
        };
        let page_off = (cur_dst_va.get() as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let dst_left = (PAGE_SIZE_4K as usize) - page_off;
        let chunk = core::cmp::min(size - done, dst_left);
        if can_use_current_process_fastpath(pid) {
            // SAFETY: destination user range is validated in the current
            // address space for this chunk.
            if !crate::mm::linear_map::copy_from_phys(cur_dst_va.as_mut_ptr::<u8>(), cur_src_pa, chunk)
            {
                return false;
            }
        } else {
            let Some(dst_pa) = translate_user_va(pid, cur_dst_va, VM_ACCESS_WRITE) else {
                return false;
            };
            if !crate::mm::linear_map::copy_phys(dst_pa, cur_src_pa, chunk) {
                return false;
            }
        }
        done += chunk;
    }
    true
}

pub(crate) fn current_pid() -> Option<u32> {
    let pid = crate::process::current_pid();
    if pid == 0 {
        None
    } else {
        Some(pid)
    }
}

pub(crate) fn current_process_user_ptr(
    pid: u32,
    va: UserVa,
    size: usize,
    access: u8,
) -> Option<*mut u8> {
    if !crate::process::current_process_context_matches(pid)
        || !ensure_user_range_access(pid, va, size, access)
    {
        return None;
    }
    Some(va.as_mut_ptr::<u8>())
}

pub(crate) fn copy_from_current_user(src: *const u8, dst: *mut u8, size: usize) -> bool {
    let Some(pid) = current_pid() else {
        return false;
    };
    copy_from_process_user(pid, UserVa::new(src as u64), dst, size)
}

pub(crate) fn copy_to_current_user(dst: *mut u8, src: *const u8, size: usize) -> bool {
    let Some(pid) = current_pid() else {
        return false;
    };
    copy_to_process_user(pid, UserVa::new(dst as u64), src, size)
}

pub(crate) fn read_user_at<T: Copy>(pid: u32, user_va: UserVa) -> Option<T> {
    if user_va.is_null() {
        return None;
    }
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    if !copy_from_process_user(
        pid,
        user_va,
        value.as_mut_ptr().cast::<u8>(),
        core::mem::size_of::<T>(),
    ) {
        return None;
    }
    // SAFETY: the buffer has been fully initialized by copy_from_process_user.
    Some(unsafe { value.assume_init() })
}

pub(crate) fn write_user_at<T: Copy>(pid: u32, user_va: UserVa, value: T) -> bool {
    if user_va.is_null() {
        return false;
    }
    copy_to_process_user(
        pid,
        user_va,
        (&value as *const T).cast::<u8>(),
        core::mem::size_of::<T>(),
    )
}

pub(crate) fn read_user_value<T: Copy>(pid: u32, user_ptr: *const T) -> Option<T> {
    read_user_at(pid, UserVa::new(user_ptr as u64))
}

pub(crate) fn write_user_value<T: Copy>(pid: u32, user_ptr: *mut T, value: T) -> bool {
    write_user_at(pid, UserVa::new(user_ptr as u64), value)
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
