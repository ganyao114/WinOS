use crate::arch::mmu::{
    GUEST_PHYS_BASE, GUEST_PHYS_LIMIT, KERNEL_PHYSMAP_BASE, KERNEL_PHYSMAP_LIMIT,
};
use crate::mm::{KernelVa, PhysAddr};
use crate::nt::constants::PAGE_SIZE_4K;

/// Canonical kernel linear-map helpers for guest RAM.
///
/// Even though this module is still named `physmap.rs`, callers should use the
/// semantic alias `crate::mm::linear_map::*`.

#[inline(always)]
pub fn phys_to_kva(pa: PhysAddr) -> Option<KernelVa> {
    if !(GUEST_PHYS_BASE..GUEST_PHYS_LIMIT).contains(&pa.get()) {
        return None;
    }
    let offset = pa.get().checked_sub(GUEST_PHYS_BASE)?;
    let kva = KERNEL_PHYSMAP_BASE.checked_add(offset)?;
    if !(KERNEL_PHYSMAP_BASE..KERNEL_PHYSMAP_LIMIT).contains(&kva) {
        return None;
    }
    Some(KernelVa::new(kva))
}

#[inline(always)]
pub fn kva_to_phys(kva: KernelVa) -> Option<PhysAddr> {
    if !(KERNEL_PHYSMAP_BASE..KERNEL_PHYSMAP_LIMIT).contains(&kva.get()) {
        return None;
    }
    let offset = kva.get().checked_sub(KERNEL_PHYSMAP_BASE)?;
    let pa = GUEST_PHYS_BASE.checked_add(offset)?;
    if !(GUEST_PHYS_BASE..GUEST_PHYS_LIMIT).contains(&pa) {
        return None;
    }
    Some(PhysAddr::new(pa))
}

#[inline(always)]
pub fn phys_range_valid(pa: PhysAddr, len: usize) -> bool {
    if len == 0 {
        return (GUEST_PHYS_BASE..GUEST_PHYS_LIMIT).contains(&pa.get());
    }
    let Some(end) = pa.get().checked_add((len as u64).saturating_sub(1)) else {
        return false;
    };
    pa.get() >= GUEST_PHYS_BASE && end < GUEST_PHYS_LIMIT
}

#[inline(always)]
pub fn copy_from_phys(dst: *mut u8, src_pa: PhysAddr, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if dst.is_null() || !phys_range_valid(src_pa, len) {
        return false;
    }

    let mut done = 0usize;
    while done < len {
        let Some(cur_pa) = src_pa.checked_add(done as u64) else {
            return false;
        };
        let page_off = phys_page_offset(cur_pa);
        let chunk = page_chunk_len(cur_pa, len - done);
        if let Some(src) = phys_to_kva(cur_pa) {
            // SAFETY: `src` points into the permanent linear map and `dst.add(done)`
            // points into a caller-provided kernel buffer with `chunk` bytes available.
            unsafe {
                core::ptr::copy_nonoverlapping(src.as_ptr::<u8>(), dst.add(done), chunk);
            }
        } else {
            let Some(src_map) = crate::mm::kmap::MappedPage::from_phys(cur_pa) else {
                return false;
            };
            // SAFETY: `src_map` keeps the temporary mapping alive for the duration of
            // the copy, and `dst.add(done)` points into a caller-provided kernel buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src_map.as_ptr::<u8>().add(page_off),
                    dst.add(done),
                    chunk,
                );
            }
        }
        done += chunk;
    }
    true
}

#[inline(always)]
pub fn copy_to_phys(dst_pa: PhysAddr, src: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if src.is_null() || !phys_range_valid(dst_pa, len) {
        return false;
    }

    let mut done = 0usize;
    while done < len {
        let Some(cur_pa) = dst_pa.checked_add(done as u64) else {
            return false;
        };
        let page_off = phys_page_offset(cur_pa);
        let chunk = page_chunk_len(cur_pa, len - done);
        let Some(mut dst_map) = crate::mm::kmap::MappedPage::from_phys(cur_pa) else {
            return false;
        };
        let dst_ptr =
            // SAFETY: `page_off < PAGE_SIZE_4K` for the current chunk.
            unsafe { dst_map.as_mut_ptr::<u8>().add(page_off) };
        // SAFETY: `src.add(done)` points into the caller-provided kernel buffer and
        // `dst_ptr` points into a mapped physical page window with `chunk` bytes available.
        unsafe {
            core::ptr::copy_nonoverlapping(src.add(done), dst_ptr, chunk);
        }
        done += chunk;
    }
    true
}

#[inline(always)]
pub fn copy_phys(dst_pa: PhysAddr, src_pa: PhysAddr, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if !phys_range_valid(src_pa, len) || !phys_range_valid(dst_pa, len) {
        return false;
    }

    let mut done = 0usize;
    while done < len {
        let Some(cur_src_pa) = src_pa.checked_add(done as u64) else {
            return false;
        };
        let Some(cur_dst_pa) = dst_pa.checked_add(done as u64) else {
            return false;
        };
        let src_off = phys_page_offset(cur_src_pa);
        let dst_off = phys_page_offset(cur_dst_pa);
        let chunk = core::cmp::min(
            page_chunk_len(cur_src_pa, len - done),
            page_chunk_len(cur_dst_pa, len - done),
        );
        let Some(src_map) = crate::mm::kmap::MappedPage::from_phys(cur_src_pa) else {
            return false;
        };
        let Some(mut dst_map) = crate::mm::kmap::MappedPage::from_phys(cur_dst_pa) else {
            return false;
        };
        // SAFETY: both pointers point into mapped physical page windows with `chunk`
        // bytes available. `ptr::copy` preserves overlap semantics.
        unsafe {
            core::ptr::copy(
                src_map.as_ptr::<u8>().add(src_off),
                dst_map.as_mut_ptr::<u8>().add(dst_off),
                chunk,
            );
        }
        done += chunk;
    }
    true
}

#[inline(always)]
pub fn memset_phys(dst_pa: PhysAddr, value: u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if !phys_range_valid(dst_pa, len) {
        return false;
    }

    let mut done = 0usize;
    while done < len {
        let Some(cur_pa) = dst_pa.checked_add(done as u64) else {
            return false;
        };
        let page_off = phys_page_offset(cur_pa);
        let chunk = page_chunk_len(cur_pa, len - done);
        let Some(mut dst_map) = crate::mm::kmap::MappedPage::from_phys(cur_pa) else {
            return false;
        };
        // SAFETY: `dst_ptr` points into a mapped physical page window with `chunk`
        // bytes available.
        unsafe {
            core::ptr::write_bytes(dst_map.as_mut_ptr::<u8>().add(page_off), value, chunk);
        }
        done += chunk;
    }
    true
}

#[inline(always)]
fn phys_page_offset(pa: PhysAddr) -> usize {
    (pa.get() & (PAGE_SIZE_4K - 1)) as usize
}

#[inline(always)]
fn page_chunk_len(pa: PhysAddr, remaining: usize) -> usize {
    let page_remaining = (PAGE_SIZE_4K as usize).saturating_sub(phys_page_offset(pa));
    core::cmp::min(page_remaining, remaining)
}
