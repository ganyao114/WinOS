use crate::arch::mmu::{
    GUEST_PHYS_BASE, GUEST_PHYS_LIMIT, KERNEL_PHYSMAP_BASE, KERNEL_PHYSMAP_LIMIT,
};

#[inline(always)]
pub fn gpa_to_kva(gpa: u64) -> Option<*mut u8> {
    if !(GUEST_PHYS_BASE..GUEST_PHYS_LIMIT).contains(&gpa) {
        return None;
    }
    let offset = gpa.checked_sub(GUEST_PHYS_BASE)?;
    let kva = KERNEL_PHYSMAP_BASE.checked_add(offset)?;
    if !(KERNEL_PHYSMAP_BASE..KERNEL_PHYSMAP_LIMIT).contains(&kva) {
        return None;
    }
    Some(kva as *mut u8)
}

#[inline(always)]
pub fn gpa_range_valid(gpa: u64, len: usize) -> bool {
    if len == 0 {
        return (GUEST_PHYS_BASE..GUEST_PHYS_LIMIT).contains(&gpa);
    }
    let Some(end) = gpa.checked_add((len as u64).saturating_sub(1)) else {
        return false;
    };
    gpa >= GUEST_PHYS_BASE && end < GUEST_PHYS_LIMIT
}

#[inline(always)]
pub fn copy_from_gpa(dst: *mut u8, src_gpa: u64, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if dst.is_null() || !gpa_range_valid(src_gpa, len) {
        return false;
    }
    let Some(src) = gpa_to_kva(src_gpa) else {
        return false;
    };
    // SAFETY: source GPA range is validated and translated into the dedicated
    // kernel physmap; destination is a caller-provided kernel buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(src.cast::<u8>(), dst, len);
    }
    true
}

#[inline(always)]
pub fn copy_to_gpa(dst_gpa: u64, src: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if src.is_null() || !gpa_range_valid(dst_gpa, len) {
        return false;
    }
    let Some(dst) = gpa_to_kva(dst_gpa) else {
        return false;
    };
    // SAFETY: destination GPA range is validated and translated into the
    // dedicated kernel physmap; source is a caller-provided kernel buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst.cast::<u8>(), len);
    }
    true
}

#[inline(always)]
pub fn copy_gpa(dst_gpa: u64, src_gpa: u64, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if !gpa_range_valid(src_gpa, len) || !gpa_range_valid(dst_gpa, len) {
        return false;
    }
    let Some(src) = gpa_to_kva(src_gpa) else {
        return false;
    };
    let Some(dst) = gpa_to_kva(dst_gpa) else {
        return false;
    };
    // SAFETY: both GPA ranges are validated and translated into the dedicated
    // kernel physmap. Use overlap-safe semantics conservatively.
    unsafe {
        core::ptr::copy(src.cast::<u8>(), dst.cast::<u8>(), len);
    }
    true
}

#[inline(always)]
pub fn memset_gpa(dst_gpa: u64, value: u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if !gpa_range_valid(dst_gpa, len) {
        return false;
    }
    let Some(dst) = gpa_to_kva(dst_gpa) else {
        return false;
    };
    // SAFETY: destination GPA range is validated and translated into the
    // dedicated kernel physmap.
    unsafe {
        core::ptr::write_bytes(dst, value, len);
    }
    true
}
