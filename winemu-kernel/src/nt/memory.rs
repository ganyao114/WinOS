use winemu_shared::status;

use super::common::{align_up_4k, MEM_COMMIT};
use super::constants::{PAGE_MASK_4K, PAGE_SIZE_4K};
use super::state::{vm_alloc_region_typed, vm_find_region, vm_free_region, vm_set_region_prot};
use super::SvcFrame;
use crate::mm::vaspace::VmaType;

// x1=*BaseAddress, x3=*RegionSize, x5=Protect
pub(crate) fn handle_allocate_virtual_memory(frame: &mut SvcFrame) {
    let base_ptr = frame.x[1] as *mut u64;
    let size_ptr = frame.x[3] as *mut u64;
    if size_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let req_size = unsafe { size_ptr.read_volatile() };
    if req_size == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let prot = frame.x[5] as u32;
    let size = align_up_4k(req_size);
    let owner_pid = crate::process::current_pid();
    let hint = if !base_ptr.is_null() {
        unsafe { base_ptr.read_volatile() }
    } else {
        0
    };

    let base = match vm_alloc_region_typed(owner_pid, hint, size, prot, VmaType::Private) {
        Some(v) => v,
        None => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };
    if !base_ptr.is_null() {
        unsafe { base_ptr.write_volatile(base) };
    }
    unsafe { size_ptr.write_volatile(size) };
    frame.x[0] = status::SUCCESS as u64;
}

// x1=*BaseAddress
pub(crate) fn handle_free_virtual_memory(frame: &mut SvcFrame) {
    let base_ptr = frame.x[1] as *const u64;
    if base_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let base = unsafe { base_ptr.read_volatile() };
    let owner_pid = crate::process::current_pid();
    let _ = vm_free_region(owner_pid, base);
    frame.x[0] = status::SUCCESS as u64;
}

// x1=*BaseAddress, x3=NewProtect, x4=*OldProtect
pub(crate) fn handle_protect_virtual_memory(frame: &mut SvcFrame) {
    let base_ptr = frame.x[1] as *const u64;
    let old_ptr = frame.x[4] as *mut u32;
    if base_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let base = unsafe { base_ptr.read_volatile() };
    let owner_pid = crate::process::current_pid();
    if let Some((idx, region)) = vm_find_region(owner_pid, base) {
        if !old_ptr.is_null() {
            unsafe { old_ptr.write_volatile(region.prot) };
        }
        let _ = vm_set_region_prot(idx, frame.x[3] as u32);
    } else if !old_ptr.is_null() {
        unsafe { old_ptr.write_volatile(0) };
    }
    frame.x[0] = status::SUCCESS as u64;
}

// x1=BaseAddress, x3=Buffer, x4=BufferSize, x5=*ReturnLength
pub(crate) fn handle_query_virtual_memory(frame: &mut SvcFrame) {
    let addr = frame.x[1];
    let buf = frame.x[3] as *mut u8;
    let buf_len = frame.x[4] as usize;
    let ret_len_ptr = frame.x[5] as *mut u64;
    if buf_len < 48 || buf.is_null() {
        frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
        return;
    }
    let owner_pid = crate::process::current_pid();

    let (base, size, prot, state) = if let Some((_, r)) = vm_find_region(owner_pid, addr) {
        (r.base, r.size, r.prot, MEM_COMMIT)
    } else {
        (addr & PAGE_MASK_4K, PAGE_SIZE_4K, 0u32, 0u32)
    };

    let mut mbi = [0u8; 48];
    mbi[0..8].copy_from_slice(&base.to_le_bytes());
    mbi[8..16].copy_from_slice(&base.to_le_bytes());
    mbi[16..20].copy_from_slice(&prot.to_le_bytes());
    mbi[24..32].copy_from_slice(&size.to_le_bytes());
    mbi[32..36].copy_from_slice(&state.to_le_bytes());
    mbi[36..40].copy_from_slice(&prot.to_le_bytes());
    unsafe {
        core::ptr::copy_nonoverlapping(mbi.as_ptr(), buf, 48);
    }
    if !ret_len_ptr.is_null() {
        unsafe { ret_len_ptr.write_volatile(48) };
    }
    frame.x[0] = status::SUCCESS as u64;
}
