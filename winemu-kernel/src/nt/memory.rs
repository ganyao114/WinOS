use winemu_shared::status;

use super::common::{align_up_4k, MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE};
use super::constants::{PAGE_MASK_4K, PAGE_SIZE_4K};
use super::state::{
    vm_commit_private, vm_decommit_private, vm_protect_range, vm_query_region, vm_release_private,
    vm_reserve_private,
};
use super::SvcFrame;

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
    let alloc_type = frame.x[4] as u32;
    let prot = frame.x[5] as u32;
    let size = align_up_4k(req_size);
    let owner_pid = crate::process::current_pid();
    let req_base = if !base_ptr.is_null() {
        (unsafe { base_ptr.read_volatile() }) & PAGE_MASK_4K
    } else {
        0
    };

    let reserve = (alloc_type & MEM_RESERVE) != 0;
    let commit = (alloc_type & MEM_COMMIT) != 0;
    if !reserve && !commit {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    if reserve {
        let base = match vm_reserve_private(owner_pid, req_base, size, prot) {
            Ok(v) => v,
            Err(st) => {
                frame.x[0] = st as u64;
                return;
            }
        };
        if commit {
            let st = vm_commit_private(owner_pid, base, size, prot);
            if st != status::SUCCESS {
                let _ = vm_release_private(owner_pid, base);
                frame.x[0] = st as u64;
                return;
            }
        }
        if !base_ptr.is_null() {
            unsafe { base_ptr.write_volatile(base) };
        }
        unsafe { size_ptr.write_volatile(size) };
        frame.x[0] = status::SUCCESS as u64;
        return;
    }

    if req_base == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let st = vm_commit_private(owner_pid, req_base, size, prot);
    if st != status::SUCCESS {
        frame.x[0] = st as u64;
        return;
    }
    if !base_ptr.is_null() {
        unsafe { base_ptr.write_volatile(req_base) };
    }
    unsafe { size_ptr.write_volatile(size) };
    frame.x[0] = status::SUCCESS as u64;
}

// x1=*BaseAddress, x2=*RegionSize, x3=FreeType
pub(crate) fn handle_free_virtual_memory(frame: &mut SvcFrame) {
    let base_ptr = frame.x[1] as *mut u64;
    let size_ptr = frame.x[2] as *mut u64;
    let free_type = frame.x[3] as u32;
    if base_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let base = unsafe { base_ptr.read_volatile() };
    let owner_pid = crate::process::current_pid();
    match free_type {
        MEM_RELEASE => {
            if !size_ptr.is_null() {
                let size = unsafe { size_ptr.read_volatile() };
                if size != 0 {
                    frame.x[0] = status::INVALID_PARAMETER as u64;
                    return;
                }
            }
            frame.x[0] = vm_release_private(owner_pid, base) as u64;
        }
        MEM_DECOMMIT => {
            if size_ptr.is_null() {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            let size = unsafe { size_ptr.read_volatile() };
            if size == 0 {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            frame.x[0] = vm_decommit_private(owner_pid, base, size) as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

// x1=*BaseAddress, x2=*RegionSize, x3=NewProtect, x4=*OldProtect
pub(crate) fn handle_protect_virtual_memory(frame: &mut SvcFrame) {
    let base_ptr = frame.x[1] as *mut u64;
    let size_ptr = frame.x[2] as *mut u64;
    let old_ptr = frame.x[4] as *mut u32;
    if base_ptr.is_null() || size_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let base = unsafe { base_ptr.read_volatile() } & PAGE_MASK_4K;
    let size = align_up_4k(unsafe { size_ptr.read_volatile() });
    if size == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let owner_pid = crate::process::current_pid();
    match vm_protect_range(owner_pid, base, size, frame.x[3] as u32) {
        Ok(old) => {
            if !old_ptr.is_null() {
                unsafe { old_ptr.write_volatile(old) };
            }
            unsafe {
                base_ptr.write_volatile(base);
                size_ptr.write_volatile(size);
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        Err(st) => {
            if !old_ptr.is_null() {
                unsafe { old_ptr.write_volatile(0) };
            }
            frame.x[0] = st as u64;
        }
    }
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

    let (base, size, prot, state, mem_type) = if let Some(q) = vm_query_region(owner_pid, addr) {
        (q.base, q.size, q.prot, q.state, q.mem_type)
    } else {
        (addr & PAGE_MASK_4K, PAGE_SIZE_4K, 0u32, 0u32, 0u32)
    };

    let mut mbi = [0u8; 48];
    mbi[0..8].copy_from_slice(&base.to_le_bytes());
    mbi[8..16].copy_from_slice(&base.to_le_bytes());
    mbi[16..20].copy_from_slice(&prot.to_le_bytes());
    mbi[24..32].copy_from_slice(&size.to_le_bytes());
    mbi[32..36].copy_from_slice(&state.to_le_bytes());
    mbi[36..40].copy_from_slice(&prot.to_le_bytes());
    mbi[40..44].copy_from_slice(&mem_type.to_le_bytes());
    unsafe {
        core::ptr::copy_nonoverlapping(mbi.as_ptr(), buf, 48);
    }
    if !ret_len_ptr.is_null() {
        unsafe { ret_len_ptr.write_volatile(48) };
    }
    frame.x[0] = status::SUCCESS as u64;
}
