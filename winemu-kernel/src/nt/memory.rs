use winemu_shared::status;
use core::sync::atomic::{AtomicU32, Ordering};

use super::common::{align_up_4k, MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE};
use super::constants::PAGE_MASK_4K;
use super::state::{
    vm_commit_private, vm_decommit_private, vm_protect_range, vm_query_region, vm_release_private,
    vm_reserve_private, VM_ACCESS_READ, VM_ACCESS_WRITE,
};
use super::SvcFrame;

const PAGE_SIZE_4K: u64 = 0x1000;
const USER_VA_BASE: u64 = crate::process::USER_VA_BASE;
const USER_VA_LIMIT: u64 = crate::process::USER_VA_LIMIT;
static AVM_TRACE_BUDGET: AtomicU32 = AtomicU32::new(64);

fn ensure_user_range_access(pid: u32, addr: u64, size: usize, access: u8) -> bool {
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
        if page < USER_VA_BASE || page >= USER_VA_LIMIT {
            // Disallow non-user pointers from user syscall buffers.
            return false;
        }
        if !super::state::vm_handle_page_fault(pid, page, access) {
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

fn translate_user_va(pid: u32, va: u64, access: u8) -> Option<u64> {
    crate::process::with_process(pid, |p| p.address_space.translate_user_va_for_access(va, access))
        .flatten()
}

fn copy_from_process_user(pid: u32, src_va: u64, dst: *mut u8, size: usize) -> bool {
    let mut done = 0usize;
    while done < size {
        let cur_va = src_va + done as u64;
        let Some(src_pa) = translate_user_va(pid, cur_va, VM_ACCESS_READ) else {
            return false;
        };
        let page_off = (cur_va as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let chunk = core::cmp::min(size - done, (PAGE_SIZE_4K as usize) - page_off);
        unsafe {
            core::ptr::copy_nonoverlapping(src_pa as *const u8, dst.add(done), chunk);
        }
        done += chunk;
    }
    true
}

fn copy_to_process_user(pid: u32, dst_va: u64, src: *const u8, size: usize) -> bool {
    let mut done = 0usize;
    while done < size {
        let cur_va = dst_va + done as u64;
        let Some(dst_pa) = translate_user_va(pid, cur_va, VM_ACCESS_WRITE) else {
            return false;
        };
        let page_off = (cur_va as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let chunk = core::cmp::min(size - done, (PAGE_SIZE_4K as usize) - page_off);
        unsafe {
            core::ptr::copy_nonoverlapping(src.add(done), dst_pa as *mut u8, chunk);
        }
        done += chunk;
    }
    true
}

fn read_user_u64(pid: u32, user_ptr: *const u64) -> Option<u64> {
    if user_ptr.is_null() {
        return None;
    }
    if !ensure_user_range_access(pid, user_ptr as u64, core::mem::size_of::<u64>(), VM_ACCESS_READ) {
        return None;
    }
    let mut v = 0u64;
    if !copy_from_process_user(
        pid,
        user_ptr as u64,
        (&mut v as *mut u64).cast::<u8>(),
        core::mem::size_of::<u64>(),
    ) {
        return None;
    }
    Some(v)
}

fn write_user_u64(pid: u32, user_ptr: *mut u64, value: u64) -> bool {
    if user_ptr.is_null() {
        return false;
    }
    if !ensure_user_range_access(pid, user_ptr as u64, core::mem::size_of::<u64>(), VM_ACCESS_WRITE) {
        return false;
    }
    copy_to_process_user(
        pid,
        user_ptr as u64,
        (&value as *const u64).cast::<u8>(),
        core::mem::size_of::<u64>(),
    )
}

fn trace_avm_success(
    owner_pid: u32,
    base_ptr: *mut u64,
    size_ptr: *mut u64,
    base: u64,
    size: u64,
    req_size: u64,
) {
    let remain = AVM_TRACE_BUDGET.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        if v == 0 {
            None
        } else {
            Some(v - 1)
        }
    });
    if remain.is_err() {
        return;
    }
    let readback_base = if base_ptr.is_null() {
        0
    } else {
        read_user_u64(owner_pid, base_ptr as *const u64).unwrap_or(0)
    };
    let readback_size = read_user_u64(owner_pid, size_ptr as *const u64).unwrap_or(0);
    crate::hypercall::debug_print("nt: avm ok pid=");
    crate::hypercall::debug_u64(owner_pid as u64);
    crate::hypercall::debug_print(" bp=");
    crate::hypercall::debug_u64(base_ptr as u64);
    crate::hypercall::debug_print(" sp=");
    crate::hypercall::debug_u64(size_ptr as u64);
    crate::hypercall::debug_print(" base=");
    crate::hypercall::debug_u64(base);
    crate::hypercall::debug_print(" size=");
    crate::hypercall::debug_u64(size);
    crate::hypercall::debug_print(" req=");
    crate::hypercall::debug_u64(req_size);
    crate::hypercall::debug_print(" rb_base=");
    crate::hypercall::debug_u64(readback_base);
    crate::hypercall::debug_print(" rb_size=");
    crate::hypercall::debug_u64(readback_size);
    crate::hypercall::debug_print("\n");
}

// x1=*BaseAddress, x3=*RegionSize, x5=Protect
pub(crate) fn handle_allocate_virtual_memory(frame: &mut SvcFrame) {
    let base_ptr = frame.x[1] as *mut u64;
    let size_ptr = frame.x[3] as *mut u64;
    let owner_pid = crate::process::current_pid();
    if owner_pid == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if size_ptr.is_null() {
        crate::hypercall::debug_u64(0xE215_E001);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Some(req_size) = read_user_u64(owner_pid, size_ptr as *const u64) else {
        crate::hypercall::debug_u64(0xE215_E005);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    if req_size == 0 {
        crate::hypercall::debug_u64(0xE215_E002);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let alloc_type = frame.x[4] as u32;
    let prot = frame.x[5] as u32;
    let size = align_up_4k(req_size);
    let req_base = if !base_ptr.is_null() {
        let Some(v) = read_user_u64(owner_pid, base_ptr as *const u64) else {
            crate::hypercall::debug_u64(0xE215_E006);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };
        v & PAGE_MASK_4K
    } else {
        0
    };

    let reserve = (alloc_type & MEM_RESERVE) != 0;
    let commit = (alloc_type & MEM_COMMIT) != 0;
    if !reserve && !commit {
        crate::hypercall::debug_u64(0xE215_E003);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    if reserve {
        let base = match vm_reserve_private(owner_pid, req_base, size, prot) {
            Ok(v) => v,
            Err(st) => {
                crate::hypercall::debug_u64(0xE215_0000 | st as u64);
                frame.x[0] = st as u64;
                return;
            }
        };
        if commit {
            let st = vm_commit_private(owner_pid, base, size, prot);
            if st != status::SUCCESS {
                crate::hypercall::debug_u64(0xE215_1000 | st as u64);
                let _ = vm_release_private(owner_pid, base);
                frame.x[0] = st as u64;
                return;
            }
        }
        if !base_ptr.is_null() && !write_user_u64(owner_pid, base_ptr, base) {
            crate::hypercall::debug_u64(0xE215_E007);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
        if !write_user_u64(owner_pid, size_ptr, size) {
            crate::hypercall::debug_u64(0xE215_E008);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
        if base < USER_VA_BASE || base >= USER_VA_LIMIT {
            crate::hypercall::debug_u64(0xE215_E00B);
            crate::hypercall::debug_u64(base);
        }
        trace_avm_success(owner_pid, base_ptr, size_ptr, base, size, req_size);
        frame.x[0] = status::SUCCESS as u64;
        return;
    }

    if req_base == 0 {
        crate::hypercall::debug_u64(0xE215_E004);
        crate::hypercall::debug_print("nt: avm invalid commit-only null base alloc_type=");
        crate::hypercall::debug_u64(alloc_type as u64);
        crate::hypercall::debug_print(" prot=");
        crate::hypercall::debug_u64(prot as u64);
        crate::hypercall::debug_print(" req=");
        crate::hypercall::debug_u64(req_size);
        crate::hypercall::debug_print("\n");
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let st = vm_commit_private(owner_pid, req_base, size, prot);
    if st != status::SUCCESS {
        crate::hypercall::debug_u64(0xE215_2000 | st as u64);
        frame.x[0] = st as u64;
        return;
    }
    if !base_ptr.is_null() && !write_user_u64(owner_pid, base_ptr, req_base) {
        crate::hypercall::debug_u64(0xE215_E009);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if !write_user_u64(owner_pid, size_ptr, size) {
        crate::hypercall::debug_u64(0xE215_E00A);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if req_base < USER_VA_BASE || req_base >= USER_VA_LIMIT {
        crate::hypercall::debug_u64(0xE215_E00C);
        crate::hypercall::debug_u64(req_base);
    }
    trace_avm_success(owner_pid, base_ptr, size_ptr, req_base, size, req_size);
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

    let (base, alloc_base, alloc_prot, size, prot, state, mem_type) =
        if let Some(q) = vm_query_region(owner_pid, addr) {
            (
                q.base,
                q.allocation_base,
                q.allocation_prot,
                q.size,
                q.prot,
                q.state,
                q.mem_type,
            )
        } else {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };

    let mut mbi = [0u8; 48];
    mbi[0..8].copy_from_slice(&base.to_le_bytes());
    mbi[8..16].copy_from_slice(&alloc_base.to_le_bytes());
    mbi[16..20].copy_from_slice(&alloc_prot.to_le_bytes());
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

// NtReadVirtualMemory:
// x0=ProcessHandle, x1=BaseAddress, x2=Buffer, x3=Size, x4=*BytesRead(opt)
pub(crate) fn handle_read_virtual_memory(frame: &mut SvcFrame) {
    let process_handle = frame.x[0];
    let src = frame.x[1] as *const u8;
    let dst = frame.x[2] as *mut u8;
    let size = frame.x[3] as usize;
    let out_len = frame.x[4] as *mut u64;

    let Some(pid) = crate::process::resolve_process_handle(process_handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    let caller_pid = crate::process::current_pid();

    if size == 0 {
        if !out_len.is_null() {
            if !ensure_user_range_access(caller_pid, out_len as u64, core::mem::size_of::<u64>(), VM_ACCESS_WRITE) {
                frame.x[0] = status::NOT_COMMITTED as u64;
                return;
            }
            unsafe { out_len.write_volatile(0) };
        }
        frame.x[0] = status::SUCCESS as u64;
        return;
    }

    if src.is_null() || dst.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if !out_len.is_null()
        && !ensure_user_range_access(
            caller_pid,
            out_len as u64,
            core::mem::size_of::<u64>(),
            VM_ACCESS_WRITE,
        )
    {
        frame.x[0] = status::NOT_COMMITTED as u64;
        return;
    }
    if !ensure_user_range_access(caller_pid, dst as u64, size, VM_ACCESS_WRITE) {
        frame.x[0] = status::NOT_COMMITTED as u64;
        return;
    }
    if !ensure_user_range_access(pid, src as u64, size, VM_ACCESS_READ) {
        frame.x[0] = status::NOT_COMMITTED as u64;
        return;
    }

    if pid == caller_pid {
        unsafe {
            core::ptr::copy(src, dst, size);
        }
    } else {
        if !copy_from_process_user(pid, src as u64, dst, size) {
            frame.x[0] = status::NOT_COMMITTED as u64;
            return;
        }
    }
    if !out_len.is_null() {
        unsafe { out_len.write_volatile(size as u64) };
    }
    frame.x[0] = status::SUCCESS as u64;
}

// NtWriteVirtualMemory:
// x0=ProcessHandle, x1=BaseAddress, x2=Buffer, x3=Size, x4=*BytesWritten(opt)
pub(crate) fn handle_write_virtual_memory(frame: &mut SvcFrame) {
    let process_handle = frame.x[0];
    let dst = frame.x[1] as *mut u8;
    let src = frame.x[2] as *const u8;
    let size = frame.x[3] as usize;
    let out_len = frame.x[4] as *mut u64;

    let Some(pid) = crate::process::resolve_process_handle(process_handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    let caller_pid = crate::process::current_pid();

    if size == 0 {
        if !out_len.is_null() {
            if !ensure_user_range_access(caller_pid, out_len as u64, core::mem::size_of::<u64>(), VM_ACCESS_WRITE) {
                frame.x[0] = status::NOT_COMMITTED as u64;
                return;
            }
            unsafe { out_len.write_volatile(0) };
        }
        frame.x[0] = status::SUCCESS as u64;
        return;
    }

    if src.is_null() || dst.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if !out_len.is_null()
        && !ensure_user_range_access(
            caller_pid,
            out_len as u64,
            core::mem::size_of::<u64>(),
            VM_ACCESS_WRITE,
        )
    {
        frame.x[0] = status::NOT_COMMITTED as u64;
        return;
    }
    if !ensure_user_range_access(caller_pid, src as u64, size, VM_ACCESS_READ) {
        frame.x[0] = status::NOT_COMMITTED as u64;
        return;
    }
    if !ensure_user_range_access(pid, dst as u64, size, VM_ACCESS_WRITE) {
        frame.x[0] = status::NOT_COMMITTED as u64;
        return;
    }

    if pid == caller_pid {
        unsafe {
            core::ptr::copy(src, dst, size);
        }
    } else {
        if !copy_to_process_user(pid, dst as u64, src, size) {
            frame.x[0] = status::NOT_COMMITTED as u64;
            return;
        }
    }
    if !out_len.is_null() {
        unsafe { out_len.write_volatile(size as u64) };
    }
    frame.x[0] = status::SUCCESS as u64;
}
