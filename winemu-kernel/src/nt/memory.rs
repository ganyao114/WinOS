use winemu_shared::status;

use super::common::{align_up_4k, MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE};
use super::constants::PAGE_MASK_4K;
use super::user_args::UserOutPtr;
use super::SvcFrame;
use crate::mm::usercopy::{
    copy_between_process_users, copy_to_process_user, ensure_user_range_access,
};
use crate::mm::{
    vm_commit_private, vm_decommit_private, vm_protect_range, vm_query_region, vm_release_private,
    vm_reserve_private, UserVa, VM_ACCESS_WRITE,
};
use core::sync::atomic::{AtomicU32, Ordering};

const PAGE_SIZE_4K: u64 = 0x1000;
const USER_VA_BASE: u64 = crate::process::USER_VA_BASE;
const USER_VA_LIMIT: u64 = crate::process::USER_VA_LIMIT;
const MEMORY_BASIC_INFORMATION_CLASS: u32 = 0;
const MEMORY_WINE_UNIX_FUNCS_CLASS: u32 = 1000;
const MEMORY_WINE_UNIX_WOW64_FUNCS_CLASS: u32 = 1001;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;
const WINE_UNIX_FUNCS_EXPORT: &str = "__wine_unix_call_funcs";
const WINE_UNIX_WOW64_FUNCS_EXPORT: &str = "__wine_unix_call_wow64_funcs";
static TRACE_PRIVATE_ALLOC_4K_BUDGET: AtomicU32 = AtomicU32::new(128);

fn read_user_u64(pid: u32, user_ptr: UserOutPtr<u64>) -> Option<u64> {
    user_ptr.read_for_pid(pid)
}

fn write_user_u64(pid: u32, user_ptr: UserOutPtr<u64>, value: u64) -> bool {
    user_ptr.write_for_pid(pid, value)
}

fn write_user_u32(pid: u32, user_ptr: UserOutPtr<u32>, value: u32) -> bool {
    user_ptr.write_for_pid(pid, value)
}

#[inline]
fn trace_private_alloc_4k(
    frame: &SvcFrame,
    target_pid: u32,
    base: u64,
    size: u64,
    alloc_type: u32,
    prot: u32,
) {
    if target_pid != 1 || size != PAGE_SIZE_4K {
        return;
    }
    if TRACE_PRIVATE_ALLOC_4K_BUDGET
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1))
        .is_err()
    {
        return;
    }
    crate::kdebug!(
        "nt: alloc4k pid={} tid={} base={:#x} size={:#x} type={:#x} prot={:#x} pc={:#x} lr={:#x} sp={:#x}",
        target_pid,
        crate::sched::current_tid(),
        base,
        size,
        alloc_type,
        prot,
        frame.program_counter(),
        frame.x[30],
        frame.user_sp()
    );
    let mut lr_matched = false;
    crate::dll::for_each_loaded(|name, dll_base, dll_size, entry| {
        if lr_matched || dll_size == 0 {
            return;
        }
        let end = dll_base.saturating_add(dll_size as u64);
        if frame.x[30] < dll_base || frame.x[30] >= end {
            return;
        }
        lr_matched = true;
        crate::kdebug!(
            "nt: alloc4k_lr_module pid={} tid={} addr={:#x} module={} base={:#x} size={:#x} entry={:#x}",
            target_pid,
            crate::sched::current_tid(),
            frame.x[30],
            name,
            dll_base,
            dll_size,
            entry
        );
    });
}

// NtAllocateVirtualMemory:
// x0=ProcessHandle, x1=*BaseAddress, x2=ZeroBits, x3=*RegionSize, x4=AllocationType, x5=Protect
pub(crate) fn handle_allocate_virtual_memory(frame: &mut SvcFrame) {
    let base_ptr = UserOutPtr::from_raw(frame.x[1] as *mut u64);
    let size_ptr = UserOutPtr::from_raw(frame.x[3] as *mut u64);
    let caller_pid = crate::process::current_pid();
    if caller_pid == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let Some(target_pid) = crate::process::resolve_process_handle(frame.x[0]) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    if size_ptr.is_null() {
        crate::log::debug_u64(0xE215_E001);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Some(req_size) = read_user_u64(caller_pid, size_ptr) else {
        crate::log::debug_u64(0xE215_E005);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    if req_size == 0 {
        crate::log::debug_u64(0xE215_E002);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let alloc_type = frame.x[4] as u32;
    let prot = frame.x[5] as u32;
    let size = align_up_4k(req_size);
    let req_base = if !base_ptr.is_null() {
        let Some(v) = read_user_u64(caller_pid, base_ptr) else {
            crate::log::debug_u64(0xE215_E006);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };
        v & PAGE_MASK_4K
    } else {
        0
    };

    let mut reserve = (alloc_type & MEM_RESERVE) != 0;
    let commit = (alloc_type & MEM_COMMIT) != 0;
    if !reserve && !commit {
        crate::log::debug_u64(0xE215_E003);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    // Runtime compatibility: some userspace paths request MEM_COMMIT with
    // *BaseAddress == NULL. Real NT rejects this, but many higher layers assume
    // "allocate fresh committed region" behavior. Treat it as RESERVE|COMMIT.
    if !reserve && commit && req_base == 0 {
        reserve = true;
    }

    if reserve {
        let base = match vm_reserve_private(target_pid, req_base, size, prot) {
            Ok(v) => v,
            Err(st) => {
                crate::log::debug_u64(0xE215_0000 | st as u64);
                frame.x[0] = st as u64;
                return;
            }
        };
        if commit {
            let st = vm_commit_private(target_pid, base, size, prot);
            if st != status::SUCCESS {
                crate::log::debug_u64(0xE215_1000 | st as u64);
                let _ = vm_release_private(target_pid, base);
                frame.x[0] = st as u64;
                return;
            }
        }
        if !base_ptr.is_null() && !write_user_u64(caller_pid, base_ptr, base) {
            crate::log::debug_u64(0xE215_E007);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
        if !write_user_u64(caller_pid, size_ptr, size) {
            crate::log::debug_u64(0xE215_E008);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
        trace_private_alloc_4k(frame, target_pid, base, size, alloc_type, prot);
        if base < USER_VA_BASE || base >= USER_VA_LIMIT {
            crate::log::debug_u64(0xE215_E00B);
            crate::log::debug_u64(base);
        }
        frame.x[0] = status::SUCCESS as u64;
        return;
    }

    if req_base == 0 {
        crate::log::debug_u64(0xE215_E004);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let st = vm_commit_private(target_pid, req_base, size, prot);
    if st != status::SUCCESS {
        crate::log::debug_u64(0xE215_2000 | st as u64);
        frame.x[0] = st as u64;
        return;
    }
    if !base_ptr.is_null() && !write_user_u64(caller_pid, base_ptr, req_base) {
        crate::log::debug_u64(0xE215_E009);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if !write_user_u64(caller_pid, size_ptr, size) {
        crate::log::debug_u64(0xE215_E00A);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    trace_private_alloc_4k(frame, target_pid, req_base, size, alloc_type, prot);
    if req_base < USER_VA_BASE || req_base >= USER_VA_LIMIT {
        crate::log::debug_u64(0xE215_E00C);
        crate::log::debug_u64(req_base);
    }
    frame.x[0] = status::SUCCESS as u64;
}

// NtFreeVirtualMemory:
// x0=ProcessHandle, x1=*BaseAddress, x2=*RegionSize, x3=FreeType
pub(crate) fn handle_free_virtual_memory(frame: &mut SvcFrame) {
    let base_ptr = UserOutPtr::from_raw(frame.x[1] as *mut u64);
    let size_ptr = UserOutPtr::from_raw(frame.x[2] as *mut u64);
    let free_type = frame.x[3] as u32;
    if base_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let caller_pid = crate::process::current_pid();
    if caller_pid == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let Some(target_pid) = crate::process::resolve_process_handle(frame.x[0]) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    let Some(base) = read_user_u64(caller_pid, base_ptr) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    match free_type {
        MEM_RELEASE => {
            if !size_ptr.is_null() {
                let Some(size) = read_user_u64(caller_pid, size_ptr) else {
                    frame.x[0] = status::INVALID_PARAMETER as u64;
                    return;
                };
                if size != 0 {
                    frame.x[0] = status::INVALID_PARAMETER as u64;
                    return;
                }
            }
            let st = vm_release_private(target_pid, base);
            frame.x[0] = st as u64;
        }
        MEM_DECOMMIT => {
            if size_ptr.is_null() {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            let Some(size) = read_user_u64(caller_pid, size_ptr) else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            if size == 0 {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            let st = vm_decommit_private(target_pid, base, size);
            frame.x[0] = st as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

// NtProtectVirtualMemory:
// x0=ProcessHandle, x1=*BaseAddress, x2=*RegionSize, x3=NewProtect, x4=*OldProtect
pub(crate) fn handle_protect_virtual_memory(frame: &mut SvcFrame) {
    let base_ptr = UserOutPtr::from_raw(frame.x[1] as *mut u64);
    let size_ptr = UserOutPtr::from_raw(frame.x[2] as *mut u64);
    let old_ptr = UserOutPtr::from_raw(frame.x[4] as *mut u32);
    if base_ptr.is_null() || size_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let caller_pid = crate::process::current_pid();
    if caller_pid == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let Some(target_pid) = crate::process::resolve_process_handle(frame.x[0]) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    let Some(base_raw) = read_user_u64(caller_pid, base_ptr) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    let Some(size_raw) = read_user_u64(caller_pid, size_ptr) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    let base = base_raw & PAGE_MASK_4K;
    let size = align_up_4k(size_raw);
    if size == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    match vm_protect_range(target_pid, base, size, frame.x[3] as u32) {
        Ok(old) => {
            if !old_ptr.is_null() && !write_user_u32(caller_pid, old_ptr, old) {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            if !write_user_u64(caller_pid, base_ptr, base)
                || !write_user_u64(caller_pid, size_ptr, size)
            {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        Err(st) => {
            if !old_ptr.is_null() && !write_user_u32(caller_pid, old_ptr, 0) {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            frame.x[0] = st as u64;
        }
    }
}

// NtQueryVirtualMemory:
// x0=ProcessHandle, x1=BaseAddress, x2=MemoryInformationClass, x3=Buffer, x4=BufferSize, x5=*ReturnLength
pub(crate) fn handle_query_virtual_memory(frame: &mut SvcFrame) {
    let addr = frame.x[1];
    let info_class = frame.x[2] as u32;
    let buf = frame.x[3] as *mut u8;
    let buf_len = frame.x[4] as usize;
    let ret_len_ptr = UserOutPtr::from_raw(frame.x[5] as *mut u64);
    let caller_pid = crate::process::current_pid();
    if caller_pid == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let Some(target_pid) = crate::process::resolve_process_handle(frame.x[0]) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    if info_class != MEMORY_BASIC_INFORMATION_CLASS {
        crate::ktrace!(
            "nt: NtQueryVirtualMemory class={} addr={:#x} buf={:#x} len={:#x} caller_pid={} target_pid={}",
            info_class,
            addr,
            buf as u64,
            buf_len,
            caller_pid,
            target_pid
        );
    }
    if !ret_len_ptr.is_null()
        && !ensure_user_range_access(
            caller_pid,
            UserVa::new(ret_len_ptr.as_raw() as u64),
            core::mem::size_of::<u64>(),
            VM_ACCESS_WRITE,
        )
    {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    match info_class {
        MEMORY_BASIC_INFORMATION_CLASS => {}
        MEMORY_WINE_UNIX_FUNCS_CLASS | MEMORY_WINE_UNIX_WOW64_FUNCS_CLASS => {
            if target_pid != caller_pid {
                frame.x[0] = status::INVALID_HANDLE as u64;
                return;
            }
            if buf.is_null() || buf_len != core::mem::size_of::<u64>() {
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            if !ensure_user_range_access(
                caller_pid,
                UserVa::new(buf as u64),
                core::mem::size_of::<u64>(),
                VM_ACCESS_WRITE,
            ) {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }

            let export_name = if info_class == MEMORY_WINE_UNIX_WOW64_FUNCS_CLASS {
                WINE_UNIX_WOW64_FUNCS_EXPORT
            } else {
                WINE_UNIX_FUNCS_EXPORT
            };
            let Some(module_base) = crate::dll::find_loaded_base_for_addr(addr) else {
                crate::kdebug!(
                    "nt: NtQueryVirtualMemory wine-unix module-miss class={} addr={:#x}",
                    info_class,
                    addr
                );
                frame.x[0] = STATUS_DLL_NOT_FOUND as u64;
                return;
            };
            let Some(handle) = crate::dll::resolve_loaded_export(module_base, export_name) else {
                let null_handle = 0u64;
                if !copy_to_process_user(
                    caller_pid,
                    UserVa::new(buf as u64),
                    (&null_handle as *const u64).cast(),
                    core::mem::size_of::<u64>(),
                ) {
                    frame.x[0] = status::INVALID_PARAMETER as u64;
                    return;
                }
                if !ret_len_ptr.is_null()
                    && !write_user_u64(caller_pid, ret_len_ptr, core::mem::size_of::<u64>() as u64)
                {
                    frame.x[0] = status::INVALID_PARAMETER as u64;
                    return;
                }
                frame.x[0] = status::SUCCESS as u64;
                return;
            };
            if !copy_to_process_user(
                caller_pid,
                UserVa::new(buf as u64),
                (&handle as *const u64).cast(),
                core::mem::size_of::<u64>(),
            ) {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            if !ret_len_ptr.is_null()
                && !write_user_u64(caller_pid, ret_len_ptr, core::mem::size_of::<u64>() as u64)
            {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            frame.x[0] = status::SUCCESS as u64;
            return;
        }
        _ => {
            crate::kdebug!(
                "nt: NtQueryVirtualMemory unsupported class={} addr={:#x}",
                info_class,
                addr
            );
            frame.x[0] = STATUS_INVALID_INFO_CLASS as u64;
            return;
        }
    }
    if !ensure_user_range_access(caller_pid, UserVa::new(buf as u64), 48, VM_ACCESS_WRITE) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let (base, alloc_base, alloc_prot, size, prot, state, mem_type) =
        if let Some(q) = vm_query_region(target_pid, UserVa::new(addr)) {
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
            crate::kdebug!(
                "nt: NtQueryVirtualMemory basic query miss addr={:#x} caller_pid={} target_pid={}",
                addr,
                caller_pid,
                target_pid
            );
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };

    let mut mbi = [0u8; 48];
    mbi[0..8].copy_from_slice(&base.get().to_le_bytes());
    mbi[8..16].copy_from_slice(&alloc_base.get().to_le_bytes());
    mbi[16..20].copy_from_slice(&alloc_prot.to_le_bytes());
    mbi[24..32].copy_from_slice(&size.to_le_bytes());
    mbi[32..36].copy_from_slice(&state.to_le_bytes());
    mbi[36..40].copy_from_slice(&prot.to_le_bytes());
    mbi[40..44].copy_from_slice(&mem_type.to_le_bytes());
    if !copy_to_process_user(caller_pid, UserVa::new(buf as u64), mbi.as_ptr(), 48) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if !ret_len_ptr.is_null() && !write_user_u64(caller_pid, ret_len_ptr, 48) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
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
    let out_len = UserOutPtr::from_raw(frame.x[4] as *mut u64);

    let Some(pid) = crate::process::resolve_process_handle(process_handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    let caller_pid = crate::process::current_pid();

    if size == 0 {
        if !out_len.is_null() {
            if !ensure_user_range_access(
                caller_pid,
                UserVa::new(out_len.as_raw() as u64),
                core::mem::size_of::<u64>(),
                VM_ACCESS_WRITE,
            ) {
                frame.x[0] = status::NOT_COMMITTED as u64;
                return;
            }
            if !write_user_u64(caller_pid, out_len, 0) {
                frame.x[0] = status::NOT_COMMITTED as u64;
                return;
            }
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
            UserVa::new(out_len.as_raw() as u64),
            core::mem::size_of::<u64>(),
            VM_ACCESS_WRITE,
        )
    {
        frame.x[0] = status::NOT_COMMITTED as u64;
        return;
    }
    if !copy_between_process_users(
        pid,
        UserVa::new(src as u64),
        caller_pid,
        UserVa::new(dst as u64),
        size,
    ) {
        frame.x[0] = status::NOT_COMMITTED as u64;
        return;
    }
    if !out_len.is_null() {
        if !write_user_u64(caller_pid, out_len, size as u64) {
            frame.x[0] = status::NOT_COMMITTED as u64;
            return;
        }
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
    let out_len = UserOutPtr::from_raw(frame.x[4] as *mut u64);

    let Some(pid) = crate::process::resolve_process_handle(process_handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    let caller_pid = crate::process::current_pid();

    if size == 0 {
        if !out_len.is_null() {
            if !ensure_user_range_access(
                caller_pid,
                UserVa::new(out_len.as_raw() as u64),
                core::mem::size_of::<u64>(),
                VM_ACCESS_WRITE,
            ) {
                frame.x[0] = status::NOT_COMMITTED as u64;
                return;
            }
            if !write_user_u64(caller_pid, out_len, 0) {
                frame.x[0] = status::NOT_COMMITTED as u64;
                return;
            }
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
            UserVa::new(out_len.as_raw() as u64),
            core::mem::size_of::<u64>(),
            VM_ACCESS_WRITE,
        )
    {
        frame.x[0] = status::NOT_COMMITTED as u64;
        return;
    }
    if !copy_between_process_users(
        caller_pid,
        UserVa::new(src as u64),
        pid,
        UserVa::new(dst as u64),
        size,
    ) {
        frame.x[0] = status::NOT_COMMITTED as u64;
        return;
    }
    if !out_len.is_null() {
        if !write_user_u64(caller_pid, out_len, size as u64) {
            frame.x[0] = status::NOT_COMMITTED as u64;
            return;
        }
    }
    frame.x[0] = status::SUCCESS as u64;
}
