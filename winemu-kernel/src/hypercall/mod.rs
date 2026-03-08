mod hostcall;

use winemu_shared::hostcall as hc;
use winemu_shared::nr;

pub use crate::log::{logf, LogLevel};
pub use hostcall::{
    hostcall_cancel, hostcall_poll_batch, hostcall_query_sched_wake_stats, hostcall_setup,
    hostcall_submit_tagged,
    HostCallCompletion,
};

/// 6 引数 hypercall（HVC #0）
/// x0 = nr, x1-x6 = args, 返回值在 x0
#[inline(always)]
pub fn hypercall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    crate::arch::hypercall::invoke6(nr, a0, a1, a2, a3, a4, a5)
}

/// 6 引数 hypercall，返回 (x0, x1)
#[inline(always)]
pub fn hypercall6_pair(
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> (u64, u64) {
    crate::arch::hypercall::invoke6_pair(nr, a0, a1, a2, a3, a4, a5)
}

#[inline(always)]
pub fn hypercall(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    hypercall6(nr, a0, a1, a2, 0, 0, 0)
}

#[inline(always)]
fn hostcall_sync(opcode: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> (u64, u64) {
    let owner_pid = crate::process::current_pid();
    let res = crate::hostcall::call_sync(
        owner_pid,
        crate::hostcall::SubmitArgs {
            opcode,
            flags: 0,
            arg0,
            arg1,
            arg2,
            arg3,
            user_tag: 0,
        },
    );
    match res {
        Ok(done) => (done.host_result, done.value0),
        Err(_) => (hc::HC_BUSY, 0),
    }
}

/// KERNEL_READY — 通知 VMM 内核已就绪，传入 PE 入口点、栈、TEB、heap_start。
/// x5/x6 预留；当前固定传 0。
/// 返回值仅用于诊断（当前实现固定为 0）。
pub fn kernel_ready(
    entry_va: u64,
    stack_va: u64,
    teb_gva: u64,
    heap_start: u64,
    reserved0: u64,
    reserved1: u64,
) -> u64 {
    hypercall6(
        nr::KERNEL_READY,
        entry_va,
        stack_va,
        teb_gva,
        heap_start,
        reserved0,
        reserved1,
    )
}

pub fn debug_print(msg: &str) {
    hypercall(nr::DEBUG_PRINT, msg.as_ptr() as u64, msg.len() as u64, 0);
}

pub fn process_exit(code: u32) -> ! {
    hypercall(nr::PROCESS_EXIT, code as u64, 0, 0);
    loop {
        crate::arch::cpu::wait_for_interrupt();
    }
}

pub fn alloc_virtual(hint: u64, size: u64, prot: u32) -> u64 {
    hypercall(nr::NT_ALLOC_VIRTUAL, hint, size, prot as u64)
}

pub fn free_virtual(base: u64) -> u64 {
    hypercall(nr::NT_FREE_VIRTUAL, base, 0, 0)
}

pub fn yield_execution() {
    hypercall(nr::NT_YIELD_EXECUTION, 0, 0, 0);
}

#[inline(always)]
pub fn kick_vcpu_mask(mask: u32) {
    if mask == 0 {
        return;
    }
    let _ = hypercall6(nr::KICK_VCPU_MASK, mask as u64, 0, 0, 0, 0, 0);
}

/// NtCreateSection — file_handle=0 表示 pagefile-backed
/// 返回 (status << 32) | section_handle
pub fn create_section(file_handle: u64, size: u64, prot: u32) -> u64 {
    hypercall6(
        nr::NT_CREATE_SECTION,
        file_handle,
        size,
        prot as u64,
        0,
        0,
        0,
    )
}

/// NtMapViewOfSection — 返回 (status << 32) | mapped_va
pub fn map_view_of_section(
    section_handle: u64,
    base_hint: u64,
    size: u64,
    offset: u64,
    prot: u32,
) -> u64 {
    hypercall6(
        nr::NT_MAP_VIEW_OF_SECTION,
        section_handle,
        base_hint,
        size,
        offset,
        prot as u64,
        0,
    )
}

/// NtUnmapViewOfSection — 返回 NTSTATUS
pub fn unmap_view_of_section(base_va: u64) -> u64 {
    hypercall6(nr::NT_UNMAP_VIEW_OF_SECTION, base_va, 0, 0, 0, 0, 0)
}

// ── Host 文件操作 ──────────────────────────────────────────

/// HOST_OPEN — 打开宿主文件，返回 fd（失败返回 u64::MAX）
pub fn host_open(path: &str, flags: u64) -> u64 {
    let (ret, aux) = hostcall_sync(
        hc::OP_OPEN,
        path.as_ptr() as u64,
        path.len() as u64,
        flags,
        0,
    );
    if ret == hc::HC_OK {
        aux
    } else {
        u64::MAX
    }
}

/// HOST_READ — 读取文件到 dst 指针，返回实际读取字节数
pub fn host_read(fd: u64, dst: *mut u8, len: usize, offset: u64) -> usize {
    let (ret, aux) = hostcall_sync(hc::OP_READ, fd, dst as u64, len as u64, offset);
    if ret == hc::HC_OK {
        aux as usize
    } else {
        0
    }
}

/// HOST_WRITE — 写入 src 指针到文件，返回实际写入字节数
pub fn host_write(fd: u64, src: *const u8, len: usize, offset: u64) -> usize {
    let (ret, aux) = hostcall_sync(hc::OP_WRITE, fd, src as u64, len as u64, offset);
    if ret == hc::HC_OK {
        aux as usize
    } else {
        0
    }
}

/// HOST_CLOSE — 关闭文件
pub fn host_close(fd: u64) {
    let _ = hostcall_sync(hc::OP_CLOSE, fd, 0, 0, 0);
}

/// HOST_STAT — 查询文件大小
pub fn host_stat(fd: u64) -> u64 {
    let (ret, aux) = hostcall_sync(hc::OP_STAT, fd, 0, 0, 0);
    if ret == hc::HC_OK {
        aux
    } else {
        0
    }
}

/// HOST_READDIR — 读取目录下一项名称
/// 返回:
/// - 0: no more files
/// - u64::MAX: invalid / not directory
/// - 其他: bit63=is_dir, low32=name_len
pub fn host_readdir(fd: u64, dst: *mut u8, len: usize, restart: bool) -> u64 {
    let (ret, aux) = hostcall_sync(hc::OP_READDIR, fd, dst as u64, len as u64, restart as u64);
    if ret == hc::HC_OK {
        aux
    } else {
        u64::MAX
    }
}

/// HOST_NOTIFY_DIR — 查询目录变更（非阻塞）
/// 返回:
/// - 0: no change
/// - u64::MAX: invalid / not directory
/// - 其他: bits[39:32]=action, low32=name_len
pub fn host_notify_dir(
    fd: u64,
    dst: *mut u8,
    len: usize,
    watch_tree: bool,
    completion_filter: u32,
) -> u64 {
    let mut opts = completion_filter as u64;
    if watch_tree {
        opts |= 1u64 << 63;
    }
    let (ret, aux) = hostcall_sync(hc::OP_NOTIFY_DIR, fd, dst as u64, len as u64, opts);
    if ret == hc::HC_OK {
        aux
    } else {
        u64::MAX
    }
}

/// HOST_MEMSET — fill guest physical memory range.
/// Returns true on success.
pub fn host_memset(dst_gpa: u64, len: usize, value: u8) -> bool {
    hypercall6(
        nr::HOST_MEMSET,
        dst_gpa,
        len as u64,
        value as u64,
        0,
        0,
        0,
    ) == 0
}

/// HOST_MEMCPY — copy guest physical memory range.
/// Returns true on success.
pub fn host_memcpy(dst_gpa: u64, src_gpa: u64, len: usize) -> bool {
    hypercall6(
        nr::HOST_MEMCPY,
        dst_gpa,
        src_gpa,
        len as u64,
        0,
        0,
        0,
    ) == 0
}

/// Raw HOST_MMAP primitive. Keep internal so callers must choose explicit
/// tracked/untracked mapping semantics.
fn host_mmap_raw(fd: u64, offset: u64, size: u64, prot: u32) -> u64 {
    let (ret, aux) = hostcall_sync(hc::OP_MMAP, fd, offset, size, prot as u64);
    if ret == hc::HC_OK {
        aux
    } else {
        0
    }
}

/// HOST_MMAP (untracked) — for transient in-kernel file source mappings.
/// Caller is responsible for lifetime and HOST_MUNMAP.
pub fn host_mmap_untracked(fd: u64, offset: u64, size: u64, prot: u32) -> u64 {
    host_mmap_raw(fd, offset, size, prot)
}

/// HOST_MMAP (tracked) — map host file and register the VA range into
/// current process VM metadata as an external file mapping.
///
/// Returns mapped base on success; returns 0 if mapping or tracking fails.
/// On tracking failure the just-created host mapping is rolled back.
pub fn host_mmap_tracked(fd: u64, offset: u64, size: u64, map_prot: u32, vm_prot: u32) -> u64 {
    let base = host_mmap_raw(fd, offset, size, map_prot);
    if base == 0 {
        return 0;
    }
    let owner_pid = crate::process::current_pid();
    if owner_pid == 0 {
        let _ = host_munmap(base, size);
        return 0;
    }
    if crate::nt::state::vm_track_existing_file_mapping(owner_pid, base, size, vm_prot) {
        base
    } else {
        let _ = host_munmap(base, size);
        0
    }
}

/// HOST_MUNMAP — 解除映射
/// 返回 0 表示成功
pub fn host_munmap(base: u64, size: u64) -> u64 {
    let (ret, _) = hostcall_sync(hc::OP_MUNMAP, base, size, 0, 0);
    if ret == hc::HC_OK {
        0
    } else {
        u64::MAX
    }
}

/// QUERY_EXE_INFO — VMM 打开 exe 并返回 packed (size<<32 | fd)
/// 返回 (fd, file_size)，fd == u64::MAX 表示失败
pub fn query_exe_info() -> (u64, u64) {
    let ret = hypercall(nr::QUERY_EXE_INFO, 0, 0, 0);
    if ret == u64::MAX {
        (u64::MAX, 0)
    } else {
        let fd = ret & 0xFFFF_FFFF;
        let size = ret >> 32;
        (fd, size)
    }
}

/// Query monotonic elapsed time from host, in 100ns units.
#[inline(always)]
pub fn query_mono_time_100ns() -> u64 {
    hypercall(nr::QUERY_MONO_TIME, 0, 0, 0)
}

/// Query host wall-clock system time in NT epoch 100ns units.
#[inline(always)]
pub fn query_system_time_100ns() -> u64 {
    hypercall(nr::QUERY_SYSTEM_TIME, 0, 0, 0)
}

#[inline(always)]
pub fn alloc_phys_pages(num_pages: u64) -> u64 {
    hypercall6(nr::ALLOC_PHYS_PAGES, num_pages, 0, 0, 0, 0, 0)
}

#[inline(always)]
pub fn free_phys_pages(gpa: u64, num_pages: u64) -> u64 {
    hypercall6(nr::FREE_PHYS_PAGES, gpa, num_pages, 0, 0, 0, 0)
}

pub fn debug_u64(val: u64) {
    let hex = b"0123456789abcdef";
    let mut buf = [0u8; 18]; // "0x" + 16 hex digits
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16usize {
        let shift = (15 - i) * 4;
        buf[2 + i] = hex[((val >> shift) & 0xF) as usize];
    }
    let s = unsafe { core::str::from_utf8_unchecked(&buf) };
    debug_print(s);
}
