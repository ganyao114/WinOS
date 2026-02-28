use winemu_shared::nr;

/// 6 引数 hypercall（HVC #0）
/// x0 = nr, x1-x6 = args, 返回值在 x0
#[inline(always)]
pub fn hypercall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    crate::arch::hypercall::invoke6(nr, a0, a1, a2, a3, a4, a5)
}

#[inline(always)]
pub fn hypercall(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    hypercall6(nr, a0, a1, a2, 0, 0, 0)
}

/// KERNEL_READY — 通知 VMM 内核已就绪，传入 PE 入口点、栈、TEB、heap_start
/// 返回 Thread 0 的 tid
pub fn kernel_ready(entry_va: u64, stack_va: u64, teb_gva: u64, heap_start: u64) -> u64 {
    hypercall6(nr::KERNEL_READY, entry_va, stack_va, teb_gva, heap_start, 0, 0)
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

pub fn thread_create(entry_va: u64, stack_va: u64, arg: u64, teb_gva: u64) -> u64 {
    hypercall6(nr::THREAD_CREATE, entry_va, stack_va, arg, teb_gva, 0, 0)
}

pub fn thread_exit(code: u32) -> ! {
    hypercall(nr::THREAD_EXIT, code as u64, 0, 0);
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

/// NtCreateSection — file_handle=0 表示 pagefile-backed
/// 返回 (status << 32) | section_handle
pub fn create_section(file_handle: u64, size: u64, prot: u32) -> u64 {
    hypercall6(nr::NT_CREATE_SECTION, file_handle, size, prot as u64, 0, 0, 0)
}

/// NtMapViewOfSection — 返回 (status << 32) | mapped_va
pub fn map_view_of_section(
    section_handle: u64,
    base_hint: u64,
    size: u64,
    offset: u64,
    prot: u32,
) -> u64 {
    hypercall6(nr::NT_MAP_VIEW_OF_SECTION, section_handle, base_hint, size, offset, prot as u64, 0)
}

/// NtUnmapViewOfSection — 返回 NTSTATUS
pub fn unmap_view_of_section(base_va: u64) -> u64 {
    hypercall6(nr::NT_UNMAP_VIEW_OF_SECTION, base_va, 0, 0, 0, 0, 0)
}

/// 请求 VMM 加载 DLL，返回 guest_base（失败返回 u64::MAX）
pub fn load_dll(name: &str) -> u64 {
    hypercall(nr::LOAD_DLL_IMAGE, name.as_ptr() as u64, name.len() as u64, 0)
}

/// 从已加载 DLL 的 export 表查找函数 VA（失败返回 0）
pub fn get_proc_address(dll_base: u64, name: &str) -> u64 {
    hypercall6(
        nr::GET_PROC_ADDRESS,
        dll_base,
        name.as_ptr() as u64,
        name.len() as u64,
        0, 0, 0,
    )
}

// ── Host 文件操作 ──────────────────────────────────────────

/// HOST_OPEN — 打开宿主文件，返回 fd（失败返回 u64::MAX）
pub fn host_open(path: &str, flags: u64) -> u64 {
    hypercall(nr::HOST_OPEN, path.as_ptr() as u64, path.len() as u64, flags)
}

/// HOST_READ — 读取文件到 dst 指针，返回实际读取字节数
pub fn host_read(fd: u64, dst: *mut u8, len: usize, offset: u64) -> usize {
    hypercall6(nr::HOST_READ, fd, dst as u64, len as u64, offset, 0, 0) as usize
}

/// HOST_WRITE — 写入 src 指针到文件，返回实际写入字节数
pub fn host_write(fd: u64, src: *const u8, len: usize, offset: u64) -> usize {
    hypercall6(nr::HOST_WRITE, fd, src as u64, len as u64, offset, 0, 0) as usize
}

/// HOST_CLOSE — 关闭文件
pub fn host_close(fd: u64) {
    hypercall(nr::HOST_CLOSE, fd, 0, 0);
}

/// HOST_STAT — 查询文件大小
pub fn host_stat(fd: u64) -> u64 {
    hypercall(nr::HOST_STAT, fd, 0, 0)
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
