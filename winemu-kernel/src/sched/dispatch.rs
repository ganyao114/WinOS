// svc_dispatch — EL1 SVC 分发器
// 由 vectors.rs 的 SVC handler 汇编调用，处理所有来自 EL0 的 syscall。
// 若需要线程切换，直接修改 SvcFrame 中的寄存器，ERET 后进入新线程。

use crate::sched::{
    current_tid, register_thread0, schedule, spawn, vcpu_id, with_thread, with_thread_mut,
    ThreadState,
};
use crate::sched::sync::{
    self, close_handle, event_alloc, event_reset, event_set, make_handle, mutex_alloc,
    mutex_release, semaphore_alloc, semaphore_release, wait_handle, EventType, STATUS_SUCCESS,
    HANDLE_TYPE_EVENT, HANDLE_TYPE_FILE, HANDLE_TYPE_MUTEX, HANDLE_TYPE_SECTION,
    HANDLE_TYPE_SEMAPHORE, HANDLE_TYPE_THREAD,
};
use crate::hypercall;
use winemu_shared::status;

// ── SvcFrame 镜像（与汇编布局一致）──────────────────────────

#[repr(C)]
pub struct SvcFrame {
    pub x:       [u64; 31],  // x0–x30  (+0x000)
    pub sp_el0:  u64,         // +0x0F8
    pub elr:     u64,         // +0x100
    pub spsr:    u64,         // +0x108
    pub tpidr:   u64,         // +0x110
    pub x8_orig: u64,         // +0x118  syscall tag
}

// ── NT syscall 号（Wine ARM64 约定）──────────────────────────

// Table 0 = Nt*, Table 1 = Win32k (ignored here)
// 只列出我们在 guest 内处理的号码
// 其余转发给 VMM via HVC NT_SYSCALL

const NR_CREATE_EVENT:          u16 = 0x0048;
const NR_SET_INFORMATION_THREAD:u16 = 0x000D;
const NR_READ_FILE:             u16 = 0x0006;
const NR_WRITE_FILE:            u16 = 0x0008;
const NR_SET_EVENT:             u16 = 0x000E;
const NR_QUERY_INFORMATION_FILE:u16 = 0x0011;
const NR_OPEN_FILE:             u16 = 0x0030;
const NR_QUERY_INFORMATION_PROCESS: u16 = 0x0019;
const NR_QUERY_INFORMATION_THREAD: u16 = 0x0025;
const NR_SET_INFORMATION_FILE:  u16 = 0x0027;
const NR_FREE_VIRTUAL_MEMORY:   u16 = 0x001E;
const NR_QUERY_VIRTUAL_MEMORY:  u16 = 0x0023;
const NR_PROTECT_VIRTUAL_MEMORY:u16 = 0x004D;
const NR_MAP_VIEW_OF_SECTION:   u16 = 0x0028;
const NR_UNMAP_VIEW_OF_SECTION: u16 = 0x002A;
const NR_CREATE_FILE:           u16 = 0x0055;
const NR_RESET_EVENT:           u16 = 0x0034;
const NR_DUPLICATE_OBJECT:      u16 = 0x003C;
const NR_ALLOCATE_VIRTUAL_MEMORY: u16 = 0x0015;
const NR_WAIT_SINGLE:           u16 = 0x0004;
const NR_WAIT_MULTIPLE:         u16 = 0x0040;
const NR_CREATE_SECTION:        u16 = 0x004A;
const NR_CREATE_PROCESS_EX:     u16 = 0x004B;
const NR_QUERY_DIRECTORY_FILE:  u16 = 0x004E;
const NR_CREATE_MUTEX:          u16 = 0x00A9;
const NR_RELEASE_MUTANT:        u16 = 0x001C;
const NR_CREATE_SEMAPHORE:      u16 = 0x00C3;
const NR_RELEASE_SEMAPHORE:     u16 = 0x0033;
const NR_CLOSE:                 u16 = 0x000F;
const NR_YIELD_EXECUTION:       u16 = 0x0046;
const NR_CREATE_THREAD_EX:      u16 = 0x00C1;
const NR_TERMINATE_THREAD:      u16 = 0x0053; // approximate
const NR_TERMINATE_PROCESS:     u16 = 0x002C;

const STD_INPUT_HANDLE:  u64 = 0xFFFF_FFFF_FFFF_FFF6;
const STD_OUTPUT_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFF5;
const STD_ERROR_HANDLE:  u64 = 0xFFFF_FFFF_FFFF_FFF4;

const MEM_COMMIT: u32 = 0x1000;
const FILE_OPEN: u32 = 1;

const HOST_OPEN_READ: u64 = 0;
const HOST_OPEN_WRITE: u64 = 1;
const HOST_OPEN_RW: u64 = 2;
const HOST_OPEN_CREATE: u64 = 3;

const MAX_GUEST_FILES: usize = 256;
const MAX_GUEST_SECTIONS: usize = 128;
const MAX_GUEST_VIEWS: usize = 256;
const MAX_VM_REGIONS: usize = 512;

#[derive(Clone, Copy)]
struct GuestFile {
    in_use: bool,
    host_fd: u64,
}

impl GuestFile {
    const fn empty() -> Self {
        Self {
            in_use: false,
            host_fd: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct GuestSection {
    in_use: bool,
    size: u64,
    prot: u32,
    file_handle: u64,
}

impl GuestSection {
    const fn empty() -> Self {
        Self {
            in_use: false,
            size: 0,
            prot: 0,
            file_handle: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct GuestView {
    in_use: bool,
    base: u64,
    size: u64,
}

impl GuestView {
    const fn empty() -> Self {
        Self {
            in_use: false,
            base: 0,
            size: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct VmRegion {
    in_use: bool,
    base: u64,
    size: u64,
    prot: u32,
}

impl VmRegion {
    const fn empty() -> Self {
        Self {
            in_use: false,
            base: 0,
            size: 0,
            prot: 0,
        }
    }
}

static mut GUEST_FILES: [GuestFile; MAX_GUEST_FILES] = [const { GuestFile::empty() }; MAX_GUEST_FILES];
static mut GUEST_SECTIONS: [GuestSection; MAX_GUEST_SECTIONS] =
    [const { GuestSection::empty() }; MAX_GUEST_SECTIONS];
static mut GUEST_VIEWS: [GuestView; MAX_GUEST_VIEWS] = [const { GuestView::empty() }; MAX_GUEST_VIEWS];
static mut VM_REGIONS: [VmRegion; MAX_VM_REGIONS] = [const { VmRegion::empty() }; MAX_VM_REGIONS];
static mut DUP_TAG: u64 = 1;

#[repr(C)]
struct IoStatusBlock {
    status: u64,
    info: u64,
}

// ── 主分发函数（extern "C"，由汇编调用）─────────────────────

#[no_mangle]
pub extern "C" fn svc_dispatch(frame: &mut SvcFrame) {
    // Lazy-init: register Thread 0 on first SVC entry (TPIDR_EL1 starts at 0)
    if current_tid() == 0 {
        register_thread0(frame.tpidr);
    }

    let tag      = frame.x8_orig;
    let nr       = (tag & 0xFFF) as u16;
    let table    = ((tag >> 12) & 0x3) as u8;

    // Table 1 = Win32k — always forward to VMM
    if table != 0 {
        forward_to_vmm(frame, nr, table);
        return;
    }

    match nr {
        NR_CREATE_FILE      => handle_create_file(frame),
        NR_OPEN_FILE        => handle_open_file(frame),
        NR_READ_FILE        => handle_read_file(frame),
        NR_CREATE_EVENT     => handle_create_event(frame),
        NR_WRITE_FILE       => handle_write_file(frame),
        NR_QUERY_INFORMATION_FILE => handle_query_information_file(frame),
        NR_SET_INFORMATION_FILE => handle_set_information_file(frame),
        NR_QUERY_DIRECTORY_FILE => handle_query_directory_file(frame),
        NR_QUERY_INFORMATION_PROCESS => handle_query_information_process(frame),
        NR_QUERY_INFORMATION_THREAD => handle_query_information_thread(frame),
        NR_SET_INFORMATION_THREAD => handle_set_information_thread(frame),
        NR_ALLOCATE_VIRTUAL_MEMORY => handle_allocate_virtual_memory(frame),
        NR_FREE_VIRTUAL_MEMORY => handle_free_virtual_memory(frame),
        NR_QUERY_VIRTUAL_MEMORY => handle_query_virtual_memory(frame),
        NR_PROTECT_VIRTUAL_MEMORY => handle_protect_virtual_memory(frame),
        NR_CREATE_SECTION => handle_create_section(frame),
        NR_MAP_VIEW_OF_SECTION => handle_map_view_of_section(frame),
        NR_UNMAP_VIEW_OF_SECTION => handle_unmap_view_of_section(frame),
        NR_SET_EVENT        => handle_set_event(frame),
        NR_RESET_EVENT      => handle_reset_event(frame),
        NR_DUPLICATE_OBJECT => handle_duplicate_object(frame),
        NR_WAIT_SINGLE      => handle_wait_single(frame),
        NR_WAIT_MULTIPLE    => handle_wait_multiple(frame),
        NR_CREATE_MUTEX     => handle_create_mutex(frame),
        NR_RELEASE_MUTANT   => handle_release_mutant(frame),
        NR_CREATE_SEMAPHORE => handle_create_semaphore(frame),
        NR_RELEASE_SEMAPHORE => handle_release_semaphore(frame),
        NR_CLOSE            => handle_close(frame),
        NR_YIELD_EXECUTION  => handle_yield(frame),
        NR_CREATE_THREAD_EX => handle_create_thread(frame),
        NR_CREATE_PROCESS_EX => handle_create_process(frame),
        NR_TERMINATE_THREAD => handle_terminate_thread(frame),
        NR_TERMINATE_PROCESS => handle_terminate_process(frame),
        _                   => forward_to_vmm(frame, nr, table),
    }

    // After any syscall that may have changed the ready queue,
    // check if we should switch to a higher-priority thread.
    maybe_preempt(frame);
}

// ── 上下文切换辅助 ────────────────────────────────────────────

/// 保存指定线程上下文到 KThread，从 frame 读取
fn save_ctx_for(tid: u32, frame: &SvcFrame) {
    with_thread_mut(tid, |t| {
        t.ctx.x.copy_from_slice(&frame.x);
        t.ctx.sp    = frame.sp_el0;
        t.ctx.pc    = frame.elr;
        t.ctx.pstate = frame.spsr;
        t.ctx.tpidr = frame.tpidr;
    });
}

/// 将目标线程上下文写入 frame（ERET 后进入该线程）
fn restore_ctx_to_frame(tid: u32, frame: &mut SvcFrame) {
    with_thread_mut(tid, |t| {
        frame.x.copy_from_slice(&t.ctx.x);
        frame.sp_el0 = t.ctx.sp;
        frame.elr    = t.ctx.pc;
        frame.spsr   = t.ctx.pstate;
        frame.tpidr  = t.ctx.tpidr;
    });
}

/// 若就绪队列中有更高优先级线程，执行上下文切换
fn maybe_preempt(frame: &mut SvcFrame) {
    let vid = vcpu_id();
    // Capture current tid BEFORE schedule() updates TPIDR_EL1
    let from = current_tid();
    let (_, to) = schedule(vid);
    if to == 0 {
        if crate::sched::all_threads_done() {
            hypercall::process_exit(0);
        }
        unsafe { core::arch::asm!("wfi", options(nostack, nomem)); }
        return;
    }
    if from != to {
        save_ctx_for(from, frame);
        restore_ctx_to_frame(to, frame);
    }
}

#[inline(always)]
fn align_up_4k(v: u64) -> u64 {
    (v + 0xFFF) & !0xFFF
}

fn write_iosb(iosb_ptr: *mut IoStatusBlock, st: u32, info: u64) {
    if !iosb_ptr.is_null() {
        unsafe {
            iosb_ptr.write_volatile(IoStatusBlock {
                status: st as u64,
                info,
            });
        }
    }
}

fn normalize_nt_path(path: &mut [u8], len: usize) -> usize {
    let mut start = 0usize;
    if len >= 4
        && ((path[0] == b'/' && path[1] == b'?' && path[2] == b'?' && path[3] == b'/')
            || (path[0] == b'/' && path[1] == b'/' && path[2] == b'?' && path[3] == b'/')
            || (path[0] == b'/' && path[1] == b'/' && path[2] == b'.' && path[3] == b'/'))
    {
        start = 4;
    }
    while start < len && path[start] == b'/' {
        start += 1;
    }
    if start + 1 < len && path[start + 1] == b':' {
        start += 2;
        if start < len && path[start] == b'/' {
            start += 1;
        }
    }
    while start < len && path[start] == b'/' {
        start += 1;
    }
    let mut out = 0usize;
    for i in start..len {
        path[out] = path[i];
        out += 1;
    }
    out
}

fn read_oa_path(oa_ptr: u64, out: &mut [u8]) -> usize {
    if oa_ptr == 0 || out.is_empty() {
        return 0;
    }
    let us_ptr = unsafe { ((oa_ptr + 0x10) as *const u64).read_volatile() };
    if us_ptr == 0 {
        return 0;
    }
    let byte_len = unsafe { (us_ptr as *const u16).read_volatile() as usize };
    let buf_ptr = unsafe { ((us_ptr + 8) as *const u64).read_volatile() };
    if byte_len == 0 || buf_ptr == 0 {
        return 0;
    }
    let count = core::cmp::min(byte_len / 2, out.len());
    for i in 0..count {
        let wc = unsafe { ((buf_ptr + (i as u64 * 2)) as *const u16).read_volatile() };
        let mut ch = if wc < 0x80 { wc as u8 } else { b'?' };
        if ch == b'\\' {
            ch = b'/';
        }
        out[i] = ch;
    }
    normalize_nt_path(out, count)
}

fn map_open_flags(access: u32, disposition: u32) -> u64 {
    let can_read = (access & (0x8000_0000 | 0x0001)) != 0;
    let can_write = (access & (0x4000_0000 | 0x0002)) != 0;
    if disposition != FILE_OPEN {
        return HOST_OPEN_CREATE;
    }
    match (can_read, can_write) {
        (true, true) => HOST_OPEN_RW,
        (false, true) => HOST_OPEN_WRITE,
        _ => HOST_OPEN_READ,
    }
}

fn file_handle_to_host_fd(file_handle: u64) -> Option<u64> {
    match file_handle {
        STD_INPUT_HANDLE => Some(0),
        STD_OUTPUT_HANDLE => Some(1),
        STD_ERROR_HANDLE => Some(2),
        _ => {
            if sync::handle_type(file_handle) == HANDLE_TYPE_FILE {
                file_host_fd(sync::handle_idx(file_handle))
            } else {
                None
            }
        }
    }
}

fn vm_alloc_region(size: u64, prot: u32) -> Option<u64> {
    let size = align_up_4k(size.max(0x1000));
    let base = crate::alloc::alloc_zeroed(size as usize, 0x1000).map(|p| p as u64)?;
    unsafe {
        for i in 1..MAX_VM_REGIONS {
            if !VM_REGIONS[i].in_use {
                VM_REGIONS[i].in_use = true;
                VM_REGIONS[i].base = base;
                VM_REGIONS[i].size = size;
                VM_REGIONS[i].prot = prot;
                return Some(base);
            }
        }
    }
    None
}

fn vm_find_region(base_or_addr: u64) -> Option<(usize, VmRegion)> {
    unsafe {
        for i in 1..MAX_VM_REGIONS {
            let r = VM_REGIONS[i];
            if r.in_use && base_or_addr >= r.base && base_or_addr < r.base + r.size {
                return Some((i, r));
            }
        }
    }
    None
}

fn vm_free_region(base: u64) -> bool {
    unsafe {
        for i in 1..MAX_VM_REGIONS {
            if VM_REGIONS[i].in_use && VM_REGIONS[i].base == base {
                VM_REGIONS[i].in_use = false;
                return true;
            }
        }
    }
    false
}

fn file_alloc(host_fd: u64) -> Option<u16> {
    unsafe {
        for i in 1..MAX_GUEST_FILES {
            if !GUEST_FILES[i].in_use {
                GUEST_FILES[i].in_use = true;
                GUEST_FILES[i].host_fd = host_fd;
                return Some(i as u16);
            }
        }
    }
    None
}

fn file_host_fd(idx: u16) -> Option<u64> {
    unsafe {
        let i = idx as usize;
        if i < MAX_GUEST_FILES && GUEST_FILES[i].in_use {
            return Some(GUEST_FILES[i].host_fd);
        }
    }
    None
}

fn file_free(idx: u16) {
    unsafe {
        let i = idx as usize;
        if i < MAX_GUEST_FILES && GUEST_FILES[i].in_use {
            hypercall::host_close(GUEST_FILES[i].host_fd);
            GUEST_FILES[i].in_use = false;
            GUEST_FILES[i].host_fd = 0;
        }
    }
}

fn section_alloc(size: u64, prot: u32, file_handle: u64) -> Option<u16> {
    unsafe {
        for i in 1..MAX_GUEST_SECTIONS {
            if !GUEST_SECTIONS[i].in_use {
                GUEST_SECTIONS[i].in_use = true;
                GUEST_SECTIONS[i].size = size;
                GUEST_SECTIONS[i].prot = prot;
                GUEST_SECTIONS[i].file_handle = file_handle;
                return Some(i as u16);
            }
        }
    }
    None
}

fn section_get(idx: u16) -> Option<GuestSection> {
    unsafe {
        let i = idx as usize;
        if i < MAX_GUEST_SECTIONS && GUEST_SECTIONS[i].in_use {
            return Some(GUEST_SECTIONS[i]);
        }
    }
    None
}

fn section_free(idx: u16) {
    unsafe {
        let i = idx as usize;
        if i < MAX_GUEST_SECTIONS {
            GUEST_SECTIONS[i].in_use = false;
        }
    }
}

fn view_alloc(base: u64, size: u64) -> bool {
    unsafe {
        for i in 1..MAX_GUEST_VIEWS {
            if !GUEST_VIEWS[i].in_use {
                GUEST_VIEWS[i].in_use = true;
                GUEST_VIEWS[i].base = base;
                GUEST_VIEWS[i].size = size;
                return true;
            }
        }
    }
    false
}

fn view_free(base: u64) -> bool {
    unsafe {
        for i in 1..MAX_GUEST_VIEWS {
            if GUEST_VIEWS[i].in_use && GUEST_VIEWS[i].base == base {
                GUEST_VIEWS[i].in_use = false;
                GUEST_VIEWS[i].base = 0;
                GUEST_VIEWS[i].size = 0;
                return true;
            }
        }
    }
    false
}

// ── NtCreateEvent ─────────────────────────────────────────────
// x0 = EventHandle* (out), x1 = DesiredAccess, x2 = ObjectAttributes*
// x3 = EventType (0=Notification, 1=Sync), x4 = InitialState

// ── NtCreateFile ──────────────────────────────────────────────
// x0=*FileHandle, x1=DesiredAccess, x2=ObjectAttributes, x3=*IoStatusBlock
// x7=CreateDisposition

fn handle_create_file(frame: &mut SvcFrame) {
    let out_ptr = frame.x[0] as *mut u64;
    let access = frame.x[1] as u32;
    let oa_ptr = frame.x[2];
    let iosb_ptr = frame.x[3] as *mut IoStatusBlock;
    let disposition = frame.x[7] as u32;
    let mut path_buf = [0u8; 512];
    let path_len = read_oa_path(oa_ptr, &mut path_buf);
    if path_len == 0 {
        write_iosb(iosb_ptr, status::OBJECT_NAME_NOT_FOUND, 0);
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    let path = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => {
            write_iosb(iosb_ptr, status::INVALID_PARAMETER, 0);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
    };
    let fd = hypercall::host_open(path, map_open_flags(access, disposition));
    if fd == u64::MAX {
        write_iosb(iosb_ptr, status::OBJECT_NAME_NOT_FOUND, 0);
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    let idx = match file_alloc(fd) {
        Some(v) => v,
        None => {
            hypercall::host_close(fd);
            write_iosb(iosb_ptr, status::NO_MEMORY, 0);
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(make_handle(HANDLE_TYPE_FILE, idx)); }
    }
    write_iosb(iosb_ptr, status::SUCCESS, 0);
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtOpenFile ────────────────────────────────────────────────
// x0=*FileHandle, x1=DesiredAccess, x2=ObjectAttributes, x3=*IoStatusBlock

fn handle_open_file(frame: &mut SvcFrame) {
    frame.x[7] = FILE_OPEN as u64;
    handle_create_file(frame);
}

fn handle_create_event(frame: &mut SvcFrame) {
    let ev_type = if frame.x[3] == 1 {
        EventType::SynchronizationEvent
    } else {
        EventType::NotificationEvent
    };
    let initial = frame.x[4] != 0;
    match event_alloc(ev_type, initial) {
        Some(idx) => {
            let h = make_handle(HANDLE_TYPE_EVENT, idx);
            // Write handle to *EventHandle (x0 = pointer)
            let out_ptr = frame.x[0] as *mut u64;
            unsafe { out_ptr.write_volatile(h); }
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        None => { frame.x[0] = 0xC000_0017u64; } // STATUS_INSUFFICIENT_RESOURCES
    }
}

// ── NtWriteFile ───────────────────────────────────────────────
// x0=FileHandle, x4=IoStatusBlock*, x5=Buffer, x6=Length, x7=ByteOffset*

fn handle_write_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    let buf = frame.x[5] as *const u8;
    let len = frame.x[6] as usize;
    let byte_offset_ptr = frame.x[7] as *const u64;

    let host_fd = match file_handle_to_host_fd(file_handle) {
        Some(fd) => fd,
        None => {
            write_iosb(iosb_ptr, status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let offset = if byte_offset_ptr.is_null() {
        u64::MAX
    } else {
        unsafe { byte_offset_ptr.read_volatile() }
    };

    let written = hypercall::host_write(host_fd, buf, len, offset) as u64;
    write_iosb(iosb_ptr, status::SUCCESS, written);
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtReadFile ────────────────────────────────────────────────
// x0=FileHandle, x4=IoStatusBlock*, x5=Buffer, x6=Length, x7=ByteOffset*

fn handle_read_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    let buf = frame.x[5] as *mut u8;
    let len = frame.x[6] as usize;
    let byte_offset_ptr = frame.x[7] as *const u64;

    let host_fd = match file_handle_to_host_fd(file_handle) {
        Some(fd) => fd,
        None => {
            write_iosb(iosb_ptr, status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let offset = if byte_offset_ptr.is_null() {
        u64::MAX
    } else {
        unsafe { byte_offset_ptr.read_volatile() }
    };
    let read = hypercall::host_read(host_fd, buf, len, offset) as u64;
    let st = if read == 0 && len != 0 {
        status::END_OF_FILE
    } else {
        status::SUCCESS
    };
    write_iosb(iosb_ptr, st, read);
    frame.x[0] = st as u64;
}

// ── NtQueryInformationFile ────────────────────────────────────
// x0=FileHandle, x1=*IoStatusBlock, x2=FileInformation, x3=Length, x4=Class

fn handle_query_information_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[1] as *mut IoStatusBlock;
    let out_ptr = frame.x[2] as *mut u8;
    let out_len = frame.x[3] as usize;
    let info_class = frame.x[4] as u32;
    let host_fd = match file_handle_to_host_fd(file_handle) {
        Some(fd) => fd,
        None => {
            write_iosb(iosb_ptr, status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };
    if info_class == 5 {
        if out_ptr.is_null() || out_len < 24 {
            write_iosb(iosb_ptr, status::INFO_LENGTH_MISMATCH, 0);
            frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
            return;
        }
        let size = if host_fd <= 2 {
            0u64
        } else {
            hypercall::host_stat(host_fd)
        };
        let mut info = [0u8; 24];
        info[0..8].copy_from_slice(&size.to_le_bytes()); // AllocationSize
        info[8..16].copy_from_slice(&size.to_le_bytes()); // EndOfFile
        info[16..20].copy_from_slice(&1u32.to_le_bytes()); // NumberOfLinks
        unsafe { core::ptr::copy_nonoverlapping(info.as_ptr(), out_ptr, 24); }
        write_iosb(iosb_ptr, status::SUCCESS, 24);
        frame.x[0] = status::SUCCESS as u64;
        return;
    }
    if !out_ptr.is_null() && out_len != 0 {
        unsafe { core::ptr::write_bytes(out_ptr, 0, out_len); }
    }
    write_iosb(iosb_ptr, status::SUCCESS, 0);
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtSetInformationFile ──────────────────────────────────────

fn handle_set_information_file(frame: &mut SvcFrame) {
    let iosb_ptr = frame.x[1] as *mut IoStatusBlock;
    write_iosb(iosb_ptr, status::SUCCESS, 0);
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtQueryDirectoryFile ──────────────────────────────────────

fn handle_query_directory_file(frame: &mut SvcFrame) {
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    write_iosb(iosb_ptr, status::NO_MORE_FILES, 0);
    frame.x[0] = status::NO_MORE_FILES as u64;
}

// ── NtSetEvent ────────────────────────────────────────────────
// x0 = EventHandle, x1 = PreviousState* (optional, can be NULL)

fn handle_set_event(frame: &mut SvcFrame) {
    let h = frame.x[0];
    if sync::handle_type(h) != HANDLE_TYPE_EVENT {
        frame.x[0] = sync::STATUS_INVALID_HANDLE as u64;
        return;
    }
    frame.x[0] = event_set(sync::handle_idx(h)) as u64;
}

// ── NtResetEvent ──────────────────────────────────────────────

fn handle_reset_event(frame: &mut SvcFrame) {
    let h = frame.x[0];
    if sync::handle_type(h) != HANDLE_TYPE_EVENT {
        frame.x[0] = sync::STATUS_INVALID_HANDLE as u64;
        return;
    }
    frame.x[0] = event_reset(sync::handle_idx(h)) as u64;
}

// ── NtWaitForSingleObject ─────────────────────────────────────
// x0 = Handle, x1 = Alertable, x2 = Timeout* (LARGE_INTEGER*)

fn handle_wait_single(frame: &mut SvcFrame) {
    let h        = frame.x[0];
    let timeout_ptr = frame.x[2] as *const i64;
    let deadline = if timeout_ptr.is_null() {
        0u64 // wait forever
    } else {
        let rel = unsafe { timeout_ptr.read_volatile() };
        // Guest scheduler currently treats deadline as monotonic ticks.
        // For now we keep relative values as durations and absolute values
        // as raw deadlines; timeout scanning is handled by check_timeouts().
        if rel < 0 { (-rel) as u64 } else { rel as u64 }
    };

    frame.x[0] = wait_handle(h, deadline) as u64;
}

// ── NtWaitForMultipleObjects ──────────────────────────────────
// Minimal guest implementation: sequential wait on first handle.

fn handle_wait_multiple(frame: &mut SvcFrame) {
    let count = frame.x[0] as usize;
    let arr = frame.x[1] as *const u64;
    if arr.is_null() || count == 0 || count > 64 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let first = unsafe { arr.read_volatile() };
    frame.x[0] = wait_handle(first, 0) as u64;
}

// ── NtAllocateVirtualMemory ──────────────────────────────────
// x1=*BaseAddress, x3=*RegionSize, x5=Protect

fn handle_allocate_virtual_memory(frame: &mut SvcFrame) {
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

    let base = match vm_alloc_region(size, prot) {
        Some(v) => v,
        None => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };
    if !base_ptr.is_null() {
        unsafe { base_ptr.write_volatile(base); }
    }
    unsafe { size_ptr.write_volatile(size); }
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtFreeVirtualMemory ──────────────────────────────────────
// x1=*BaseAddress

fn handle_free_virtual_memory(frame: &mut SvcFrame) {
    let base_ptr = frame.x[1] as *const u64;
    if base_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let base = unsafe { base_ptr.read_volatile() };
    let _ = vm_free_region(base);
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtProtectVirtualMemory ───────────────────────────────────
// x1=*BaseAddress, x3=NewProtect, x4=*OldProtect

fn handle_protect_virtual_memory(frame: &mut SvcFrame) {
    let base_ptr = frame.x[1] as *const u64;
    let old_ptr = frame.x[4] as *mut u32;
    if base_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let base = unsafe { base_ptr.read_volatile() };
    if let Some((idx, region)) = vm_find_region(base) {
        if !old_ptr.is_null() {
            unsafe { old_ptr.write_volatile(region.prot); }
        }
        unsafe { VM_REGIONS[idx].prot = frame.x[3] as u32; }
    } else if !old_ptr.is_null() {
        unsafe { old_ptr.write_volatile(0); }
    }
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtQueryVirtualMemory ─────────────────────────────────────
// x1=BaseAddress, x3=Buffer, x4=BufferSize, x5=*ReturnLength

fn handle_query_virtual_memory(frame: &mut SvcFrame) {
    let addr = frame.x[1];
    let buf = frame.x[3] as *mut u8;
    let buf_len = frame.x[4] as usize;
    let ret_len_ptr = frame.x[5] as *mut u64;
    if buf_len < 48 || buf.is_null() {
        frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
        return;
    }

    let (base, size, prot, state) = if let Some((_, r)) = vm_find_region(addr) {
        (r.base, r.size, r.prot, MEM_COMMIT)
    } else {
        (addr & !0xFFF, 0x1000, 0u32, 0u32)
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
        unsafe { ret_len_ptr.write_volatile(48); }
    }
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtCreateSection ──────────────────────────────────────────
// x0=*SectionHandle, x3=*MaximumSize, x4=Protection, x6=FileHandle

fn handle_create_section(frame: &mut SvcFrame) {
    let out_ptr = frame.x[0] as *mut u64;
    let max_size_ptr = frame.x[3] as *const u64;
    let prot = frame.x[4] as u32;
    let file_handle = frame.x[6];
    let size = if max_size_ptr.is_null() {
        0x1000
    } else {
        align_up_4k(unsafe { max_size_ptr.read_volatile().max(0x1000) })
    };

    let idx = match section_alloc(size, prot, file_handle) {
        Some(i) => i,
        None => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };
    let handle = make_handle(HANDLE_TYPE_SECTION, idx);
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(handle); }
    }
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtMapViewOfSection ───────────────────────────────────────
// x0=SectionHandle, x2=*BaseAddress, x5=*SectionOffset, x6=*ViewSize
// stack[0]=AllocationType, stack[1]=Win32Protect

fn handle_map_view_of_section(frame: &mut SvcFrame) {
    let h = frame.x[0];
    if sync::handle_type(h) != HANDLE_TYPE_SECTION {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
    let sec = match section_get(sync::handle_idx(h)) {
        Some(s) => s,
        None => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let base_ptr = frame.x[2] as *mut u64;
    let view_size_ptr = frame.x[6] as *mut u64;
    let _offset_ptr = frame.x[5] as *const u64;
    let win32_protect = unsafe { (frame.sp_el0 as *const u64).add(1).read_volatile() } as u32;

    let req_size = if view_size_ptr.is_null() {
        0
    } else {
        unsafe { view_size_ptr.read_volatile() }
    };
    let map_size = align_up_4k(if req_size == 0 { sec.size } else { req_size }.max(0x1000));
    let prot = if win32_protect == 0 { sec.prot } else { win32_protect };

    let base = match vm_alloc_region(map_size, prot) {
        Some(v) => v,
        None => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };

    // File-backed section support is temporary: only guest-managed file handles.
    if sec.file_handle != 0 && sync::handle_type(sec.file_handle) == HANDLE_TYPE_FILE {
        if let Some(fd) = file_host_fd(sync::handle_idx(sec.file_handle)) {
            let _ = hypercall::host_read(fd, base as *mut u8, map_size as usize, 0);
        }
    }

    if !view_alloc(base, map_size) {
        let _ = vm_free_region(base);
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    }

    if !base_ptr.is_null() {
        unsafe { base_ptr.write_volatile(base); }
    }
    if !view_size_ptr.is_null() {
        unsafe { view_size_ptr.write_volatile(map_size); }
    }
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtUnmapViewOfSection ─────────────────────────────────────
// x1=BaseAddress

fn handle_unmap_view_of_section(frame: &mut SvcFrame) {
    let base = frame.x[1];
    let _ = view_free(base);
    let _ = vm_free_region(base);
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtQueryInformationProcess ────────────────────────────────
// x1=ProcessInformationClass, x2=Buffer, x3=BufferLength, x4=*ReturnLength

fn handle_query_information_process(frame: &mut SvcFrame) {
    let info_class = frame.x[1] as u32;
    let buf = frame.x[2] as *mut u8;
    let buf_len = frame.x[3] as usize;
    let ret_len = frame.x[4] as *mut u32;

    match info_class {
        0 => {
            // PROCESS_BASIC_INFORMATION (48 bytes)
            if buf.is_null() || buf_len < 48 {
                if !ret_len.is_null() {
                    unsafe { ret_len.write_volatile(48); }
                }
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            let mut pbi = [0u8; 48];
            pbi[8..16].copy_from_slice(&0u64.to_le_bytes()); // PEB base (best-effort)
            pbi[16..24].copy_from_slice(&1u64.to_le_bytes()); // AffinityMask
            pbi[24..28].copy_from_slice(&8i32.to_le_bytes()); // BasePriority
            pbi[32..40].copy_from_slice(&1u64.to_le_bytes()); // UniqueProcessId
            pbi[40..48].copy_from_slice(&0u64.to_le_bytes()); // InheritedFrom
            unsafe { core::ptr::copy_nonoverlapping(pbi.as_ptr(), buf, 48); }
            if !ret_len.is_null() {
                unsafe { ret_len.write_volatile(48); }
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        27 => {
            // ProcessImageFileName: minimal empty UNICODE_STRING
            if buf.is_null() || buf_len < 16 {
                if !ret_len.is_null() {
                    unsafe { ret_len.write_volatile(16); }
                }
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            unsafe { core::ptr::write_bytes(buf, 0, 16); }
            if !ret_len.is_null() {
                unsafe { ret_len.write_volatile(16); }
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

// ── NtQueryInformationThread ──────────────────────────────────
// x1=ThreadInformationClass, x2=Buffer, x3=BufferLength, x4=*ReturnLength

fn handle_query_information_thread(frame: &mut SvcFrame) {
    let info_class = frame.x[1] as u32;
    let buf = frame.x[2] as *mut u8;
    let buf_len = frame.x[3] as usize;
    let ret_len = frame.x[4] as *mut u32;
    match info_class {
        0 => {
            if buf.is_null() || buf_len < 48 {
                if !ret_len.is_null() {
                    unsafe { ret_len.write_volatile(48); }
                }
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            let tid = current_tid() as u64;
            let teb = with_thread(current_tid(), |t| t.teb_va);
            let mut tbi = [0u8; 48];
            tbi[8..16].copy_from_slice(&teb.to_le_bytes());
            tbi[16..24].copy_from_slice(&1u64.to_le_bytes());
            tbi[24..32].copy_from_slice(&tid.to_le_bytes());
            tbi[32..40].copy_from_slice(&1u64.to_le_bytes());
            tbi[40..44].copy_from_slice(&8i32.to_le_bytes());
            tbi[44..48].copy_from_slice(&8i32.to_le_bytes());
            unsafe { core::ptr::copy_nonoverlapping(tbi.as_ptr(), buf, 48); }
            if !ret_len.is_null() {
                unsafe { ret_len.write_volatile(48); }
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

// ── NtSetInformationThread ────────────────────────────────────

fn handle_set_information_thread(frame: &mut SvcFrame) {
    let _ = frame.x[1];
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtDuplicateObject ────────────────────────────────────────
// x1=SourceHandle, x3=*TargetHandle

fn handle_duplicate_object(frame: &mut SvcFrame) {
    let src = frame.x[1];
    let out_ptr = frame.x[3] as *mut u64;
    let htype = sync::handle_type(src);
    if htype == 0 {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
    unsafe {
        let dup = src | ((DUP_TAG & 0xFFFF_FFFF) << 16);
        DUP_TAG = DUP_TAG.wrapping_add(1);
        if !out_ptr.is_null() {
            out_ptr.write_volatile(dup);
        }
    }
    frame.x[0] = status::SUCCESS as u64;
}

// ── NtCreateMutant ────────────────────────────────────────────
// x0 = MutantHandle* (out), x1 = DesiredAccess, x2 = ObjAttr*
// x3 = InitialOwner (bool)

fn handle_create_mutex(frame: &mut SvcFrame) {
    let initial_owner = frame.x[3] != 0;
    match mutex_alloc(initial_owner) {
        Some(idx) => {
            let h = make_handle(HANDLE_TYPE_MUTEX, idx);
            let out_ptr = frame.x[0] as *mut u64;
            unsafe { out_ptr.write_volatile(h); }
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        None => { frame.x[0] = 0xC000_0017u64; }
    }
}

// ── NtReleaseMutant ───────────────────────────────────────────
// x0 = MutantHandle, x1 = PreviousCount* (optional)

fn handle_release_mutant(frame: &mut SvcFrame) {
    let h = frame.x[0];
    if sync::handle_type(h) != HANDLE_TYPE_MUTEX {
        frame.x[0] = sync::STATUS_INVALID_HANDLE as u64;
        return;
    }
    frame.x[0] = mutex_release(sync::handle_idx(h)) as u64;
}

// ── NtCreateSemaphore ─────────────────────────────────────────
// x0 = SemaphoreHandle* (out), x1 = DesiredAccess, x2 = ObjAttr*
// x3 = InitialCount, x4 = MaximumCount

fn handle_create_semaphore(frame: &mut SvcFrame) {
    let initial = frame.x[3] as i32;
    let maximum = frame.x[4] as i32;
    match semaphore_alloc(initial, maximum) {
        Some(idx) => {
            let h = make_handle(HANDLE_TYPE_SEMAPHORE, idx);
            let out_ptr = frame.x[0] as *mut u64;
            unsafe { out_ptr.write_volatile(h); }
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        None => { frame.x[0] = 0xC000_0017u64; }
    }
}

// ── NtReleaseSemaphore ────────────────────────────────────────
// x0 = SemaphoreHandle, x1 = ReleaseCount, x2 = PreviousCount* (opt)

fn handle_release_semaphore(frame: &mut SvcFrame) {
    let h     = frame.x[0];
    let count = frame.x[1] as i32;
    if sync::handle_type(h) != HANDLE_TYPE_SEMAPHORE {
        frame.x[0] = sync::STATUS_INVALID_HANDLE as u64;
        return;
    }
    let prev = semaphore_release(sync::handle_idx(h), count);
    if let Some(ptr) = unsafe { (frame.x[2] as *mut u32).as_mut() } {
        unsafe { (ptr as *mut u32).write_volatile(prev); }
    }
    frame.x[0] = if prev & 0x8000_0000 != 0 { prev as u64 } else { STATUS_SUCCESS as u64 };
}

// ── NtClose ───────────────────────────────────────────────────

fn handle_close(frame: &mut SvcFrame) {
    let h = frame.x[0];
    if h == STD_INPUT_HANDLE || h == STD_OUTPUT_HANDLE || h == STD_ERROR_HANDLE {
        frame.x[0] = STATUS_SUCCESS as u64;
        return;
    }
    // Only close handles we own; others forward to VMM
    let htype = sync::handle_type(h);
    if htype == HANDLE_TYPE_EVENT
        || htype == HANDLE_TYPE_MUTEX
        || htype == HANDLE_TYPE_SEMAPHORE
        || htype == HANDLE_TYPE_THREAD
    {
        frame.x[0] = close_handle(h) as u64;
    } else if htype == HANDLE_TYPE_FILE {
        file_free(sync::handle_idx(h));
        frame.x[0] = STATUS_SUCCESS as u64;
    } else if htype == HANDLE_TYPE_SECTION {
        section_free(sync::handle_idx(h));
        frame.x[0] = STATUS_SUCCESS as u64;
    } else {
        forward_to_vmm(frame, NR_CLOSE, 0);
    }
}

// ── NtYieldExecution ──────────────────────────────────────────

fn handle_yield(frame: &mut SvcFrame) {
    // Mark current thread as Ready so schedule() will pick another thread.
    // maybe_preempt (called by svc_dispatch) will do the actual switch.
    let cur = current_tid();
    with_thread_mut(cur, |t| {
        if t.state == ThreadState::Running {
            t.state = ThreadState::Ready;
            unsafe { (*crate::sched::SCHED.ready.get()).push(t); }
        }
    });
    frame.x[0] = STATUS_SUCCESS as u64;
}

// ── NtCreateThreadEx / NtCreateThread ────────────────────────
// NtCreateThreadEx:
// x0=ThreadHandle*(out), x4=StartRoutine, x5=Argument, x6=CreateFlags
// stack[0]=StackSize, stack[1]=MaxStackSize, stack[2]=AttributeList

fn handle_create_thread(frame: &mut SvcFrame) {
    let out_ptr = frame.x[0] as *mut u64;
    let entry_va = frame.x[4];
    let arg = frame.x[5];
    let create_flags = frame.x[6] as u32;
    let _stack_size_arg = unsafe { (frame.sp_el0 as *const u64).read_volatile() };
    let max_stack_size_arg = unsafe { (frame.sp_el0 as *const u64).add(2).read_volatile() };
    let stack_size = if max_stack_size_arg == 0 {
        0x10000u64
    } else {
        (max_stack_size_arg + 0xFFFF) & !0xFFFF
    };

    if entry_va == 0 {
        frame.x[0] = 0xC000_000Du64; // STATUS_INVALID_PARAMETER
        return;
    }

    let stack_base = match crate::alloc::alloc_zeroed(stack_size as usize, 0x10000) {
        Some(p) => p as u64,
        None => {
            frame.x[0] = 0xC000_0017u64; // STATUS_INSUFFICIENT_RESOURCES
            return;
        }
    };
    let stack_top = stack_base + stack_size;
    let teb_va = crate::alloc::alloc_zeroed(0x1000, 0x1000).map_or(0, |p| p as u64);

    let tid = spawn(entry_va, stack_top, arg, teb_va, 8);
    if tid == 0 {
        frame.x[0] = 0xC000_0017u64; // STATUS_INSUFFICIENT_RESOURCES
        return;
    }
    let handle = make_handle(HANDLE_TYPE_THREAD, tid as u16);
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(handle); }
    }
    // CREATE_SUSPENDED (0x1) currently ignored; thread is created runnable.
    let _ = create_flags;
    frame.x[0] = STATUS_SUCCESS as u64;
}

// ── NtTerminateThread ─────────────────────────────────────────

fn handle_terminate_thread(frame: &mut SvcFrame) {
    let cur = current_tid();
    with_thread_mut(cur, |t| t.state = ThreadState::Terminated);
    // maybe_preempt will pick the next thread (or WFI if none)
    frame.x[0] = STATUS_SUCCESS as u64;
}

// ── NtCreateProcessEx ─────────────────────────────────────────

fn handle_create_process(frame: &mut SvcFrame) {
    let _ = frame.x[0];
    frame.x[0] = status::NOT_IMPLEMENTED as u64;
}

// ── NtTerminateProcess ────────────────────────────────────────
// x0 = ProcessHandle, x1 = ExitStatus

fn handle_terminate_process(frame: &mut SvcFrame) {
    let code = frame.x[1] as u32;
    hypercall::process_exit(code);
}

// ── EL1 fault handler ─────────────────────────────────────────

#[no_mangle]
pub extern "C" fn el1_fault_dispatch(frame: &mut SvcFrame) {
    let esr: u64;
    let far: u64;
    unsafe {
        core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nostack, nomem));
        core::arch::asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
    }
    hypercall::debug_u64(0xE100_0000_0000_0000 | esr);
    hypercall::debug_u64(0xE102_0000_0000_0000 | far);
    hypercall::debug_u64(0xE103_0000_0000_0000 | frame.elr);
    hypercall::debug_u64(0xE104_0000_0000_0000 | frame.spsr);
    hypercall::process_exit(0xE1);
}

// ── EL0 fault handler ─────────────────────────────────────────

#[no_mangle]
pub extern "C" fn el0_fault_dispatch(frame: &mut SvcFrame) {
    let esr: u64;
    let far: u64;
    unsafe {
        core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nostack, nomem));
        core::arch::asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
    }
    hypercall::debug_u64(0xFA01_0000_0000_0000 | esr);
    hypercall::debug_u64(0xFA02_0000_0000_0000 | far);
    hypercall::debug_u64(0xFA03_0000_0000_0000 | frame.elr);
    hypercall::debug_u64(0xFA04_0000_0000_0000 | frame.spsr);
    hypercall::process_exit(0xFF);
}

// ── VMM 转发 ──────────────────────────────────────────────────

fn forward_to_vmm(frame: &mut SvcFrame, nr: u16, table: u8) {
    // VMM (vcpu.rs) reads:
    // x0=NT_SYSCALL, x9=syscall_nr, x10=table_nr, x11=orig_x0, x12=SvcFrame*
    // x1-x7 pass remaining args as-is (VMM reads x1..x7 directly)
    let ret = unsafe {
        let mut r: u64;
        core::arch::asm!(
            "hvc #0",
            inout("x0") winemu_shared::nr::NT_SYSCALL => r,
            in("x1") frame.x[1],
            in("x2") frame.x[2],
            in("x3") frame.x[3],
            in("x4") frame.x[4],
            in("x5") frame.x[5],
            in("x6") frame.x[6],
            in("x7") frame.x[7],
            in("x9") nr as u64,
            in("x10") table as u64,
            in("x11") frame.x[0],
            in("x12") frame as *const SvcFrame as u64,
            options(nostack)
        );
        r
    };
    frame.x[0] = ret;
}
