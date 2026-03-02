// TEB / PEB 初始化 — 在 Guest 内存中构建最小 NT 线程/进程环境块
// 参考: Wine dlls/ntdll/unix/signal_arm64.c call_init_thunk
//       Wine dlls/ntdll/unix/virtual.c init_teb / init_peb

use crate::mm::vaspace::VmaType;
use crate::nt::constants::PAGE_SIZE_4K;
use crate::nt::state::{vm_alloc_region_typed, vm_free_region, vm_make_guard_page};
use winemu_shared::{peb, teb};

/// 已初始化的 TEB/PEB 描述符
pub struct TebPeb {
    pub teb_va: u64,
    pub peb_va: u64,
    /// 栈顶（StackBase，高地址）
    pub stack_base: u64,
    /// 栈底（StackLimit，低地址）
    pub stack_limit: u64,
}

/// 写 u64 到 buf[offset]（小端）
#[inline(always)]
fn wu64(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

/// 写 u32 到 buf[offset]（小端）
#[inline(always)]
fn wu32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

/// 写 u16 到 buf[offset]（小端）
#[inline(always)]
fn wu16(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

/// RTL_USER_PROCESS_PARAMETERS 最小布局（64-bit）
/// 只填写 loader 和 CRT 启动代码会读的字段
mod upp {
    /// 结构体总大小（分配 1 页）
    pub const SIZE: usize = 0x1000;

    // 字段偏移（参考 Wine/ReactOS winternl.h）
    pub const MAXIMUM_LENGTH:    usize = 0x0000; // u32
    pub const LENGTH:            usize = 0x0004; // u32
    pub const FLAGS:             usize = 0x0008; // u32  (1 = normalized)
    pub const DEBUG_FLAGS:       usize = 0x000C; // u32
    pub const CONSOLE_HANDLE:    usize = 0x0010; // u64
    pub const CONSOLE_FLAGS:     usize = 0x0018; // u32
    // UNICODE_STRING = { Length u16, MaxLength u16, pad u32, Buffer u64 }
    pub const IMAGE_PATH_NAME:   usize = 0x0060; // UNICODE_STRING (16 bytes)
    pub const COMMAND_LINE:      usize = 0x0070; // UNICODE_STRING (16 bytes)
    pub const ENVIRONMENT:       usize = 0x0080; // u64 pointer (NULL ok)
    pub const CURRENT_DIR_PATH:  usize = 0x0038; // UNICODE_STRING (16 bytes)
    /// 字符串数据区起始偏移（紧跟在固定字段之后）
    pub const STR_DATA_OFF:      usize = 0x0200;
}

/// LDR_DATA_TABLE_ENTRY 最小布局（64-bit）
/// 参考 Wine/ReactOS ntdll/ldr.c
mod ldr_entry {
    pub const SIZE:              usize = 0x0120; // 保守分配
    // LIST_ENTRY InLoadOrderLinks (+0x00)
    pub const IN_LOAD_ORDER:     usize = 0x0000; // Flink+8, Blink+8
    // LIST_ENTRY InMemoryOrderLinks (+0x10)
    pub const IN_MEMORY_ORDER:   usize = 0x0010;
    // LIST_ENTRY InInitializationOrderLinks (+0x20)
    pub const IN_INIT_ORDER:     usize = 0x0020;
    pub const DLL_BASE:          usize = 0x0030; // u64
    pub const ENTRY_POINT:       usize = 0x0038; // u64
    pub const SIZE_OF_IMAGE:     usize = 0x0040; // u32
    // FullDllName UNICODE_STRING (+0x48)
    pub const FULL_DLL_NAME:     usize = 0x0048; // {u16 len, u16 maxlen, u32 pad, u64 buf}
    // BaseDllName UNICODE_STRING (+0x58)
    pub const BASE_DLL_NAME:     usize = 0x0058;
    pub const FLAGS:             usize = 0x0068; // u32
    pub const LOAD_COUNT:        usize = 0x006c; // u16
    pub const TLS_INDEX:         usize = 0x006e; // u16
}

/// PEB_LDR_DATA 布局（64-bit）
mod ldr_data {
    pub const SIZE:              usize = 0x0058;
    pub const LENGTH:            usize = 0x0000; // u32
    pub const INITIALIZED:       usize = 0x0004; // u32
    // InLoadOrderModuleList LIST_ENTRY (+0x10)
    pub const IN_LOAD_ORDER:     usize = 0x0010;
    // InMemoryOrderModuleList LIST_ENTRY (+0x20)
    pub const IN_MEMORY_ORDER:   usize = 0x0020;
    // InInitializationOrderModuleList LIST_ENTRY (+0x30)
    pub const IN_INIT_ORDER:     usize = 0x0030;
}

/// ProcessParameters 里标准句柄偏移
mod upp_handles {
    pub const STANDARD_INPUT:    usize = 0x0020; // u64
    pub const STANDARD_OUTPUT:   usize = 0x0028; // u64
    pub const STANDARD_ERROR:    usize = 0x0030; // u64
}

/// 写一个循环链表头（Flink = Blink = self_va + offset）
fn write_list_head(buf: &mut [u8], offset: usize, self_va: u64) {
    let ptr = self_va + offset as u64;
    wu64(buf, offset,     ptr); // Flink
    wu64(buf, offset + 8, ptr); // Blink
}

/// 把 entry_va 插入以 head_va 为头的双向链表（在头部之前，即尾插）
/// head_buf: 链表头所在内存（PEB_LDR_DATA）
/// entry_buf: 新节点所在内存
/// head_list_off: 链表头在 head_buf 中的偏移
/// entry_list_off: 链表指针在 entry_buf 中的偏移
fn list_insert_tail(
    head_buf:      &mut [u8],
    head_va:       u64,
    head_list_off: usize,
    entry_buf:     &mut [u8],
    entry_va:      u64,
    entry_list_off: usize,
) {
    // 读当前 Blink（尾节点）
    let blink_ptr = {
        let b = &head_buf[head_list_off + 8..head_list_off + 16];
        u64::from_le_bytes(b.try_into().unwrap())
    };
    let entry_ptr = entry_va + entry_list_off as u64;
    let head_ptr  = head_va  + head_list_off  as u64;

    // entry.Flink = head
    wu64(entry_buf, entry_list_off,     head_ptr);
    // entry.Blink = old_blink
    wu64(entry_buf, entry_list_off + 8, blink_ptr);

    // head.Blink = entry
    wu64(head_buf, head_list_off + 8, entry_ptr);

    // old_blink.Flink = entry
    if blink_ptr == head_ptr {
        wu64(head_buf, head_list_off, entry_ptr);
    } else {
        unsafe {
            (blink_ptr as *mut u64).write_volatile(entry_ptr);
        }
    }
}

fn init_ldr_entry(
    entry_buf: &mut [u8],
    entry_va: u64,
    dll_base: u64,
    size_of_image: u32,
    entry_point: u64,
    full_name: &str,
    base_name: &str,
) {
    wu64(entry_buf, ldr_entry::DLL_BASE, dll_base);
    wu64(entry_buf, ldr_entry::ENTRY_POINT, entry_point);
    wu32(entry_buf, ldr_entry::SIZE_OF_IMAGE, size_of_image);
    wu32(entry_buf, ldr_entry::FLAGS, 0x0004);
    wu16(entry_buf, ldr_entry::LOAD_COUNT, 0xFFFF);

    let name_data_off = 0x100usize;
    let mut full_off = name_data_off;
    let full_va = write_utf16(entry_buf, &mut full_off, full_name, entry_va);
    let full_len = (full_name.len() * 2) as u16;
    wu16(entry_buf, ldr_entry::FULL_DLL_NAME, full_len);
    wu16(entry_buf, ldr_entry::FULL_DLL_NAME + 2, full_len + 2);
    wu64(entry_buf, ldr_entry::FULL_DLL_NAME + 8, full_va);

    let mut base_off = full_off;
    let base_va = write_utf16(entry_buf, &mut base_off, base_name, entry_va);
    let base_len = (base_name.len() * 2) as u16;
    wu16(entry_buf, ldr_entry::BASE_DLL_NAME, base_len);
    wu16(entry_buf, ldr_entry::BASE_DLL_NAME + 2, base_len + 2);
    wu64(entry_buf, ldr_entry::BASE_DLL_NAME + 8, base_va);
}

pub fn init(
    image_base: u64,
    pid: u32,
    tid: u32,
    stack_reserve: u64,
    stack_commit: u64,
    image_path: &str,
    cmdline: &str,
) -> Option<TebPeb> {
    let stack_size = align_up(stack_reserve.max(0x10_0000), 0x10000) as usize;
    let max_commit = (stack_size as u64).saturating_sub(PAGE_SIZE_4K);
    let mut commit_size = align_up(stack_commit.max(PAGE_SIZE_4K), PAGE_SIZE_4K);
    if commit_size > max_commit {
        commit_size = max_commit.max(PAGE_SIZE_4K);
    }
    let mut allocated = [0u64; 128];
    let mut allocated_count = 0usize;
    let stack_reserve_base = match alloc_user_region(
        pid,
        stack_size,
        VmaType::ThreadStack,
        &mut allocated,
        &mut allocated_count,
    ) {
        Some(v) => v,
        None => return None,
    };
    let stack_base = stack_reserve_base + stack_size as u64;
    let mut stack_limit = stack_base.saturating_sub(commit_size);
    if stack_limit <= stack_reserve_base {
        stack_limit = stack_reserve_base.saturating_add(PAGE_SIZE_4K);
    }
    let guard_page = stack_limit.saturating_sub(PAGE_SIZE_4K);
    if guard_page < stack_reserve_base || !vm_make_guard_page(pid, guard_page) {
        free_user_regions(pid, &allocated, allocated_count);
        return None;
    }

    let peb_va = match alloc_user_region(
        pid,
        peb::SIZE,
        VmaType::Private,
        &mut allocated,
        &mut allocated_count,
    ) {
        Some(v) => v,
        None => {
            free_user_regions(pid, &allocated, allocated_count);
            return None;
        }
    };

    // Dedicated mapped page as default ProcessHeap anchor for user-mode runtime.
    let process_heap_va = match alloc_user_region(
        pid,
        0x1000,
        VmaType::Private,
        &mut allocated,
        &mut allocated_count,
    ) {
        Some(v) => v,
        None => {
            free_user_regions(pid, &allocated, allocated_count);
            return None;
        }
    };

    let teb_va = match alloc_user_region(
        pid,
        teb::SIZE,
        VmaType::Private,
        &mut allocated,
        &mut allocated_count,
    ) {
        Some(v) => v,
        None => {
            free_user_regions(pid, &allocated, allocated_count);
            return None;
        }
    };

    // ── ProcessParameters ────────────────────────────────────
    let upp_va = match alloc_user_region(
        pid,
        upp::SIZE,
        VmaType::Private,
        &mut allocated,
        &mut allocated_count,
    ) {
        Some(v) => v,
        None => {
            free_user_regions(pid, &allocated, allocated_count);
            return None;
        }
    };
    let upp_buf = unsafe { core::slice::from_raw_parts_mut(upp_va as *mut u8, upp::SIZE) };

    // 把 image_path 和 cmdline 编码为 UTF-16LE，写入字符串数据区
    let mut str_off = upp::STR_DATA_OFF;

    let img_va  = write_utf16(upp_buf, &mut str_off, image_path, upp_va);
    let img_len = (image_path.len() * 2) as u16;

    let cmd_va  = write_utf16(upp_buf, &mut str_off, cmdline, upp_va);
    let cmd_len = (cmdline.len() * 2) as u16;

    // Minimal environment block. Wine/kernelbase locale bootstrap expects
    // WINEUSERLOCALE/WINEUNIXCP to be queryable at process start.
    let env_va = upp_va + str_off as u64;
    for key_value in ["WINEUSERLOCALE=en_US", "WINEUNIXCP=65001"] {
        let _ = write_utf16(upp_buf, &mut str_off, key_value, upp_va);
    }
    // Multi-SZ terminator (extra trailing NUL).
    if str_off + 2 <= upp_buf.len() {
        upp_buf[str_off] = 0;
        upp_buf[str_off + 1] = 0;
        str_off += 2;
    }

    // 固定字段
    wu32(upp_buf, upp::MAXIMUM_LENGTH, upp::SIZE as u32);
    wu32(upp_buf, upp::LENGTH,         upp::SIZE as u32);
    wu32(upp_buf, upp::FLAGS,          1); // normalized

    // ImagePathName UNICODE_STRING
    wu16(upp_buf, upp::IMAGE_PATH_NAME,     img_len);
    wu16(upp_buf, upp::IMAGE_PATH_NAME + 2, img_len + 2);
    wu64(upp_buf, upp::IMAGE_PATH_NAME + 8, img_va);

    // CommandLine UNICODE_STRING
    wu16(upp_buf, upp::COMMAND_LINE,     cmd_len);
    wu16(upp_buf, upp::COMMAND_LINE + 2, cmd_len + 2);
    wu64(upp_buf, upp::COMMAND_LINE + 8, cmd_va);
    wu64(upp_buf, upp::ENVIRONMENT,      env_va);

    // ── PEB ──────────────────────────────────────────────────
    let peb_buf = unsafe { core::slice::from_raw_parts_mut(peb_va as *mut u8, peb::SIZE) };
    wu64(peb_buf, peb::IMAGE_BASE_ADDRESS,  image_base);
    wu64(peb_buf, peb::PROCESS_PARAMETERS,  upp_va);
    wu64(peb_buf, peb::PROCESS_HEAP,        process_heap_va);
    wu32(peb_buf, peb::OS_MAJOR_VERSION,    10);
    wu32(peb_buf, peb::OS_MINOR_VERSION,    0);
    wu32(peb_buf, peb::OS_BUILD_NUMBER,     19045);
    wu32(peb_buf, peb::OS_PLATFORM_ID,      2);

    // ── PEB_LDR_DATA ─────────────────────────────────────────
    let ldr_va = match alloc_user_region(
        pid,
        ldr_data::SIZE,
        VmaType::Private,
        &mut allocated,
        &mut allocated_count,
    ) {
        Some(v) => v,
        None => {
            free_user_regions(pid, &allocated, allocated_count);
            return None;
        }
    };
    let ldr_buf = unsafe { core::slice::from_raw_parts_mut(ldr_va as *mut u8, ldr_data::SIZE) };

    wu32(ldr_buf, ldr_data::LENGTH,      ldr_data::SIZE as u32);
    wu32(ldr_buf, ldr_data::INITIALIZED, 1);
    // 初始化三个链表头为空循环链表
    write_list_head(ldr_buf, ldr_data::IN_LOAD_ORDER,   ldr_va);
    write_list_head(ldr_buf, ldr_data::IN_MEMORY_ORDER,  ldr_va);
    write_list_head(ldr_buf, ldr_data::IN_INIT_ORDER,    ldr_va);

    // ── LDR_DATA_TABLE_ENTRY for main module ─────────────────
    let entry_va = match alloc_user_region(
        pid,
        ldr_entry::SIZE,
        VmaType::Private,
        &mut allocated,
        &mut allocated_count,
    ) {
        Some(v) => v,
        None => {
            free_user_regions(pid, &allocated, allocated_count);
            return None;
        }
    };
    let entry_buf = unsafe { core::slice::from_raw_parts_mut(entry_va as *mut u8, ldr_entry::SIZE) };

    let base_name = image_path.rfind('\\')
        .map(|i| &image_path[i+1..])
        .unwrap_or(image_path);
    init_ldr_entry(entry_buf, entry_va, image_base, 0, 0, image_path, base_name);

    // 插入三个链表
    list_insert_tail(ldr_buf, ldr_va, ldr_data::IN_LOAD_ORDER,
                     entry_buf, entry_va, ldr_entry::IN_LOAD_ORDER);
    list_insert_tail(ldr_buf, ldr_va, ldr_data::IN_MEMORY_ORDER,
                     entry_buf, entry_va, ldr_entry::IN_MEMORY_ORDER);
    list_insert_tail(ldr_buf, ldr_va, ldr_data::IN_INIT_ORDER,
                     entry_buf, entry_va, ldr_entry::IN_INIT_ORDER);

    // ── LDR_DATA_TABLE_ENTRY for preloaded DLLs ─────────────
    crate::dll::for_each_loaded(|dll_name, dll_base, dll_size, dll_entry| {
        if dll_base == 0 || dll_base == image_base {
            return;
        }

        let Some(dll_entry_va) = alloc_user_region(
            pid,
            ldr_entry::SIZE,
            VmaType::Private,
            &mut allocated,
            &mut allocated_count,
        ) else {
            return;
        };
        let dll_entry_buf = unsafe {
            core::slice::from_raw_parts_mut(dll_entry_va as *mut u8, ldr_entry::SIZE)
        };
        init_ldr_entry(
            dll_entry_buf,
            dll_entry_va,
            dll_base,
            dll_size,
            dll_entry,
            dll_name,
            dll_name,
        );

        list_insert_tail(
            ldr_buf,
            ldr_va,
            ldr_data::IN_LOAD_ORDER,
            dll_entry_buf,
            dll_entry_va,
            ldr_entry::IN_LOAD_ORDER,
        );
        list_insert_tail(
            ldr_buf,
            ldr_va,
            ldr_data::IN_MEMORY_ORDER,
            dll_entry_buf,
            dll_entry_va,
            ldr_entry::IN_MEMORY_ORDER,
        );
        list_insert_tail(
            ldr_buf,
            ldr_va,
            ldr_data::IN_INIT_ORDER,
            dll_entry_buf,
            dll_entry_va,
            ldr_entry::IN_INIT_ORDER,
        );
    });

    // PEB.Ldr = ldr_va
    wu64(peb_buf, peb::LDR, ldr_va);

    // ── 标准句柄（stdin=0, stdout=1, stderr=2 作为伪句柄）────
    // Windows 用负数句柄表示伪句柄，但 guest 的 WriteFile 会通过
    // NtWriteFile hypercall 传给 VMM，VMM 侧 FileTable 已把 fd 1/2 注册为 stdout/stderr
    wu64(upp_buf, upp_handles::STANDARD_INPUT,  0xFFFF_FFFF_FFFF_FFF6u64); // -10
    wu64(upp_buf, upp_handles::STANDARD_OUTPUT, 0xFFFF_FFFF_FFFF_FFF5u64); // -11
    wu64(upp_buf, upp_handles::STANDARD_ERROR,  0xFFFF_FFFF_FFFF_FFF4u64); // -12

    // ── TEB ──────────────────────────────────────────────────
    let teb_buf = unsafe { core::slice::from_raw_parts_mut(teb_va as *mut u8, teb::SIZE) };
    wu64(teb_buf, teb::EXCEPTION_LIST, u64::MAX);
    wu64(teb_buf, teb::STACK_BASE,     stack_base);
    wu64(teb_buf, teb::STACK_LIMIT,    stack_limit);
    wu64(teb_buf, teb::SELF,           teb_va);
    wu64(teb_buf, teb::PEB,            peb_va);
    wu64(teb_buf, teb::CLIENT_ID,      pid as u64);
    wu64(teb_buf, teb::CLIENT_ID + 8,  tid as u64);

    Some(TebPeb { teb_va, peb_va, stack_base, stack_limit })
}

fn free_user_regions(pid: u32, regions: &[u64], count: usize) {
    for i in 0..count.min(regions.len()) {
        let base = regions[i];
        if base != 0 {
            let _ = vm_free_region(pid, base);
        }
    }
}

fn alloc_user_region(
    pid: u32,
    size: usize,
    vma_type: VmaType,
    regions: &mut [u64],
    count: &mut usize,
) -> Option<u64> {
    let base = vm_alloc_region_typed(pid, 0, size as u64, 0x04, vma_type)?;
    if *count < regions.len() {
        regions[*count] = base;
        *count += 1;
        Some(base)
    } else {
        let _ = vm_free_region(pid, base);
        None
    }
}

/// 将 UTF-8 字符串编码为 UTF-16LE 写入 buf[*off..]，返回该字符串在 guest 内存中的 VA。
/// 写完后 *off 向后推进（含 NUL 终止符）。
fn write_utf16(buf: &mut [u8], off: &mut usize, s: &str, base_va: u64) -> u64 {
    let va = base_va + *off as u64;
    for ch in s.encode_utf16() {
        if *off + 2 > buf.len() { break; }
        buf[*off]     = (ch & 0xFF) as u8;
        buf[*off + 1] = (ch >> 8)   as u8;
        *off += 2;
    }
    // NUL terminator
    if *off + 2 <= buf.len() {
        buf[*off]     = 0;
        buf[*off + 1] = 0;
        *off += 2;
    }
    va
}

fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}
