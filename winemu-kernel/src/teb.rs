// TEB / PEB 初始化 — 在 Guest 内存中构建最小 NT 线程/进程环境块
// 参考: Wine dlls/ntdll/unix/signal_arm64.c call_init_thunk
//       Wine dlls/ntdll/unix/virtual.c init_teb / init_peb

use crate::mm::usercopy::{
    translate_user_va, with_current_process_user_slice, with_current_process_user_slice_mut,
    write_user_value,
};
use crate::mm::VmaType;
use crate::mm::{
    vm_alloc_region_typed, vm_free_region, vm_make_guard_page, UserVa, VM_ACCESS_READ,
    VM_ACCESS_WRITE,
};
use crate::rust_alloc::string::String;
use crate::rust_alloc::vec::Vec;
use crate::nt::constants::PAGE_SIZE_4K;
use winemu_shared::{pe, peb, teb};

/// 已初始化的 TEB/PEB 描述符
pub struct TebPeb {
    pub teb_va: u64,
    pub peb_va: u64,
    /// 栈顶（StackBase，高地址）
    pub stack_base: u64,
    /// 栈底（StackLimit，低地址）
    pub stack_limit: u64,
}

pub struct UserThreadStack {
    pub reserve_base: u64,
    pub reserve_size: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
}

const KUSER_SHARED_DATA_VA: u64 = 0x7ffe_0000;
const KUSER_SHARED_DATA_SIZE: usize = PAGE_SIZE_4K as usize;
const PERF_COUNTER_FREQUENCY_100NS: u64 = 10_000_000;
const PROCESSOR_ARCHITECTURE_ARM64: u16 = 12;
const NT_PRODUCT_WIN_NT: u32 = 1;
const DEFAULT_THREAD_STACK_RESERVE: u64 = 0x10_0000;
const THREAD_STACK_RESERVE_ALIGN: u64 = 0x1_0000;

mod kusd {
    pub const TICK_COUNT_LOW_DEPRECATED: usize = 0x000;
    pub const TICK_COUNT_MULTIPLIER: usize = 0x004;
    pub const INTERRUPT_TIME: usize = 0x008;
    pub const SYSTEM_TIME: usize = 0x014;
    pub const TIME_ZONE_BIAS: usize = 0x020;
    pub const NT_SYSTEM_ROOT: usize = 0x030;
    pub const NT_BUILD_NUMBER: usize = 0x260;
    pub const NT_PRODUCT_TYPE: usize = 0x264;
    pub const PRODUCT_TYPE_IS_VALID: usize = 0x268;
    pub const NATIVE_PROCESSOR_ARCHITECTURE: usize = 0x26a;
    pub const NT_MAJOR_VERSION: usize = 0x26c;
    pub const NT_MINOR_VERSION: usize = 0x270;
    pub const QPC_FREQUENCY: usize = 0x300;
    pub const TICK_COUNT: usize = 0x320;
    pub const COOKIE: usize = 0x330;
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

#[inline(always)]
fn wu8(buf: &mut [u8], offset: usize, val: u8) {
    buf[offset] = val;
}

fn write_ksystem_time(buf: &mut [u8], offset: usize, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    wu32(buf, offset, low);
    wu32(buf, offset + 4, high);
    wu32(buf, offset + 8, high);
}

/// RTL_USER_PROCESS_PARAMETERS 最小布局（64-bit）
/// 只填写 loader 和 CRT 启动代码会读的字段
mod upp {
    /// 结构体总大小（分配 1 页）
    pub const SIZE: usize = 0x1000;

    // 字段偏移（参考 Wine/ReactOS winternl.h）
    pub const MAXIMUM_LENGTH: usize = 0x0000; // u32
    pub const LENGTH: usize = 0x0004; // u32
    pub const FLAGS: usize = 0x0008; // u32  (1 = normalized)
    pub const DEBUG_FLAGS: usize = 0x000C; // u32
    pub const CONSOLE_HANDLE: usize = 0x0010; // u64
    pub const CONSOLE_FLAGS: usize = 0x0018; // u32
                                             // UNICODE_STRING = { Length u16, MaxLength u16, pad u32, Buffer u64 }
    pub const IMAGE_PATH_NAME: usize = 0x0060; // UNICODE_STRING (16 bytes)
    pub const COMMAND_LINE: usize = 0x0070; // UNICODE_STRING (16 bytes)
    pub const ENVIRONMENT: usize = 0x0080; // u64 pointer (NULL ok)
    pub const CURRENT_DIR_PATH: usize = 0x0038; // UNICODE_STRING (16 bytes)
    /// 字符串数据区起始偏移（紧跟在固定字段之后）
    pub const STR_DATA_OFF: usize = 0x0200;
}

/// LDR_DATA_TABLE_ENTRY 最小布局（64-bit）
/// 参考 Wine/ReactOS ntdll/ldr.c
mod ldr_entry {
    pub const SIZE: usize = 0x0120; // 保守分配
                                    // LIST_ENTRY InLoadOrderLinks (+0x00)
    pub const IN_LOAD_ORDER: usize = 0x0000; // Flink+8, Blink+8
                                             // LIST_ENTRY InMemoryOrderLinks (+0x10)
    pub const IN_MEMORY_ORDER: usize = 0x0010;
    // LIST_ENTRY InInitializationOrderLinks (+0x20)
    pub const IN_INIT_ORDER: usize = 0x0020;
    pub const DLL_BASE: usize = 0x0030; // u64
    pub const ENTRY_POINT: usize = 0x0038; // u64
    pub const SIZE_OF_IMAGE: usize = 0x0040; // u32
                                             // FullDllName UNICODE_STRING (+0x48)
    pub const FULL_DLL_NAME: usize = 0x0048; // {u16 len, u16 maxlen, u32 pad, u64 buf}
                                             // BaseDllName UNICODE_STRING (+0x58)
    pub const BASE_DLL_NAME: usize = 0x0058;
    pub const FLAGS: usize = 0x0068; // u32
    pub const LOAD_COUNT: usize = 0x006c; // u16
    pub const TLS_INDEX: usize = 0x006e; // u16
}

/// PEB_LDR_DATA 布局（64-bit）
mod ldr_data {
    pub const SIZE: usize = 0x0058;
    pub const LENGTH: usize = 0x0000; // u32
    pub const INITIALIZED: usize = 0x0004; // u32
                                           // InLoadOrderModuleList LIST_ENTRY (+0x10)
    pub const IN_LOAD_ORDER: usize = 0x0010;
    // InMemoryOrderModuleList LIST_ENTRY (+0x20)
    pub const IN_MEMORY_ORDER: usize = 0x0020;
    // InInitializationOrderModuleList LIST_ENTRY (+0x30)
    pub const IN_INIT_ORDER: usize = 0x0030;
}

/// ProcessParameters 里标准句柄偏移
mod upp_handles {
    pub const STANDARD_INPUT: usize = 0x0020; // u64
    pub const STANDARD_OUTPUT: usize = 0x0028; // u64
    pub const STANDARD_ERROR: usize = 0x0030; // u64
}

/// 写一个循环链表头（Flink = Blink = self_va + offset）
fn write_list_head(buf: &mut [u8], offset: usize, self_va: u64) {
    let ptr = self_va + offset as u64;
    wu64(buf, offset, ptr); // Flink
    wu64(buf, offset + 8, ptr); // Blink
}

/// 把 entry_va 插入以 head_va 为头的双向链表（在头部之前，即尾插）
/// head_buf: 链表头所在内存（PEB_LDR_DATA）
/// entry_buf: 新节点所在内存
/// head_list_off: 链表头在 head_buf 中的偏移
/// entry_list_off: 链表指针在 entry_buf 中的偏移
fn list_insert_tail(
    pid: u32,
    head_buf: &mut [u8],
    head_va: u64,
    head_list_off: usize,
    entry_buf: &mut [u8],
    entry_va: u64,
    entry_list_off: usize,
) -> bool {
    // 读当前 Blink（尾节点）
    let blink_ptr = {
        let b = &head_buf[head_list_off + 8..head_list_off + 16];
        let mut raw = [0u8; 8];
        raw.copy_from_slice(b);
        u64::from_le_bytes(raw)
    };
    let entry_ptr = entry_va + entry_list_off as u64;
    let head_ptr = head_va + head_list_off as u64;

    // entry.Flink = head
    wu64(entry_buf, entry_list_off, head_ptr);
    // entry.Blink = old_blink
    wu64(entry_buf, entry_list_off + 8, blink_ptr);

    // head.Blink = entry
    wu64(head_buf, head_list_off + 8, entry_ptr);

    // old_blink.Flink = entry
    if blink_ptr == head_ptr {
        wu64(head_buf, head_list_off, entry_ptr);
    } else {
        if !write_user_value(pid, blink_ptr as *mut u64, entry_ptr) {
            return false;
        }
    }
    true
}

fn with_process_user_buf_mut<R>(
    pid: u32,
    va: u64,
    size: usize,
    f: impl FnOnce(&mut [u8]) -> R,
) -> Option<R> {
    with_current_process_user_slice_mut(pid, UserVa::new(va), size, VM_ACCESS_WRITE, f)
}

fn read_ascii_cstr(bytes: &[u8], start: usize, out: &mut [u8]) -> Option<usize> {
    if start >= bytes.len() || out.is_empty() {
        return None;
    }
    let mut len = 0usize;
    let mut idx = start;
    while idx < bytes.len() && len < out.len() {
        let ch = bytes[idx];
        if ch == 0 {
            return if len == 0 { None } else { Some(len) };
        }
        out[len] = ch.to_ascii_lowercase();
        len += 1;
        idx += 1;
    }
    None
}

fn module_import_dependencies(pid: u32, base: u64, size: u32, out: &mut Vec<String>) -> bool {
    with_current_process_user_slice(
        pid,
        UserVa::new(base),
        size as usize,
        VM_ACCESS_READ,
        |image| {
            let Ok(hdrs) = pe::PeHeaders::from_slice(image) else {
                return false;
            };
            let Some(dir) = hdrs.data_dir(pe::DIR_IMPORT) else {
                return true;
            };
            if !dir.is_present() {
                return true;
            }
            let mut desc_off = dir.rva as usize;
            while desc_off + 20 <= image.len() {
                let desc = &image[desc_off..desc_off + 20];
                let orig_first_thunk = u32::from_le_bytes(desc[0..4].try_into().unwrap());
                let time_date_stamp = u32::from_le_bytes(desc[4..8].try_into().unwrap());
                let forwarder_chain = u32::from_le_bytes(desc[8..12].try_into().unwrap());
                let name_rva = u32::from_le_bytes(desc[12..16].try_into().unwrap()) as usize;
                let first_thunk = u32::from_le_bytes(desc[16..20].try_into().unwrap());
                if orig_first_thunk == 0
                    && time_date_stamp == 0
                    && forwarder_chain == 0
                    && name_rva == 0
                    && first_thunk == 0
                {
                    break;
                }
                let mut buf = [0u8; 96];
                let Some(len) = read_ascii_cstr(image, name_rva, &mut buf) else {
                    desc_off += 20;
                    continue;
                };
                let Ok(name) = core::str::from_utf8(&buf[..len]) else {
                    desc_off += 20;
                    continue;
                };
                let _ = out.try_reserve(1);
                out.push(String::from(name));
                desc_off += 20;
            }
            true
        },
    )
    .unwrap_or(false)
}

fn topo_visit_module(idx: usize, deps: &[Vec<usize>], marks: &mut [u8], out: &mut Vec<usize>) {
    if marks[idx] == 2 || marks[idx] == 1 {
        return;
    }
    marks[idx] = 1;
    for dep in deps[idx].iter().copied() {
        topo_visit_module(dep, deps, marks, out);
    }
    marks[idx] = 2;
    let _ = out.try_reserve(1);
    out.push(idx);
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
    let mut allocated = [0u64; 128];
    let mut allocated_count = 0usize;
    let stack = match alloc_thread_stack(pid, stack_reserve, stack_commit) {
        Some(stack) => stack,
        None => return None,
    };
    if allocated_count < allocated.len() {
        allocated[allocated_count] = stack.reserve_base;
        allocated_count += 1;
    } else {
        let _ = vm_free_region(pid, stack.reserve_base);
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
    let upp_ok = with_process_user_buf_mut(pid, upp_va, upp::SIZE, |upp_buf| {
        // 把 image_path 和 cmdline 编码为 UTF-16LE，写入字符串数据区
        let mut str_off = upp::STR_DATA_OFF;

        let img_va = write_utf16(upp_buf, &mut str_off, image_path, upp_va);
        let img_len = (image_path.len() * 2) as u16;

        let cmd_va = write_utf16(upp_buf, &mut str_off, cmdline, upp_va);
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
        }

        // 固定字段
        wu32(upp_buf, upp::MAXIMUM_LENGTH, upp::SIZE as u32);
        wu32(upp_buf, upp::LENGTH, upp::SIZE as u32);
        wu32(upp_buf, upp::FLAGS, 1); // normalized

        // ImagePathName UNICODE_STRING
        wu16(upp_buf, upp::IMAGE_PATH_NAME, img_len);
        wu16(upp_buf, upp::IMAGE_PATH_NAME + 2, img_len + 2);
        wu64(upp_buf, upp::IMAGE_PATH_NAME + 8, img_va);

        // CommandLine UNICODE_STRING
        wu16(upp_buf, upp::COMMAND_LINE, cmd_len);
        wu16(upp_buf, upp::COMMAND_LINE + 2, cmd_len + 2);
        wu64(upp_buf, upp::COMMAND_LINE + 8, cmd_va);
        wu64(upp_buf, upp::ENVIRONMENT, env_va);
    })
    .is_some();
    if !upp_ok {
        free_user_regions(pid, &allocated, allocated_count);
        return None;
    }

    if init_kuser_shared_data(pid, &mut allocated, &mut allocated_count).is_none() {
        free_user_regions(pid, &allocated, allocated_count);
        return None;
    }

    // ── PEB ──────────────────────────────────────────────────
    let peb_ok = with_process_user_buf_mut(pid, peb_va, peb::SIZE, |peb_buf| {
        wu64(peb_buf, peb::IMAGE_BASE_ADDRESS, image_base);
        wu64(peb_buf, peb::PROCESS_PARAMETERS, upp_va);
        wu64(peb_buf, peb::PROCESS_HEAP, process_heap_va);
        wu32(peb_buf, peb::OS_MAJOR_VERSION, 10);
        wu32(peb_buf, peb::OS_MINOR_VERSION, 0);
        wu32(peb_buf, peb::OS_BUILD_NUMBER, 19045);
        wu32(peb_buf, peb::OS_PLATFORM_ID, 2);
    })
    .is_some();
    if !peb_ok {
        free_user_regions(pid, &allocated, allocated_count);
        return None;
    }

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
    let base_name = image_path
        .rfind('\\')
        .map(|i| &image_path[i + 1..])
        .unwrap_or(image_path);
    let ldr_ok = with_process_user_buf_mut(pid, ldr_va, ldr_data::SIZE, |ldr_buf| {
        wu32(ldr_buf, ldr_data::LENGTH, ldr_data::SIZE as u32);
        wu32(ldr_buf, ldr_data::INITIALIZED, 1);
        write_list_head(ldr_buf, ldr_data::IN_LOAD_ORDER, ldr_va);
        write_list_head(ldr_buf, ldr_data::IN_MEMORY_ORDER, ldr_va);
        write_list_head(ldr_buf, ldr_data::IN_INIT_ORDER, ldr_va);

        let mut ok = with_process_user_buf_mut(pid, entry_va, ldr_entry::SIZE, |entry_buf| {
            init_ldr_entry(entry_buf, entry_va, image_base, 0, 0, image_path, base_name);
            list_insert_tail(
                pid,
                ldr_buf,
                ldr_va,
                ldr_data::IN_LOAD_ORDER,
                entry_buf,
                entry_va,
                ldr_entry::IN_LOAD_ORDER,
            ) && list_insert_tail(
                pid,
                ldr_buf,
                ldr_va,
                ldr_data::IN_MEMORY_ORDER,
                entry_buf,
                entry_va,
                ldr_entry::IN_MEMORY_ORDER,
            ) && list_insert_tail(
                pid,
                ldr_buf,
                ldr_va,
                ldr_data::IN_INIT_ORDER,
                entry_buf,
                entry_va,
                ldr_entry::IN_INIT_ORDER,
            )
        })
        .unwrap_or(false);
        if !ok {
            return false;
        }

        let mut loaded = Vec::new();
        crate::dll::for_each_loaded(|dll_name, dll_base, dll_size, dll_entry| {
            if dll_base == 0 || dll_base == image_base {
                return;
            }
            let _ = loaded.try_reserve(1);
            loaded.push((String::from(dll_name), dll_base, dll_size, dll_entry));
        });

        let mut deps = Vec::new();
        let _ = deps.try_reserve(loaded.len());
        for _ in 0..loaded.len() {
            deps.push(Vec::new());
        }
        for idx in 0..loaded.len() {
            let (_, dll_base, dll_size, _) = &loaded[idx];
            let mut import_names = Vec::new();
            if !module_import_dependencies(pid, *dll_base, *dll_size, &mut import_names) {
                ok = false;
                break;
            }
            for import_name in import_names {
                for dep_idx in 0..loaded.len() {
                    if dep_idx != idx && loaded[dep_idx].0 == import_name {
                        let _ = deps[idx].try_reserve(1);
                        deps[idx].push(dep_idx);
                        break;
                    }
                }
            }
        }
        if !ok {
            return false;
        }

        let mut init_order = Vec::new();
        let mut marks = Vec::new();
        let _ = marks.try_reserve(loaded.len());
        for _ in 0..loaded.len() {
            marks.push(0u8);
        }
        for idx in 0..loaded.len() {
            topo_visit_module(idx, &deps, &mut marks, &mut init_order);
        }

        let mut entry_vas = Vec::new();
        let _ = entry_vas.try_reserve(loaded.len());
        for _ in 0..loaded.len() {
            entry_vas.push(0u64);
        }

        for (idx, (dll_name, dll_base, dll_size, dll_entry)) in loaded.iter().enumerate() {
            if !ok {
                break;
            }
            let Some(dll_entry_va) = alloc_user_region(
                pid,
                ldr_entry::SIZE,
                VmaType::Private,
                &mut allocated,
                &mut allocated_count,
            ) else {
                ok = false;
                break;
            };
            entry_vas[idx] = dll_entry_va;

            let inserted =
                with_process_user_buf_mut(pid, dll_entry_va, ldr_entry::SIZE, |dll_entry_buf| {
                    init_ldr_entry(
                        dll_entry_buf,
                        dll_entry_va,
                        *dll_base,
                        *dll_size,
                        *dll_entry,
                        dll_name,
                        dll_name,
                    );
                    list_insert_tail(
                        pid,
                        ldr_buf,
                        ldr_va,
                        ldr_data::IN_LOAD_ORDER,
                        dll_entry_buf,
                        dll_entry_va,
                        ldr_entry::IN_LOAD_ORDER,
                    ) && list_insert_tail(
                        pid,
                        ldr_buf,
                        ldr_va,
                        ldr_data::IN_MEMORY_ORDER,
                        dll_entry_buf,
                        dll_entry_va,
                        ldr_entry::IN_MEMORY_ORDER,
                    )
                })
                .unwrap_or(false);
            if !inserted {
                ok = false;
            }
        }

        if ok {
            for idx in init_order {
                let dll_entry_va = entry_vas.get(idx).copied().unwrap_or(0);
                if dll_entry_va == 0 {
                    ok = false;
                    break;
                }
                let inserted = with_process_user_buf_mut(
                    pid,
                    dll_entry_va,
                    ldr_entry::SIZE,
                    |dll_entry_buf| {
                        list_insert_tail(
                            pid,
                            ldr_buf,
                            ldr_va,
                            ldr_data::IN_INIT_ORDER,
                            dll_entry_buf,
                            dll_entry_va,
                            ldr_entry::IN_INIT_ORDER,
                        )
                    },
                )
                .unwrap_or(false);
                if !inserted {
                    ok = false;
                    break;
                }
            }
        }
        ok
    })
    .unwrap_or(false);
    if !ldr_ok || !write_user_value(pid, (peb_va + peb::LDR as u64) as *mut u64, ldr_va) {
        free_user_regions(pid, &allocated, allocated_count);
        return None;
    }

    // ── 标准句柄（stdin=0, stdout=1, stderr=2 作为伪句柄）────
    // Windows 用负数句柄表示伪句柄，但 guest 的 WriteFile 会通过
    // NtWriteFile hypercall 传给 VMM，VMM 侧 FileTable 已把 fd 1/2 注册为 stdout/stderr
    if !write_user_value(
        pid,
        (upp_va + upp_handles::STANDARD_INPUT as u64) as *mut u64,
        0xFFFF_FFFF_FFFF_FFF6u64,
    ) || !write_user_value(
        pid,
        (upp_va + upp_handles::STANDARD_OUTPUT as u64) as *mut u64,
        0xFFFF_FFFF_FFFF_FFF5u64,
    ) || !write_user_value(
        pid,
        (upp_va + upp_handles::STANDARD_ERROR as u64) as *mut u64,
        0xFFFF_FFFF_FFFF_FFF4u64,
    ) {
        free_user_regions(pid, &allocated, allocated_count);
        return None;
    }

    // ── TEB ──────────────────────────────────────────────────
    let teb_ok = with_process_user_buf_mut(pid, teb_va, teb::SIZE, |teb_buf| {
        wu64(teb_buf, teb::EXCEPTION_LIST, u64::MAX);
        wu64(teb_buf, teb::STACK_BASE, stack.stack_base);
        wu64(teb_buf, teb::STACK_LIMIT, stack.stack_limit);
        wu64(teb_buf, teb::SELF, teb_va);
        wu64(teb_buf, teb::PEB, peb_va);
        wu64(teb_buf, teb::CLIENT_ID, pid as u64);
        wu64(teb_buf, teb::CLIENT_ID + 8, tid as u64);
    })
    .is_some();
    if !teb_ok {
        free_user_regions(pid, &allocated, allocated_count);
        return None;
    }

    Some(TebPeb {
        teb_va,
        peb_va,
        stack_base: stack.stack_base,
        stack_limit: stack.stack_limit,
    })
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

fn alloc_user_region_at(
    pid: u32,
    base: u64,
    size: usize,
    prot: u32,
    vma_type: VmaType,
    regions: &mut [u64],
    count: &mut usize,
) -> Option<u64> {
    let actual = vm_alloc_region_typed(pid, base, size as u64, prot, vma_type)?;
    if actual != base {
        let _ = vm_free_region(pid, actual);
        return None;
    }
    if *count < regions.len() {
        regions[*count] = actual;
        *count += 1;
        Some(actual)
    } else {
        let _ = vm_free_region(pid, actual);
        None
    }
}

fn init_kuser_shared_data(
    pid: u32,
    regions: &mut [u64],
    count: &mut usize,
) -> Option<u64> {
    let base = alloc_user_region_at(
        pid,
        KUSER_SHARED_DATA_VA,
        KUSER_SHARED_DATA_SIZE,
        0x02,
        VmaType::Private,
        regions,
        count,
    )?;
    let pa = translate_user_va(pid, UserVa::new(base), VM_ACCESS_READ)?;

    let mono_100ns = crate::hypercall::query_mono_time_100ns();
    let system_100ns = crate::hypercall::query_system_time_100ns();
    let tick_ms = mono_100ns / 10_000;
    let mut page = [0u8; KUSER_SHARED_DATA_SIZE];

    wu32(page.as_mut_slice(), kusd::TICK_COUNT_LOW_DEPRECATED, tick_ms as u32);
    wu32(page.as_mut_slice(), kusd::TICK_COUNT_MULTIPLIER, 0);
    write_ksystem_time(page.as_mut_slice(), kusd::INTERRUPT_TIME, mono_100ns);
    write_ksystem_time(page.as_mut_slice(), kusd::SYSTEM_TIME, system_100ns);
    write_ksystem_time(page.as_mut_slice(), kusd::TIME_ZONE_BIAS, 0);
    let mut root_off = kusd::NT_SYSTEM_ROOT;
    let _ = write_utf16(page.as_mut_slice(), &mut root_off, "C:\\Windows", 0);
    wu32(page.as_mut_slice(), kusd::NT_BUILD_NUMBER, 22631);
    wu32(page.as_mut_slice(), kusd::NT_PRODUCT_TYPE, NT_PRODUCT_WIN_NT);
    wu8(page.as_mut_slice(), kusd::PRODUCT_TYPE_IS_VALID, 1);
    wu16(
        page.as_mut_slice(),
        kusd::NATIVE_PROCESSOR_ARCHITECTURE,
        PROCESSOR_ARCHITECTURE_ARM64,
    );
    wu32(page.as_mut_slice(), kusd::NT_MAJOR_VERSION, 10);
    wu32(page.as_mut_slice(), kusd::NT_MINOR_VERSION, 0);
    wu64(
        page.as_mut_slice(),
        kusd::QPC_FREQUENCY,
        PERF_COUNTER_FREQUENCY_100NS,
    );
    write_ksystem_time(page.as_mut_slice(), kusd::TICK_COUNT, tick_ms);
    wu32(
        page.as_mut_slice(),
        kusd::COOKIE,
        (system_100ns as u32) ^ (tick_ms as u32) ^ 0x4d45_5557,
    );

    if !crate::mm::linear_map::copy_to_phys(pa, page.as_ptr(), page.len()) {
        return None;
    }
    Some(base)
}

/// 将 UTF-8 字符串编码为 UTF-16LE 写入 buf[*off..]，返回该字符串在 guest 内存中的 VA。
/// 写完后 *off 向后推进（含 NUL 终止符）。
fn write_utf16(buf: &mut [u8], off: &mut usize, s: &str, base_va: u64) -> u64 {
    let va = base_va + *off as u64;
    for ch in s.encode_utf16() {
        if *off + 2 > buf.len() {
            break;
        }
        buf[*off] = (ch & 0xFF) as u8;
        buf[*off + 1] = (ch >> 8) as u8;
        *off += 2;
    }
    // NUL terminator
    if *off + 2 <= buf.len() {
        buf[*off] = 0;
        buf[*off + 1] = 0;
        *off += 2;
    }
    va
}

fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

fn normalize_thread_stack_sizes(stack_reserve: u64, stack_commit: u64) -> (u64, u64) {
    let reserve_size =
        align_up(stack_reserve.max(DEFAULT_THREAD_STACK_RESERVE), THREAD_STACK_RESERVE_ALIGN);
    let max_commit = reserve_size.saturating_sub(PAGE_SIZE_4K);
    let mut commit_size = align_up(stack_commit.max(PAGE_SIZE_4K), PAGE_SIZE_4K);
    if commit_size > max_commit {
        commit_size = max_commit.max(PAGE_SIZE_4K);
    }
    (reserve_size, commit_size)
}

pub fn alloc_thread_stack(
    pid: u32,
    stack_reserve: u64,
    stack_commit: u64,
) -> Option<UserThreadStack> {
    let (reserve_size, commit_size) = normalize_thread_stack_sizes(stack_reserve, stack_commit);
    let reserve_base = vm_alloc_region_typed(pid, 0, reserve_size, 0x04, VmaType::ThreadStack)?;
    let stack_base = reserve_base + reserve_size;
    let stack_limit = stack_base.saturating_sub(commit_size);
    let guard_page = stack_limit.saturating_sub(PAGE_SIZE_4K);
    if guard_page < reserve_base || !vm_make_guard_page(pid, guard_page) {
        let _ = vm_free_region(pid, reserve_base);
        return None;
    }
    Some(UserThreadStack {
        reserve_base,
        reserve_size,
        stack_base,
        stack_limit,
    })
}

/// Allocate a minimal TEB page for a new thread in `pid`.
/// Returns the TEB VA on success, or None on OOM.
pub fn alloc_teb(pid: u32) -> Option<u64> {
    use winemu_shared::teb as teb_off;
    let teb_va =
        crate::mm::vm_alloc_region_typed(pid, 0, teb_off::SIZE as u64, 0x04, VmaType::Private)?;
    if !write_user_value(pid, (teb_va + teb_off::SELF as u64) as *mut u64, teb_va) {
        let _ = vm_free_region(pid, teb_va);
        return None;
    }
    Some(teb_va)
}

pub fn init_thread_teb(
    pid: u32,
    tid: u32,
    teb_va: u64,
    stack_base: u64,
    stack_limit: u64,
) -> bool {
    use winemu_shared::teb as teb_off;

    let Some(peb_va) = crate::process::with_process(pid, |p| p.peb_va) else {
        return false;
    };

    write_user_value(pid, (teb_va + teb_off::EXCEPTION_LIST as u64) as *mut u64, u64::MAX)
        && write_user_value(pid, (teb_va + teb_off::STACK_BASE as u64) as *mut u64, stack_base)
        && write_user_value(
            pid,
            (teb_va + teb_off::STACK_LIMIT as u64) as *mut u64,
            stack_limit,
        )
        && write_user_value(pid, (teb_va + teb_off::SELF as u64) as *mut u64, teb_va)
        && write_user_value(pid, (teb_va + teb_off::PEB as u64) as *mut u64, peb_va)
        && write_user_value(pid, (teb_va + teb_off::CLIENT_ID as u64) as *mut u64, pid as u64)
        && write_user_value(
            pid,
            (teb_va + teb_off::CLIENT_ID as u64 + 8) as *mut u64,
            tid as u64,
        )
}
