// NT syscall 分发器 — VMM 侧
// 过渡期：接收 guest NT_SYSCALL hypercall，按领域模块分发。
// 架构目标仍是将 NT 语义收敛到 guest kernel，VMM 仅保留 host 资源原语。

mod file;
mod memory;
mod object;
mod process;
mod section;
mod sync;
mod thread;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use winemu_core::addr::Gpa;
use winemu_shared::status;

use crate::file_io::FileTable;
use crate::memory::GuestMemory;
use crate::sched::{SchedResult, Scheduler, ThreadId};
use crate::section::SectionTable;

pub(crate) struct DispatchContext<'a> {
    pub(crate) tid: ThreadId,
    pub(crate) memory: &'a Arc<RwLock<GuestMemory>>,
    pub(crate) files: &'a FileTable,
    pub(crate) sections: &'a SectionTable,
    pub(crate) sched: &'a Arc<Scheduler>,
    pub(crate) vaspace: &'a Arc<Mutex<crate::vaspace::VaSpace>>,
}

pub(crate) struct SyscallArgs<'a> {
    regs: [u64; 8],
    guest_sp: u64,
    memory: &'a Arc<RwLock<GuestMemory>>,
}

impl<'a> SyscallArgs<'a> {
    fn new(regs: [u64; 8], guest_sp: u64, memory: &'a Arc<RwLock<GuestMemory>>) -> Self {
        Self {
            regs,
            guest_sp,
            memory,
        }
    }

    pub(crate) fn get(&self, idx: usize) -> u64 {
        if idx < 8 {
            return self.regs[idx];
        }
        let off = (idx - 8) as u64 * 8;
        let mem = self.memory.read().unwrap();
        let bytes = mem.read_bytes(Gpa(self.guest_sp + 16 + off), 8);
        u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))
    }

    pub(crate) fn memory(&self) -> &'a Arc<RwLock<GuestMemory>> {
        self.memory
    }
}

// ── syscall 表 ───────────────────────────────────────────────

pub struct SyscallTable {
    /// table_nr → (syscall_nr → handler_name)
    tables: [HashMap<u32, String>; 4],
}

impl SyscallTable {
    pub fn from_toml(toml: &str) -> Self {
        let mut tables: [HashMap<u32, String>; 4] = std::array::from_fn(|_| HashMap::new());

        // TOML 格式：[nt] / [win32k] 节，每行 "Name = 0xNNNN"
        // [nt]     → table 0
        // [win32k] → table 1
        let mut cur_table: usize = usize::MAX; // skip [meta] etc.
        for line in toml.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                cur_table = match line {
                    "[nt]" => 0,
                    "[win32k]" => 1,
                    _ => usize::MAX,
                };
            } else if cur_table < 4 {
                if let Some((name, val)) = line.split_once('=') {
                    let name = name.trim();
                    let val = val.trim().trim_start_matches("0x");
                    if let Ok(nr) = u32::from_str_radix(val, 16) {
                        tables[cur_table].insert(nr, name.to_string());
                    }
                }
            }
        }
        Self { tables }
    }

    pub fn lookup(&self, table_nr: u32, syscall_nr: u32) -> Option<&str> {
        self.tables
            .get(table_nr as usize)?
            .get(&syscall_nr)
            .map(|s| s.as_str())
    }
}

// ── syscall 分发器 ───────────────────────────────────────────

pub struct SyscallDispatcher {
    table: RwLock<SyscallTable>,
}

unsafe impl Send for SyscallDispatcher {}
unsafe impl Sync for SyscallDispatcher {}

impl SyscallDispatcher {
    pub fn new(toml: &str) -> Self {
        Self {
            table: RwLock::new(SyscallTable::from_toml(toml)),
        }
    }

    /// 分发 NT_SYSCALL hypercall
    /// args: [syscall_nr, table_nr, arg0, arg1, arg2, arg3]
    pub fn dispatch(
        &self,
        args: [u64; 6],
        tid: ThreadId,
        memory: &Arc<RwLock<GuestMemory>>,
        files: &FileTable,
        sections: &SectionTable,
        sched: &Arc<Scheduler>,
        vaspace: &Arc<Mutex<crate::vaspace::VaSpace>>,
        guest_sp: u64,
    ) -> DispatchResult {
        self.dispatch_full(
            args, [0u64; 4], tid, memory, files, sections, sched, vaspace, guest_sp,
        )
    }

    /// Full dispatch with x4-x7 passed directly from vCPU registers.
    /// args: [syscall_nr, table_nr, x0, x1, x2, x3]
    /// regs47: [x4, x5, x6, x7]
    pub fn dispatch_full(
        &self,
        args: [u64; 6],
        regs47: [u64; 4],
        tid: ThreadId,
        memory: &Arc<RwLock<GuestMemory>>,
        files: &FileTable,
        sections: &SectionTable,
        sched: &Arc<Scheduler>,
        vaspace: &Arc<Mutex<crate::vaspace::VaSpace>>,
        guest_sp: u64,
    ) -> DispatchResult {
        let syscall_nr = args[0] as u32;
        let table_nr = args[1] as u32;
        let call = SyscallArgs::new(
            [
                args[2], args[3], args[4], args[5], regs47[0], regs47[1], regs47[2], regs47[3],
            ],
            guest_sp,
            memory,
        );
        let ctx = DispatchContext {
            tid,
            memory,
            files,
            sections,
            sched,
            vaspace,
        };

        let name = match self.table.read().unwrap().lookup(table_nr, syscall_nr) {
            Some(n) => n.to_owned(),
            None => {
                log::warn!(
                    "NT_SYSCALL: unknown syscall table={} nr={:#x}",
                    table_nr,
                    syscall_nr
                );
                return DispatchResult::Sync(status::INVALID_PARAMETER as u64);
            }
        };

        log::debug!("NT_SYSCALL: {} ({:#x})", name, syscall_nr);

        match name.as_str() {
            // ── 文件 I/O ─────────────────────────────────────
            "NtCreateFile" => file::nt_create_file(&call, &ctx),
            "NtReadFile" => file::nt_read_file(&call, &ctx),
            "NtWriteFile" => file::nt_write_file(&call, &ctx),
            "NtClose" => file::nt_close(&call, &ctx),
            "NtOpenFile" => file::nt_open_file(&call, &ctx),
            "NtSetInformationFile" => file::nt_set_information_file(&call, &ctx),
            "NtQueryDirectoryFile" => file::nt_query_directory_file(&call, &ctx),

            // ── 同步 ─────────────────────────────────────────
            "NtCreateEvent" => sync::nt_create_event(&call, &ctx),
            "NtWaitForSingleObject" => sync::nt_wait_for_single_object(&call, &ctx),
            "NtSetEvent" => sync::nt_set_event(&call, &ctx),
            "NtResetEvent" => sync::nt_reset_event(&call, &ctx),
            "NtWaitForMultipleObjects" => sync::nt_wait_for_multiple_objects(&call, &ctx),

            // ── 内存 ─────────────────────────────────────────
            "NtAllocateVirtualMemory" => memory::nt_allocate_virtual_memory(&call, &ctx),
            "NtFreeVirtualMemory" => memory::nt_free_virtual_memory(&call, &ctx),
            "NtQueryVirtualMemory" => memory::nt_query_virtual_memory(&call, &ctx),
            "NtProtectVirtualMemory" => memory::nt_protect_virtual_memory(&call, &ctx),

            // ── 注册表（应由 guest kernel 处理） ───────────────
            "NtOpenKey"
            | "NtOpenKeyEx"
            | "NtCreateKey"
            | "NtQueryValueKey"
            | "NtEnumerateKey"
            | "NtEnumerateValueKey"
            | "NtSetValueKey"
            | "NtDeleteKey"
            | "NtDeleteValueKey"
            | "NtFlushKey" => {
                log::warn!("NT_SYSCALL: {} must be handled in guest kernel", name);
                DispatchResult::Sync(status::INVALID_PARAMETER as u64)
            }

            // ── 进程/线程信息 ─────────────────────────────────
            "NtQueryInformationProcess" => process::nt_query_information_process(&call, &ctx),
            "NtQueryInformationThread" => thread::nt_query_information_thread(&call, &ctx),
            "NtSetInformationThread" => thread::nt_set_information_thread(&call),

            // ── 进程/线程 ─────────────────────────────────────
            "NtTerminateProcess" => process::nt_terminate_process(&call),
            "NtTerminateThread" => thread::nt_terminate_thread(&call),
            "NtYieldExecution" => thread::nt_yield_execution(),
            "NtCreateProcessEx" | "NtCreateProcess" => process::nt_create_process(),
            "NtCreateThreadEx" | "NtCreateThread" => thread::nt_create_thread(&call, &ctx),

            // ── Section / 映射 ────────────────────────────────
            "NtCreateSection" => section::nt_create_section(&call, &ctx),
            "NtMapViewOfSection" => section::nt_map_view_of_section(&call, &ctx),
            "NtUnmapViewOfSection" => section::nt_unmap_view_of_section(&call, &ctx),

            // ── 对象 / 系统信息 ───────────────────────────────
            "NtDuplicateObject" => object::nt_duplicate_object(&call, &ctx),
            "NtQueryObject" => object::nt_query_object(&call, &ctx),
            "NtQuerySystemInformation" => object::nt_query_system_information(&call, &ctx),

            _ => {
                log::warn!("NT_SYSCALL: unimplemented {}", name);
                DispatchResult::Sync(status::INVALID_PARAMETER as u64)
            }
        }
    }
}

pub enum DispatchResult {
    Sync(u64),
    Sched(SchedResult),
}

// ── 辅助函数 ─────────────────────────────────────────────────

/// 从 guest 内存读取 UNICODE_STRING（ObjectAttributes->ObjectName）
pub(crate) fn read_unicode_string(memory: &Arc<RwLock<GuestMemory>>, oa_gpa: u64) -> String {
    if oa_gpa == 0 {
        return String::new();
    }
    let mem = memory.read().unwrap();
    // OBJECT_ATTRIBUTES layout (64-bit):
    // +0x00 ULONG Length
    // +0x08 HANDLE RootDirectory
    // +0x10 PUNICODE_STRING ObjectName
    let on_ptr_bytes = mem.read_bytes(Gpa(oa_gpa + 0x10), 8);
    let on_gpa = u64::from_le_bytes(on_ptr_bytes.try_into().unwrap_or([0; 8]));
    if on_gpa == 0 {
        return String::new();
    }
    // UNICODE_STRING: +0 Length(u16), +2 MaxLength(u16), +8 Buffer(u64)
    let len_bytes = mem.read_bytes(Gpa(on_gpa), 2);
    let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
    let buf_bytes = mem.read_bytes(Gpa(on_gpa + 8), 8);
    let buf_gpa = u64::from_le_bytes(buf_bytes.try_into().unwrap_or([0; 8]));
    if buf_gpa == 0 || len == 0 || len > 1024 {
        return String::new();
    }
    let wchars = mem.read_bytes(Gpa(buf_gpa), len);
    let u16s: Vec<u16> = wchars
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}
