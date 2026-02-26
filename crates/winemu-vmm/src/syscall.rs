// NT syscall 分发器 — VMM 侧
// 接收 guest NT_SYSCALL hypercall，查 TOML syscall 表，执行对应 handler
//
// syscall 表格式（TOML）：
// [table.0]
// 0x0055 = "NtCreateFile"
// 0x0006 = "NtReadFile"
// ...

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use winemu_core::addr::Gpa;
use crate::memory::GuestMemory;
use crate::file_io::FileTable;
use crate::section::SectionTable;
use crate::sched::{Scheduler, ThreadId, SchedResult};
use crate::sched::sync::{SyncHandle, SyncObject, EventObj};
use winemu_shared::status;
use winereg::{KeyNode, RegistryKey, RegistryValue, RegistryValueData, RegistryParser,
    REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_MULTI_SZ, REG_QWORD};

/// In-process registry database backed by winereg KeyNode tree.
pub struct RegistryDb {
    root: KeyNode,
}

// Safety: RegistryDb uses Rc<RefCell<>> internally but is always accessed
// under a Mutex, so cross-thread access is serialized.
unsafe impl Send for RegistryDb {}
unsafe impl Sync for RegistryDb {}

impl RegistryDb {
    pub fn new() -> Self {
        Self { root: RegistryKey::create_root() }
    }

    /// Load a Wine-format .reg file into the database.
    pub fn load_file(&self, path: &str) -> Result<(), String> {
        let result = RegistryParser.load_from_file(path)
            .map_err(|e| format!("{:?}", e))?;
        merge_tree(&result.root_key, &self.root);
        Ok(())
    }

    pub fn open_key(&self, path: &str) -> Option<KeyNode> {
        RegistryKey::find_key(&self.root, &normalize_path(path))
    }

    pub fn create_key(&self, path: &str) -> KeyNode {
        RegistryKey::create_key_recursive(&self.root, &normalize_path(path))
    }
}

fn normalize_path(path: &str) -> String {
    // Strip leading \Registry\Machine\ or HKLM\ etc. — keep relative path
    let p = path.trim_start_matches('\\');
    for prefix in &["Registry\\Machine\\", "Registry\\User\\", "HKEY_LOCAL_MACHINE\\", "HKLM\\"] {
        if let Some(rest) = p.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    p.to_string()
}

fn merge_tree(src: &KeyNode, dst: &KeyNode) {
    // Snapshot to avoid holding borrow across recursive calls
    let values  = RegistryKey::snapshot_values(src);
    let subkeys = RegistryKey::snapshot_subkeys(src);
    for (name, val) in values {
        dst.borrow_mut().set_value_for_loading(name, val);
    }
    for (name, sub) in subkeys {
        let dst_sub = RegistryKey::create_subkey(dst, name);
        merge_tree(&sub, &dst_sub);
    }
}

// ── syscall 表 ───────────────────────────────────────────────

pub struct SyscallTable {
    /// table_nr → (syscall_nr → handler_name)
    tables: [HashMap<u32, String>; 4],
}

impl SyscallTable {
    pub fn from_toml(toml: &str) -> Self {
        let mut tables: [HashMap<u32, String>; 4] =
            std::array::from_fn(|_| HashMap::new());

        // TOML 格式：[nt] / [win32k] 节，每行 "Name = 0xNNNN"
        // [nt]     → table 0
        // [win32k] → table 1
        let mut cur_table: usize = usize::MAX; // skip [meta] etc.
        for line in toml.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                cur_table = match line {
                    "[nt]"     => 0,
                    "[win32k]" => 1,
                    _          => usize::MAX,
                };
            } else if cur_table < 4 {
                if let Some((name, val)) = line.split_once('=') {
                    let name = name.trim();
                    let val  = val.trim().trim_start_matches("0x");
                    if let Ok(nr) = u32::from_str_radix(val, 16) {
                        tables[cur_table].insert(nr, name.to_string());
                    }
                }
            }
        }
        Self { tables }
    }

    pub fn lookup(&self, table_nr: u32, syscall_nr: u32) -> Option<&str> {
        self.tables.get(table_nr as usize)?.get(&syscall_nr).map(|s| s.as_str())
    }
}

// ── syscall 分发器 ───────────────────────────────────────────

/// All registry state in one place — accessed only under SyscallDispatcher's
/// internal Mutex, so the Rc<RefCell<>> inside KeyNode is safe to share.
struct RegistryState {
    db:              RegistryDb,
    key_handles:     HashMap<u64, KeyNode>,
    next_key_handle: u64,
}

impl RegistryState {
    fn new() -> Self {
        Self {
            db:              RegistryDb::new(),
            key_handles:     HashMap::new(),
            next_key_handle: 0x9000_0001,
        }
    }

    fn alloc_handle(&mut self, node: KeyNode) -> u64 {
        let h = self.next_key_handle;
        self.next_key_handle += 2;
        self.key_handles.insert(h, node);
        h
    }
}

pub struct SyscallDispatcher {
    table:    RwLock<SyscallTable>,
    reg:      Mutex<RegistryState>,
}

// Safety: RegistryState contains Rc<RefCell<>> (from winereg) but is always
// accessed under the Mutex above, so no concurrent access occurs.
unsafe impl Send for SyscallDispatcher {}
unsafe impl Sync for SyscallDispatcher {}

impl SyscallDispatcher {
    pub fn new(toml: &str) -> Self {
        Self {
            table: RwLock::new(SyscallTable::from_toml(toml)),
            reg:   Mutex::new(RegistryState::new()),
        }
    }

    pub fn load_registry_file(&self, path: &str) -> Result<(), String> {
        self.reg.lock().unwrap().db.load_file(path)
    }

    /// 分发 NT_SYSCALL hypercall
    /// args: [syscall_nr, table_nr, arg0, arg1, arg2, arg3]
    pub fn dispatch(
        &self,
        args: [u64; 6],
        tid: ThreadId,
        memory: &std::sync::Arc<std::sync::RwLock<GuestMemory>>,
        files: &FileTable,
        sections: &SectionTable,
        sched: &std::sync::Arc<Scheduler>,
        vaspace: &std::sync::Arc<std::sync::Mutex<crate::vaspace::VaSpace>>,
        guest_sp: u64,
    ) -> DispatchResult {
        self.dispatch_full(args, [0u64; 4], tid, memory, files, sections, sched, vaspace, guest_sp)
    }

    /// Full dispatch with x4-x7 passed directly from vCPU registers.
    /// args: [syscall_nr, table_nr, x0, x1, x2, x3]
    /// regs47: [x4, x5]  (x6, x7 via stack for now)
    pub fn dispatch_full(
        &self,
        args: [u64; 6],
        regs47: [u64; 4],
        tid: ThreadId,
        memory: &std::sync::Arc<std::sync::RwLock<GuestMemory>>,
        files: &FileTable,
        sections: &SectionTable,
        sched: &std::sync::Arc<Scheduler>,
        vaspace: &std::sync::Arc<std::sync::Mutex<crate::vaspace::VaSpace>>,
        guest_sp: u64,
    ) -> DispatchResult {
        let syscall_nr = args[0] as u32;
        let table_nr   = args[1] as u32;
        // a[0..3] = x0..x3, a[4..7] = x4..x7 from regs47
        let a = [args[2], args[3], args[4], args[5], regs47[0], regs47[1], regs47[2], regs47[3]];

        // 从 guest 栈读取额外参数（超过6个寄存器时）
        let extra = |idx: usize| -> u64 {
            if idx < 8 { return a[idx]; }
            let off = (idx - 8) as u64 * 8;
            let mem = memory.read().unwrap();
            let bytes = mem.read_bytes(Gpa(guest_sp + 16 + off), 8);
            u64::from_le_bytes(bytes.try_into().unwrap_or([0;8]))
        };

        let name = match self.table.read().unwrap().lookup(table_nr, syscall_nr) {
            Some(n) => n.to_owned(),
            None => {
                log::warn!("NT_SYSCALL: unknown syscall table={} nr={:#x}", table_nr, syscall_nr);
                return DispatchResult::Sync(status::INVALID_PARAMETER as u64);
            }
        };

        log::debug!("NT_SYSCALL: {} ({:#x})", name, syscall_nr);

        match name.as_str() {
            // ── 文件 I/O ─────────────────────────────────────
            "NtCreateFile" => {
                // Simplified: args map to our NT_CREATE_FILE hypercall layout
                // a[0]=ObjectAttributes*, a[1]=access, a[2]=..., a[3]=disposition
                // Full NtCreateFile has 11 params; we handle the common subset
                let access      = extra(1) as u32;
                let disposition = extra(7) as u32;
                // ObjectAttributes->ObjectName->Buffer (GPA)
                let oa_gpa = extra(2);
                let path = read_unicode_string(memory, oa_gpa);
                let (st, h) = files.create(&path, access, disposition);
                log::debug!("NtCreateFile: path={} status={:#x} handle={}", path, st, h);
                DispatchResult::Sync((st << 32) | h)
            }
            "NtReadFile" => {
                let handle = extra(0);
                let buf_gpa = Gpa(extra(5));
                let length  = extra(6) as usize;
                let offset  = if extra(7) == u64::MAX { None } else { Some(extra(7)) };
                if length == 0 || length > 64 * 1024 * 1024 {
                    return DispatchResult::Sync(status::INVALID_PARAMETER as u64);
                }
                let mut buf = vec![0u8; length];
                let (st, n) = files.read(handle, &mut buf, offset);
                if st == status::SUCCESS as u64 && n > 0 {
                    memory.write().unwrap().write_bytes(buf_gpa, &buf[..n]);
                }
                DispatchResult::Sync((st << 32) | n as u64)
            }
            "NtWriteFile" => {
                let handle  = extra(0);
                let buf_gpa = Gpa(extra(5));
                let length  = extra(6) as usize;
                let offset  = if extra(7) == u64::MAX { None } else { Some(extra(7)) };
                log::debug!("NtWriteFile: handle={:#x} buf={:#x} len={}", handle, buf_gpa.0, length);
                if length == 0 || length > 64 * 1024 * 1024 {
                    return DispatchResult::Sync(status::INVALID_PARAMETER as u64);
                }
                let buf = memory.read().unwrap().read_bytes(buf_gpa, length).to_vec();
                let (st, _n) = files.write(handle, &buf, offset);
                DispatchResult::Sync(st)
            }
            "NtClose" => {
                let handle = extra(0);
                // Try file handle first, then sync handle
                let st = if files.close(handle) == status::SUCCESS as u64 {
                    status::SUCCESS as u64
                } else if sched.close_handle(SyncHandle(handle as u32)) {
                    status::SUCCESS as u64
                } else {
                    status::INVALID_HANDLE as u64
                };
                DispatchResult::Sync(st)
            }
            // ── 同步 ─────────────────────────────────────────
            "NtCreateEvent" => {
                let event_type = extra(2) as u32; // 0=NotificationEvent(manual), 1=SynchronizationEvent(auto)
                let initial    = extra(3) != 0;
                let manual     = event_type == 0;
                let h = sched.alloc_handle();
                sched.insert_object(h, SyncObject::Event(EventObj::new(manual, initial)));
                DispatchResult::Sync(h.0 as u64)
            }
            "NtWaitForSingleObject" => {
                let handle  = SyncHandle(extra(0) as u32);
                let alertable = extra(1) != 0;
                let timeout = extra(2) as i64;
                let _ = alertable; // Phase 3: APC
                DispatchResult::Sched(sched.wait_single(tid, handle, timeout))
            }
            "NtWaitForMultipleObjects" => {
                let count    = extra(0) as usize;
                let arr_gpa  = Gpa(extra(1));
                let wait_all = extra(2) != 0;
                let timeout  = extra(4) as i64;
                if count == 0 || count > 64 {
                    return DispatchResult::Sync(status::INVALID_PARAMETER as u64);
                }
                let handles: Vec<SyncHandle> = {
                    let mem = memory.read().unwrap();
                    (0..count).map(|i| {
                        let bytes = mem.read_bytes(Gpa(arr_gpa.0 + i as u64 * 4), 4);
                        SyncHandle(u32::from_le_bytes(bytes.try_into().unwrap_or([0;4])))
                    }).collect()
                };
                DispatchResult::Sched(sched.wait_multiple(tid, handles, wait_all, timeout))
            }
            // ── 内存 ─────────────────────────────────────────
            "NtAllocateVirtualMemory" => {
                // a[0]=ProcessHandle(-1=self), a[1]=*BaseAddress GPA, a[2]=ZeroBits
                // a[3]=*RegionSize GPA, a[4]=AllocationType, a[5]=Protect
                let base_ptr_gpa = extra(1);
                let size_ptr_gpa = extra(3);
                let prot         = extra(5) as u32;

                let hint = if base_ptr_gpa != 0 {
                    let mem = memory.read().unwrap();
                    let b = mem.read_bytes(Gpa(base_ptr_gpa), 8);
                    u64::from_le_bytes(b.try_into().unwrap_or([0;8]))
                } else { 0 };
                let size = if size_ptr_gpa != 0 {
                    let mem = memory.read().unwrap();
                    let b = mem.read_bytes(Gpa(size_ptr_gpa), 8);
                    u64::from_le_bytes(b.try_into().unwrap_or([0;8]))
                } else { 0 };

                if size == 0 {
                    return DispatchResult::Sync(status::INVALID_PARAMETER as u64);
                }
                match vaspace.lock().unwrap().alloc(hint, size, prot) {
                    Some(va) => {
                        // Zero-initialize committed memory (Windows guarantee)
                        let aligned = (size + 0xFFFF) & !0xFFFF;
                        let zero = vec![0u8; aligned as usize];
                        memory.write().unwrap().write_bytes(Gpa(va), &zero);
                        // Write back allocated base and size
                        if base_ptr_gpa != 0 {
                            memory.write().unwrap().write_bytes(Gpa(base_ptr_gpa), &va.to_le_bytes());
                        }
                        if size_ptr_gpa != 0 {
                            memory.write().unwrap().write_bytes(Gpa(size_ptr_gpa), &aligned.to_le_bytes());
                        }
                        DispatchResult::Sync(status::SUCCESS as u64)
                    }
                    None => DispatchResult::Sync(status::NO_MEMORY as u64),
                }
            }
            "NtFreeVirtualMemory" => {
                // a[0]=ProcessHandle, a[1]=*BaseAddress GPA, a[2]=*RegionSize GPA, a[3]=FreeType
                let base_ptr_gpa = extra(1);
                let base = if base_ptr_gpa != 0 {
                    let mem = memory.read().unwrap();
                    let b = mem.read_bytes(Gpa(base_ptr_gpa), 8);
                    u64::from_le_bytes(b.try_into().unwrap_or([0;8]))
                } else { 0 };
                vaspace.lock().unwrap().free(base);
                DispatchResult::Sync(status::SUCCESS as u64)
            }
            "NtQueryVirtualMemory" => {
                // a[0]=ProcessHandle, a[1]=BaseAddress, a[2]=InfoClass
                // a[3]=Buffer GPA, a[4]=BufferSize, a[5]=*ReturnLength GPA
                let addr      = extra(1);
                let buf_gpa   = Gpa(extra(3));
                let buf_size  = extra(4) as usize;
                let ret_gpa   = extra(5);
                // MEMORY_BASIC_INFORMATION64 size = 48
                if buf_size < 48 {
                    return DispatchResult::Sync(status::INFO_LENGTH_MISMATCH as u64);
                }
                let (base, size, state, prot) = {
                    let va = vaspace.lock().unwrap();
                    match va.query(addr) {
                        Some(r) => (r.base, r.size, r.state as u32, r.prot),
                        None    => (addr & !0xFFFF, 0x10000, 0u32, 0u32),
                    }
                };
                // Write MEMORY_BASIC_INFORMATION64
                let mut mbi = [0u8; 48];
                mbi[0..8].copy_from_slice(&base.to_le_bytes());
                mbi[8..16].copy_from_slice(&base.to_le_bytes()); // AllocationBase
                mbi[16..20].copy_from_slice(&prot.to_le_bytes()); // AllocationProtect
                mbi[24..32].copy_from_slice(&size.to_le_bytes()); // RegionSize
                mbi[32..36].copy_from_slice(&state.to_le_bytes()); // State
                mbi[36..40].copy_from_slice(&prot.to_le_bytes()); // Protect
                memory.write().unwrap().write_bytes(buf_gpa, &mbi);
                if ret_gpa != 0 {
                    memory.write().unwrap().write_bytes(Gpa(ret_gpa), &48u64.to_le_bytes());
                }
                DispatchResult::Sync(status::SUCCESS as u64)
            }
            // ── 注册表 ───────────────────────────────────────
            "NtOpenKey" | "NtOpenKeyEx" => {
                let oa_gpa = extra(2);
                let path = read_unicode_string(memory, oa_gpa);
                log::debug!("NtOpenKey: {}", path);
                let mut reg = self.reg.lock().unwrap();
                let node = reg.db.open_key(&path);
                match node {
                    Some(n) => {
                        let h = reg.alloc_handle(n);
                        DispatchResult::Sync(h)
                    }
                    None => DispatchResult::Sync(status::OBJECT_NAME_NOT_FOUND as u64),
                }
            }
            "NtCreateKey" => {
                let oa_gpa = extra(2);
                let path = read_unicode_string(memory, oa_gpa);
                log::debug!("NtCreateKey: {}", path);
                let mut reg = self.reg.lock().unwrap();
                let node = reg.db.create_key(&path);
                let h = reg.alloc_handle(node);
                DispatchResult::Sync(h)
            }
            "NtQueryValueKey" => {
                let handle   = extra(0);
                let vn_gpa   = extra(1);
                let buf_gpa  = Gpa(extra(3));
                let buf_len  = extra(4) as usize;
                let ret_gpa  = extra(5);
                let val_name = read_unicode_string_direct(memory, vn_gpa);
                let node = self.reg.lock().unwrap().key_handles.get(&handle).cloned();
                match node {
                    None => DispatchResult::Sync(status::INVALID_HANDLE as u64),
                    Some(n) => {
                        let guard = n.borrow();
                        match guard.get_value(&val_name) {
                            None => DispatchResult::Sync(status::OBJECT_NAME_NOT_FOUND as u64),
                            Some(val) => {
                                let data = encode_key_value_full(&val_name, val);
                                if buf_len < data.len() {
                                    if ret_gpa != 0 {
                                        memory.write().unwrap().write_bytes(Gpa(ret_gpa), &(data.len() as u32).to_le_bytes());
                                    }
                                    return DispatchResult::Sync(status::BUFFER_TOO_SMALL as u64);
                                }
                                memory.write().unwrap().write_bytes(buf_gpa, &data);
                                if ret_gpa != 0 {
                                    memory.write().unwrap().write_bytes(Gpa(ret_gpa), &(data.len() as u32).to_le_bytes());
                                }
                                DispatchResult::Sync(status::SUCCESS as u64)
                            }
                        }
                    }
                }
            }
            "NtEnumerateKey" => {
                let handle  = extra(0);
                let index   = extra(1) as usize;
                let buf_gpa = Gpa(extra(3));
                let buf_len = extra(4) as usize;
                let ret_gpa = extra(5);
                let node = self.reg.lock().unwrap().key_handles.get(&handle).cloned();
                match node {
                    None => DispatchResult::Sync(status::INVALID_HANDLE as u64),
                    Some(n) => {
                        let guard = n.borrow();
                        let subkeys: Vec<_> = guard.subkeys().keys().cloned().collect();
                        if index >= subkeys.len() {
                            return DispatchResult::Sync(status::NO_MORE_ENTRIES as u64);
                        }
                        let name = &subkeys[index];
                        let data = encode_key_basic_info(name);
                        if buf_len < data.len() {
                            if ret_gpa != 0 {
                                memory.write().unwrap().write_bytes(Gpa(ret_gpa), &(data.len() as u32).to_le_bytes());
                            }
                            return DispatchResult::Sync(status::BUFFER_TOO_SMALL as u64);
                        }
                        memory.write().unwrap().write_bytes(buf_gpa, &data);
                        if ret_gpa != 0 {
                            memory.write().unwrap().write_bytes(Gpa(ret_gpa), &(data.len() as u32).to_le_bytes());
                        }
                        DispatchResult::Sync(status::SUCCESS as u64)
                    }
                }
            }
            "NtEnumerateValueKey" => {
                let handle  = extra(0);
                let index   = extra(1) as usize;
                let buf_gpa = Gpa(extra(3));
                let buf_len = extra(4) as usize;
                let ret_gpa = extra(5);
                let node = self.reg.lock().unwrap().key_handles.get(&handle).cloned();
                match node {
                    None => DispatchResult::Sync(status::INVALID_HANDLE as u64),
                    Some(n) => {
                        let guard = n.borrow();
                        let vals: Vec<_> = guard.values().values().cloned().collect();
                        if index >= vals.len() {
                            return DispatchResult::Sync(status::NO_MORE_ENTRIES as u64);
                        }
                        let val = &vals[index];
                        let data = encode_key_value_full(&val.name, val);
                        if buf_len < data.len() {
                            if ret_gpa != 0 {
                                memory.write().unwrap().write_bytes(Gpa(ret_gpa), &(data.len() as u32).to_le_bytes());
                            }
                            return DispatchResult::Sync(status::BUFFER_TOO_SMALL as u64);
                        }
                        memory.write().unwrap().write_bytes(buf_gpa, &data);
                        if ret_gpa != 0 {
                            memory.write().unwrap().write_bytes(Gpa(ret_gpa), &(data.len() as u32).to_le_bytes());
                        }
                        DispatchResult::Sync(status::SUCCESS as u64)
                    }
                }
            }
            "NtSetValueKey" => {
                let handle   = extra(0);
                let vn_gpa   = extra(1);
                let val_type = extra(3) as u32;
                let data_gpa = extra(4);
                let data_len = extra(5) as usize;
                let val_name = read_unicode_string_direct(memory, vn_gpa);
                let raw = if data_len > 0 && data_len <= 65536 {
                    memory.read().unwrap().read_bytes(Gpa(data_gpa), data_len).to_vec()
                } else { vec![] };
                let node = self.reg.lock().unwrap().key_handles.get(&handle).cloned();
                if let Some(n) = node {
                    let val = RegistryValue::new(
                        val_name.clone(),
                        decode_reg_value(val_type, &raw),
                    );
                    n.borrow_mut().set_value(val_name, val);
                }
                DispatchResult::Sync(status::SUCCESS as u64)
            }
            "NtDeleteKey" => {
                let handle = extra(0);
                self.reg.lock().unwrap().key_handles.remove(&handle);
                DispatchResult::Sync(status::SUCCESS as u64)
            }
            "NtDeleteValueKey" => {
                let handle   = extra(0);
                let vn_gpa   = extra(1);
                let val_name = read_unicode_string_direct(memory, vn_gpa);
                let node = self.reg.lock().unwrap().key_handles.get(&handle).cloned();
                if let Some(n) = node {
                    n.borrow_mut().delete_value(&val_name);
                }
                DispatchResult::Sync(status::SUCCESS as u64)
            }
            "NtFlushKey" => {
                DispatchResult::Sync(status::SUCCESS as u64)
            }
            // ── 进程/线程信息 ─────────────────────────────────
            "NtQueryInformationProcess" => {
                // a[0]=ProcessHandle, a[1]=ProcessInformationClass
                // a[2]=ProcessInformation GPA, a[3]=ProcessInformationLength
                // a[4]=ReturnLength GPA
                let info_class = extra(1) as u32;
                let buf_gpa    = Gpa(extra(2));
                let buf_len    = extra(3) as usize;
                let ret_gpa    = extra(4);

                match info_class {
                    // ProcessBasicInformation = 0
                    // PROCESS_BASIC_INFORMATION (48 bytes):
                    // +0  ExitStatus          i32 (pad 4)
                    // +8  PebBaseAddress      u64
                    // +16 AffinityMask        u64
                    // +24 BasePriority        i32 (pad 4)
                    // +32 UniqueProcessId     u64
                    // +40 InheritedFromUniqueProcessId u64
                    0 => {
                        if buf_len < 48 {
                            if ret_gpa != 0 {
                                memory.write().unwrap().write_bytes(Gpa(ret_gpa), &48u32.to_le_bytes());
                            }
                            return DispatchResult::Sync(status::INFO_LENGTH_MISMATCH as u64);
                        }
                        // Read PEB pointer from TEB (TEB+0x60)
                        let teb_gpa = sched.get_teb(tid).unwrap_or(0);
                        let peb_base = if teb_gpa != 0 {
                            let mem = memory.read().unwrap();
                            let b = mem.read_bytes(Gpa(teb_gpa + 0x60), 8);
                            u64::from_le_bytes(b.try_into().unwrap_or([0;8]))
                        } else { 0 };
                        let mut pbi = [0u8; 48];
                        // ExitStatus = 0 (STATUS_PENDING)
                        pbi[8..16].copy_from_slice(&peb_base.to_le_bytes());
                        pbi[16..24].copy_from_slice(&1u64.to_le_bytes()); // AffinityMask
                        // BasePriority = 8 (NORMAL)
                        pbi[24..28].copy_from_slice(&8i32.to_le_bytes());
                        pbi[32..40].copy_from_slice(&1u64.to_le_bytes()); // UniqueProcessId
                        pbi[40..48].copy_from_slice(&0u64.to_le_bytes()); // InheritedFrom
                        memory.write().unwrap().write_bytes(buf_gpa, &pbi);
                        if ret_gpa != 0 {
                            memory.write().unwrap().write_bytes(Gpa(ret_gpa), &48u32.to_le_bytes());
                        }
                        DispatchResult::Sync(status::SUCCESS as u64)
                    }
                    // ProcessImageFileName = 27 — return UNICODE_STRING with image path
                    27 => {
                        // Minimal: return empty UNICODE_STRING (Length=0, MaxLength=0, Buffer=0)
                        if buf_len < 16 {
                            if ret_gpa != 0 {
                                memory.write().unwrap().write_bytes(Gpa(ret_gpa), &16u32.to_le_bytes());
                            }
                            return DispatchResult::Sync(status::INFO_LENGTH_MISMATCH as u64);
                        }
                        let us = [0u8; 16];
                        memory.write().unwrap().write_bytes(buf_gpa, &us);
                        if ret_gpa != 0 {
                            memory.write().unwrap().write_bytes(Gpa(ret_gpa), &16u32.to_le_bytes());
                        }
                        DispatchResult::Sync(status::SUCCESS as u64)
                    }
                    _ => {
                        log::debug!("NtQueryInformationProcess: unhandled class {}", info_class);
                        DispatchResult::Sync(status::INVALID_PARAMETER as u64)
                    }
                }
            }
            "NtQueryInformationThread" => {
                // a[0]=ThreadHandle, a[1]=ThreadInformationClass
                // a[2]=ThreadInformation GPA, a[3]=ThreadInformationLength
                // a[4]=ReturnLength GPA
                let info_class = extra(1) as u32;
                let buf_gpa    = Gpa(extra(2));
                let buf_len    = extra(3) as usize;
                let ret_gpa    = extra(4);

                match info_class {
                    // ThreadBasicInformation = 0
                    // THREAD_BASIC_INFORMATION (48 bytes):
                    // +0  ExitStatus      i32 (pad 4)
                    // +8  TebBaseAddress  u64
                    // +16 ClientId.UniqueProcess u64
                    // +24 ClientId.UniqueThread  u64
                    // +32 AffinityMask    u64
                    // +40 Priority        i32
                    // +44 BasePriority    i32
                    0 => {
                        if buf_len < 48 {
                            if ret_gpa != 0 {
                                memory.write().unwrap().write_bytes(Gpa(ret_gpa), &48u32.to_le_bytes());
                            }
                            return DispatchResult::Sync(status::INFO_LENGTH_MISMATCH as u64);
                        }
                        let teb_gpa = sched.get_teb(tid).unwrap_or(0);
                        let thread_id = tid.0 as u64;
                        let mut tbi = [0u8; 48];
                        tbi[8..16].copy_from_slice(&teb_gpa.to_le_bytes());
                        tbi[16..24].copy_from_slice(&1u64.to_le_bytes()); // pid
                        tbi[24..32].copy_from_slice(&thread_id.to_le_bytes());
                        tbi[32..40].copy_from_slice(&1u64.to_le_bytes()); // AffinityMask
                        tbi[40..44].copy_from_slice(&8i32.to_le_bytes()); // Priority
                        tbi[44..48].copy_from_slice(&8i32.to_le_bytes()); // BasePriority
                        memory.write().unwrap().write_bytes(buf_gpa, &tbi);
                        if ret_gpa != 0 {
                            memory.write().unwrap().write_bytes(Gpa(ret_gpa), &48u32.to_le_bytes());
                        }
                        DispatchResult::Sync(status::SUCCESS as u64)
                    }
                    _ => {
                        log::debug!("NtQueryInformationThread: unhandled class {}", info_class);
                        DispatchResult::Sync(status::INVALID_PARAMETER as u64)
                    }
                }
            }
            "NtSetInformationThread" => {
                // Most classes are no-ops in emulation (ThreadHideFromDebugger, etc.)
                let info_class = extra(1) as u32;
                log::debug!("NtSetInformationThread: class={}", info_class);
                DispatchResult::Sync(status::SUCCESS as u64)
            }
            // ── 进程/线程 ─────────────────────────────────────
            "NtTerminateProcess" => {
                let code = extra(1) as u32;
                DispatchResult::Sched(SchedResult::Exit(code))
            }
            "NtTerminateThread" => {
                let code = extra(1) as u32;
                DispatchResult::Sched(SchedResult::Exit(code))
            }
            "NtYieldExecution" => {
                DispatchResult::Sched(SchedResult::Yield)
            }
            // ── 虚拟内存保护 ──────────────────────────────────
            "NtProtectVirtualMemory" => {
                // a[0]=ProcessHandle, a[1]=*BaseAddress, a[2]=*RegionSize
                // a[3]=NewProtect, a[4]=*OldProtect
                // Stub: write OldProtect=PAGE_READWRITE, return SUCCESS
                let old_protect_gpa = extra(4);
                if old_protect_gpa != 0 {
                    memory.write().unwrap()
                        .write_bytes(Gpa(old_protect_gpa), &4u32.to_le_bytes()); // PAGE_READWRITE
                }
                DispatchResult::Sync(status::SUCCESS as u64)
            }
            // ── 文件 ──────────────────────────────────────────
            "NtOpenFile" => {
                // a[0]=*FileHandle, a[1]=DesiredAccess, a[2]=ObjectAttributes
                // a[3]=IoStatusBlock, a[4]=ShareAccess, a[5]=OpenOptions
                let handle_out_gpa = extra(0);
                let access         = extra(1) as u32;
                let oa_gpa         = extra(2);
                let path = read_unicode_string(memory, oa_gpa);
                log::debug!("NtOpenFile: {}", path);
                let (st, h) = files.create(&path, access, 1 /* FILE_OPEN */);
                if st == 0 && handle_out_gpa != 0 {
                    memory.write().unwrap()
                        .write_bytes(Gpa(handle_out_gpa), &h.to_le_bytes());
                }
                DispatchResult::Sync(st)
            }
            "NtSetInformationFile" => {
                // Stub — most callers don't check return value for non-critical ops
                log::debug!("NtSetInformationFile: class={}", extra(4) as u32);
                DispatchResult::Sync(status::SUCCESS as u64)
            }
            "NtQueryDirectoryFile" => {
                // Stub — return STATUS_NO_MORE_FILES so callers stop iterating
                DispatchResult::Sync(status::NO_MORE_FILES as u64)
            }
            // ── Section / 映射 ────────────────────────────────
            "NtCreateSection" => {
                let handle_out_gpa = extra(0);
                let prot            = extra(4) as u32;
                let file_handle     = extra(6);
                log::debug!("NtCreateSection args: handle_out_gpa={:#x} prot={:#x} file={:#x} a={:?}",
                    handle_out_gpa, prot, file_handle, &a[..]);
                let size = if extra(3) != 0 {
                    let mem = memory.read().unwrap();
                    let b = mem.read_bytes(Gpa(extra(3)), 8);
                    u64::from_le_bytes(b.try_into().unwrap_or([0;8]))
                } else { 0 };
                let (st, h) = sections.create(file_handle, size, prot, files);
                if st == status::SUCCESS as u64 && handle_out_gpa != 0 {
                    memory.write().unwrap()
                        .write_bytes(Gpa(handle_out_gpa), &h.to_le_bytes());
                }
                log::debug!("NtCreateSection: status={:#x} handle={:#x}", st, h);
                DispatchResult::Sync(st)
            }
            "NtMapViewOfSection" => {
                // a[0]=SectionHandle, a[1]=ProcessHandle, a[2]=*BaseAddress
                // a[3]=ZeroBits, a[4]=CommitSize, a[5]=SectionOffset*
                // a[6]=ViewSize*, a[7]=InheritDisposition, a[8]=AllocationType
                // a[9]=Win32Protect
                let section_handle  = extra(0);
                log::debug!("NtMapViewOfSection: section_handle={:#x} args={:?}", section_handle, &args[..]);
                let base_ptr_gpa    = extra(2);
                let offset_ptr_gpa  = extra(5);
                let size_ptr_gpa    = extra(6);
                let prot            = extra(9) as u32;

                let base_hint = if base_ptr_gpa != 0 {
                    let mem = memory.read().unwrap();
                    let b = mem.read_bytes(Gpa(base_ptr_gpa), 8);
                    u64::from_le_bytes(b.try_into().unwrap_or([0;8]))
                } else { 0 };
                let offset = if offset_ptr_gpa != 0 {
                    let mem = memory.read().unwrap();
                    let b = mem.read_bytes(Gpa(offset_ptr_gpa), 8);
                    u64::from_le_bytes(b.try_into().unwrap_or([0;8]))
                } else { 0 };
                let map_size = if size_ptr_gpa != 0 {
                    let mem = memory.read().unwrap();
                    let b = mem.read_bytes(Gpa(size_ptr_gpa), 8);
                    u64::from_le_bytes(b.try_into().unwrap_or([0;8]))
                } else { 0 };

                let mut vs = vaspace.lock().unwrap();
                let mut mem = memory.write().unwrap();
                let (st, va) = sections.map_view(
                    section_handle, base_hint, map_size, offset, prot,
                    &mut vs, &mut mem,
                );
                drop(vs);
                drop(mem);
                if st == status::SUCCESS as u64 {
                    if base_ptr_gpa != 0 {
                        memory.write().unwrap()
                            .write_bytes(Gpa(base_ptr_gpa), &va.to_le_bytes());
                    }
                    if size_ptr_gpa != 0 {
                        // write back actual mapped size (we don't track it here, leave as-is)
                    }
                }
                log::debug!("NtMapViewOfSection: status={:#x} va={:#x}", st, va);
                DispatchResult::Sync(st)
            }
            "NtUnmapViewOfSection" => {
                // a[0]=ProcessHandle, a[1]=BaseAddress
                let base_va = extra(1);
                let st = sections.unmap_view(base_va, &mut vaspace.lock().unwrap());
                log::debug!("NtUnmapViewOfSection: status={:#x} va={:#x}", st, base_va);
                DispatchResult::Sync(st)
            }
            // ── 进程/线程创建 ─────────────────────────────────
            "NtCreateProcessEx" | "NtCreateProcess" => {
                log::warn!("NtCreateProcessEx: not supported");
                DispatchResult::Sync(status::NOT_IMPLEMENTED as u64)
            }
            "NtCreateThreadEx" | "NtCreateThread" => {
                log::warn!("NtCreateThreadEx: not supported in Phase 2");
                DispatchResult::Sync(status::NOT_IMPLEMENTED as u64)
            }
            // ── 句柄复制 ──────────────────────────────────────
            "NtDuplicateObject" => {
                // a[0]=SrcProcess, a[1]=SrcHandle, a[2]=DstProcess
                // a[3]=*DstHandle, a[4]=DesiredAccess, a[5]=HandleAttributes, a[6]=Options
                // Simple: copy the handle value as-is
                let src_handle = extra(1);
                let dst_gpa    = extra(3);
                if dst_gpa != 0 {
                    memory.write().unwrap()
                        .write_bytes(Gpa(dst_gpa), &src_handle.to_le_bytes());
                }
                DispatchResult::Sync(status::SUCCESS as u64)
            }
            // ── 对象查询 ──────────────────────────────────────
            "NtQueryObject" => {
                // Return minimal info; most callers just check status
                let ret_len_gpa = extra(4);
                if ret_len_gpa != 0 {
                    memory.write().unwrap()
                        .write_bytes(Gpa(ret_len_gpa), &0u32.to_le_bytes());
                }
                DispatchResult::Sync(status::SUCCESS as u64)
            }
            "NtQuerySystemInformation" => {
                // a[0]=SystemInformationClass, a[1]=buf, a[2]=len, a[3]=*ReturnLength
                let ret_len_gpa = extra(3);
                if ret_len_gpa != 0 {
                    memory.write().unwrap()
                        .write_bytes(Gpa(ret_len_gpa), &0u32.to_le_bytes());
                }
                log::debug!("NtQuerySystemInformation: class={}", extra(0) as u32);
                DispatchResult::Sync(status::SUCCESS as u64)
            }
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
fn read_unicode_string(
    memory: &std::sync::Arc<std::sync::RwLock<GuestMemory>>,
    oa_gpa: u64,
) -> String {
    if oa_gpa == 0 { return String::new(); }
    let mem = memory.read().unwrap();
    // OBJECT_ATTRIBUTES layout (64-bit):
    // +0x00 ULONG Length
    // +0x08 HANDLE RootDirectory
    // +0x10 PUNICODE_STRING ObjectName
    let on_ptr_bytes = mem.read_bytes(Gpa(oa_gpa + 0x10), 8);
    let on_gpa = u64::from_le_bytes(on_ptr_bytes.try_into().unwrap_or([0;8]));
    if on_gpa == 0 { return String::new(); }
    // UNICODE_STRING: +0 Length(u16), +2 MaxLength(u16), +8 Buffer(u64)
    let len_bytes = mem.read_bytes(Gpa(on_gpa), 2);
    let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
    let buf_bytes = mem.read_bytes(Gpa(on_gpa + 8), 8);
    let buf_gpa = u64::from_le_bytes(buf_bytes.try_into().unwrap_or([0;8]));
    if buf_gpa == 0 || len == 0 || len > 1024 { return String::new(); }
    let wchars = mem.read_bytes(Gpa(buf_gpa), len);
    // UTF-16LE → String
    let u16s: Vec<u16> = wchars.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

/// Read a UNICODE_STRING directly (pointer to UNICODE_STRING struct, not OBJECT_ATTRIBUTES)
fn read_unicode_string_direct(
    memory: &std::sync::Arc<std::sync::RwLock<GuestMemory>>,
    us_gpa: u64,
) -> String {
    if us_gpa == 0 { return String::new(); }
    let mem = memory.read().unwrap();
    let len_bytes = mem.read_bytes(Gpa(us_gpa), 2);
    let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
    let buf_bytes = mem.read_bytes(Gpa(us_gpa + 8), 8);
    let buf_gpa = u64::from_le_bytes(buf_bytes.try_into().unwrap_or([0;8]));
    if buf_gpa == 0 || len == 0 || len > 1024 { return String::new(); }
    let wchars = mem.read_bytes(Gpa(buf_gpa), len);
    let u16s: Vec<u16> = wchars.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

/// Encode KEY_VALUE_FULL_INFORMATION for NtQueryValueKey / NtEnumerateValueKey
fn encode_key_value_full(name: &str, val: &RegistryValue) -> Vec<u8> {
    let name_utf16: Vec<u16> = name.encode_utf16().collect();
    let name_bytes: Vec<u8> = name_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let (type_id, data_bytes) = encode_value_data(&val.data);
    // KEY_VALUE_FULL_INFORMATION:
    // +0  TitleIndex u32
    // +4  Type       u32
    // +8  DataOffset u32
    // +12 DataLength u32
    // +16 NameLength u32
    // +20 Name[1]   (variable)
    // data follows after name
    let name_len = name_bytes.len() as u32;
    let data_offset = 20 + name_len;
    let data_len = data_bytes.len() as u32;
    let mut out = Vec::with_capacity((data_offset + data_len) as usize);
    out.extend_from_slice(&0u32.to_le_bytes());          // TitleIndex
    out.extend_from_slice(&type_id.to_le_bytes());       // Type
    out.extend_from_slice(&data_offset.to_le_bytes());   // DataOffset
    out.extend_from_slice(&data_len.to_le_bytes());      // DataLength
    out.extend_from_slice(&name_len.to_le_bytes());      // NameLength
    out.extend_from_slice(&name_bytes);
    out.extend_from_slice(&data_bytes);
    out
}

/// Encode KEY_BASIC_INFORMATION for NtEnumerateKey
fn encode_key_basic_info(name: &str) -> Vec<u8> {
    let name_utf16: Vec<u16> = name.encode_utf16().collect();
    let name_bytes: Vec<u8> = name_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let name_len = name_bytes.len() as u32;
    // KEY_BASIC_INFORMATION:
    // +0  LastWriteTime LARGE_INTEGER (u64)
    // +8  TitleIndex    u32
    // +12 NameLength    u32
    // +16 Name[1]
    let mut out = Vec::with_capacity(16 + name_bytes.len());
    out.extend_from_slice(&0u64.to_le_bytes()); // LastWriteTime
    out.extend_from_slice(&0u32.to_le_bytes()); // TitleIndex
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(&name_bytes);
    out
}

fn encode_value_data(data: &RegistryValueData) -> (u32, Vec<u8>) {
    match data {
        RegistryValueData::String(s) => {
            let mut u: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            u.extend_from_slice(&[0, 0]);
            (REG_SZ, u)
        }
        RegistryValueData::ExpandString(s) => {
            let mut u: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            u.extend_from_slice(&[0, 0]);
            (REG_EXPAND_SZ, u)
        }
        RegistryValueData::Binary(b, ty) => (*ty, b.clone()),
        RegistryValueData::Dword(v) => (REG_DWORD, v.to_le_bytes().to_vec()),
        RegistryValueData::MultiString(parts) => {
            let mut u: Vec<u8> = Vec::new();
            for s in parts {
                u.extend(s.encode_utf16().flat_map(|c| c.to_le_bytes()));
                u.extend_from_slice(&[0, 0]);
            }
            u.extend_from_slice(&[0, 0]);
            (REG_MULTI_SZ, u)
        }
        RegistryValueData::Qword(v) => (REG_QWORD, v.to_le_bytes().to_vec()),
    }
}

fn decode_reg_value(type_id: u32, raw: &[u8]) -> RegistryValueData {
    match type_id {
        REG_SZ => {
            let u16s: Vec<u16> = raw.chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            RegistryValueData::String(String::from_utf16_lossy(&u16s).trim_end_matches('\0').to_string())
        }
        REG_EXPAND_SZ => {
            let u16s: Vec<u16> = raw.chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            RegistryValueData::ExpandString(String::from_utf16_lossy(&u16s).trim_end_matches('\0').to_string())
        }
        REG_DWORD if raw.len() >= 4 =>
            RegistryValueData::Dword(u32::from_le_bytes([raw[0],raw[1],raw[2],raw[3]])),
        REG_QWORD if raw.len() >= 8 =>
            RegistryValueData::Qword(u64::from_le_bytes(raw[..8].try_into().unwrap())),
        _ => RegistryValueData::Binary(raw.to_vec(), type_id),
    }
}
