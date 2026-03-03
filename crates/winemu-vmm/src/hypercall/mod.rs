use crate::file_io::FileTable;
use crate::host_file::HostFileTable;
use crate::hostcall::HostCallBroker;
use crate::memory::GuestMemory;
use crate::sched::sync::{EventObj, MutexObj, SemaphoreObj, SyncHandle, SyncObject};
use crate::sched::{SchedResult, Scheduler, ThreadId};
use crate::section::SectionTable;
use crate::syscall::{DispatchResult, SyscallDispatcher};
use crate::vaspace::VaSpace;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use winemu_shared::hostcall as hc;
use winemu_shared::nr;

// HOST_MMAP can be used before KERNEL_READY (guest DLL resolve during boot).
// Keep that early mapping away from kernel image/heap region to avoid clobbering.
const EARLY_HOST_MMAP_BASE: u64 = 0x5000_0000;
const MAX_HOSTCALL_EXT_BUF: usize = 256;

fn encode_completion(cpl: &crate::hostcall::HostCallCompletion) -> [u8; hc::CPL_SIZE] {
    let mut out = [0u8; hc::CPL_SIZE];
    out[0..8].copy_from_slice(&cpl.request_id.to_le_bytes());
    out[8..12].copy_from_slice(&cpl.host_result.to_le_bytes());
    out[12..16].copy_from_slice(&cpl.flags.to_le_bytes());
    out[16..24].copy_from_slice(&cpl.value0.to_le_bytes());
    out[24..32].copy_from_slice(&cpl.value1.to_le_bytes());
    out[32..40].copy_from_slice(&cpl.user_tag.to_le_bytes());
    out
}

fn decode_hostcall_submit_ext(
    memory: &Arc<RwLock<GuestMemory>>,
    ext_gpa: u64,
    ext_len: usize,
) -> Option<([u64; 4], u64)> {
    if ext_len < (4 * core::mem::size_of::<u64>())
        || ext_len > MAX_HOSTCALL_EXT_BUF
        || (ext_len & (core::mem::size_of::<u64>() - 1)) != 0
    {
        return None;
    }
    let words = {
        let mem = memory.read().ok()?;
        let bytes = mem.read_bytes(winemu_core::addr::Gpa(ext_gpa), ext_len);
        if bytes.len() < ext_len {
            return None;
        }
        let word_count = ext_len / core::mem::size_of::<u64>();
        let mut out = [0u64; 4];
        let mut i = 0usize;
        while i < 4 {
            let off = i * 8;
            out[i] = u64::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ]);
            i += 1;
        }
        let user_tag = if word_count >= 5 {
            let off = 4 * 8;
            u64::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ])
        } else {
            0
        };
        (out, user_tag)
    };
    Some(words)
}

fn append_u64_le(dst: &mut Vec<u8>, v: u64) -> bool {
    if dst.try_reserve(8).is_err() {
        return false;
    }
    dst.extend_from_slice(&v.to_le_bytes());
    true
}

fn encode_hostcall_stats(snap: &crate::hostcall::HostCallStatsSnapshot, dst_cap: usize) -> Vec<u8> {
    if dst_cap < hc::STATS_HEADER_SIZE {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut max_ops = (dst_cap - hc::STATS_HEADER_SIZE) / hc::STATS_OP_SIZE;
    if max_ops > snap.op_stats.len() {
        max_ops = snap.op_stats.len();
    }

    if !append_u64_le(&mut out, hc::STATS_VERSION)
        || !append_u64_le(&mut out, snap.submit_sync_total)
        || !append_u64_le(&mut out, snap.submit_async_total)
        || !append_u64_le(&mut out, snap.complete_sync_total)
        || !append_u64_le(&mut out, snap.complete_async_total)
        || !append_u64_le(&mut out, snap.cancel_total)
        || !append_u64_le(&mut out, snap.backpressure_total)
        || !append_u64_le(&mut out, snap.completion_queue_high_watermark as u64)
        || !append_u64_le(&mut out, max_ops as u64)
    {
        return Vec::new();
    }

    for op in snap.op_stats.iter().take(max_ops) {
        if !append_u64_le(&mut out, op.opcode)
            || !append_u64_le(&mut out, op.submit_sync)
            || !append_u64_le(&mut out, op.submit_async)
            || !append_u64_le(&mut out, op.complete_sync)
            || !append_u64_le(&mut out, op.complete_async)
            || !append_u64_le(&mut out, op.cancel)
            || !append_u64_le(&mut out, op.backpressure)
        {
            break;
        }
    }

    out
}

pub enum HypercallResult {
    Sync(u64),
    Sync2 { x0: u64, x1: u64 },
    Sched(SchedResult),
}

pub struct HypercallManager {
    syscall_table_toml: String,
    exe_image: Vec<u8>,
    exe_path: std::path::PathBuf,
    memory: Arc<RwLock<GuestMemory>>,
    vaspace: Arc<Mutex<VaSpace>>,
    phys_pool: Mutex<crate::phys::PhysPagePool>,
    files: FileTable,
    sections: SectionTable,
    pub sched: Arc<Scheduler>,
    syscall_disp: SyscallDispatcher,
    host_files: Arc<HostFileTable>,
    hostcall: HostCallBroker,
    mono_start: Instant,
}

impl HypercallManager {
    pub fn new(
        syscall_table_toml: String,
        memory: Arc<RwLock<GuestMemory>>,
        root: impl Into<std::path::PathBuf>,
        sched: Arc<Scheduler>,
        exe_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        let exe_path: std::path::PathBuf = exe_path.into();
        let exe_image = std::fs::read(&exe_path).unwrap_or_default();
        let root_path: std::path::PathBuf = root.into();
        let syscall_disp = SyscallDispatcher::new(&syscall_table_toml);
        let host_files = Arc::new(HostFileTable::new(root_path.clone()));
        let mut vaspace_init = VaSpace::new();
        vaspace_init.set_base(EARLY_HOST_MMAP_BASE);
        let vaspace = Arc::new(Mutex::new(vaspace_init));
        let hostcall = HostCallBroker::new(
            Arc::clone(&memory),
            Arc::clone(&host_files),
            Arc::clone(&vaspace),
            Arc::clone(&sched),
        );
        Self {
            syscall_table_toml,
            exe_image,
            exe_path,
            memory,
            vaspace,
            phys_pool: Mutex::new(crate::phys::PhysPagePool::new()),
            files: FileTable::new(root_path),
            sections: SectionTable::new(),
            sched,
            syscall_disp,
            host_files,
            hostcall,
            mono_start: Instant::now(),
        }
    }

    pub fn dispatch(&self, hypercall_nr: u64, args: [u64; 6], tid: ThreadId) -> HypercallResult {
        match hypercall_nr {
            nr::KERNEL_READY => {
                // args[0] = entry_va, args[1] = stack_va, args[2] = teb_gva, args[3] = heap_start
                let entry_va = args[0];
                let stack_va = args[1];
                let teb_gva = args[2];
                let heap_start = args[3];
                log::info!(
                    "Guest kernel ready: entry={:#x} stack={:#x} teb={:#x} heap={:#x}",
                    entry_va,
                    stack_va,
                    teb_gva,
                    heap_start
                );

                // Initialize user VaSpace from heap_start
                if heap_start != 0 {
                    self.vaspace.lock().unwrap().set_base(heap_start);
                }

                if entry_va == 0 {
                    // 内核就绪但无 EXE，等待（Phase 3 改为接收 EXE 路径）
                    return HypercallResult::Sync(0);
                }

                // 读取 PEB VA（TEB+0x60，参考 winemu-shared::teb::PEB）
                let peb_va = {
                    let mem = self.memory.read().unwrap();
                    let peb_off = winemu_shared::teb::PEB as u64;
                    let bytes = mem.read_bytes(winemu_core::addr::Gpa(teb_gva + peb_off), 8);
                    u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))
                };

                // 构建 Thread 0 上下文（参考 Wine signal_arm64.c call_init_thunk）
                // pc  = entry_va（Phase 3 改为 RtlUserThreadStart）
                // sp  = stack_va（teb->Tib.StackBase）
                // x0  = entry_va（RtlUserThreadStart 的第一个参数）
                // x1  = peb_va（arg）
                // x18 = teb_va（ARM64 thread register）
                let tid = self.sched.alloc_tid();
                let mut ctx = crate::sched::ThreadContext::default();
                ctx.gpr[32] = entry_va; // pc
                ctx.gpr[31] = stack_va; // sp
                ctx.gpr[0] = entry_va; // x0 = entry
                ctx.gpr[1] = peb_va; // x1 = peb
                ctx.gpr[18] = teb_gva; // x18 = teb (ARM64 thread register)
                ctx.pstate = 0x0; // EL0t
                self.sched.spawn(tid, ctx, teb_gva);
                log::info!("Thread 0 created: tid={} entry={:#x}", tid.0, entry_va);
                HypercallResult::Sync(tid.0 as u64)
            }
            nr::DEBUG_PRINT => {
                // args[0] = GPA of string, args[1] = length
                let gpa = winemu_core::addr::Gpa(args[0]);
                let len = args[1] as usize;
                if len > 0 && len <= 4096 {
                    let mem = self.memory.read().unwrap();
                    let bytes = mem.read_bytes(gpa, len);
                    if let Ok(s) = std::str::from_utf8(bytes) {
                        log::debug!("[guest] {}", s);
                    }
                }
                HypercallResult::Sync(0)
            }
            nr::LOAD_SYSCALL_TABLE => {
                if args[2] == 0 {
                    // Query: return exe image size
                    HypercallResult::Sync(self.exe_image.len() as u64)
                } else {
                    // Write exe image to guest memory at GPA args[0], max args[1] bytes
                    let gpa = winemu_core::addr::Gpa(args[0]);
                    let max_len = args[1] as usize;
                    let data = &self.exe_image;
                    let write_len = data.len().min(max_len);
                    if write_len > 0 {
                        let mut mem = self.memory.write().unwrap();
                        mem.write_bytes(gpa, &data[..write_len]);
                    }
                    log::debug!(
                        "LOAD_SYSCALL_TABLE(exe): wrote {} bytes to gpa={:#x}",
                        write_len,
                        args[0]
                    );
                    HypercallResult::Sync(write_len as u64)
                }
            }
            nr::LOAD_DLL_IMAGE | nr::GET_PROC_ADDRESS => HypercallResult::Sync(u64::MAX),
            nr::PROCESS_CREATE => {
                // args[0] = image_base_gva
                log::info!("PROCESS_CREATE: image_base={:#x}", args[0]);
                HypercallResult::Sync(0)
            }
            nr::PROCESS_EXIT => {
                let code = args[0] as u32;
                log::info!("PROCESS_EXIT: code={}", code);
                // Terminate the calling thread; vCPU loop will drain remaining threads
                HypercallResult::Sched(SchedResult::Exit(code))
            }
            nr::THREAD_CREATE => {
                // args[0] = entry_va, args[1] = stack_va
                // args[2] = arg (passed in x0), args[3] = teb_gva
                let entry_va = args[0];
                let stack_va = args[1];
                let arg = args[2];
                let teb_gva = args[3];
                if entry_va == 0 {
                    return HypercallResult::Sync(u64::MAX);
                }
                let new_tid = self.sched.alloc_tid();
                let mut ctx = crate::sched::ThreadContext::default();
                ctx.gpr[32] = entry_va;
                ctx.gpr[31] = stack_va;
                ctx.gpr[0] = arg;
                ctx.pstate = 0x0; // EL0t
                self.sched.spawn(new_tid, ctx, teb_gva);
                log::debug!(
                    "THREAD_CREATE: tid={} entry={:#x} stack={:#x}",
                    new_tid.0,
                    entry_va,
                    stack_va
                );
                HypercallResult::Sync(new_tid.0 as u64)
            }
            nr::THREAD_EXIT => {
                // args[0] = exit code
                let code = args[0] as u32;
                log::debug!("THREAD_EXIT: tid={} code={}", tid.0, code);
                HypercallResult::Sched(SchedResult::Exit(code))
            }
            nr::NT_ALLOC_VIRTUAL => {
                // args[0] = hint VA (0 = any), args[1] = size, args[2] = prot
                let hint = args[0];
                let size = args[1];
                let prot = args[2] as u32;
                let result = self.vaspace.lock().unwrap().alloc(hint, size, prot);
                match result {
                    Some(va) => {
                        log::debug!("NT_ALLOC_VIRTUAL: va={:#x} size={:#x}", va, size);
                        HypercallResult::Sync(va)
                    }
                    None => {
                        log::warn!("NT_ALLOC_VIRTUAL: out of VA space");
                        HypercallResult::Sync(0)
                    }
                }
            }
            nr::NT_FREE_VIRTUAL => {
                // args[0] = base VA
                let base = args[0];
                let ok = self.vaspace.lock().unwrap().free(base);
                log::debug!("NT_FREE_VIRTUAL: va={:#x} ok={}", base, ok);
                HypercallResult::Sync(if ok { 0 } else { u32::MAX as u64 })
            }
            nr::NT_QUERY_VIRTUAL => {
                // args[0] = addr to query
                // Returns: (base << 32 | size_pages) — simplified
                let addr = args[0];
                let result = self
                    .vaspace
                    .lock()
                    .unwrap()
                    .query(addr)
                    .map(|r| (r.base, r.size, r.prot));
                match result {
                    Some((base, size, prot)) => {
                        log::debug!(
                            "NT_QUERY_VIRTUAL: addr={:#x} base={:#x} size={:#x} prot={:#x}",
                            addr,
                            base,
                            size,
                            prot
                        );
                        HypercallResult::Sync(base)
                    }
                    None => HypercallResult::Sync(u64::MAX),
                }
            }
            nr::NT_PROTECT_VIRTUAL => {
                log::debug!(
                    "NT_PROTECT_VIRTUAL: va={:#x} size={:#x} prot={:#x}",
                    args[0],
                    args[1],
                    args[2]
                );
                HypercallResult::Sync(0)
            }
            nr::NT_CREATE_FILE => {
                // args[0] = GPA of NT path string, args[1] = path len
                // args[2] = access mask, args[3] = disposition
                let path_gpa = winemu_core::addr::Gpa(args[0]);
                let path_len = args[1] as usize;
                if path_len == 0 || path_len > 1024 {
                    return HypercallResult::Sync(crate::file_io::STATUS_OBJECT_NOT_FOUND);
                }
                let path = {
                    let mem = self.memory.read().unwrap();
                    let bytes = mem.read_bytes(path_gpa, path_len);
                    match std::str::from_utf8(bytes) {
                        Ok(s) => s.to_owned(),
                        Err(_) => {
                            return HypercallResult::Sync(crate::file_io::STATUS_OBJECT_NOT_FOUND)
                        }
                    }
                };
                let access = args[2] as u32;
                let disposition = args[3] as u32;
                let (status, handle) = self.files.create(&path, access, disposition);
                log::debug!(
                    "NT_CREATE_FILE: path={} status={:#x} handle={}",
                    path,
                    status,
                    handle
                );
                // Pack status in high 32 bits, handle in low 32 bits
                HypercallResult::Sync((status << 32) | handle)
            }
            nr::NT_READ_FILE => {
                // args[0] = handle, args[1] = GPA of buffer, args[2] = length
                // args[3] = offset (u64::MAX = use current position)
                let handle = args[0];
                let buf_gpa = winemu_core::addr::Gpa(args[1]);
                let length = args[2] as usize;
                let offset = if args[3] == u64::MAX {
                    None
                } else {
                    Some(args[3])
                };
                if length == 0 || length > 64 * 1024 * 1024 {
                    return HypercallResult::Sync(crate::file_io::STATUS_INVALID_HANDLE);
                }
                let mut buf = vec![0u8; length];
                let (status, n) = self.files.read(handle, &mut buf, offset);
                if status == crate::file_io::STATUS_SUCCESS && n > 0 {
                    let mut mem = self.memory.write().unwrap();
                    mem.write_bytes(buf_gpa, &buf[..n]);
                }
                log::debug!(
                    "NT_READ_FILE: handle={} n={} status={:#x}",
                    handle,
                    n,
                    status
                );
                HypercallResult::Sync((status << 32) | n as u64)
            }
            nr::NT_WRITE_FILE => {
                // args[0] = handle, args[1] = GPA of buffer, args[2] = length
                // args[3] = offset (u64::MAX = use current position)
                let handle = args[0];
                let buf_gpa = winemu_core::addr::Gpa(args[1]);
                let length = args[2] as usize;
                let offset = if args[3] == u64::MAX {
                    None
                } else {
                    Some(args[3])
                };
                if length == 0 || length > 64 * 1024 * 1024 {
                    return HypercallResult::Sync(crate::file_io::STATUS_INVALID_HANDLE);
                }
                let buf = {
                    let mem = self.memory.read().unwrap();
                    mem.read_bytes(buf_gpa, length).to_vec()
                };
                let (status, n) = self.files.write(handle, &buf, offset);
                log::debug!(
                    "NT_WRITE_FILE: handle={} n={} status={:#x}",
                    handle,
                    n,
                    status
                );
                HypercallResult::Sync((status << 32) | n as u64)
            }
            nr::NT_CLOSE => {
                let handle = args[0];
                // Try section handle first, then file handle
                if !self.sections.close(handle) {
                    let status = self.files.close(handle);
                    log::debug!("NT_CLOSE: handle={} status={:#x}", handle, status);
                    HypercallResult::Sync(status)
                } else {
                    log::debug!("NT_CLOSE: section handle={:#x}", handle);
                    HypercallResult::Sync(0)
                }
            }
            nr::NT_CREATE_SECTION => {
                // args: [file_handle, size, prot, 0, 0, 0]
                let file_handle = args[0];
                let size = args[1];
                let prot = args[2] as u32;
                let (status, handle) = self.sections.create(file_handle, size, prot, &self.files);
                log::debug!(
                    "NT_CREATE_SECTION: status={:#x} handle={:#x}",
                    status,
                    handle
                );
                HypercallResult::Sync((status << 32) | handle)
            }
            nr::NT_MAP_VIEW_OF_SECTION => {
                // args: [section_handle, base_hint, size, offset, prot, 0]
                let section_handle = args[0];
                let base_hint = args[1];
                let map_size = args[2];
                let offset = args[3];
                let prot = args[4] as u32;
                let mut vaspace = self.vaspace.lock().unwrap();
                let mut mem = self.memory.write().unwrap();
                let (status, va) = self.sections.map_view(
                    section_handle,
                    base_hint,
                    map_size,
                    offset,
                    prot,
                    &mut vaspace,
                    &mut mem,
                );
                log::debug!("NT_MAP_VIEW_OF_SECTION: status={:#x} va={:#x}", status, va);
                HypercallResult::Sync((status << 32) | va)
            }
            nr::NT_UNMAP_VIEW_OF_SECTION => {
                // args: [base_va, 0, 0, 0, 0, 0]
                let base_va = args[0];
                let mut vaspace = self.vaspace.lock().unwrap();
                let status = self.sections.unmap_view(base_va, &mut vaspace);
                log::debug!(
                    "NT_UNMAP_VIEW_OF_SECTION: status={:#x} va={:#x}",
                    status,
                    base_va
                );
                HypercallResult::Sync(status)
            }
            nr::NT_QUERY_INFO_FILE => {
                // args[0] = handle — returns file size
                let handle = args[0];
                let (status, size) = self.files.query_size(handle);
                log::debug!(
                    "NT_QUERY_INFO_FILE: handle={} size={} status={:#x}",
                    handle,
                    size,
                    status
                );
                HypercallResult::Sync((status << 32) | size)
            }
            // ── NT 同步对象 ──────────────────────────────────
            nr::NT_CREATE_EVENT => {
                // args[0] = manual_reset (1=manual, 0=auto), args[1] = initial_state
                let manual = args[0] != 0;
                let initial = args[1] != 0;
                let h = self.sched.alloc_handle();
                self.sched
                    .insert_object(h, SyncObject::Event(EventObj::new(manual, initial)));
                log::debug!(
                    "NT_CREATE_EVENT: handle={} manual={} initial={}",
                    h.0,
                    manual,
                    initial
                );
                HypercallResult::Sync(h.0 as u64)
            }
            nr::NT_SET_EVENT => {
                let h = SyncHandle(args[0] as u32);
                let shard = Scheduler::object_shard_pub(h);
                let woken = {
                    let mut objects = self.sched.objects[shard].lock().unwrap();
                    match objects.get_mut(&h) {
                        Some(SyncObject::Event(e)) => e.set(),
                        _ => return HypercallResult::Sync(0xC000_0008),
                    }
                };
                log::debug!("NT_SET_EVENT: handle={} woke={}", h.0, woken.len());
                self.sched.wake_waiters(woken);
                HypercallResult::Sync(0)
            }
            nr::NT_RESET_EVENT => {
                let h = SyncHandle(args[0] as u32);
                let shard = Scheduler::object_shard_pub(h);
                let mut objects = self.sched.objects[shard].lock().unwrap();
                match objects.get_mut(&h) {
                    Some(SyncObject::Event(e)) => {
                        e.reset();
                        HypercallResult::Sync(0)
                    }
                    _ => HypercallResult::Sync(0xC000_0008),
                }
            }
            nr::NT_CREATE_MUTEX => {
                // args[0] = initial_owner (1 = caller owns it)
                let owner = if args[0] != 0 { Some(tid) } else { None };
                let h = self.sched.alloc_handle();
                self.sched
                    .insert_object(h, SyncObject::Mutex(MutexObj::new(owner)));
                log::debug!("NT_CREATE_MUTEX: handle={} owner={:?}", h.0, owner);
                HypercallResult::Sync(h.0 as u64)
            }
            nr::NT_RELEASE_MUTEX => {
                let h = SyncHandle(args[0] as u32);
                let shard = Scheduler::object_shard_pub(h);
                let result = {
                    let mut objects = self.sched.objects[shard].lock().unwrap();
                    match objects.get_mut(&h) {
                        Some(SyncObject::Mutex(m)) => m.release(tid),
                        _ => return HypercallResult::Sync(0xC000_0008),
                    }
                };
                match result {
                    Ok(Some(next_tid)) => {
                        self.sched.wake_waiters(vec![next_tid]);
                        HypercallResult::Sync(0)
                    }
                    Ok(None) => HypercallResult::Sync(0),
                    Err(status) => HypercallResult::Sync(status),
                }
            }
            nr::NT_CREATE_SEMAPHORE => {
                // args[0] = initial_count, args[1] = maximum_count
                let initial = args[0] as i64;
                let maximum = args[1] as i64;
                let h = self.sched.alloc_handle();
                self.sched.insert_object(
                    h,
                    SyncObject::Semaphore(SemaphoreObj::new(initial, maximum)),
                );
                log::debug!(
                    "NT_CREATE_SEMAPHORE: handle={} initial={} max={}",
                    h.0,
                    initial,
                    maximum
                );
                HypercallResult::Sync(h.0 as u64)
            }
            nr::NT_RELEASE_SEMAPHORE => {
                // args[0] = handle, args[1] = release_count
                let h = SyncHandle(args[0] as u32);
                let n = args[1] as i64;
                let shard = Scheduler::object_shard_pub(h);
                let result = {
                    let mut objects = self.sched.objects[shard].lock().unwrap();
                    match objects.get_mut(&h) {
                        Some(SyncObject::Semaphore(s)) => s.release(n),
                        _ => return HypercallResult::Sync(0xC000_0008),
                    }
                };
                match result {
                    Ok(woken) => {
                        self.sched.wake_waiters(woken);
                        HypercallResult::Sync(0)
                    }
                    Err(status) => HypercallResult::Sync(status),
                }
            }
            nr::NT_WAIT_SINGLE => {
                // args[0] = handle, args[1] = timeout_100ns (i64 cast)
                let h = SyncHandle(args[0] as u32);
                let timeout = args[1] as i64;
                HypercallResult::Sched(self.sched.wait_single(tid, h, timeout))
            }
            nr::NT_WAIT_MULTIPLE => {
                // args[0] = GPA of handle array, args[1] = count
                // args[2] = wait_all, args[3] = timeout_100ns
                let arr_gpa = winemu_core::addr::Gpa(args[0]);
                let count = args[1] as usize;
                let wait_all = args[2] != 0;
                let timeout = args[3] as i64;
                if count == 0 || count > 64 {
                    return HypercallResult::Sync(0xC000_000D); // STATUS_INVALID_PARAMETER
                }
                let handles: Vec<SyncHandle> = {
                    let mem = self.memory.read().unwrap();
                    (0..count)
                        .map(|i| {
                            let gpa = winemu_core::addr::Gpa(arr_gpa.0 + i as u64 * 4);
                            let bytes = mem.read_bytes(gpa, 4);
                            let v = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                            SyncHandle(v)
                        })
                        .collect()
                };
                HypercallResult::Sched(self.sched.wait_multiple(tid, handles, wait_all, timeout))
            }
            nr::NT_CLOSE_HANDLE => {
                let h = SyncHandle(args[0] as u32);
                let ok = self.sched.close_handle(h);
                HypercallResult::Sync(if ok { 0 } else { 0xC000_0008 })
            }
            nr::NT_YIELD_EXECUTION => HypercallResult::Sched(SchedResult::Yield),
            nr::ALLOC_PHYS_PAGES => {
                let pages = args[0] as usize;
                if pages == 0 {
                    return HypercallResult::Sync(0);
                }
                let gpa = self
                    .phys_pool
                    .lock()
                    .unwrap()
                    .alloc_contiguous(pages)
                    .unwrap_or(0);
                log::debug!("ALLOC_PHYS_PAGES: pages={} gpa={:#x}", pages, gpa);
                HypercallResult::Sync(gpa)
            }
            nr::FREE_PHYS_PAGES => {
                let gpa = args[0];
                let pages = args[1] as usize;
                let ok = self.phys_pool.lock().unwrap().free_contiguous(gpa, pages);
                log::debug!("FREE_PHYS_PAGES: gpa={:#x} pages={} ok={}", gpa, pages, ok);
                HypercallResult::Sync(if ok { 0 } else { u64::MAX })
            }
            // ── Host 文件操作 ──────────────────────────────────
            nr::HOST_OPEN => {
                let (host_result, aux) =
                    match self
                        .hostcall
                        .submit(hc::OP_OPEN, 0, [args[0], args[1], args[2], 0], 0)
                    {
                        crate::hostcall::SubmitResult::Completed { host_result, aux } => {
                            (host_result, aux)
                        }
                        crate::hostcall::SubmitResult::Pending { .. } => (hc::HC_BUSY, 0),
                    };
                if host_result == hc::HC_OK {
                    HypercallResult::Sync(aux)
                } else {
                    HypercallResult::Sync(u64::MAX)
                }
            }
            nr::HOST_READ => {
                let (host_result, aux) = match self.hostcall.submit(
                    hc::OP_READ,
                    0,
                    [args[0], args[1], args[2], args[3]],
                    0,
                ) {
                    crate::hostcall::SubmitResult::Completed { host_result, aux } => {
                        (host_result, aux)
                    }
                    crate::hostcall::SubmitResult::Pending { .. } => (hc::HC_BUSY, 0),
                };
                if host_result == hc::HC_OK {
                    HypercallResult::Sync(aux)
                } else {
                    HypercallResult::Sync(0)
                }
            }
            nr::HOST_WRITE => {
                let (host_result, aux) = match self.hostcall.submit(
                    hc::OP_WRITE,
                    0,
                    [args[0], args[1], args[2], args[3]],
                    0,
                ) {
                    crate::hostcall::SubmitResult::Completed { host_result, aux } => {
                        (host_result, aux)
                    }
                    crate::hostcall::SubmitResult::Pending { .. } => (hc::HC_BUSY, 0),
                };
                if host_result == hc::HC_OK {
                    HypercallResult::Sync(aux)
                } else {
                    HypercallResult::Sync(0)
                }
            }
            nr::HOST_CLOSE => {
                let _ = self.hostcall.submit(hc::OP_CLOSE, 0, [args[0], 0, 0, 0], 0);
                HypercallResult::Sync(0)
            }
            nr::HOST_STAT => {
                let (host_result, aux) =
                    match self.hostcall.submit(hc::OP_STAT, 0, [args[0], 0, 0, 0], 0) {
                        crate::hostcall::SubmitResult::Completed { host_result, aux } => {
                            (host_result, aux)
                        }
                        crate::hostcall::SubmitResult::Pending { .. } => (hc::HC_BUSY, 0),
                    };
                if host_result == hc::HC_OK {
                    HypercallResult::Sync(aux)
                } else {
                    HypercallResult::Sync(0)
                }
            }
            nr::HOST_READDIR => {
                let (host_result, aux) = match self.hostcall.submit(
                    hc::OP_READDIR,
                    0,
                    [args[0], args[1], args[2], args[3]],
                    0,
                ) {
                    crate::hostcall::SubmitResult::Completed { host_result, aux } => {
                        (host_result, aux)
                    }
                    crate::hostcall::SubmitResult::Pending { .. } => (hc::HC_BUSY, 0),
                };
                if host_result == hc::HC_OK {
                    HypercallResult::Sync(aux)
                } else {
                    HypercallResult::Sync(u64::MAX)
                }
            }
            nr::HOST_NOTIFY_DIR => {
                let watch_tree = args[3] != 0;
                let completion_filter = args[4] as u32;
                let mut notify_opts = completion_filter as u64;
                if watch_tree {
                    notify_opts |= 1u64 << 63;
                }
                let (host_result, aux) = match self.hostcall.submit(
                    hc::OP_NOTIFY_DIR,
                    0,
                    [args[0], args[1], args[2], notify_opts],
                    0,
                ) {
                    crate::hostcall::SubmitResult::Completed { host_result, aux } => {
                        (host_result, aux)
                    }
                    crate::hostcall::SubmitResult::Pending { .. } => (hc::HC_BUSY, 0),
                };
                if host_result == hc::HC_OK {
                    HypercallResult::Sync(aux)
                } else {
                    HypercallResult::Sync(u64::MAX)
                }
            }
            nr::HOSTCALL_SUBMIT => {
                // args: [opcode, flags, arg0, arg1, arg2, arg3]
                let opcode = args[0];
                let flags = args[1];
                let mut submit_args = [args[2], args[3], args[4], args[5]];
                let mut user_tag = 0u64;
                if (flags & hc::FLAG_EXT_BUF) != 0 {
                    let ext_ptr = args[2];
                    let ext_len = args[3] as usize;
                    let Some((decoded_args, decoded_tag)) =
                        decode_hostcall_submit_ext(&self.memory, ext_ptr, ext_len)
                    else {
                        return HypercallResult::Sync2 {
                            x0: hc::HC_INVALID,
                            x1: 0,
                        };
                    };
                    submit_args = decoded_args;
                    user_tag = decoded_tag;
                }
                match self.hostcall.submit(opcode, flags, submit_args, user_tag) {
                    crate::hostcall::SubmitResult::Completed { host_result, aux } => {
                        HypercallResult::Sync2 {
                            x0: host_result,
                            x1: aux,
                        }
                    }
                    crate::hostcall::SubmitResult::Pending { request_id } => {
                        HypercallResult::Sync2 {
                            x0: hc::PENDING_RESULT,
                            x1: request_id,
                        }
                    }
                }
            }
            nr::HOSTCALL_SETUP => HypercallResult::Sync(hc::HC_OK),
            nr::HOSTCALL_CANCEL => {
                let request_id = args[0];
                HypercallResult::Sync(self.hostcall.cancel(request_id))
            }
            nr::HOSTCALL_POLL => {
                let dst_gpa = args[0];
                let cap = args[1] as usize;
                if cap == 0 {
                    return HypercallResult::Sync(0);
                }
                let batch = self.hostcall.poll_batch(cap.min(1));
                if batch.is_empty() {
                    return HypercallResult::Sync(0);
                }
                let mut mem = self.memory.write().unwrap();
                let bytes = encode_completion(&batch[0]);
                mem.write_bytes(winemu_core::addr::Gpa(dst_gpa), &bytes);
                HypercallResult::Sync(1)
            }
            nr::HOSTCALL_POLL_BATCH => {
                let dst_gpa = args[0];
                let cap_entries = args[1] as usize;
                if cap_entries == 0 {
                    return HypercallResult::Sync(0);
                }
                let batch = self.hostcall.poll_batch(cap_entries);
                if batch.is_empty() {
                    return HypercallResult::Sync(0);
                }
                let mut mem = self.memory.write().unwrap();
                let mut off = 0u64;
                for cpl in batch.iter() {
                    let bytes = encode_completion(cpl);
                    mem.write_bytes(winemu_core::addr::Gpa(dst_gpa + off), &bytes);
                    off += hc::CPL_SIZE as u64;
                }
                HypercallResult::Sync(batch.len() as u64)
            }
            nr::HOSTCALL_QUERY_STATS => {
                let dst_gpa = args[0];
                let dst_len = args[1] as usize;
                let flags = args[2];
                if dst_len < hc::STATS_HEADER_SIZE {
                    return HypercallResult::Sync(0);
                }
                let snap = self.hostcall.stats_snapshot();
                let bytes = encode_hostcall_stats(&snap, dst_len);
                if bytes.is_empty() {
                    return HypercallResult::Sync(0);
                }
                let mut mem = self.memory.write().unwrap();
                mem.write_bytes(winemu_core::addr::Gpa(dst_gpa), &bytes);
                if (flags & hc::STATS_RESET_AFTER_READ) != 0 {
                    self.hostcall.reset_stats();
                }
                HypercallResult::Sync(bytes.len() as u64)
            }
            nr::HOST_MMAP => {
                let (host_result, aux) = match self.hostcall.submit(
                    hc::OP_MMAP,
                    0,
                    [args[0], args[1], args[2], args[3]],
                    0,
                ) {
                    crate::hostcall::SubmitResult::Completed { host_result, aux } => {
                        (host_result, aux)
                    }
                    crate::hostcall::SubmitResult::Pending { .. } => (hc::HC_BUSY, 0),
                };
                if host_result == hc::HC_OK {
                    HypercallResult::Sync(aux)
                } else {
                    HypercallResult::Sync(0)
                }
            }
            nr::HOST_MUNMAP => {
                let (host_result, _) =
                    match self
                        .hostcall
                        .submit(hc::OP_MUNMAP, 0, [args[0], args[1], 0, 0], 0)
                    {
                        crate::hostcall::SubmitResult::Completed { host_result, aux } => {
                            (host_result, aux)
                        }
                        crate::hostcall::SubmitResult::Pending { .. } => (hc::HC_BUSY, 0),
                    };
                HypercallResult::Sync(if host_result == hc::HC_OK {
                    0
                } else {
                    u64::MAX
                })
            }
            nr::QUERY_EXE_INFO => {
                let fd = self.host_files.open_absolute(&self.exe_path, 0);
                if fd == u64::MAX {
                    log::error!("QUERY_EXE_INFO: failed to open {:?}", self.exe_path);
                    return HypercallResult::Sync(u64::MAX);
                }
                let size = self.host_files.stat(fd);
                log::info!("QUERY_EXE_INFO: fd={} size={:#x}", fd, size);
                HypercallResult::Sync(fd | (size << 32))
            }
            nr::QUERY_MONO_TIME => {
                let elapsed = self.mono_start.elapsed();
                HypercallResult::Sync((elapsed.as_nanos() / 100) as u64)
            }
            nr::QUERY_SYSTEM_TIME => {
                const NT_EPOCH_OFFSET_100NS: u64 = 116_444_736_000_000_000;
                let unix_100ns = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| (d.as_nanos() / 100) as u64)
                    .unwrap_or(0);
                HypercallResult::Sync(unix_100ns.saturating_add(NT_EPOCH_OFFSET_100NS))
            }
            _ => {
                log::warn!("unhandled hypercall nr={:#x}", hypercall_nr);
                HypercallResult::Sync(u32::MAX as u64)
            }
        }
    }

    pub fn pump_hostcall_main_thread(&self, max_jobs: usize) -> usize {
        self.hostcall.run_main_thread_budget(max_jobs)
    }

    /// Read EL0 return context snapshot from guest SVC frame (SP_EL1 at hvc time).
    ///
    /// New guest `SvcFrame` layout (winemu-kernel `sched::dispatch::SvcFrame`):
    /// - elr_orig  @ +0x100
    /// - spsr_orig @ +0x108
    /// - x11_orig  @ +0x058
    /// - x12_orig  @ +0x060
    /// - x9_orig   @ +0x048
    /// - x10_orig  @ +0x050
    /// - x29_orig  @ +0x0e8
    /// - x30_orig  @ +0x0f0
    ///
    /// Return order remains:
    /// [elr_orig, spsr_orig, x11_orig, x12_orig, x9_orig, x10_orig, x29_orig, x30_orig]
    pub fn read_svc_stack(&self, svc_sp: u64) -> [u64; 8] {
        let mem = self.memory.read().unwrap();
        let read_u64 = |off: u64| -> u64 {
            let b = mem.read_bytes(winemu_core::addr::Gpa(svc_sp + off), 8);
            u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
        };
        [
            read_u64(0x100), // elr_orig
            read_u64(0x108), // spsr_orig
            read_u64(0x058), // x11_orig
            read_u64(0x060), // x12_orig
            read_u64(0x048), // x9_orig
            read_u64(0x050), // x10_orig
            read_u64(0x0e8), // x29_orig
            read_u64(0x0f0), // x30_orig
        ]
    }

    /// NT_SYSCALL with full register layout:
    /// args = [syscall_nr, table_nr, x0, x1, x2, x3, x4, x5, x6, x7]
    /// guest_sp = user stack pointer at SVC time
    pub fn dispatch_nt_syscall(
        &self,
        args: [u64; 10],
        guest_sp: u64,
        tid: ThreadId,
    ) -> HypercallResult {
        let syscall_nr = args[0];
        let table_nr = args[1];
        let dispatch_args = [syscall_nr, table_nr, args[2], args[3], args[4], args[5]];
        let result = self.syscall_disp.dispatch_full(
            dispatch_args,
            [args[6], args[7], args[8], args[9]],
            tid,
            &self.memory,
            &self.files,
            &self.sections,
            &self.sched,
            &self.vaspace,
            guest_sp,
        );
        match result {
            DispatchResult::Sync(v) => HypercallResult::Sync(v),
            DispatchResult::Sched(s) => HypercallResult::Sched(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::decode_hostcall_submit_ext;
    use super::encode_hostcall_stats;
    use crate::hostcall::{HostCallOpStats, HostCallStatsSnapshot};
    use crate::memory::GuestMemory;
    use std::sync::{Arc, RwLock};
    use winemu_core::addr::Gpa;
    use winemu_shared::hostcall as hc;

    #[test]
    fn decode_submit_ext_reads_args_and_user_tag() {
        let memory = Arc::new(RwLock::new(GuestMemory::new(1024 * 1024).unwrap()));
        let base = memory.read().unwrap().base_gpa().0;
        let ptr = base + 0x2000;
        let words = [0x11u64, 0x22, 0x33, 0x44, 0x55AA55AA];
        let mut bytes = [0u8; hc::EXT_SUBMIT_SIZE];
        for (i, w) in words.iter().enumerate() {
            let off = i * 8;
            bytes[off..off + 8].copy_from_slice(&w.to_le_bytes());
        }
        memory.write().unwrap().write_bytes(Gpa(ptr), &bytes);

        let decoded = decode_hostcall_submit_ext(&memory, ptr, hc::EXT_SUBMIT_SIZE)
            .expect("decode ext submit payload");
        assert_eq!(decoded.0, [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(decoded.1, 0x55AA55AA);
    }

    #[test]
    fn decode_submit_ext_rejects_short_payload() {
        let memory = Arc::new(RwLock::new(GuestMemory::new(1024 * 1024).unwrap()));
        let base = memory.read().unwrap().base_gpa().0;
        assert!(decode_hostcall_submit_ext(&memory, base + 0x1000, 16).is_none());
    }

    #[test]
    fn decode_submit_ext_supports_variable_word_count() {
        let memory = Arc::new(RwLock::new(GuestMemory::new(1024 * 1024).unwrap()));
        let base = memory.read().unwrap().base_gpa().0;
        let ptr = base + 0x2400;
        let words = [0x1u64, 0x2, 0x3, 0x4, 0xA5A5, 0xB6B6, 0xC7C7];
        let mut bytes = [0u8; 56];
        for (i, w) in words.iter().enumerate() {
            let off = i * 8;
            bytes[off..off + 8].copy_from_slice(&w.to_le_bytes());
        }
        memory.write().unwrap().write_bytes(Gpa(ptr), &bytes);
        let decoded =
            decode_hostcall_submit_ext(&memory, ptr, bytes.len()).expect("decode variable ext");
        assert_eq!(decoded.0, [1, 2, 3, 4]);
        assert_eq!(decoded.1, 0xA5A5);
    }

    #[test]
    fn encode_hostcall_stats_respects_capacity() {
        let mut snap = HostCallStatsSnapshot {
            submit_sync_total: 1,
            submit_async_total: 2,
            complete_sync_total: 3,
            complete_async_total: 4,
            cancel_total: 5,
            backpressure_total: 6,
            completion_queue_high_watermark: 7,
            op_stats: Vec::new(),
        };
        snap.op_stats.push(HostCallOpStats {
            opcode: hc::OP_OPEN,
            submit_sync: 11,
            submit_async: 12,
            complete_sync: 13,
            complete_async: 14,
            cancel: 15,
            backpressure: 16,
        });
        snap.op_stats.push(HostCallOpStats {
            opcode: hc::OP_READ,
            submit_sync: 21,
            submit_async: 22,
            complete_sync: 23,
            complete_async: 24,
            cancel: 25,
            backpressure: 26,
        });

        let one_op_cap = hc::STATS_HEADER_SIZE + hc::STATS_OP_SIZE;
        let one_op = encode_hostcall_stats(&snap, one_op_cap);
        assert_eq!(one_op.len(), one_op_cap);
        let op_count = u64::from_le_bytes(one_op[64..72].try_into().unwrap());
        assert_eq!(op_count, 1);

        let full_cap = hc::STATS_HEADER_SIZE + hc::STATS_OP_SIZE * 4;
        let full = encode_hostcall_stats(&snap, full_cap);
        assert_eq!(full.len(), hc::STATS_HEADER_SIZE + hc::STATS_OP_SIZE * 2);
        let op_count = u64::from_le_bytes(full[64..72].try_into().unwrap());
        assert_eq!(op_count, 2);
    }
}
