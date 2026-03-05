use super::types::{HostCallCompletion, HostCallOpStats, HostCallStatsSnapshot, SubmitResult};
use crate::host_file::HostFileTable;
use crate::memory::GuestMemory;
use crate::sched::Scheduler;
use crate::vaspace::VaSpace;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;
use winemu_core::addr::Gpa;
use winemu_shared::hostcall as hc;
use winemu_shared::status;

const DEFAULT_IO_QUEUE_CAP: usize = 4096;
const DEFAULT_MAIN_QUEUE_CAP: usize = 1024;
const COMPLETION_WARN_HWM: usize = 2048;
const MAX_HOST_PATH: usize = 1024;
const MAX_IO_SIZE: usize = 64 * 1024 * 1024;
const MAX_DIR_BUF: usize = 4096;
const NOTIFY_OPT_WATCH_TREE: u64 = 1u64 << 63;
const NOTIFY_OPT_FILTER_MASK: u64 = 0xFFFF_FFFF;

#[derive(Clone)]
pub struct HostCallBroker {
    inner: Arc<BrokerInner>,
}

struct BrokerInner {
    memory: Arc<RwLock<GuestMemory>>,
    host_files: Arc<HostFileTable>,
    vaspace: Arc<Mutex<VaSpace>>,
    scheduler: Arc<Scheduler>,
    io_submit_tx: SyncSender<WorkerJob>,
    main_submit_tx: SyncSender<WorkerJob>,
    main_submit_rx: Mutex<Receiver<WorkerJob>>,
    inflight: Mutex<HashMap<u64, InflightReq>>,
    completions: Mutex<VecDeque<HostCallCompletion>>,
    next_request_id: AtomicU64,
    stats: BrokerStats,
    completion_queue_hwm: AtomicU64,
}

#[derive(Clone)]
struct InflightReq {
    cancel: Arc<AtomicBool>,
    opcode: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ExecClass {
    Io,
    MainThread,
}

#[derive(Clone, Copy)]
enum QueueSendError {
    Full,
    Disconnected,
}

struct OpCounters {
    submit_sync: AtomicU64,
    submit_async: AtomicU64,
    complete_sync: AtomicU64,
    complete_async: AtomicU64,
    cancel: AtomicU64,
    backpressure: AtomicU64,
}

impl OpCounters {
    fn new() -> Self {
        Self {
            submit_sync: AtomicU64::new(0),
            submit_async: AtomicU64::new(0),
            complete_sync: AtomicU64::new(0),
            complete_async: AtomicU64::new(0),
            cancel: AtomicU64::new(0),
            backpressure: AtomicU64::new(0),
        }
    }
}

struct BrokerStats {
    submit_sync_total: AtomicU64,
    submit_async_total: AtomicU64,
    complete_sync_total: AtomicU64,
    complete_async_total: AtomicU64,
    cancel_total: AtomicU64,
    backpressure_total: AtomicU64,
    per_op: Vec<OpCounters>,
}

impl BrokerStats {
    fn new() -> Self {
        let mut per_op = Vec::new();
        let max_opcode = hc::OP_WIN32K_CALL as usize;
        if per_op.try_reserve(max_opcode + 1).is_ok() {
            for _ in 0..=max_opcode {
                per_op.push(OpCounters::new());
            }
        }
        Self {
            submit_sync_total: AtomicU64::new(0),
            submit_async_total: AtomicU64::new(0),
            complete_sync_total: AtomicU64::new(0),
            complete_async_total: AtomicU64::new(0),
            cancel_total: AtomicU64::new(0),
            backpressure_total: AtomicU64::new(0),
            per_op,
        }
    }

    fn with_op(&self, opcode: u64, f: impl FnOnce(&OpCounters)) {
        let idx = opcode as usize;
        if idx < self.per_op.len() {
            f(&self.per_op[idx]);
        }
    }

    fn on_submit_sync(&self, opcode: u64) {
        self.submit_sync_total.fetch_add(1, Ordering::Relaxed);
        self.with_op(opcode, |op| {
            op.submit_sync.fetch_add(1, Ordering::Relaxed);
        });
    }

    fn on_submit_async(&self, opcode: u64) {
        self.submit_async_total.fetch_add(1, Ordering::Relaxed);
        self.with_op(opcode, |op| {
            op.submit_async.fetch_add(1, Ordering::Relaxed);
        });
    }

    fn on_complete_sync(&self, opcode: u64) {
        self.complete_sync_total.fetch_add(1, Ordering::Relaxed);
        self.with_op(opcode, |op| {
            op.complete_sync.fetch_add(1, Ordering::Relaxed);
        });
    }

    fn on_complete_async(&self, opcode: u64) {
        self.complete_async_total.fetch_add(1, Ordering::Relaxed);
        self.with_op(opcode, |op| {
            op.complete_async.fetch_add(1, Ordering::Relaxed);
        });
    }

    fn on_cancel(&self, opcode: u64) {
        self.cancel_total.fetch_add(1, Ordering::Relaxed);
        self.with_op(opcode, |op| {
            op.cancel.fetch_add(1, Ordering::Relaxed);
        });
    }

    fn on_backpressure(&self, opcode: u64) {
        self.backpressure_total.fetch_add(1, Ordering::Relaxed);
        self.with_op(opcode, |op| {
            op.backpressure.fetch_add(1, Ordering::Relaxed);
        });
    }

    fn reset(&self) {
        self.submit_sync_total.store(0, Ordering::Relaxed);
        self.submit_async_total.store(0, Ordering::Relaxed);
        self.complete_sync_total.store(0, Ordering::Relaxed);
        self.complete_async_total.store(0, Ordering::Relaxed);
        self.cancel_total.store(0, Ordering::Relaxed);
        self.backpressure_total.store(0, Ordering::Relaxed);
        for op in self.per_op.iter() {
            op.submit_sync.store(0, Ordering::Relaxed);
            op.submit_async.store(0, Ordering::Relaxed);
            op.complete_sync.store(0, Ordering::Relaxed);
            op.complete_async.store(0, Ordering::Relaxed);
            op.cancel.store(0, Ordering::Relaxed);
            op.backpressure.store(0, Ordering::Relaxed);
        }
    }
}

enum WorkerPayload {
    None,
    Path(Box<str>),
    Bytes(Box<[u8]>),
}

struct WorkerJob {
    request_id: u64,
    opcode: u64,
    args: [u64; 4],
    payload: WorkerPayload,
    user_tag: u64,
    cancel: Arc<AtomicBool>,
    exec_class: ExecClass,
}

impl HostCallBroker {
    pub fn new(
        memory: Arc<RwLock<GuestMemory>>,
        host_files: Arc<HostFileTable>,
        vaspace: Arc<Mutex<VaSpace>>,
        scheduler: Arc<Scheduler>,
    ) -> Self {
        let (io_tx, io_rx) = sync_channel(DEFAULT_IO_QUEUE_CAP);
        let (main_tx, main_rx) = sync_channel(DEFAULT_MAIN_QUEUE_CAP);
        let inner = Arc::new(BrokerInner {
            memory,
            host_files,
            vaspace,
            scheduler,
            io_submit_tx: io_tx,
            main_submit_tx: main_tx,
            main_submit_rx: Mutex::new(main_rx),
            inflight: Mutex::new(HashMap::new()),
            completions: Mutex::new(VecDeque::new()),
            next_request_id: AtomicU64::new(1),
            stats: BrokerStats::new(),
            completion_queue_hwm: AtomicU64::new(0),
        });
        spawn_workers(Arc::clone(&inner), io_rx);
        Self { inner }
    }

    pub fn submit(&self, opcode: u64, flags: u64, args: [u64; 4], user_tag: u64) -> SubmitResult {
        if !is_supported_opcode(opcode) {
            return SubmitResult::Completed {
                host_result: hc::HC_INVALID,
                aux: 0,
            };
        }

        if !should_async(opcode, flags, args) {
            let (host_result, aux) = execute_sync(&self.inner, opcode, args, None);
            self.inner.stats.on_submit_sync(opcode);
            self.inner.stats.on_complete_sync(opcode);
            return SubmitResult::Completed { host_result, aux };
        }

        let request_id = self
            .inner
            .next_request_id
            .fetch_add(1, Ordering::Relaxed)
            .max(1);
        let cancel = Arc::new(AtomicBool::new(false));
        let payload = match prepare_async_payload(&self.inner, opcode, args) {
            Ok(v) => v,
            Err((host_result, aux)) => {
                self.inner.stats.on_submit_sync(opcode);
                self.inner.stats.on_complete_sync(opcode);
                return SubmitResult::Completed { host_result, aux };
            }
        };
        self.inner.inflight.lock().unwrap().insert(
            request_id,
            InflightReq {
                cancel: Arc::clone(&cancel),
                opcode,
            },
        );

        let job = WorkerJob {
            request_id,
            opcode,
            args,
            payload,
            user_tag,
            cancel,
            exec_class: route_exec_class(flags),
        };
        self.inner.stats.on_submit_async(opcode);
        match enqueue_job(&self.inner, job) {
            Ok(()) => SubmitResult::Pending { request_id },
            Err(QueueSendError::Full) => {
                self.inner.inflight.lock().unwrap().remove(&request_id);
                self.inner.stats.on_backpressure(opcode);
                SubmitResult::Completed {
                    host_result: hc::HC_BUSY,
                    aux: 0,
                }
            }
            Err(QueueSendError::Disconnected) => {
                self.inner.inflight.lock().unwrap().remove(&request_id);
                SubmitResult::Completed {
                    host_result: hc::HC_IO_ERROR,
                    aux: 0,
                }
            }
        }
    }

    pub fn cancel(&self, request_id: u64) -> u64 {
        let inflight = self.inner.inflight.lock().unwrap();
        let Some(req) = inflight.get(&request_id) else {
            return hc::HC_INVALID;
        };
        req.cancel.store(true, Ordering::Release);
        self.inner.stats.on_cancel(req.opcode);
        hc::HC_OK
    }

    pub fn poll_batch(&self, max_entries: usize) -> Vec<HostCallCompletion> {
        if max_entries == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut queue = self.inner.completions.lock().unwrap();
        let target = max_entries.min(queue.len());
        if out.try_reserve(target).is_err() {
            return Vec::new();
        }
        for _ in 0..target {
            if let Some(cpl) = queue.pop_front() {
                out.push(cpl);
            }
        }
        out
    }

    pub fn stats_snapshot(&self) -> HostCallStatsSnapshot {
        let mut op_stats = Vec::new();
        if op_stats.try_reserve(self.inner.stats.per_op.len()).is_ok() {
            for (opcode, counters) in self.inner.stats.per_op.iter().enumerate() {
                let snap = HostCallOpStats {
                    opcode: opcode as u64,
                    submit_sync: counters.submit_sync.load(Ordering::Relaxed),
                    submit_async: counters.submit_async.load(Ordering::Relaxed),
                    complete_sync: counters.complete_sync.load(Ordering::Relaxed),
                    complete_async: counters.complete_async.load(Ordering::Relaxed),
                    cancel: counters.cancel.load(Ordering::Relaxed),
                    backpressure: counters.backpressure.load(Ordering::Relaxed),
                };
                if snap.submit_sync != 0
                    || snap.submit_async != 0
                    || snap.complete_sync != 0
                    || snap.complete_async != 0
                    || snap.cancel != 0
                    || snap.backpressure != 0
                {
                    op_stats.push(snap);
                }
            }
        }
        HostCallStatsSnapshot {
            submit_sync_total: self.inner.stats.submit_sync_total.load(Ordering::Relaxed),
            submit_async_total: self.inner.stats.submit_async_total.load(Ordering::Relaxed),
            complete_sync_total: self.inner.stats.complete_sync_total.load(Ordering::Relaxed),
            complete_async_total: self
                .inner
                .stats
                .complete_async_total
                .load(Ordering::Relaxed),
            cancel_total: self.inner.stats.cancel_total.load(Ordering::Relaxed),
            backpressure_total: self.inner.stats.backpressure_total.load(Ordering::Relaxed),
            completion_queue_high_watermark: self.inner.completion_queue_hwm.load(Ordering::Relaxed)
                as usize,
            op_stats,
        }
    }

    pub fn run_main_thread_budget(&self, max_jobs: usize) -> usize {
        if max_jobs == 0 {
            return 0;
        }
        let mut processed = 0usize;
        loop {
            if processed >= max_jobs {
                break;
            }
            let recv = {
                let rx = self.inner.main_submit_rx.lock().unwrap();
                rx.try_recv()
            };
            let job = match recv {
                Ok(job) => job,
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            };
            let cpl = execute_job(&self.inner, &job);
            self.inner.inflight.lock().unwrap().remove(&job.request_id);
            self.inner.stats.on_complete_async(job.opcode);
            enqueue_completion(&self.inner, cpl);
            processed += 1;
        }
        processed
    }

    pub fn reset_stats(&self) {
        self.inner.stats.reset();
        self.inner.completion_queue_hwm.store(0, Ordering::Relaxed);
    }
}

fn is_supported_opcode(opcode: u64) -> bool {
    matches!(
        opcode,
        hc::OP_OPEN
            | hc::OP_READ
            | hc::OP_WRITE
            | hc::OP_CLOSE
            | hc::OP_STAT
            | hc::OP_READDIR
            | hc::OP_NOTIFY_DIR
            | hc::OP_MMAP
            | hc::OP_MUNMAP
            | hc::OP_WIN32K_CALL
    )
}

fn should_async(opcode: u64, flags: u64, args: [u64; 4]) -> bool {
    if (flags & hc::FLAG_FORCE_ASYNC) != 0 {
        return true;
    }
    if (flags & hc::FLAG_MAIN_THREAD) != 0 {
        return true;
    }
    if (flags & hc::FLAG_ALLOW_ASYNC) == 0 {
        return false;
    }
    match opcode {
        hc::OP_OPEN | hc::OP_STAT | hc::OP_READDIR => true,
        hc::OP_NOTIFY_DIR => true,
        hc::OP_READ | hc::OP_WRITE => (args[2] as usize) >= 128 * 1024,
        hc::OP_MMAP => (args[2] as usize) >= 2 * 1024 * 1024,
        _ => false,
    }
}

fn route_exec_class(flags: u64) -> ExecClass {
    if (flags & hc::FLAG_MAIN_THREAD) != 0 {
        ExecClass::MainThread
    } else {
        ExecClass::Io
    }
}

fn enqueue_job(inner: &Arc<BrokerInner>, job: WorkerJob) -> Result<(), QueueSendError> {
    let sender = match job.exec_class {
        ExecClass::Io => &inner.io_submit_tx,
        ExecClass::MainThread => &inner.main_submit_tx,
    };
    match sender.try_send(job) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => Err(QueueSendError::Full),
        Err(TrySendError::Disconnected(_)) => Err(QueueSendError::Disconnected),
    }
}

fn prepare_async_payload(
    inner: &Arc<BrokerInner>,
    opcode: u64,
    args: [u64; 4],
) -> Result<WorkerPayload, (u64, u64)> {
    match opcode {
        hc::OP_OPEN => {
            let path = decode_guest_path(&inner.memory, args[0], args[1] as usize)?;
            Ok(WorkerPayload::Path(path.into_boxed_str()))
        }
        hc::OP_WRITE => {
            let len = args[2] as usize;
            if len == 0 {
                return Ok(WorkerPayload::Bytes(Box::new([])));
            }
            if len > MAX_IO_SIZE {
                return Err((hc::HC_INVALID, 0));
            }
            let src = args[1];
            let data = {
                let mem = inner.memory.read().unwrap();
                mem.read_bytes(Gpa(src), len).to_vec().into_boxed_slice()
            };
            Ok(WorkerPayload::Bytes(data))
        }
        _ => Ok(WorkerPayload::None),
    }
}

fn spawn_workers(inner: Arc<BrokerInner>, io_rx: Receiver<WorkerJob>) {
    let io_workers = num_cpus::get().clamp(2, 8);
    let io_rx = Arc::new(Mutex::new(io_rx));
    for worker_idx in 0..io_workers {
        let inner_ref = Arc::clone(&inner);
        let rx_ref = Arc::clone(&io_rx);
        let _ = thread::Builder::new()
            .name(format!("hostcall-io-{worker_idx}"))
            .spawn(move || worker_loop(inner_ref, rx_ref));
    }
}

fn worker_loop(inner: Arc<BrokerInner>, rx: Arc<Mutex<Receiver<WorkerJob>>>) {
    loop {
        let job = {
            let guard = rx.lock().unwrap();
            guard.recv()
        };
        let Ok(job) = job else {
            return;
        };
        let cpl = execute_job(&inner, &job);
        inner.inflight.lock().unwrap().remove(&job.request_id);
        inner.stats.on_complete_async(job.opcode);
        enqueue_completion(&inner, cpl);
    }
}

fn enqueue_completion(inner: &Arc<BrokerInner>, cpl: HostCallCompletion) {
    let mut queue = inner.completions.lock().unwrap();
    queue.push_back(cpl);
    let qlen = queue.len() as u64;
    let mut cur_hwm = inner.completion_queue_hwm.load(Ordering::Relaxed);
    while qlen > cur_hwm
        && inner
            .completion_queue_hwm
            .compare_exchange(cur_hwm, qlen, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        cur_hwm = inner.completion_queue_hwm.load(Ordering::Relaxed);
    }
    if qlen as usize == COMPLETION_WARN_HWM {
        log::warn!("hostcall completion queue reached high-watermark: {}", qlen);
    }
    inner.scheduler.request_external_irq();
}

fn make_completion(
    job: &WorkerJob,
    host_result: u64,
    flags: u32,
    value0: u64,
    value1: u64,
) -> HostCallCompletion {
    HostCallCompletion {
        request_id: job.request_id,
        host_result: host_result.min(i32::MAX as u64) as i32,
        flags,
        value0,
        value1,
        user_tag: job.user_tag,
    }
}

fn execute_job(inner: &Arc<BrokerInner>, job: &WorkerJob) -> HostCallCompletion {
    let mut cpl_flags = 0u32;
    if job.exec_class == ExecClass::MainThread {
        cpl_flags |= hc::CPLF_MAIN_THREAD;
    }
    if job.cancel.load(Ordering::Acquire) {
        cpl_flags |= hc::CPLF_CANCELED;
        return make_completion(job, hc::HC_CANCELED, cpl_flags, 0, 0);
    }
    match job.opcode {
        hc::OP_NOTIFY_DIR => execute_notify_dir_async(inner, job),
        _ => {
            let (host_result, aux) = execute_sync(inner, job.opcode, job.args, Some(&job.payload));
            make_completion(job, host_result, cpl_flags, aux, 0)
        }
    }
}

fn execute_notify_dir_async(inner: &Arc<BrokerInner>, job: &WorkerJob) -> HostCallCompletion {
    let mut cpl_flags = 0u32;
    if job.exec_class == ExecClass::MainThread {
        cpl_flags |= hc::CPLF_MAIN_THREAD;
    }
    loop {
        if job.cancel.load(Ordering::Acquire) {
            cpl_flags |= hc::CPLF_CANCELED;
            return make_completion(job, hc::HC_CANCELED, cpl_flags, 0, 0);
        }
        let (host_result, packed) = execute_sync(inner, hc::OP_NOTIFY_DIR, job.args, None);
        if host_result != hc::HC_OK {
            return make_completion(job, host_result, cpl_flags, 0, 0);
        }
        if packed != 0 {
            return make_completion(job, hc::HC_OK, cpl_flags, packed, 0);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn decode_guest_path(
    memory: &Arc<RwLock<GuestMemory>>,
    path_gpa: u64,
    path_len: usize,
) -> Result<String, (u64, u64)> {
    if path_len == 0 || path_len > MAX_HOST_PATH {
        return Err((hc::HC_INVALID, 0));
    }
    let mem = memory.read().unwrap();
    let bytes = mem.read_bytes(Gpa(path_gpa), path_len);
    let path = std::str::from_utf8(bytes).map_err(|_| (hc::HC_INVALID, 0))?;
    Ok(path.to_owned())
}

fn execute_sync(
    inner: &Arc<BrokerInner>,
    opcode: u64,
    args: [u64; 4],
    payload: Option<&WorkerPayload>,
) -> (u64, u64) {
    match opcode {
        hc::OP_OPEN => execute_open(inner, args, payload),
        hc::OP_READ => execute_read(inner, args),
        hc::OP_WRITE => execute_write(inner, args, payload),
        hc::OP_CLOSE => execute_close(inner, args),
        hc::OP_STAT => execute_stat(inner, args),
        hc::OP_READDIR => execute_readdir(inner, args),
        hc::OP_NOTIFY_DIR => execute_notify_dir(inner, args),
        hc::OP_MMAP => execute_mmap(inner, args),
        hc::OP_MUNMAP => execute_munmap(inner, args),
        hc::OP_WIN32K_CALL => execute_win32k_call(inner, args),
        _ => (hc::HC_INVALID, 0),
    }
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let src = bytes.get(off..end)?;
    Some(u32::from_le_bytes([src[0], src[1], src[2], src[3]]))
}

fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let src = bytes.get(off..end)?;
    Some(u64::from_le_bytes([
        src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
    ]))
}

fn execute_win32k_call(inner: &Arc<BrokerInner>, args: [u64; 4]) -> (u64, u64) {
    let packet_gpa = args[0];
    let packet_len = args[1] as usize;
    if packet_len < hc::WIN32K_CALL_PACKET_SIZE || packet_len > 1024 {
        return (hc::HC_INVALID, 0);
    }

    let bytes = {
        let mem = inner.memory.read().unwrap();
        mem.read_bytes(Gpa(packet_gpa), packet_len).to_vec()
    };
    if bytes.len() < hc::WIN32K_CALL_PACKET_SIZE {
        return (hc::HC_INVALID, 0);
    }

    let version = match read_u32_le(&bytes, 0) {
        Some(v) => v,
        None => return (hc::HC_INVALID, 0),
    };
    let table = match read_u32_le(&bytes, 4) {
        Some(v) => v,
        None => return (hc::HC_INVALID, 0),
    };
    let syscall_nr = match read_u32_le(&bytes, 8) {
        Some(v) => v,
        None => return (hc::HC_INVALID, 0),
    };
    let arg_count = match read_u32_le(&bytes, 12) {
        Some(v) => v as usize,
        None => return (hc::HC_INVALID, 0),
    };
    let owner_pid = match read_u32_le(&bytes, 16) {
        Some(v) => v,
        None => return (hc::HC_INVALID, 0),
    };
    let owner_tid = match read_u32_le(&bytes, 20) {
        Some(v) => v,
        None => return (hc::HC_INVALID, 0),
    };
    if version != hc::WIN32K_CALL_PACKET_VERSION {
        return (hc::HC_INVALID, 0);
    }

    let mut call_args = [0u64; hc::WIN32K_CALL_MAX_ARGS];
    let mut i = 0usize;
    while i < hc::WIN32K_CALL_MAX_ARGS {
        let off = 32 + i * 8;
        let Some(v) = read_u64_le(&bytes, off) else {
            return (hc::HC_INVALID, 0);
        };
        call_args[i] = v;
        i += 1;
    }
    let _effective_arg_count = core::cmp::min(arg_count, hc::WIN32K_CALL_MAX_ARGS);
    let _ = (owner_pid, owner_tid, call_args);

    // Phase-1 bridge landing: parse packet and route through a single opcode.
    // Host win32k runtime is not wired yet, so keep semantic NTSTATUS explicit.
    match (table, syscall_nr) {
        _ => (hc::HC_OK, status::NOT_IMPLEMENTED as u64),
    }
}

fn execute_open(
    inner: &Arc<BrokerInner>,
    args: [u64; 4],
    payload: Option<&WorkerPayload>,
) -> (u64, u64) {
    let flags = args[2];
    let fd = match payload {
        Some(WorkerPayload::Path(path)) => inner.host_files.open(path, flags),
        _ => match decode_guest_path(&inner.memory, args[0], args[1] as usize) {
            Ok(path) => inner.host_files.open(&path, flags),
            Err(e) => return e,
        },
    };
    if fd == u64::MAX {
        (hc::HC_IO_ERROR, 0)
    } else {
        (hc::HC_OK, fd)
    }
}

fn execute_read(inner: &Arc<BrokerInner>, args: [u64; 4]) -> (u64, u64) {
    let fd = args[0];
    let dst_gpa = args[1];
    let len = args[2] as usize;
    let offset = args[3];
    if len == 0 {
        return (hc::HC_OK, 0);
    }
    if len > MAX_IO_SIZE {
        return (hc::HC_INVALID, 0);
    }
    let mut buf = vec![0u8; len];
    let got = inner.host_files.read(fd, &mut buf, offset);
    if got > 0 {
        let mut mem = inner.memory.write().unwrap();
        mem.write_bytes(Gpa(dst_gpa), &buf[..got]);
    }
    (hc::HC_OK, got as u64)
}

fn execute_write(
    inner: &Arc<BrokerInner>,
    args: [u64; 4],
    payload: Option<&WorkerPayload>,
) -> (u64, u64) {
    let fd = args[0];
    let src_gpa = args[1];
    let len = args[2] as usize;
    let offset = args[3];
    if len == 0 {
        return (hc::HC_OK, 0);
    }
    if len > MAX_IO_SIZE {
        return (hc::HC_INVALID, 0);
    }
    let written = match payload {
        Some(WorkerPayload::Bytes(bytes)) if bytes.len() == len => {
            inner.host_files.write(fd, bytes, offset)
        }
        _ => {
            let buf = {
                let mem = inner.memory.read().unwrap();
                mem.read_bytes(Gpa(src_gpa), len).to_vec()
            };
            inner.host_files.write(fd, &buf, offset)
        }
    };
    (hc::HC_OK, written as u64)
}

fn execute_close(inner: &Arc<BrokerInner>, args: [u64; 4]) -> (u64, u64) {
    inner.host_files.close(args[0]);
    (hc::HC_OK, 0)
}

fn execute_stat(inner: &Arc<BrokerInner>, args: [u64; 4]) -> (u64, u64) {
    (hc::HC_OK, inner.host_files.stat(args[0]))
}

fn execute_readdir(inner: &Arc<BrokerInner>, args: [u64; 4]) -> (u64, u64) {
    let fd = args[0];
    let dst_gpa = args[1];
    let len = args[2] as usize;
    let restart = args[3] != 0;
    if len == 0 || len > MAX_DIR_BUF {
        return (hc::HC_INVALID, 0);
    }
    let mut buf = vec![0u8; len];
    let ret = inner.host_files.readdir(fd, &mut buf, restart);
    if ret == u64::MAX {
        return (hc::HC_IO_ERROR, 0);
    }
    if ret != 0 {
        let copied = (ret & 0xFFFF_FFFF) as usize;
        if copied != 0 {
            let copied = copied.min(len);
            let mut mem = inner.memory.write().unwrap();
            mem.write_bytes(Gpa(dst_gpa), &buf[..copied]);
        }
    }
    (hc::HC_OK, ret)
}

fn notify_watch_tree(opts: u64) -> bool {
    (opts & NOTIFY_OPT_WATCH_TREE) != 0
}

fn notify_completion_filter(opts: u64) -> u32 {
    (opts & NOTIFY_OPT_FILTER_MASK) as u32
}

fn execute_notify_dir(inner: &Arc<BrokerInner>, args: [u64; 4]) -> (u64, u64) {
    let fd = args[0];
    let dst_gpa = args[1];
    let len = args[2] as usize;
    let opts = args[3];
    if len == 0 || len > MAX_DIR_BUF {
        return (hc::HC_INVALID, 0);
    }
    let watch_tree = notify_watch_tree(opts);
    let completion_filter = notify_completion_filter(opts);
    let mut buf = vec![0u8; len];
    let ret = inner
        .host_files
        .notify_dir_change(fd, &mut buf, watch_tree, completion_filter);
    if ret == u64::MAX {
        return (hc::HC_IO_ERROR, 0);
    }
    if ret != 0 {
        let copied = (ret & 0xFFFF_FFFF) as usize;
        if copied != 0 {
            let copied = copied.min(len);
            let mut mem = inner.memory.write().unwrap();
            mem.write_bytes(Gpa(dst_gpa), &buf[..copied]);
        }
    }
    (hc::HC_OK, ret)
}

fn execute_mmap(inner: &Arc<BrokerInner>, args: [u64; 4]) -> (u64, u64) {
    let fd = args[0];
    let offset = args[1];
    let size = args[2] as usize;
    let prot = args[3] as u32;
    if size == 0 || size > MAX_IO_SIZE {
        return (hc::HC_INVALID, 0);
    }

    let va = inner.vaspace.lock().unwrap().alloc(0, size as u64, prot);
    match va {
        Some(gpa) => {
            let mut buf = vec![0u8; size];
            let got = inner.host_files.read(fd, &mut buf, offset);
            if got > 0 {
                let mut mem = inner.memory.write().unwrap();
                mem.write_bytes(Gpa(gpa), &buf[..got]);
            }
            log::debug!(
                "HOSTCALL_MMAP: fd={} off={:#x} size={:#x} -> gpa={:#x}",
                fd,
                offset,
                size,
                gpa
            );
            (hc::HC_OK, gpa)
        }
        None => {
            log::warn!("HOSTCALL_MMAP: VA alloc failed size={:#x}", size);
            (hc::HC_NO_MEMORY, 0)
        }
    }
}

fn execute_munmap(inner: &Arc<BrokerInner>, args: [u64; 4]) -> (u64, u64) {
    let base = args[0];
    let ok = inner.vaspace.lock().unwrap().free(base);
    if ok {
        (hc::HC_OK, 0)
    } else {
        (hc::HC_IO_ERROR, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_file::HostFileTable;
    use crate::memory::GuestMemory;
    use crate::sched::Scheduler;
    use crate::vaspace::VaSpace;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use winemu_core::addr::Gpa;

    static NEXT_TMP_ID: AtomicU64 = AtomicU64::new(1);

    fn temp_root() -> PathBuf {
        let mut p = std::env::temp_dir();
        let id = NEXT_TMP_ID.fetch_add(1, Ordering::Relaxed);
        p.push(format!(
            "winemu-hostcall-test-{}-{}",
            std::process::id(),
            id
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn test_setup(
        root: &std::path::Path,
    ) -> (
        HostCallBroker,
        Arc<RwLock<GuestMemory>>,
        Arc<HostFileTable>,
        Arc<Mutex<VaSpace>>,
    ) {
        let memory = Arc::new(RwLock::new(GuestMemory::new(8 * 1024 * 1024).unwrap()));
        let sched = Scheduler::new(1);
        let host_files = Arc::new(HostFileTable::new(root.to_path_buf()));
        let vaspace = Arc::new(Mutex::new(VaSpace::new()));
        let broker = HostCallBroker::new(
            Arc::clone(&memory),
            Arc::clone(&host_files),
            Arc::clone(&vaspace),
            Arc::clone(&sched),
        );
        (broker, memory, host_files, vaspace)
    }

    #[test]
    fn open_and_read_sync_path_roundtrip() {
        let root = temp_root();
        let path = root.join("sync.txt");
        std::fs::write(&path, b"hello-hostcall").unwrap();

        let (broker, memory, _host_files, _) = test_setup(&root);
        let base = memory.read().unwrap().base_gpa().0;
        let path_ptr = base + 0x1000;
        let read_ptr = base + 0x2000;
        memory
            .write()
            .unwrap()
            .write_bytes(Gpa(path_ptr), b"sync.txt");

        let open = broker.submit(hc::OP_OPEN, 0, [path_ptr, 8, 0, 0], 0);
        let fd = match open {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                aux
            }
            SubmitResult::Pending { .. } => panic!("sync open should not pend"),
        };
        assert_ne!(fd, 0);

        let read = broker.submit(hc::OP_READ, 0, [fd, read_ptr, 14, 0], 0);
        let got = match read {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                aux as usize
            }
            SubmitResult::Pending { .. } => panic!("sync read should not pend"),
        };
        assert_eq!(got, 14);
        let bytes = memory
            .read()
            .unwrap()
            .read_bytes(Gpa(read_ptr), got)
            .to_vec();
        assert_eq!(&bytes, b"hello-hostcall");

        let close = broker.submit(hc::OP_CLOSE, 0, [fd, 0, 0, 0], 0);
        match close {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                assert_eq!(aux, 0);
            }
            SubmitResult::Pending { .. } => panic!("sync close should not pend"),
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_async_force_path_completes() {
        let root = temp_root();
        let path = root.join("async_open.txt");
        std::fs::write(&path, b"x").unwrap();

        let (broker, memory, _host_files, _) = test_setup(&root);
        let path_ptr = memory.read().unwrap().base_gpa().0 + 0x1000;
        memory
            .write()
            .unwrap()
            .write_bytes(Gpa(path_ptr), b"async_open.txt");

        let submit = broker.submit(
            hc::OP_OPEN,
            hc::FLAG_FORCE_ASYNC,
            [path_ptr, 14, 0, 0],
            0xAA55,
        );
        let request_id = match submit {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("force async open should pend"),
        };

        let mut got = None;
        for _ in 0..200 {
            let _ = broker.run_main_thread_budget(8);
            for cpl in broker.poll_batch(16) {
                if cpl.request_id == request_id {
                    got = Some(cpl);
                    break;
                }
            }
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let cpl = got.expect("no completion for async open");
        assert_eq!(cpl.host_result as u64, hc::HC_OK);
        assert_eq!(cpl.user_tag, 0xAA55);
        assert_ne!(cpl.value0, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_async_allow_path_completes() {
        let root = temp_root();
        let path = root.join("async_open_allow.txt");
        std::fs::write(&path, b"x").unwrap();

        let (broker, memory, _host_files, _) = test_setup(&root);
        let path_ptr = memory.read().unwrap().base_gpa().0 + 0x1200;
        memory
            .write()
            .unwrap()
            .write_bytes(Gpa(path_ptr), b"async_open_allow.txt");

        let submit = broker.submit(
            hc::OP_OPEN,
            hc::FLAG_ALLOW_ASYNC,
            [path_ptr, 20, 0, 0],
            0xA11A,
        );
        let request_id = match submit {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("allow-async open should pend"),
        };

        let mut got = None;
        for _ in 0..200 {
            let _ = broker.run_main_thread_budget(8);
            for cpl in broker.poll_batch(16) {
                if cpl.request_id == request_id {
                    got = Some(cpl);
                    break;
                }
            }
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let cpl = got.expect("no completion for allow-async open");
        assert_eq!(cpl.host_result as u64, hc::HC_OK);
        assert_eq!(cpl.user_tag, 0xA11A);
        assert_ne!(cpl.value0, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_write_async_force_paths_complete() {
        let root = temp_root();
        std::fs::write(root.join("rw_async.bin"), b"").unwrap();

        let (broker, memory, host_files, _) = test_setup(&root);
        let fd = host_files.open("rw_async.bin", 2);
        assert_ne!(fd, u64::MAX);

        let base = memory.read().unwrap().base_gpa().0;
        let src_ptr = base + 0x3000;
        let dst_ptr = base + 0x4000;
        memory
            .write()
            .unwrap()
            .write_bytes(Gpa(src_ptr), b"async-io-data");

        let submit_write = broker.submit(
            hc::OP_WRITE,
            hc::FLAG_FORCE_ASYNC,
            [fd, src_ptr, 13, 0],
            0xABCD,
        );
        let write_id = match submit_write {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("force async write should pend"),
        };

        let mut write_cpl = None;
        for _ in 0..200 {
            for cpl in broker.poll_batch(16) {
                if cpl.request_id == write_id {
                    write_cpl = Some(cpl);
                    break;
                }
            }
            if write_cpl.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let write_cpl = write_cpl.expect("no completion for async write");
        assert_eq!(write_cpl.host_result as u64, hc::HC_OK);
        assert_eq!(write_cpl.value0, 13);
        assert_eq!(write_cpl.user_tag, 0xABCD);

        let submit_read = broker.submit(
            hc::OP_READ,
            hc::FLAG_FORCE_ASYNC,
            [fd, dst_ptr, 13, 0],
            0xBCDE,
        );
        let read_id = match submit_read {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("force async read should pend"),
        };

        let mut read_cpl = None;
        for _ in 0..200 {
            for cpl in broker.poll_batch(16) {
                if cpl.request_id == read_id {
                    read_cpl = Some(cpl);
                    break;
                }
            }
            if read_cpl.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let read_cpl = read_cpl.expect("no completion for async read");
        assert_eq!(read_cpl.host_result as u64, hc::HC_OK);
        assert_eq!(read_cpl.value0, 13);
        assert_eq!(read_cpl.user_tag, 0xBCDE);

        let got = memory.read().unwrap().read_bytes(Gpa(dst_ptr), 13).to_vec();
        assert_eq!(&got, b"async-io-data");

        host_files.close(fd);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn notify_dir_sync_path_returns_immediate_result() {
        let root = temp_root();
        let watch = root.join("watch");
        std::fs::create_dir_all(&watch).unwrap();

        let (broker, memory, host_files, _) = test_setup(&root);
        let fd = host_files.open("watch", 0);
        assert_ne!(fd, u64::MAX);

        let out_ptr = memory.read().unwrap().base_gpa().0 + 0x10000;
        let first = broker.submit(hc::OP_NOTIFY_DIR, 0, [fd, out_ptr, 512, 0], 0);
        match first {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                assert_eq!(aux, 0);
            }
            SubmitResult::Pending { .. } => panic!("sync path should not pend"),
        }

        let changed_name = "sync_changed.txt";
        std::fs::write(watch.join(changed_name), b"x").unwrap();
        let second = broker.submit(hc::OP_NOTIFY_DIR, 0, [fd, out_ptr, 512, 0], 0);
        let packed = match second {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                aux
            }
            SubmitResult::Pending { .. } => panic!("sync path should not pend"),
        };
        assert_ne!(packed, 0);
        let name_len = (packed & 0xFFFF_FFFF) as usize;
        assert!(name_len > 0);
        let got = memory
            .read()
            .unwrap()
            .read_bytes(Gpa(out_ptr), name_len)
            .to_vec();
        let got_name = std::str::from_utf8(&got).unwrap();
        assert!(got_name.contains("sync_changed"));

        host_files.close(fd);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn notify_dir_async_path_completes_via_poll_batch() {
        let root = temp_root();
        let watch = root.join("watch");
        std::fs::create_dir_all(&watch).unwrap();

        let (broker, memory, host_files, _) = test_setup(&root);
        let fd = host_files.open("watch", 0);
        assert_ne!(fd, u64::MAX);

        let out_ptr = memory.read().unwrap().base_gpa().0 + 0x20000;
        let prime = broker.submit(hc::OP_NOTIFY_DIR, 0, [fd, out_ptr, 512, 0], 0);
        match prime {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                assert_eq!(aux, 0);
            }
            SubmitResult::Pending { .. } => panic!("prime must be sync"),
        }

        let submit = broker.submit(
            hc::OP_NOTIFY_DIR,
            hc::FLAG_FORCE_ASYNC,
            [fd, out_ptr, 512, 0],
            0x55AA,
        );
        let request_id = match submit {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("async path should pend"),
        };
        assert_ne!(request_id, 0);

        std::fs::write(watch.join("async_changed.txt"), b"x").unwrap();
        let mut got = None;
        for _ in 0..200 {
            let batch = broker.poll_batch(8);
            for cpl in batch {
                if cpl.request_id == request_id {
                    got = Some(cpl);
                    break;
                }
            }
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let cpl = got.expect("no completion for async request");
        assert_eq!(cpl.host_result as u64, hc::HC_OK);
        assert_eq!(cpl.user_tag, 0x55AA);
        let packed = cpl.value0;
        assert_ne!(packed, 0);
        let name_len = (packed & 0xFFFF_FFFF) as usize;
        assert!(name_len > 0);
        let got_name = memory
            .read()
            .unwrap()
            .read_bytes(Gpa(out_ptr), name_len)
            .to_vec();
        let got_name = std::str::from_utf8(&got_name).unwrap();
        assert!(got_name.contains("async_changed"));

        host_files.close(fd);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn main_thread_flag_routes_to_main_executor() {
        let root = temp_root();
        let path = root.join("main_exec.txt");
        std::fs::write(&path, b"m").unwrap();

        let (broker, memory, _host_files, _) = test_setup(&root);
        let path_ptr = memory.read().unwrap().base_gpa().0 + 0x1400;
        memory
            .write()
            .unwrap()
            .write_bytes(Gpa(path_ptr), b"main_exec.txt");

        let submit = broker.submit(
            hc::OP_OPEN,
            hc::FLAG_FORCE_ASYNC | hc::FLAG_MAIN_THREAD,
            [path_ptr, 13, 0, 0],
            0xD00D,
        );
        let request_id = match submit {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("main-thread async open should pend"),
        };

        let mut got = None;
        for _ in 0..200 {
            let _ = broker.run_main_thread_budget(8);
            for cpl in broker.poll_batch(16) {
                if cpl.request_id == request_id {
                    got = Some(cpl);
                    break;
                }
            }
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let cpl = got.expect("no completion for main-thread request");
        assert_eq!(cpl.host_result as u64, hc::HC_OK);
        assert_ne!(cpl.flags & hc::CPLF_MAIN_THREAD, 0);
        assert_eq!(cpl.user_tag, 0xD00D);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stats_snapshot_tracks_sync_async_paths() {
        let root = temp_root();
        let path = root.join("stats.txt");
        std::fs::write(&path, b"stats").unwrap();

        let (broker, memory, host_files, _) = test_setup(&root);
        let path_ptr = memory.read().unwrap().base_gpa().0 + 0x1800;
        memory
            .write()
            .unwrap()
            .write_bytes(Gpa(path_ptr), b"stats.txt");

        let sync_open = broker.submit(hc::OP_OPEN, 0, [path_ptr, 9, 0, 0], 0);
        let fd_sync = match sync_open {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                aux
            }
            SubmitResult::Pending { .. } => panic!("sync open should not pend"),
        };
        host_files.close(fd_sync);

        let async_open = broker.submit(hc::OP_OPEN, hc::FLAG_FORCE_ASYNC, [path_ptr, 9, 0, 0], 0);
        let request_id = match async_open {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("async open should pend"),
        };

        let mut async_fd = None;
        for _ in 0..200 {
            for cpl in broker.poll_batch(8) {
                if cpl.request_id == request_id {
                    assert_eq!(cpl.host_result as u64, hc::HC_OK);
                    async_fd = Some(cpl.value0);
                    break;
                }
            }
            if async_fd.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        host_files.close(async_fd.expect("missing async open completion"));

        let snap = broker.stats_snapshot();
        assert_eq!(snap.submit_sync_total, 1);
        assert_eq!(snap.complete_sync_total, 1);
        assert_eq!(snap.submit_async_total, 1);
        assert_eq!(snap.complete_async_total, 1);
        assert_eq!(snap.backpressure_total, 0);

        let open = snap
            .op_stats
            .iter()
            .find(|s| s.opcode == hc::OP_OPEN)
            .copied()
            .expect("missing open op stats");
        assert_eq!(open.submit_sync, 1);
        assert_eq!(open.complete_sync, 1);
        assert_eq!(open.submit_async, 1);
        assert_eq!(open.complete_async, 1);
        assert_eq!(open.backpressure, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn win32k_call_bridge_returns_not_implemented_status() {
        let root = temp_root();
        let (broker, memory, _host_files, _) = test_setup(&root);
        let pkt_ptr = memory.read().unwrap().base_gpa().0 + 0x30000;

        let mut bytes = vec![0u8; hc::WIN32K_CALL_PACKET_SIZE];
        bytes[0..4].copy_from_slice(&hc::WIN32K_CALL_PACKET_VERSION.to_le_bytes()); // version
        bytes[4..8].copy_from_slice(&(1u32).to_le_bytes()); // table
        bytes[8..12].copy_from_slice(
            &(winemu_shared::win32k_sysno::NT_USER_INITIALIZE_CLIENT_PFN_ARRAYS as u32)
                .to_le_bytes(),
        ); // syscall nr
        bytes[12..16].copy_from_slice(&(hc::WIN32K_CALL_MAX_ARGS as u32).to_le_bytes()); // arg_count
        bytes[16..20].copy_from_slice(&(1u32).to_le_bytes()); // owner_pid
        bytes[20..24].copy_from_slice(&(1u32).to_le_bytes()); // owner_tid
        memory.write().unwrap().write_bytes(Gpa(pkt_ptr), &bytes);

        let submit = broker.submit(
            hc::OP_WIN32K_CALL,
            0,
            [pkt_ptr, hc::WIN32K_CALL_PACKET_SIZE as u64, 0, 0],
            0,
        );
        match submit {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                assert_eq!(aux as u32, status::NOT_IMPLEMENTED);
            }
            SubmitResult::Pending { .. } => panic!("win32k bridge should complete on sync path"),
        }

        let _ = std::fs::remove_dir_all(&root);
    }
}
