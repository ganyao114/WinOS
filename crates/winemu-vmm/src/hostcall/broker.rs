use super::modules::file_io::FileIoModule;
use super::handlers::HandlerCtx;
use super::registry::HandlerRegistry;
use super::types::{HostCallCompletion, HostCallOpStats, HostCallStatsSnapshot, SubmitResult, WorkerPayload};
use super::modules::win32k::Win32kModule;
use crate::host_file::HostFileTable;
use crate::memory::GuestMemory;
use crate::sched::Scheduler;
use crate::vaspace::VaSpace;
use crate::hostcall::modules::win32k::Win32kState;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use winemu_shared::hostcall as hc;
use winit::event::WindowEvent;
use winit::event_loop::ActiveEventLoop;
use winit::window::WindowId;

const DEFAULT_IO_QUEUE_CAP: usize = 4096;
const DEFAULT_MAIN_QUEUE_CAP: usize = 1024;
const COMPLETION_WARN_HWM: usize = 2048;

#[derive(Clone)]
pub struct HostCallBroker {
    inner: Arc<BrokerInner>,
}

struct BrokerInner {
    memory: Arc<RwLock<GuestMemory>>,
    host_files: Arc<crate::host_file::HostFileTable>,
    vaspace: Arc<Mutex<crate::vaspace::VaSpace>>,
    scheduler: Arc<Scheduler>,
    io_submit_tx: SyncSender<WorkerJob>,
    main_submit_tx: SyncSender<WorkerJob>,
    main_submit_rx: Mutex<Receiver<WorkerJob>>,
    main_executor_thread: Mutex<Option<std::thread::ThreadId>>,
    inflight: Mutex<HashMap<u64, InflightReq>>,
    completions: Mutex<VecDeque<HostCallCompletion>>,
    next_request_id: AtomicU64,
    stats: BrokerStats,
    completion_queue_hwm: AtomicU64,
    win32k: Mutex<Win32kState>,
    registry: HandlerRegistry,
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

struct WorkerJob {
    request_id: u64,
    opcode: u64,
    args: [u64; 4],
    payload: WorkerPayload,
    user_tag: u64,
    cancel: Arc<AtomicBool>,
    exec_class: ExecClass,
    sync_reply: Option<SyncSender<(u64, u64)>>,
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
    fn new(max_opcode: usize) -> Self {
        let mut per_op = Vec::new();
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
        if let Some(op) = self.per_op.get(opcode as usize) { f(op); }
    }

    fn on_submit_sync(&self, op: u64) {
        self.submit_sync_total.fetch_add(1, Ordering::Relaxed);
        self.with_op(op, |c| { c.submit_sync.fetch_add(1, Ordering::Relaxed); });
    }
    fn on_submit_async(&self, op: u64) {
        self.submit_async_total.fetch_add(1, Ordering::Relaxed);
        self.with_op(op, |c| { c.submit_async.fetch_add(1, Ordering::Relaxed); });
    }
    fn on_complete_sync(&self, op: u64) {
        self.complete_sync_total.fetch_add(1, Ordering::Relaxed);
        self.with_op(op, |c| { c.complete_sync.fetch_add(1, Ordering::Relaxed); });
    }
    fn on_complete_async(&self, op: u64) {
        self.complete_async_total.fetch_add(1, Ordering::Relaxed);
        self.with_op(op, |c| { c.complete_async.fetch_add(1, Ordering::Relaxed); });
    }
    fn on_cancel(&self, op: u64) {
        self.cancel_total.fetch_add(1, Ordering::Relaxed);
        self.with_op(op, |c| { c.cancel.fetch_add(1, Ordering::Relaxed); });
    }
    fn on_backpressure(&self, op: u64) {
        self.backpressure_total.fetch_add(1, Ordering::Relaxed);
        self.with_op(op, |c| { c.backpressure.fetch_add(1, Ordering::Relaxed); });
    }
    fn reset(&self) {
        self.submit_sync_total.store(0, Ordering::Relaxed);
        self.submit_async_total.store(0, Ordering::Relaxed);
        self.complete_sync_total.store(0, Ordering::Relaxed);
        self.complete_async_total.store(0, Ordering::Relaxed);
        self.cancel_total.store(0, Ordering::Relaxed);
        self.backpressure_total.store(0, Ordering::Relaxed);
        for op in &self.per_op {
            op.submit_sync.store(0, Ordering::Relaxed);
            op.submit_async.store(0, Ordering::Relaxed);
            op.complete_sync.store(0, Ordering::Relaxed);
            op.complete_async.store(0, Ordering::Relaxed);
            op.cancel.store(0, Ordering::Relaxed);
            op.backpressure.store(0, Ordering::Relaxed);
        }
    }
}

// ── HostCallBroker ────────────────────────────────────────────────────────────

impl HostCallBroker {
    pub fn new(
        memory: Arc<RwLock<GuestMemory>>,
        host_files: Arc<HostFileTable>,
        vaspace: Arc<Mutex<VaSpace>>,
        scheduler: Arc<Scheduler>,
        io_workers: usize,
    ) -> Self {
        let (io_tx, io_rx) = sync_channel::<WorkerJob>(DEFAULT_IO_QUEUE_CAP);
        let (main_tx, main_rx) = sync_channel::<WorkerJob>(DEFAULT_MAIN_QUEUE_CAP);

        let mut registry = HandlerRegistry::new();
        registry.register(&FileIoModule);
        registry.register(&Win32kModule);

        let inner = Arc::new(BrokerInner {
            memory,
            host_files,
            vaspace,
            scheduler,
            io_submit_tx: io_tx,
            main_submit_tx: main_tx,
            main_submit_rx: Mutex::new(main_rx),
            main_executor_thread: Mutex::new(None),
            inflight: Mutex::new(HashMap::new()),
            completions: Mutex::new(VecDeque::new()),
            next_request_id: AtomicU64::new(1),
            stats: BrokerStats::new(32),
            completion_queue_hwm: AtomicU64::new(0),
            win32k: Mutex::new(Win32kState::new()),
            registry,
        });

        let workers = io_workers.max(1);
        let io_rx = Arc::new(Mutex::new(io_rx));
        for _ in 0..workers {
            let inner2 = Arc::clone(&inner);
            let rx = Arc::clone(&io_rx);
            thread::spawn(move || {
                loop {
                    let job = { rx.lock().unwrap().recv() };
                    match job {
                        Ok(job) => {
                            if run_job(&inner2, job) {
                                inner2.scheduler.unpark_one_vcpu();
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        Self { inner }
    }

    fn make_ctx(&self) -> HandlerCtx<'_> {
        HandlerCtx {
            memory: &self.inner.memory,
            host_files: &self.inner.host_files,
            vaspace: &self.inner.vaspace,
            win32k: &self.inner.win32k,
        }
    }
}

// ── submit / execute_sync ─────────────────────────────────────────────────────

impl HostCallBroker {
    pub fn submit(
        &self,
        opcode: u64,
        flags: u64,
        args: [u64; 4],
        user_tag: u64,
    ) -> SubmitResult {
        let inner = &*self.inner;

        if !inner.registry.is_supported(opcode) {
            return SubmitResult::Completed { host_result: hc::HC_INVALID, aux: 0 };
        }

        let force_async = (flags & hc::FLAG_FORCE_ASYNC) != 0;
        let allow_async = force_async || (flags & hc::FLAG_ALLOW_ASYNC) != 0;
        let main_thread = (flags & hc::FLAG_MAIN_THREAD) != 0
            || inner.registry.requires_main_thread(opcode);

        let exec_class = if main_thread { ExecClass::MainThread } else { ExecClass::Io };

        let do_async = allow_async && inner.registry.async_eligible(opcode, args);

        if !do_async {
            inner.stats.on_submit_sync(opcode);
            let (r0, r1) = if exec_class == ExecClass::MainThread {
                self.execute_sync_main_thread(opcode, args)
            } else {
                let ctx = self.make_ctx();
                inner
                    .registry
                    .dispatch(&ctx, opcode, args, None)
                    .unwrap_or((hc::HC_INVALID, 0))
            };
            inner.stats.on_complete_sync(opcode);
            return SubmitResult::Completed { host_result: r0, aux: r1 };
        }

        // Async path: pre-capture payload, then enqueue.
        let payload = match inner.registry.prepare_payload(opcode, &inner.memory, args) {
            Ok(p) => p,
            Err((r0, r1)) => return SubmitResult::Completed { host_result: r0, aux: r1 },
        };

        let request_id = inner.next_request_id.fetch_add(1, Ordering::Relaxed);
        let cancel = Arc::new(AtomicBool::new(false));

        inner.inflight.lock().unwrap().insert(
            request_id,
            InflightReq { cancel: Arc::clone(&cancel), opcode },
        );

        let job = WorkerJob {
            request_id,
            opcode,
            args,
            payload,
            user_tag,
            cancel,
            exec_class,
            sync_reply: None,
        };

        let send_result = match exec_class {
            ExecClass::Io => inner.io_submit_tx.try_send(job).map_err(|e| match e {
                TrySendError::Full(_) => QueueSendError::Full,
                TrySendError::Disconnected(_) => QueueSendError::Disconnected,
            }),
            ExecClass::MainThread => inner.main_submit_tx.try_send(job).map_err(|e| match e {
                TrySendError::Full(_) => QueueSendError::Full,
                TrySendError::Disconnected(_) => QueueSendError::Disconnected,
            }),
        };

        match send_result {
            Ok(()) => {
                inner.stats.on_submit_async(opcode);
                SubmitResult::Pending { request_id }
            }
            Err(QueueSendError::Full) => {
                inner.inflight.lock().unwrap().remove(&request_id);
                inner.stats.on_backpressure(opcode);
                SubmitResult::Completed { host_result: hc::HC_BUSY, aux: 0 }
            }
            Err(QueueSendError::Disconnected) => {
                inner.inflight.lock().unwrap().remove(&request_id);
                SubmitResult::Completed { host_result: hc::HC_IO_ERROR, aux: 0 }
            }
        }
    }

    fn execute_sync_main_thread(&self, opcode: u64, args: [u64; 4]) -> (u64, u64) {
        let inner = &*self.inner;

        // Headless mode keeps historical behavior: execute inline.
        if !host_ui_main_thread_mode() {
            let ctx = self.make_ctx();
            return inner
                .registry
                .dispatch(&ctx, opcode, args, None)
                .unwrap_or((hc::HC_INVALID, 0));
        }

        // If caller is already the registered main executor thread, run inline.
        if self.is_current_main_executor_thread() {
            let ctx = self.make_ctx();
            return inner
                .registry
                .dispatch(&ctx, opcode, args, None)
                .unwrap_or((hc::HC_INVALID, 0));
        }

        let (tx, rx) = sync_channel::<(u64, u64)>(1);
        let job = WorkerJob {
            request_id: 0,
            opcode,
            args,
            payload: WorkerPayload::None,
            user_tag: 0,
            cancel: Arc::new(AtomicBool::new(false)),
            exec_class: ExecClass::MainThread,
            sync_reply: Some(tx),
        };
        match inner.main_submit_tx.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return (hc::HC_BUSY, 0),
            Err(TrySendError::Disconnected(_)) => return (hc::HC_IO_ERROR, 0),
        }
        rx.recv().unwrap_or((hc::HC_IO_ERROR, 0))
    }
}

// ── cancel / poll / pump / stats ──────────────────────────────────────────────

impl HostCallBroker {
    pub fn cancel(&self, request_id: u64) -> (u64, u64) {
        let inner = &*self.inner;
        let mut inflight = inner.inflight.lock().unwrap();
        if let Some(req) = inflight.remove(&request_id) {
            req.cancel.store(true, Ordering::Relaxed);
            inner.stats.on_cancel(req.opcode);
            (hc::HC_OK, 0)
        } else {
            (hc::HC_INVALID, 0)
        }
    }

    pub fn poll_completion(&self) -> Option<HostCallCompletion> {
        self.inner.completions.lock().unwrap().pop_front()
    }

    pub fn poll_completions_batch(&self, out: &mut Vec<HostCallCompletion>, max: usize) {
        let mut q = self.inner.completions.lock().unwrap();
        let take = max.min(q.len());
        out.extend(q.drain(..take));
    }

    fn pump_main_thread_budget(&self, max_jobs: usize) {
        let inner = &*self.inner;
        self.register_main_executor_thread();
        let rx = inner.main_submit_rx.lock().unwrap();
        let mut handled = 0usize;
        loop {
            if handled >= max_jobs {
                break;
            }
            match rx.try_recv() {
                Ok(job) => {
                    if run_job(inner, job) {
                        inner.scheduler.unpark_one_vcpu();
                    }
                    handled += 1;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    /// Drive main-thread (win32k) jobs.  Call from the event-loop thread.
    pub fn pump_main_thread(&self) {
        self.pump_main_thread_budget(usize::MAX);
    }

    /// Drive a host UI event-loop tick.
    /// This must run on the UI thread that owns `ActiveEventLoop`.
    pub fn pump_main_thread_with_event_loop(&self, el: &ActiveEventLoop, elapsed_ms: u32) {
        // Bound per-tick queue drain to avoid starving window lifecycle work.
        self.pump_main_thread_budget(64);
        self.inner
            .win32k
            .lock()
            .unwrap()
            .on_event_loop_tick(el, elapsed_ms);
    }

    /// Forward host window events into the win32k message bridge.
    pub fn handle_window_event(&self, window_id: WindowId, event: &WindowEvent) {
        self.inner
            .win32k
            .lock()
            .unwrap()
            .on_window_event(window_id, event);
    }

    fn register_main_executor_thread(&self) {
        let current = thread::current().id();
        let mut owner = self.inner.main_executor_thread.lock().unwrap();
        match *owner {
            Some(id) if id == current => {}
            Some(id) => {
                log::warn!(
                    "hostcall main executor switched from {:?} to {:?}",
                    id,
                    current
                );
                *owner = Some(current);
            }
            None => {
                *owner = Some(current);
            }
        }
    }

    fn is_current_main_executor_thread(&self) -> bool {
        let owner = self.inner.main_executor_thread.lock().unwrap();
        owner
            .as_ref()
            .map(|id| *id == thread::current().id())
            .unwrap_or(false)
    }

    pub fn stats_snapshot(&self, reset: bool) -> HostCallStatsSnapshot {
        let s = &self.inner.stats;
        let snap = HostCallStatsSnapshot {
            submit_sync_total: s.submit_sync_total.load(Ordering::Relaxed),
            submit_async_total: s.submit_async_total.load(Ordering::Relaxed),
            complete_sync_total: s.complete_sync_total.load(Ordering::Relaxed),
            complete_async_total: s.complete_async_total.load(Ordering::Relaxed),
            cancel_total: s.cancel_total.load(Ordering::Relaxed),
            backpressure_total: s.backpressure_total.load(Ordering::Relaxed),
            completion_queue_high_watermark: self.inner.completion_queue_hwm.load(Ordering::Relaxed) as usize,
            op_stats: s.per_op.iter().enumerate().map(|(i, op)| HostCallOpStats {
                opcode: i as u64,
                submit_sync: op.submit_sync.load(Ordering::Relaxed),
                submit_async: op.submit_async.load(Ordering::Relaxed),
                complete_sync: op.complete_sync.load(Ordering::Relaxed),
                complete_async: op.complete_async.load(Ordering::Relaxed),
                cancel: op.cancel.load(Ordering::Relaxed),
                backpressure: op.backpressure.load(Ordering::Relaxed),
            }).collect(),
        };
        if reset { s.reset(); }
        snap
    }
}

// ── worker helpers ────────────────────────────────────────────────────────────

fn run_job(inner: &BrokerInner, job: WorkerJob) -> bool {
    if job.cancel.load(Ordering::Relaxed) {
        if let Some(reply) = job.sync_reply {
            let _ = reply.send((hc::HC_CANCELED, 0));
            return false;
        }
        push_completion(
            inner,
            job.request_id,
            job.user_tag,
            hc::HC_CANCELED,
            0,
            true,
            job.exec_class == ExecClass::MainThread,
        );
        inner.stats.on_complete_async(job.opcode);
        return true;
    }

    let ctx = HandlerCtx {
        memory: &inner.memory,
        host_files: &inner.host_files,
        vaspace: &inner.vaspace,
        win32k: &inner.win32k,
    };

    // Special case: OP_NOTIFY_DIR uses a blocking poll loop.
    let (r0, r1) = if job.opcode == winemu_shared::hostcall::OP_NOTIFY_DIR {
        let cancel_flag = Arc::clone(&job.cancel);
        super::handlers::poll_notify_dir_until_change(
            &ctx,
            job.args,
            move || cancel_flag.load(Ordering::Relaxed),
        )
    } else {
        inner.registry.dispatch(&ctx, job.opcode, job.args, Some(&job.payload))
            .unwrap_or((hc::HC_INVALID, 0))
    };

    if let Some(reply) = job.sync_reply {
        let _ = reply.send((r0, r1));
        return false;
    }

    inner.inflight.lock().unwrap().remove(&job.request_id);
    let cancelled = job.cancel.load(Ordering::Relaxed);
    push_completion(
        inner,
        job.request_id,
        job.user_tag,
        r0,
        r1,
        cancelled,
        job.exec_class == ExecClass::MainThread,
    );
    inner.stats.on_complete_async(job.opcode);
    true
}

fn push_completion(
    inner: &BrokerInner,
    request_id: u64,
    user_tag: u64,
    r0: u64,
    r1: u64,
    cancelled: bool,
    main_thread: bool,
) {
    let mut flags = 0u32;
    if cancelled {
        flags |= hc::CPLF_CANCELED;
    }
    if main_thread {
        flags |= hc::CPLF_MAIN_THREAD;
    }
    let cpl = HostCallCompletion {
        request_id,
        host_result: r0 as i32,
        flags,
        value0: r1,
        value1: 0,
        user_tag,
    };
    let mut q = inner.completions.lock().unwrap();
    q.push_back(cpl);
    let len = q.len() as u64;
    if len > inner.completion_queue_hwm.load(Ordering::Relaxed) {
        inner.completion_queue_hwm.store(len, Ordering::Relaxed);
        if len >= COMPLETION_WARN_HWM as u64 {
            log::warn!("hostcall completion queue depth={}", len);
        }
    }
}

fn host_ui_main_thread_mode() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| {
        std::env::var("WINEMU_HOST_UI_MAIN_THREAD")
            .ok()
            .as_deref()
            == Some("1")
    })
}
