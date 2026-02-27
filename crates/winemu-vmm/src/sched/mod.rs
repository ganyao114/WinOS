pub mod sync;
pub mod wait;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, atomic::{AtomicU32, AtomicBool, Ordering}};
use std::time::Instant;

pub use sync::{SyncHandle, SyncObject};

// ── 分片常量 ────────────────────────────────────────────────
const THREAD_SHARDS: usize = 16;
const SYNC_SHARDS:   usize = 16;

// ── ThreadId ────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadId(pub u32);

// ── 寄存器上下文 ─────────────────────────────────────────────
#[derive(Clone)]
pub struct ThreadContext {
    /// x0-x30 = [0..30], sp = [31], pc = [32]
    pub gpr:      [u64; 33],
    pub pstate:   u64,
    /// Q0-Q31（延迟保存）
    pub fp_regs:  [u128; 32],
    pub fp_dirty: bool,
    pub fpcr:     u64,
    pub fpsr:     u64,
}

impl Default for ThreadContext {
    fn default() -> Self {
        Self {
            gpr:      [0u64; 33],
            pstate:   0,
            fp_regs:  [0u128; 32],
            fp_dirty: false,
            fpcr:     0,
            fpsr:     0,
        }
    }
}

// ── 等待描述符 ───────────────────────────────────────────────
#[derive(Clone)]
pub enum WaitKind {
    Single(SyncHandle),
    Multiple { handles: Vec<SyncHandle>, wait_all: bool },
}

#[derive(Clone)]
pub struct WaitRequest {
    pub kind:       WaitKind,
    pub deadline:   Option<Instant>,
    /// 唤醒时填入：哪个 handle 触发（WaitMultiple 用）
    pub wake_index: Option<usize>,
}

// ── 线程状态 ─────────────────────────────────────────────────
pub enum ThreadState {
    Ready,
    Running { vcpu_id: u32 },
    Waiting(WaitRequest),
    Terminated(u32),
}

// ── Guest 线程 ───────────────────────────────────────────────
pub struct GuestThread {
    pub id:      ThreadId,
    pub state:   ThreadState,
    pub ctx:     ThreadContext,
    pub teb_gva: u64,
}

// ── hypercall 返回值 ─────────────────────────────────────────
pub enum SchedResult {
    /// 立即返回，x0 = value
    Sync(u64),
    /// 线程阻塞，vCPU 换出
    Block(WaitRequest),
    /// 线程主动让出 CPU
    Yield,
    /// 线程退出
    Exit(u32),
}

// ── Scheduler ───────────────────────────────────────────────
pub struct Scheduler {
    ready:       Mutex<VecDeque<ThreadId>>,
    pub threads: [Mutex<HashMap<ThreadId, GuestThread>>; THREAD_SHARDS],
    pub objects: [Mutex<HashMap<SyncHandle, SyncObject>>; SYNC_SHARDS],
    next_tid:    AtomicU32,
    next_handle: AtomicU32,
    pub vcpu_count: u32,
    vcpu_threads: Mutex<Vec<(u32, std::thread::Thread)>>,
    idle_vcpu_mask: AtomicU32,
    wake_cursor: AtomicU32,
    pub shutdown: AtomicBool,
}

impl Scheduler {
    pub fn new(vcpu_count: u32) -> Arc<Self> {
        Arc::new(Self {
            ready:        Mutex::new(VecDeque::new()),
            threads:      std::array::from_fn(|_| Mutex::new(HashMap::new())),
            objects:      std::array::from_fn(|_| Mutex::new(HashMap::new())),
            next_tid:     AtomicU32::new(1),
            next_handle:  AtomicU32::new(1),
            vcpu_count,
            vcpu_threads: Mutex::new(Vec::new()),
            idle_vcpu_mask: AtomicU32::new(0),
            wake_cursor: AtomicU32::new(0),
            shutdown:     AtomicBool::new(false),
        })
    }

    // ── vCPU 注册 ────────────────────────────────────────────
    pub fn register_vcpu_thread(&self, vcpu_id: u32) {
        self.vcpu_threads
            .lock()
            .unwrap()
            .push((vcpu_id, std::thread::current()));
    }

    pub fn set_vcpu_idle(&self, vcpu_id: u32, idle: bool) {
        let bit = if vcpu_id < 32 { 1u32 << vcpu_id } else { 0 };
        if bit == 0 {
            return;
        }
        if idle {
            self.idle_vcpu_mask.fetch_or(bit, Ordering::Release);
        } else {
            self.idle_vcpu_mask.fetch_and(!bit, Ordering::Release);
        }
    }

    pub fn unpark_vcpu_mask(&self, mask: u32) {
        if mask == 0 {
            return;
        }
        for (id, t) in self.vcpu_threads.lock().unwrap().iter() {
            let bit = if *id < 32 { 1u32 << *id } else { 0 };
            if (mask & bit) != 0 {
                t.unpark();
            }
        }
    }

    pub fn unpark_one_vcpu(&self) {
        let idle_mask = self.idle_vcpu_mask.load(Ordering::Acquire);
        if idle_mask != 0 {
            self.unpark_vcpu_mask(idle_mask);
            return;
        }

        let threads = self.vcpu_threads.lock().unwrap();
        let len = threads.len();
        if len == 0 {
            return;
        }
        let idx = (self.wake_cursor.fetch_add(1, Ordering::Relaxed) as usize) % len;
        threads[idx].1.unpark();
    }

    // ── ThreadId 分片 ────────────────────────────────────────
    fn thread_shard(tid: ThreadId) -> usize {
        tid.0 as usize % THREAD_SHARDS
    }

    pub fn thread_shard_pub(tid: ThreadId) -> usize {
        tid.0 as usize % THREAD_SHARDS
    }

    fn object_shard(h: SyncHandle) -> usize {
        h.0 as usize % SYNC_SHARDS
    }

    pub fn object_shard_pub(h: SyncHandle) -> usize {
        h.0 as usize % SYNC_SHARDS
    }

    // ── 线程管理 ─────────────────────────────────────────────
    pub fn alloc_tid(&self) -> ThreadId {
        ThreadId(self.next_tid.fetch_add(1, Ordering::Relaxed))
    }

    pub fn spawn(&self, tid: ThreadId, ctx: ThreadContext, teb_gva: u64) {
        let shard = Self::thread_shard(tid);
        self.threads[shard].lock().unwrap().insert(tid, GuestThread {
            id: tid,
            state: ThreadState::Ready,
            ctx,
            teb_gva,
        });
        self.push_ready(tid);
    }

    pub fn push_ready(&self, tid: ThreadId) {
        self.ready.lock().unwrap().push_back(tid);
        self.unpark_one_vcpu();
    }

    pub fn pop_ready(&self) -> Option<ThreadId> {
        self.ready.lock().unwrap().pop_front()
    }

    /// 取出线程上下文（换入前调用）
    pub fn take_ctx(&self, tid: ThreadId) -> Option<ThreadContext> {
        let shard = Self::thread_shard(tid);
        let mut map = self.threads[shard].lock().unwrap();
        let t = map.get_mut(&tid)?;
        t.state = ThreadState::Running { vcpu_id: 0 };
        Some(t.ctx.clone())
    }

    /// 保存线程上下文（换出时调用）
    pub fn save_ctx(&self, tid: ThreadId, ctx: ThreadContext) {
        let shard = Self::thread_shard(tid);
        if let Some(t) = self.threads[shard].lock().unwrap().get_mut(&tid) {
            t.ctx = ctx;
        }
    }

    /// 将线程置为 Waiting 状态
    pub fn set_waiting(&self, tid: ThreadId, req: WaitRequest) {
        let shard = Self::thread_shard(tid);
        if let Some(t) = self.threads[shard].lock().unwrap().get_mut(&tid) {
            t.state = ThreadState::Waiting(req);
        }
    }

    /// 将线程置为 Terminated
    pub fn terminate(&self, tid: ThreadId, code: u32) {
        let shard = Self::thread_shard(tid);
        if let Some(t) = self.threads[shard].lock().unwrap().get_mut(&tid) {
            t.state = ThreadState::Terminated(code);
        }
        // 唤醒所有等待该线程退出的 waiter
        self.notify_thread_exit(tid);
    }

    // ── 同步句柄管理 ─────────────────────────────────────────
    pub fn alloc_handle(&self) -> SyncHandle {
        SyncHandle(self.next_handle.fetch_add(1, Ordering::Relaxed))
    }

    pub fn insert_object(&self, h: SyncHandle, obj: SyncObject) {
        let shard = Self::object_shard(h);
        self.objects[shard].lock().unwrap().insert(h, obj);
    }

    pub fn close_handle(&self, h: SyncHandle) -> bool {
        let shard = Self::object_shard(h);
        self.objects[shard].lock().unwrap().remove(&h).is_some()
    }

    /// 检查超时，将到期的 Waiting 线程移回 Ready 队列
    pub fn check_timeouts(&self) {
        let now = Instant::now();
        let mut woke_any = false;
        for shard in &self.threads {
            let mut map = shard.lock().unwrap();
            let expired: Vec<ThreadId> = map.values()
                .filter_map(|t| {
                    if let ThreadState::Waiting(ref req) = t.state {
                        if req.deadline.map(|d| now >= d).unwrap_or(false) {
                            return Some(t.id);
                        }
                    }
                    None
                })
                .collect();
            for tid in expired {
                if let Some(t) = map.get_mut(&tid) {
                    // STATUS_TIMEOUT = 0x00000102
                    t.ctx.gpr[0] = 0x0000_0102;
                    t.state = ThreadState::Ready;
                    self.ready.lock().unwrap().push_back(tid);
                    woke_any = true;
                }
            }
        }
        if woke_any {
            self.unpark_one_vcpu();
        }
    }

    /// Return the TEB GVA for a thread, if known.
    pub fn get_teb(&self, tid: ThreadId) -> Option<u64> {
        let shard = Self::thread_shard(tid);
        self.threads[shard].lock().unwrap()
            .get(&tid)
            .map(|t| t.teb_gva)
    }

    fn notify_thread_exit(&self, _tid: ThreadId) {
        // Check if all threads are terminated — if so, signal shutdown
        let all_done = self.threads.iter().all(|shard| {
            shard.lock().unwrap().values().all(|t| matches!(t.state, ThreadState::Terminated(_)))
        });
        if all_done {
            self.shutdown.store(true, Ordering::Release);
            for (_, t) in self.vcpu_threads.lock().unwrap().iter() {
                t.unpark();
            }
        }
    }
}
