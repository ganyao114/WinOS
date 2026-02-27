// Guest kernel scheduler — EL1
// 多 vCPU：每个 vCPU 一个 KScheduler，共享全局就绪队列（自旋锁保护）。
// 借鉴 yuzu KAbstractSchedulerLock 的"延迟更新"模式。
// vCPU 空闲时执行 WFI → VM exit → VMM park 宿主线程。

pub mod sync;

use core::cell::UnsafeCell;

// ── 常量 ─────────────────────────────────────────────────────

pub const MAX_THREADS: usize = 64;
pub const MAX_VCPUS:   usize = 8;
pub const IDLE_TID:    u32   = 0;

// ── 线程状态 ──────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ThreadState {
    Free       = 0,
    Ready      = 1,
    Running    = 2,
    Waiting    = 3,
    Terminated = 4,
}

// ── EL0 寄存器上下文 ──────────────────────────────────────────

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ThreadContext {
    pub x:      [u64; 31],   // x0–x30
    pub sp:     u64,          // SP_EL0
    pub pc:     u64,          // ELR_EL1 (return address)
    pub pstate: u64,          // SPSR_EL1
    pub tpidr:  u64,          // TPIDR_EL0 (TEB pointer)
}

// ── KThread ───────────────────────────────────────────────────

#[repr(C)]
pub struct KThread {
    pub state:         ThreadState,
    pub priority:      u8,       // NT priority 0–31 (31 = highest)
    pub base_priority: u8,
    pub tid:           u32,
    pub teb_va:        u64,

    pub ctx:           ThreadContext,

    // 等待信息
    pub wait_result:   u32,      // NTSTATUS written on wake
    pub wait_deadline: u64,      // FILETIME (0 = no timeout)

    // 侵入式链表节点（就绪队列 / 等待队列）
    pub sched_next:    u32,      // TID of next in ready queue (0 = end)
    pub wait_next:     u32,      // TID of next in wait queue (0 = end)
}

impl KThread {
    const fn zeroed() -> Self {
        Self {
            state:         ThreadState::Free,
            priority:      8,
            base_priority: 8,
            tid:           0,
            teb_va:        0,
            ctx:           ThreadContext {
                x: [0u64; 31], sp: 0, pc: 0, pstate: 0, tpidr: 0,
            },
            wait_result:   0,
            wait_deadline: 0,
            sched_next:    0,
            wait_next:     0,
        }
    }
}

// ── 就绪队列（32 优先级，bitset O(1) 查找）────────────────────

pub struct ReadyQueue {
    // 每个优先级的链表头 TID（0 = empty）
    heads: [u32; 32],
    tails: [u32; 32],
    // bitset: bit i = 1 表示优先级 i 有就绪线程
    // NT 优先级 31 最高 → clz(present) 找最高
    present: u32,
}

impl ReadyQueue {
    const fn new() -> Self {
        Self { heads: [0u32; 32], tails: [0u32; 32], present: 0 }
    }

    pub fn push(&mut self, t: &mut KThread) {
        let p = t.priority as usize;
        t.sched_next = 0;
        if self.tails[p] != 0 {
            // append to tail
            let tail_tid = self.tails[p];
            with_thread_mut(tail_tid, |tail| tail.sched_next = t.tid);
        } else {
            self.heads[p] = t.tid;
        }
        self.tails[p] = t.tid;
        self.present |= 1 << p;
    }

    pub fn pop_highest(&mut self) -> u32 {
        if self.present == 0 { return 0; }
        let p = 31 - self.present.leading_zeros() as usize;
        let tid = self.heads[p];
        if tid == 0 { return 0; }
        let next = with_thread(tid, |t| t.sched_next);
        self.heads[p] = next;
        if next == 0 {
            self.tails[p] = 0;
            self.present &= !(1u32 << p);
        }
        tid
    }

    pub fn remove(&mut self, tid: u32) {
        // Linear scan per priority level — only called on wait path, not hot
        for p in 0..32usize {
            let mut prev = 0u32;
            let mut cur  = self.heads[p];
            while cur != 0 {
                let next = with_thread(cur, |t| t.sched_next);
                if cur == tid {
                    if prev == 0 {
                        self.heads[p] = next;
                    } else {
                        with_thread_mut(prev, |t| t.sched_next = next);
                    }
                    if next == 0 { self.tails[p] = prev; }
                    if self.heads[p] == 0 { self.present &= !(1u32 << p); }
                    return;
                }
                prev = cur;
                cur  = next;
            }
        }
    }
}

// ── 全局调度器状态（静态分配）────────────────────────────────

// 每 vCPU 调度器：记录当前运行线程
pub struct KScheduler {
    pub current_tid:      u32,
    pub needs_scheduling: bool,
}

impl KScheduler {
    const fn new() -> Self {
        Self { current_tid: 0, needs_scheduling: false }
    }
}

pub struct Scheduler {
    threads:    UnsafeCell<[KThread; MAX_THREADS]>,
    ready:      UnsafeCell<ReadyQueue>,
    vcpus:      UnsafeCell<[KScheduler; MAX_VCPUS]>,
    next_tid:   UnsafeCell<u32>,
    // 全局调度锁（可重入，保护 ready queue 和线程状态）
    // 多 vCPU：底层用原子自旋锁
    lock_count: UnsafeCell<u32>,
    lock_owner: UnsafeCell<u32>,  // vcpu_id + 1（0 = 未持有）
    spinlock:   UnsafeCell<u32>,  // 0 = free, 1 = locked
}

unsafe impl Sync for Scheduler {}

pub static SCHED: Scheduler = Scheduler {
    threads:    UnsafeCell::new(unsafe {
        core::mem::transmute([0u8; core::mem::size_of::<[KThread; MAX_THREADS]>()])
    }),
    ready:      UnsafeCell::new(ReadyQueue::new()),
    vcpus:      UnsafeCell::new([const { KScheduler::new() }; MAX_VCPUS]),
    next_tid:   UnsafeCell::new(1),
    lock_count: UnsafeCell::new(0),
    lock_owner: UnsafeCell::new(0),
    spinlock:   UnsafeCell::new(0),
};

// ── 线程访问辅助 ──────────────────────────────────────────────

fn thread_ptr(tid: u32) -> *mut KThread {
    if tid == 0 || tid as usize >= MAX_THREADS { return core::ptr::null_mut(); }
    unsafe { &mut (*SCHED.threads.get())[tid as usize] }
}

pub fn with_thread<R>(tid: u32, f: impl FnOnce(&KThread) -> R) -> R {
    unsafe { f(&*thread_ptr(tid)) }
}

pub fn with_thread_mut<R>(tid: u32, f: impl FnOnce(&mut KThread) -> R) -> R {
    unsafe { f(&mut *thread_ptr(tid)) }
}

pub fn current_tid() -> u32 {
    // Read TPIDR_EL1 low 32 bits — set by svc_dispatch on entry
    let val: u64;
    unsafe { core::arch::asm!("mrs {}, tpidr_el1", out(reg) val, options(nostack, nomem)); }
    val as u32
}

pub fn vcpu_id() -> usize {
    // High 32 bits of TPIDR_EL1 hold vcpu_id
    let val: u64;
    unsafe { core::arch::asm!("mrs {}, tpidr_el1", out(reg) val, options(nostack, nomem)); }
    (val >> 32) as usize
}

pub fn set_tpidr_el1(vcpu_id: usize, tid: u32) {
    let val = ((vcpu_id as u64) << 32) | (tid as u64);
    unsafe { core::arch::asm!("msr tpidr_el1, {}", in(reg) val, options(nostack, nomem)); }
}

pub fn current_thread_mut<R>(f: impl FnOnce(&mut KThread) -> R) -> R {
    with_thread_mut(current_tid(), f)
}

// ── 调度锁 ────────────────────────────────────────────────────
// 可重入；底层用原子自旋锁保护多 vCPU 并发。
// lock_owner 存 vcpu_id+1（0 = 未持有）。

fn spinlock_acquire() {
    unsafe {
        let p = SCHED.spinlock.get();
        loop {
            // STXR/LDXR 自旋
            core::arch::asm!(
                "1: ldaxr {old:w}, [{p}]",
                "   cbnz  {old:w}, 1b",
                "   stxr  {old:w}, {one:w}, [{p}]",
                "   cbnz  {old:w}, 1b",
                p   = in(reg) p,
                old = out(reg) _,
                one = in(reg) 1u32,
                options(nostack)
            );
            break;
        }
    }
}

fn spinlock_release() {
    unsafe {
        core::arch::asm!(
            "stlr wzr, [{}]",
            in(reg) SCHED.spinlock.get(),
            options(nostack)
        );
    }
}

pub fn sched_lock_acquire() {
    let vid = vcpu_id();
    let owner_key = (vid as u32) + 1;
    unsafe {
        let owner = SCHED.lock_owner.get();
        let count = SCHED.lock_count.get();
        if *owner == owner_key && *count > 0 {
            *count += 1;
            return;
        }
        spinlock_acquire();
        *owner = owner_key;
        *count = 1;
    }
}

pub fn sched_lock_release() {
    unsafe {
        let count = SCHED.lock_count.get();
        if *count == 0 { return; }
        *count -= 1;
        if *count == 0 {
            *SCHED.lock_owner.get() = 0;
            spinlock_release();
        }
    }
}

// ── 线程创建 ──────────────────────────────────────────────────

/// 分配新 TID，初始化 KThread，加入就绪队列
pub fn spawn(pc: u64, sp: u64, arg: u64, teb_va: u64, priority: u8) -> u32 {
    unsafe {
        let tid = *SCHED.next_tid.get();
        if tid as usize >= MAX_THREADS { return 0; }
        *SCHED.next_tid.get() = tid + 1;

        let t = &mut (*SCHED.threads.get())[tid as usize];
        t.state         = ThreadState::Ready;
        t.priority      = priority;
        t.base_priority = priority;
        t.tid           = tid;
        t.teb_va        = teb_va;
        t.ctx.pc        = pc;
        t.ctx.sp        = sp;
        t.ctx.x[0]      = arg;
        t.ctx.x[18]     = teb_va;
        t.ctx.pstate    = 0x0; // EL0t
        t.ctx.tpidr     = teb_va;
        t.sched_next    = 0;
        t.wait_next     = 0;

        (*SCHED.ready.get()).push(t);
        tid
    }
}

// ── 调度核心 ──────────────────────────────────────────────────

/// 选取下一个线程并切换（在 sched_lock_release 末尾调用）
/// 返回 (from_tid, to_tid)；若无需切换则 from == to；to == 0 表示 WFI idle
pub fn schedule(vcpu_id: usize) -> (u32, u32) {
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let cur_tid = vcpu.current_tid;
        let next_tid = (*SCHED.ready.get()).pop_highest();

        if next_tid == 0 {
            // No ready threads — if current thread is still Running, keep it
            if cur_tid != 0 {
                let still_running = with_thread(cur_tid, |t| t.state == ThreadState::Running);
                if still_running {
                    return (cur_tid, cur_tid);
                }
            }
            // No runnable threads at all → WFI
            return (cur_tid, 0);
        }

        if next_tid == cur_tid {
            // Same thread — keep it Running, no switch needed
            with_thread_mut(cur_tid, |t| t.state = ThreadState::Running);
            return (cur_tid, cur_tid);
        }

        if cur_tid != 0 {
            with_thread_mut(cur_tid, |t| {
                if t.state == ThreadState::Running {
                    t.state = ThreadState::Ready;
                    (*SCHED.ready.get()).push(t);
                }
            });
        }

        with_thread_mut(next_tid, |t| t.state = ThreadState::Running);
        vcpu.current_tid = next_tid;
        set_tpidr_el1(vcpu_id, next_tid);

        (cur_tid, next_tid)
    }
}

/// 将当前线程置为 Waiting，立即调度下一个线程
pub fn block_current(vcpu_id: usize, deadline: u64) -> (u32, u32) {
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let cur_tid = vcpu.current_tid;
        with_thread_mut(cur_tid, |t| {
            t.state         = ThreadState::Waiting;
            t.wait_deadline = deadline;
        });

        let next_tid = (*SCHED.ready.get()).pop_highest();
        if next_tid == 0 {
            return (cur_tid, 0);  // WFI
        }

        with_thread_mut(next_tid, |t| t.state = ThreadState::Running);
        vcpu.current_tid = next_tid;
        set_tpidr_el1(vcpu_id, next_tid);
        (cur_tid, next_tid)
    }
}

/// 唤醒指定线程
pub fn wake(tid: u32, result: u32) {
    unsafe {
        with_thread_mut(tid, |t| {
            if t.state != ThreadState::Waiting { return; }
            t.state         = ThreadState::Ready;
            t.wait_result   = result;
            t.wait_deadline = 0;
            // Resume point for blocked NtWait* should return wake result in x0.
            t.ctx.x[0] = result as u64;
            (*SCHED.ready.get()).push(t);
        });
    }
}

/// Put the current running thread back to ready queue.
pub fn yield_current_thread() {
    let cur = current_tid();
    with_thread_mut(cur, |t| {
        if t.state == ThreadState::Running {
            t.state = ThreadState::Ready;
            unsafe { (*SCHED.ready.get()).push(t); }
        }
    });
}

/// Initialize the first thread on a vCPU (called from kernel_main).
pub fn set_initial_thread(vcpu_id: usize, tid: u32) {
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        vcpu.current_tid = tid;
        with_thread_mut(tid, |t| t.state = ThreadState::Running);
        (*SCHED.ready.get()).remove(tid);
        set_tpidr_el1(vcpu_id, tid);
    }
}

/// Lazily register Thread 0 on first SVC entry.
/// Called at the top of svc_dispatch when current_tid() == 0.
pub fn register_thread0(teb_va: u64) {
    unsafe {
        let tid = *SCHED.next_tid.get();
        if tid as usize >= MAX_THREADS { return; }
        *SCHED.next_tid.get() = tid + 1;

        let t = &mut (*SCHED.threads.get())[tid as usize];
        t.state         = ThreadState::Running;
        t.priority      = 8;
        t.base_priority = 8;
        t.tid           = tid;
        t.teb_va        = teb_va;
        t.ctx           = ThreadContext::default();
        t.ctx.tpidr     = teb_va;
        t.sched_next    = 0;
        t.wait_next     = 0;

        // Register on vCPU 0
        let vcpu = &mut (*SCHED.vcpus.get())[0];
        vcpu.current_tid = tid;
        set_tpidr_el1(0, tid);
    }
}
/// Returns true if all allocated threads are Terminated or Free (process can exit).
pub fn all_threads_done() -> bool {
    unsafe {
        let max = *SCHED.next_tid.get();
        for tid in 1..max {
            let state = with_thread(tid, |t| t.state);
            if state != ThreadState::Terminated && state != ThreadState::Free {
                return false;
            }
        }
        true
    }
}

pub fn check_timeouts(now_filetime: u64) {
    for tid in 1..unsafe { *SCHED.next_tid.get() } {
        with_thread_mut(tid, |t| {
            if t.state == ThreadState::Waiting
                && t.wait_deadline != 0
                && now_filetime >= t.wait_deadline
            {
                t.state         = ThreadState::Ready;
                t.wait_result   = 0x0000_0102; // STATUS_TIMEOUT
                t.wait_deadline = 0;
                t.ctx.x[0]      = 0x0000_0102; // x0 = STATUS_TIMEOUT
                unsafe { (*SCHED.ready.get()).push(t); }
            }
        });
    }
}
