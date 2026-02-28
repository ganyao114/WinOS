// Guest kernel scheduler — EL1
// 多 vCPU：每个 vCPU 一个 KScheduler，共享全局就绪队列（自旋锁保护）。
// 借鉴 yuzu KAbstractSchedulerLock 的"延迟更新"模式。
// vCPU 空闲时执行 WFI → VM exit → VMM park 宿主线程。

mod lock;
pub mod sync;

use crate::kobj::ObjectStore;
use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;

pub use lock::{sched_lock_acquire, sched_lock_release};

// ── 常量 ─────────────────────────────────────────────────────

pub const MAX_VCPUS: usize = 8;
pub const IDLE_TID: u32 = 0;
pub const MAX_WAIT_HANDLES: usize = 64;

pub const WAIT_KIND_NONE: u8 = 0;
pub const WAIT_KIND_SINGLE: u8 = 1;
pub const WAIT_KIND_MULTI_ANY: u8 = 2;
pub const WAIT_KIND_MULTI_ALL: u8 = 3;

// ── 线程状态 ──────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ThreadState {
    Free = 0,
    Ready = 1,
    Running = 2,
    Waiting = 3,
    Terminated = 4,
}

// ── EL0 寄存器上下文 ──────────────────────────────────────────

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ThreadContext {
    pub x: [u64; 31], // x0–x30
    pub sp: u64,      // SP_EL0
    pub pc: u64,      // ELR_EL1 (return address)
    pub pstate: u64,  // SPSR_EL1
    pub tpidr: u64,   // TPIDR_EL0 (TEB pointer)
}

// ── KThread ───────────────────────────────────────────────────

#[repr(C)]
pub struct KThread {
    pub state: ThreadState,
    pub priority: u8, // NT priority 0–31 (31 = highest)
    pub base_priority: u8,
    pub tid: u32,
    pub teb_va: u64,

    pub ctx: ThreadContext,

    // 等待信息
    pub wait_result: u32,   // NTSTATUS written on wake
    pub wait_deadline: u64, // deadline in CNTVCT ticks (0 = no timeout)
    pub wait_seq: u32,      // generation used by timeout min-heap stale filtering
    pub wait_kind: u8,      // WAIT_KIND_*
    pub wait_count: u8,     // number of handles in wait_handles
    pub wait_signaled: u64, // bitmask for WAIT_KIND_MULTI_ALL

    // 时间片记账（100ns）
    pub slice_remaining_100ns: u64,
    pub last_start_100ns: u64,

    // 侵入式链表节点（就绪队列 / 等待队列）
    pub sched_next: u32, // TID of next in ready queue (0 = end)
    pub wait_next: u32,  // TID of next in wait queue (0 = end)
    pub wait_handles: [u64; MAX_WAIT_HANDLES],
}

impl KThread {
    const fn zeroed() -> Self {
        Self {
            state: ThreadState::Free,
            priority: 8,
            base_priority: 8,
            tid: 0,
            teb_va: 0,
            ctx: ThreadContext {
                x: [0u64; 31],
                sp: 0,
                pc: 0,
                pstate: 0,
                tpidr: 0,
            },
            wait_result: 0,
            wait_deadline: 0,
            wait_seq: 0,
            wait_kind: WAIT_KIND_NONE,
            wait_count: 0,
            wait_signaled: 0,
            slice_remaining_100ns: 0,
            last_start_100ns: 0,
            sched_next: 0,
            wait_next: 0,
            wait_handles: [0u64; MAX_WAIT_HANDLES],
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
        Self {
            heads: [0u32; 32],
            tails: [0u32; 32],
            present: 0,
        }
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
        if self.present == 0 {
            return 0;
        }
        let p = 31 - self.present.leading_zeros() as usize;
        let tid = self.heads[p];
        if tid == 0 {
            return 0;
        }
        let next = with_thread(tid, |t| t.sched_next);
        self.heads[p] = next;
        if next == 0 {
            self.tails[p] = 0;
            self.present &= !(1u32 << p);
        }
        tid
    }

    pub fn highest_priority(&self) -> Option<u8> {
        if self.present == 0 {
            None
        } else {
            Some((31 - self.present.leading_zeros() as usize) as u8)
        }
    }

    pub fn remove(&mut self, tid: u32) {
        // Linear scan per priority level — only called on wait path, not hot
        for p in 0..32usize {
            let mut prev = 0u32;
            let mut cur = self.heads[p];
            while cur != 0 {
                let next = with_thread(cur, |t| t.sched_next);
                if cur == tid {
                    if prev == 0 {
                        self.heads[p] = next;
                    } else {
                        with_thread_mut(prev, |t| t.sched_next = next);
                    }
                    if next == 0 {
                        self.tails[p] = prev;
                    }
                    if self.heads[p] == 0 {
                        self.present &= !(1u32 << p);
                    }
                    return;
                }
                prev = cur;
                cur = next;
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
struct TimeoutEntry {
    deadline: u64,
    tid: u32,
    seq: u32,
}

struct TimeoutMinHeap {
    data: Vec<TimeoutEntry>,
}

impl TimeoutMinHeap {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn push(&mut self, ent: TimeoutEntry) -> bool {
        if self.data.try_reserve(1).is_err() {
            return false;
        }
        self.data.push(ent);
        let mut idx = self.data.len() - 1;
        while idx > 0 {
            let parent = (idx - 1) / 2;
            if self.data[parent].deadline <= self.data[idx].deadline {
                break;
            }
            self.data.swap(parent, idx);
            idx = parent;
        }
        true
    }

    fn peek(&self) -> Option<TimeoutEntry> {
        self.data.first().copied()
    }

    fn pop(&mut self) -> Option<TimeoutEntry> {
        if self.data.is_empty() {
            return None;
        }
        let top = self.data[0];
        let tail = self.data.pop().unwrap();
        if !self.data.is_empty() {
            self.data[0] = tail;
            let mut idx = 0usize;
            loop {
                let left = idx * 2 + 1;
                let right = left + 1;
                if left >= self.data.len() {
                    break;
                }
                let mut smallest = left;
                if right < self.data.len() && self.data[right].deadline < self.data[left].deadline {
                    smallest = right;
                }
                if self.data[idx].deadline <= self.data[smallest].deadline {
                    break;
                }
                self.data.swap(idx, smallest);
                idx = smallest;
            }
        }
        Some(top)
    }
}

// ── 全局调度器状态（静态分配）────────────────────────────────

// 每 vCPU 调度器：记录当前运行线程
pub struct KScheduler {
    pub current_tid: u32,
    pub needs_scheduling: bool,
}

impl KScheduler {
    const fn new() -> Self {
        Self {
            current_tid: 0,
            needs_scheduling: false,
        }
    }
}

pub struct Scheduler {
    threads: UnsafeCell<Option<ObjectStore<KThread>>>,
    ready: UnsafeCell<ReadyQueue>,
    timeouts: UnsafeCell<Option<TimeoutMinHeap>>,
    vcpus: UnsafeCell<[KScheduler; MAX_VCPUS]>,
    pending_reschedule_mask: UnsafeCell<u32>,
    reschedule_mask: UnsafeCell<u32>,
    idle_vcpu_mask: UnsafeCell<u32>,
    timeout_overflow: UnsafeCell<bool>,
    // 全局调度锁（可重入，保护 ready queue 和线程状态）
    // 多 vCPU：底层用原子自旋锁
    lock_count: UnsafeCell<u32>,
    lock_owner: UnsafeCell<u32>, // vcpu_id + 1（0 = 未持有）
    spinlock: UnsafeCell<u32>,   // 0 = free, 1 = locked
}

unsafe impl Sync for Scheduler {}

pub static SCHED: Scheduler = Scheduler {
    threads: UnsafeCell::new(None),
    ready: UnsafeCell::new(ReadyQueue::new()),
    timeouts: UnsafeCell::new(None),
    vcpus: UnsafeCell::new([const { KScheduler::new() }; MAX_VCPUS]),
    pending_reschedule_mask: UnsafeCell::new(0),
    reschedule_mask: UnsafeCell::new(0),
    idle_vcpu_mask: UnsafeCell::new(0),
    timeout_overflow: UnsafeCell::new(false),
    lock_count: UnsafeCell::new(0),
    lock_owner: UnsafeCell::new(0),
    spinlock: UnsafeCell::new(0),
};

// ── 线程访问辅助 ──────────────────────────────────────────────

fn thread_store_mut() -> &'static mut ObjectStore<KThread> {
    unsafe {
        let slot = &mut *SCHED.threads.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn timeout_heap_mut() -> &'static mut TimeoutMinHeap {
    unsafe {
        let slot = &mut *SCHED.timeouts.get();
        if slot.is_none() {
            *slot = Some(TimeoutMinHeap::new());
        }
        slot.as_mut().unwrap()
    }
}

fn thread_ptr(tid: u32) -> *mut KThread {
    if tid == 0 {
        return core::ptr::null_mut();
    }
    thread_store_mut().get_ptr(tid)
}

pub fn thread_exists(tid: u32) -> bool {
    if tid == 0 {
        return false;
    }
    unsafe {
        let Some(store) = (&*SCHED.threads.get()).as_ref() else {
            return false;
        };
        store.contains(tid)
    }
}

pub fn with_thread<R>(tid: u32, f: impl FnOnce(&KThread) -> R) -> R {
    let ptr = thread_ptr(tid);
    unsafe { f(&*ptr) }
}

pub fn with_thread_mut<R>(tid: u32, f: impl FnOnce(&mut KThread) -> R) -> R {
    let ptr = thread_ptr(tid);
    unsafe { f(&mut *ptr) }
}

pub fn current_tid() -> u32 {
    // Read TPIDR_EL1 low 32 bits — set by svc_dispatch on entry
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el1", out(reg) val, options(nostack, nomem));
    }
    val as u32
}

pub fn vcpu_id() -> usize {
    // High 32 bits of TPIDR_EL1 hold vcpu_id
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el1", out(reg) val, options(nostack, nomem));
    }
    (val >> 32) as usize
}

pub fn set_tpidr_el1(vcpu_id: usize, tid: u32) {
    let val = ((vcpu_id as u64) << 32) | (tid as u64);
    unsafe {
        core::arch::asm!("msr tpidr_el1, {}", in(reg) val, options(nostack, nomem));
    }
}

pub fn current_thread_mut<R>(f: impl FnOnce(&mut KThread) -> R) -> R {
    with_thread_mut(current_tid(), f)
}

#[inline(always)]
fn vcpu_bit(vid: usize) -> u32 {
    if vid >= 32 {
        0
    } else {
        1u32 << vid
    }
}

pub(crate) fn mark_vcpu_needs_scheduling_locked(vid: usize) {
    if vid >= MAX_VCPUS {
        return;
    }
    unsafe {
        (*SCHED.vcpus.get())[vid].needs_scheduling = true;
    }
}

pub(crate) fn mark_all_vcpus_needs_scheduling_locked() {
    unsafe {
        for vid in 0..MAX_VCPUS {
            let bit = vcpu_bit(vid);
            if (*SCHED.vcpus.get())[vid].current_tid != 0
                || (*SCHED.idle_vcpu_mask.get() & bit) != 0
                || vid == 0
            {
                (*SCHED.vcpus.get())[vid].needs_scheduling = true;
            }
        }
    }
}

pub(crate) fn commit_deferred_scheduling_locked() {
    unsafe {
        let mut pending = *SCHED.pending_reschedule_mask.get();
        let mut mask = *SCHED.reschedule_mask.get();
        for vid in 0..MAX_VCPUS {
            if (*SCHED.vcpus.get())[vid].needs_scheduling {
                let bit = vcpu_bit(vid);
                pending |= bit;
                mask |= bit;
                if (*SCHED.idle_vcpu_mask.get() & bit) != 0 {
                    // Preserve in reschedule mask for idle-vCPU wakeup path.
                    *SCHED.reschedule_mask.get() |= bit;
                }
                (*SCHED.vcpus.get())[vid].needs_scheduling = false;
            }
        }
        *SCHED.pending_reschedule_mask.get() = pending;
        *SCHED.reschedule_mask.get() = mask;
    }
}

pub(crate) fn consume_pending_reschedule_locked(vid: usize) -> bool {
    unsafe {
        let bit = vcpu_bit(vid);
        let mask = SCHED.pending_reschedule_mask.get();
        if (*mask & bit) == 0 {
            return false;
        }
        *mask &= !bit;
        true
    }
}

pub(crate) fn set_vcpu_idle_locked(vid: usize, idle: bool) {
    unsafe {
        let bit = vcpu_bit(vid);
        let mask = SCHED.idle_vcpu_mask.get();
        if idle {
            *mask |= bit;
        } else {
            *mask &= !bit;
        }
    }
}

pub fn take_reschedule_mask() -> u32 {
    sched_lock_acquire();
    let mask = unsafe { *SCHED.reschedule_mask.get() };
    unsafe {
        *SCHED.reschedule_mask.get() = 0;
    }
    sched_lock_release();
    mask
}

pub fn idle_vcpu_mask_snapshot() -> u32 {
    sched_lock_acquire();
    let mask = unsafe { *SCHED.idle_vcpu_mask.get() };
    sched_lock_release();
    mask
}

fn timeout_entry_is_live(entry: TimeoutEntry) -> bool {
    if entry.tid == 0 || !thread_exists(entry.tid) {
        return false;
    }
    with_thread(entry.tid, |t| {
        t.state == ThreadState::Waiting
            && t.wait_deadline == entry.deadline
            && t.wait_seq == entry.seq
    })
}

fn prune_timeout_heap_head_locked() {
    let heap = timeout_heap_mut();
    while let Some(head) = heap.peek() {
        if timeout_entry_is_live(head) {
            break;
        }
        let _ = heap.pop();
    }
}

pub(crate) fn set_wait_deadline_locked(tid: u32, deadline: u64) {
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    let seq = with_thread_mut(tid, |t| {
        t.wait_deadline = deadline;
        t.wait_seq = t.wait_seq.wrapping_add(1);
        t.wait_seq
    });
    if deadline == 0 {
        return;
    }
    let ok = timeout_heap_mut().push(TimeoutEntry { deadline, tid, seq });
    if !ok {
        unsafe {
            *SCHED.timeout_overflow.get() = true;
        }
    }
}

pub(crate) fn clear_wait_deadline_locked(tid: u32) {
    set_wait_deadline_locked(tid, 0);
}

// 调度状态变迁的唯一入口（调用者必须持有 sched lock）。
pub(crate) fn set_thread_state_locked(tid: u32, new_state: ThreadState) {
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    let old_state = with_thread(tid, |t| t.state);
    if old_state == new_state {
        return;
    }

    unsafe {
        if old_state == ThreadState::Ready {
            (*SCHED.ready.get()).remove(tid);
        }

        with_thread_mut(tid, |t| {
            t.state = new_state;
            if new_state != ThreadState::Running {
                t.last_start_100ns = 0;
            }
        });

        if new_state == ThreadState::Ready {
            with_thread_mut(tid, |t| (*SCHED.ready.get()).push(t));
        }
    }
    mark_all_vcpus_needs_scheduling_locked();
}

// ── 线程创建 ──────────────────────────────────────────────────

/// 分配新 TID，初始化 KThread，加入就绪队列
pub fn spawn(pc: u64, sp: u64, arg: u64, teb_va: u64, priority: u8) -> u32 {
    sched_lock_acquire();
    let tid = thread_store_mut()
        .alloc_with(|id| {
            let mut t = KThread::zeroed();
            t.state = ThreadState::Free;
            t.priority = priority;
            t.base_priority = priority;
            t.tid = id;
            t.teb_va = teb_va;
            t.ctx.pc = pc;
            t.ctx.sp = sp;
            t.ctx.x[0] = arg;
            t.ctx.x[18] = teb_va;
            t.ctx.pstate = 0x0; // EL0t
            t.ctx.tpidr = teb_va;
            t
        })
        .unwrap_or(0);
    if tid != 0 {
        set_thread_state_locked(tid, ThreadState::Ready);
    }
    sched_lock_release();
    tid
}

// ── 调度核心 ──────────────────────────────────────────────────

/// 选取下一个线程并切换（在 trap 路径持锁调用）
/// 返回 (from_tid, to_tid)；若无需切换则 from == to；to == 0 表示 WFI idle
pub fn schedule(vcpu_id: usize, now_100ns: u64, quantum_100ns: u64) -> (u32, u32) {
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let cur_tid = vcpu.current_tid;
        let cur_running = cur_tid != 0 && with_thread(cur_tid, |t| t.state == ThreadState::Running);

        // Strict priority preemption:
        // keep current running thread unless there exists a higher-priority ready thread.
        if cur_running {
            let cur_prio = with_thread(cur_tid, |t| t.priority);
            match (*SCHED.ready.get()).highest_priority() {
                None => return (cur_tid, cur_tid),
                Some(ready_prio) if ready_prio <= cur_prio => return (cur_tid, cur_tid),
                _ => {}
            }
        }

        let next_tid = (*SCHED.ready.get()).pop_highest();

        if next_tid == 0 {
            // No ready threads — if current thread is still Running, keep it
            if cur_running {
                return (cur_tid, cur_tid);
            }
            // No runnable threads at all → WFI
            vcpu.current_tid = 0;
            set_tpidr_el1(vcpu_id, 0);
            return (cur_tid, 0);
        }

        if cur_running {
            if next_tid == cur_tid {
                set_thread_state_locked(cur_tid, ThreadState::Running);
                with_thread_mut(cur_tid, |t| {
                    if t.slice_remaining_100ns == 0 {
                        t.slice_remaining_100ns = quantum_100ns.max(1);
                    }
                    t.last_start_100ns = now_100ns;
                });
                return (cur_tid, cur_tid);
            }
            let cur_state = with_thread(cur_tid, |t| t.state);
            if cur_state == ThreadState::Running {
                set_thread_state_locked(cur_tid, ThreadState::Ready);
            }
        }

        set_thread_state_locked(next_tid, ThreadState::Running);
        with_thread_mut(next_tid, |t| {
            if t.slice_remaining_100ns == 0 {
                t.slice_remaining_100ns = quantum_100ns.max(1);
            }
            t.last_start_100ns = now_100ns;
        });
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
        set_thread_state_locked(cur_tid, ThreadState::Waiting);
        set_wait_deadline_locked(cur_tid, deadline);

        let next_tid = (*SCHED.ready.get()).pop_highest();
        if next_tid == 0 {
            return (cur_tid, 0); // WFI
        }

        set_thread_state_locked(next_tid, ThreadState::Running);
        vcpu.current_tid = next_tid;
        set_tpidr_el1(vcpu_id, next_tid);
        (cur_tid, next_tid)
    }
}

/// 唤醒指定线程
pub fn wake(tid: u32, result: u32) {
    sched_lock_acquire();
    let state = with_thread(tid, |t| t.state);
    if state != ThreadState::Waiting {
        sched_lock_release();
        return;
    }
    with_thread_mut(tid, |t| {
        t.wait_result = result;
        t.wait_seq = t.wait_seq.wrapping_add(1);
        t.wait_deadline = 0;
        t.wait_kind = WAIT_KIND_NONE;
        t.wait_count = 0;
        t.wait_signaled = 0;
        t.wait_handles.fill(0);
        // Resume point for blocked NtWait* should return wake result in x0.
        t.ctx.x[0] = result as u64;
    });
    set_thread_state_locked(tid, ThreadState::Ready);
    sched_lock_release();
}

/// Put the current running thread back to ready queue.
pub fn yield_current_thread() {
    sched_lock_acquire();
    let cur = current_tid();
    let cur_state = with_thread(cur, |t| t.state);
    if cur_state == ThreadState::Running {
        set_thread_state_locked(cur, ThreadState::Ready);
    }
    sched_lock_release();
}

pub fn terminate_current_thread() {
    sched_lock_acquire();
    let cur = current_tid();
    if cur != 0 {
        set_thread_state_locked(cur, ThreadState::Terminated);
    }
    sched_lock_release();
}

/// Initialize the first thread on a vCPU (called from kernel_main).
pub fn set_initial_thread(vcpu_id: usize, tid: u32) {
    sched_lock_acquire();
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        vcpu.current_tid = tid;
        set_thread_state_locked(tid, ThreadState::Running);
        set_tpidr_el1(vcpu_id, tid);
    }
    sched_lock_release();
}

/// Lazily register Thread 0 on first SVC entry.
/// Called at the top of svc_dispatch when current_tid() == 0.
pub fn register_thread0(teb_va: u64) {
    let tid = thread_store_mut().alloc_with(|id| {
        let mut t = KThread::zeroed();
        t.state = ThreadState::Running;
        t.priority = 8;
        t.base_priority = 8;
        t.tid = id;
        t.teb_va = teb_va;
        t.ctx = ThreadContext::default();
        t.ctx.tpidr = teb_va;
        t
    });
    let Some(tid) = tid else {
        return;
    };
    unsafe {
        let vid = vcpu_id().min(MAX_VCPUS - 1);
        let vcpu = &mut (*SCHED.vcpus.get())[vid];
        vcpu.current_tid = tid;
        set_tpidr_el1(vid, tid);
    }
}
/// Returns true if all allocated threads are Terminated or Free (process can exit).
pub fn all_threads_done() -> bool {
    unsafe {
        let Some(store) = (&*SCHED.threads.get()).as_ref() else {
            return true;
        };
        let mut all_done = true;
        store.for_each_live_ptr(|_tid, ptr| {
            if !all_done {
                return;
            }
            let state = (*ptr).state;
            if state != ThreadState::Terminated && state != ThreadState::Free {
                all_done = false;
            }
        });
        all_done
    }
}

/// Timeout dispatch hot path.
/// Caller must hold scheduler lock.
pub fn check_timeouts(now_ticks: u64) -> bool {
    let mut woke_any = false;

    unsafe {
        if *SCHED.timeout_overflow.get() {
            *SCHED.timeout_overflow.get() = false;
            *SCHED.timeouts.get() = Some(TimeoutMinHeap::new());
            if let Some(store) = (&*SCHED.threads.get()).as_ref() {
                store.for_each_live_ptr(|tid, ptr| {
                    let (state, deadline, seq) =
                        ((*ptr).state, (*ptr).wait_deadline, (*ptr).wait_seq);
                    if state == ThreadState::Waiting && deadline != 0 {
                        let _ = timeout_heap_mut().push(TimeoutEntry { deadline, tid, seq });
                    }
                });
            }
        }
    }

    loop {
        prune_timeout_heap_head_locked();
        let head = timeout_heap_mut().peek();
        let Some(ent) = head else {
            break;
        };
        if ent.deadline > now_ticks {
            break;
        }
        let _ = timeout_heap_mut().pop();
        if !timeout_entry_is_live(ent) {
            continue;
        }

        // Remove stale waiter links from all objects before re-queueing.
        crate::sched::sync::cleanup_wait_registration(ent.tid);

        let still_waiting = with_thread(ent.tid, |t| {
            t.state == ThreadState::Waiting
                && t.wait_deadline == ent.deadline
                && t.wait_seq == ent.seq
        });
        if !still_waiting {
            continue;
        }

        with_thread_mut(ent.tid, |t| {
            t.wait_result = 0x0000_0102; // STATUS_TIMEOUT
            t.wait_deadline = 0;
            t.wait_seq = t.wait_seq.wrapping_add(1);
            t.wait_kind = WAIT_KIND_NONE;
            t.wait_count = 0;
            t.wait_signaled = 0;
            t.wait_handles.fill(0);
            t.ctx.x[0] = 0x0000_0102; // x0 = STATUS_TIMEOUT
        });
        set_thread_state_locked(ent.tid, ThreadState::Ready);
        woke_any = true;
    }

    woke_any
}

/// Return the earliest waiting deadline (100ns), 0 if none.
/// Caller must hold scheduler lock.
pub fn next_wait_deadline_locked() -> u64 {
    prune_timeout_heap_head_locked();
    if timeout_heap_mut().is_empty() {
        0
    } else {
        timeout_heap_mut().peek().map_or(0, |e| e.deadline)
    }
}

/// Locking wrapper for callers that are not already in scheduler critical section.
pub fn next_wait_deadline() -> u64 {
    sched_lock_acquire();
    let d = next_wait_deadline_locked();
    sched_lock_release();
    d
}

#[inline(always)]
pub fn now_ticks() -> u64 {
    crate::hypercall::query_mono_time_100ns()
}

/// Convert a relative timeout (100ns units) to an absolute counter deadline.
pub fn deadline_after_100ns(timeout_100ns: u64) -> u64 {
    now_ticks().saturating_add(timeout_100ns)
}

// ── 优先级辅助（调用者必须持有 sched lock）──────────────────────

pub(crate) fn set_thread_priority_locked(tid: u32, new_priority: u8) {
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    let clamped = if new_priority > 31 { 31 } else { new_priority };
    let state = with_thread(tid, |t| t.state);
    if state == ThreadState::Ready {
        unsafe { (*SCHED.ready.get()).remove(tid) };
    }
    with_thread_mut(tid, |t| t.priority = clamped);
    if state == ThreadState::Ready {
        with_thread_mut(tid, |t| unsafe { (*SCHED.ready.get()).push(t) });
    }
    mark_all_vcpus_needs_scheduling_locked();
}

pub(crate) fn boost_thread_priority_locked(tid: u32, min_priority: u8) {
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    let cur = with_thread(tid, |t| t.priority);
    if min_priority > cur {
        set_thread_priority_locked(tid, min_priority);
    }
}

pub fn set_thread_base_priority(tid: u32, new_priority: u8) -> bool {
    if tid == 0 || !thread_exists(tid) {
        return false;
    }
    sched_lock_acquire();
    let valid = with_thread(tid, |t| t.state != ThreadState::Free);
    if valid {
        let clamped = if new_priority > 31 { 31 } else { new_priority };
        with_thread_mut(tid, |t| t.base_priority = clamped);
        set_thread_priority_locked(tid, clamped);
    }
    sched_lock_release();
    valid
}

// ── 时间片记账（调用者必须持有 sched lock）──────────────────────

pub fn charge_current_runtime_locked(vcpu_id: usize, now_100ns: u64, quantum_100ns: u64) -> bool {
    unsafe {
        let cur_tid = (*SCHED.vcpus.get())[vcpu_id].current_tid;
        if cur_tid == 0 {
            return false;
        }
        let mut expired = false;
        with_thread_mut(cur_tid, |t| {
            if t.state != ThreadState::Running {
                return;
            }
            if t.slice_remaining_100ns == 0 {
                t.slice_remaining_100ns = quantum_100ns.max(1);
            }
            if t.last_start_100ns == 0 {
                t.last_start_100ns = now_100ns;
                return;
            }
            let elapsed = now_100ns.saturating_sub(t.last_start_100ns);
            t.last_start_100ns = now_100ns;
            if elapsed >= t.slice_remaining_100ns {
                t.slice_remaining_100ns = 0;
                expired = true;
            } else {
                t.slice_remaining_100ns -= elapsed;
            }
        });
        expired
    }
}

pub fn rotate_current_on_quantum_expire_locked(vcpu_id: usize, quantum_100ns: u64) {
    unsafe {
        let cur_tid = (*SCHED.vcpus.get())[vcpu_id].current_tid;
        if cur_tid == 0 {
            return;
        }
        let is_running = with_thread(cur_tid, |t| t.state == ThreadState::Running);
        if !is_running {
            return;
        }
        with_thread_mut(cur_tid, |t| {
            t.slice_remaining_100ns = quantum_100ns.max(1);
            t.last_start_100ns = 0;
        });
        set_thread_state_locked(cur_tid, ThreadState::Ready);
    }
}

pub fn current_slice_remaining_100ns(vcpu_id: usize, default_100ns: u64) -> u64 {
    unsafe {
        let cur_tid = (*SCHED.vcpus.get())[vcpu_id].current_tid;
        if cur_tid == 0 {
            return default_100ns.max(1);
        }
        with_thread(cur_tid, |t| {
            if t.state != ThreadState::Running || t.slice_remaining_100ns == 0 {
                default_100ns.max(1)
            } else {
                t.slice_remaining_100ns
            }
        })
    }
}
