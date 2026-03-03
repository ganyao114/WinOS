// Guest kernel scheduler — EL1
// 多 vCPU：每个 vCPU 一个 KScheduler，共享全局就绪队列（自旋锁保护）。
// 借鉴 yuzu KAbstractSchedulerLock 的"延迟更新"模式。
// vCPU 空闲时执行 WFI → VM exit → VMM park 宿主线程。

mod lock;
pub mod sync;
mod thread_control;
mod wait;

use crate::kobj::ObjectStore;
use crate::mm::vaspace::VmaType;
use crate::nt::constants::{
    DEFAULT_THREAD_STACK_COMMIT, DEFAULT_THREAD_STACK_RESERVE, PAGE_SIZE_4K, PSEUDO_CURRENT_THREAD,
    PSEUDO_CURRENT_THREAD_ALT, THREAD_BASIC_INFORMATION_SIZE, THREAD_STACK_ALIGN,
};
use crate::nt::state::{
    vm_alloc_region_typed, vm_free_region, vm_handle_page_fault, vm_make_guard_page, VM_ACCESS_WRITE,
};
use crate::timer::{self, TimerTaskHandle, TimerTaskKind};
use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;
use winemu_shared::status;
use winemu_shared::teb as teb_layout;

pub use lock::{sched_lock_acquire, sched_lock_release, ScopedSchedulerLock};
pub(crate) use thread_control::{boost_thread_priority_locked, set_thread_priority_locked};
pub use thread_control::{
    charge_current_runtime_locked, current_slice_remaining_100ns, resolve_thread_tid_from_handle,
    resume_thread_by_handle, rotate_current_on_quantum_expire_locked,
    set_thread_base_priority_by_handle, suspend_thread_by_handle,
};
pub(crate) use wait::{
    begin_wait_locked, cancel_wait_locked, clear_wait_tracking_locked, end_wait_locked,
    ensure_current_wait_preconditions_locked, prepare_wait_tracking_locked,
};
pub use wait::{
    block_current_and_resched, check_timeouts, deadline_after_100ns, next_wait_deadline_locked,
    now_ticks, current_wait_result,
};

// ── 常量 ─────────────────────────────────────────────────────

pub const MAX_VCPUS: usize = 8;
pub const IDLE_TID: u32 = 0;
pub const MAX_WAIT_HANDLES: usize = 64;
pub const KERNEL_STACK_SIZE: usize = 64 * 1024;
const DEFERRED_KSTACK_CAP: usize = 1024;

pub const WAIT_KIND_NONE: u8 = 0;
pub const WAIT_KIND_SINGLE: u8 = 1;
pub const WAIT_KIND_MULTI_ANY: u8 = 2;
pub const WAIT_KIND_MULTI_ALL: u8 = 3;
pub const WAIT_KIND_DELAY: u8 = 4;
pub const WAIT_KIND_HOSTCALL: u8 = 5;
const DYNAMIC_BOOST_DELTA: u8 = 2;
const DYNAMIC_BOOST_MAX: u8 = 15;

// ── 线程状态 ──────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ThreadState {
    Free = 0,
    Ready = 1,
    Running = 2,
    Waiting = 3,
    Terminated = 4,
    Suspended = 5,
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

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct KernelContext {
    pub x19_x30: [u64; 12],
    pub sp_el1: u64,
    pub lr_el1: u64,
}

// ── KThread ───────────────────────────────────────────────────

#[repr(C)]
pub struct KThread {
    pub state: ThreadState,
    pub priority: u8, // NT priority 0–31 (31 = highest)
    pub base_priority: u8,
    pub suspend_count: u8,
    pub tid: u32,
    pub pid: u32,
    pub teb_va: u64,
    pub stack_base: u64,
    pub stack_size: u64,
    pub kstack_base: u64,
    pub kstack_size: u64,
    pub in_kernel: bool,

    pub ctx: ThreadContext,
    pub kctx: KernelContext,

    // 等待信息
    pub wait_result: u32,   // NTSTATUS written on wake
    pub wait_deadline: u64, // deadline in CNTVCT ticks (0 = no timeout)
    pub wait_timer_task_id: u32,
    pub wait_timer_generation: u32,
    pub wait_kind: u8,      // WAIT_KIND_*
    pub wait_count: u8,     // number of handles in wait_handles
    pub wait_signaled: u64, // bitmask for WAIT_KIND_MULTI_ALL

    // 时间片记账（100ns）
    pub slice_remaining_100ns: u64,
    pub last_start_100ns: u64,
    pub last_vcpu_hint: u8,
    pub transient_boost: u8,

    // 侵入式链表节点（就绪队列 / 等待队列）
    pub sched_next: u32, // TID of next in ready queue (0 = end)
    pub wait_next: u32,  // TID of next in wait queue (0 = end)
    pub waiters: sync::WaitQueue, // waiters blocked on this thread handle
    pub wait_handles: [u64; MAX_WAIT_HANDLES],
}

impl KThread {
    const fn zeroed() -> Self {
        Self {
            state: ThreadState::Free,
            priority: 8,
            base_priority: 8,
            suspend_count: 0,
            tid: 0,
            pid: 0,
            teb_va: 0,
            stack_base: 0,
            stack_size: 0,
            kstack_base: 0,
            kstack_size: 0,
            in_kernel: false,
            ctx: ThreadContext {
                x: [0u64; 31],
                sp: 0,
                pc: 0,
                pstate: 0,
                tpidr: 0,
            },
            kctx: KernelContext {
                x19_x30: [0u64; 12],
                sp_el1: 0,
                lr_el1: 0,
            },
            wait_result: 0,
            wait_deadline: 0,
            wait_timer_task_id: 0,
            wait_timer_generation: 0,
            wait_kind: WAIT_KIND_NONE,
            wait_count: 0,
            wait_signaled: 0,
            slice_remaining_100ns: 0,
            last_start_100ns: 0,
            last_vcpu_hint: 0,
            transient_boost: 0,
            sched_next: 0,
            wait_next: 0,
            waiters: sync::WaitQueue::new(),
            wait_handles: [0u64; MAX_WAIT_HANDLES],
        }
    }

    fn init_spawned(
        &mut self,
        tid: u32,
        pid: u32,
        pc: u64,
        sp: u64,
        arg: u64,
        teb_va: u64,
        stack_base: u64,
        stack_size: u64,
        kstack_base: u64,
        kstack_size: u64,
        priority: u8,
    ) {
        self.state = ThreadState::Free;
        self.priority = priority;
        self.base_priority = priority;
        self.suspend_count = 0;
        self.tid = tid;
        self.pid = pid;
        self.teb_va = teb_va;
        self.stack_base = stack_base;
        self.stack_size = stack_size;
        self.kstack_base = kstack_base;
        self.kstack_size = kstack_size;
        self.in_kernel = false;
        self.ctx = ThreadContext::default();
        self.kctx = KernelContext::default();
        self.ctx.pc = pc;
        self.ctx.sp = sp;
        self.ctx.x[0] = arg;
        self.ctx.x[18] = teb_va;
        self.ctx.pstate = 0x0; // EL0t
        self.ctx.tpidr = teb_va;
    }

    fn init_thread0(&mut self, tid: u32, pid: u32, teb_va: u64, kstack_base: u64, kstack_size: u64) {
        self.state = ThreadState::Running;
        self.priority = 8;
        self.base_priority = 8;
        self.suspend_count = 0;
        self.tid = tid;
        self.pid = pid;
        self.teb_va = teb_va;
        self.kstack_base = kstack_base;
        self.kstack_size = kstack_size;
        self.in_kernel = false;
        self.ctx = ThreadContext::default();
        self.kctx = KernelContext::default();
        self.ctx.tpidr = teb_va;
    }

    pub fn basic_info_record(&self) -> [u8; THREAD_BASIC_INFORMATION_SIZE] {
        let mut tbi = [0u8; THREAD_BASIC_INFORMATION_SIZE];
        tbi[8..16].copy_from_slice(&self.teb_va.to_le_bytes());
        tbi[16..24].copy_from_slice(&(self.pid as u64).to_le_bytes());
        tbi[24..32].copy_from_slice(&(self.tid as u64).to_le_bytes());
        tbi[32..40].copy_from_slice(&1u64.to_le_bytes());
        tbi[40..44].copy_from_slice(&(self.priority as i32).to_le_bytes());
        tbi[44..48].copy_from_slice(&(self.base_priority as i32).to_le_bytes());
        tbi
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
            if thread_exists(tail_tid) {
                with_thread_mut(tail_tid, |tail| tail.sched_next = t.tid);
            } else {
                // Corrupted tail; reset this priority queue to a single-node list.
                self.heads[p] = t.tid;
            }
        } else {
            self.heads[p] = t.tid;
        }
        self.tails[p] = t.tid;
        self.present |= 1 << p;
    }

    pub fn pop_highest(&mut self) -> u32 {
        while self.present != 0 {
            let p = 31 - self.present.leading_zeros() as usize;
            let tid = self.heads[p];
            if tid == 0 || !thread_exists(tid) {
                self.heads[p] = 0;
                self.tails[p] = 0;
                self.present &= !(1u32 << p);
                continue;
            }

            let mut next = with_thread(tid, |t| t.sched_next);
            if next != 0 && !thread_exists(next) {
                next = 0;
                with_thread_mut(tid, |t| t.sched_next = 0);
            }
            self.heads[p] = next;
            if next == 0 {
                self.tails[p] = 0;
                self.present &= !(1u32 << p);
            }
            with_thread_mut(tid, |t| t.sched_next = 0);
            return tid;
        }
        0
    }

    pub fn pop_highest_prefer_vcpu(&mut self, prefer_vcpu: usize) -> u32 {
        if self.present == 0 {
            return 0;
        }
        let p = 31 - self.present.leading_zeros() as usize;
        let head = self.heads[p];
        if head == 0 {
            return 0;
        }

        let hint = prefer_vcpu as u8;
        let mut prev = 0u32;
        let mut cur = head;
        while cur != 0 {
            if !thread_exists(cur) {
                if prev == 0 {
                    self.heads[p] = 0;
                    self.tails[p] = 0;
                    self.present &= !(1u32 << p);
                } else {
                    with_thread_mut(prev, |t| t.sched_next = 0);
                    self.tails[p] = prev;
                }
                break;
            }
            let cur_hint = with_thread(cur, |t| t.last_vcpu_hint);
            if cur_hint == hint {
                let mut next = with_thread(cur, |t| t.sched_next);
                if next != 0 && !thread_exists(next) {
                    next = 0;
                }
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
                with_thread_mut(cur, |t| t.sched_next = 0);
                return cur;
            }
            prev = cur;
            let mut next = with_thread(cur, |t| t.sched_next);
            if next != 0 && !thread_exists(next) {
                next = 0;
                with_thread_mut(cur, |t| t.sched_next = 0);
            }
            cur = next;
        }

        self.pop_highest()
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
                if !thread_exists(cur) {
                    if prev == 0 {
                        self.heads[p] = 0;
                        self.tails[p] = 0;
                    } else {
                        with_thread_mut(prev, |t| t.sched_next = 0);
                        self.tails[p] = prev;
                    }
                    self.present &= !(1u32 << p);
                    break;
                }

                let mut next = with_thread(cur, |t| t.sched_next);
                if next != 0 && !thread_exists(next) {
                    next = 0;
                    with_thread_mut(cur, |t| t.sched_next = 0);
                }
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
                    with_thread_mut(cur, |t| t.sched_next = 0);
                    return;
                }
                prev = cur;
                cur = next;
            }
        }
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
    ready_global: UnsafeCell<ReadyQueue>,
    ready_local: UnsafeCell<[ReadyQueue; MAX_VCPUS]>,
    vcpus: UnsafeCell<[KScheduler; MAX_VCPUS]>,
    pending_reschedule_mask: UnsafeCell<u32>,
    reschedule_mask: UnsafeCell<u32>,
    idle_vcpu_mask: UnsafeCell<u32>,
    deferred_kstack_bases: UnsafeCell<[u64; DEFERRED_KSTACK_CAP]>,
    deferred_kstack_len: UnsafeCell<usize>,
    // 全局调度锁（可重入，保护 ready queue 和线程状态）
    // 多 vCPU：底层用原子自旋锁
    lock_count: UnsafeCell<u32>,
    lock_owner: UnsafeCell<u32>, // vcpu_id + 1（0 = 未持有）
    spinlock: UnsafeCell<u32>,   // 0 = free, 1 = locked
}

unsafe impl Sync for Scheduler {}

pub static SCHED: Scheduler = Scheduler {
    threads: UnsafeCell::new(None),
    ready_global: UnsafeCell::new(ReadyQueue::new()),
    ready_local: UnsafeCell::new([const { ReadyQueue::new() }; MAX_VCPUS]),
    vcpus: UnsafeCell::new([const { KScheduler::new() }; MAX_VCPUS]),
    pending_reschedule_mask: UnsafeCell::new(0),
    reschedule_mask: UnsafeCell::new(0),
    idle_vcpu_mask: UnsafeCell::new(0),
    deferred_kstack_bases: UnsafeCell::new([0; DEFERRED_KSTACK_CAP]),
    deferred_kstack_len: UnsafeCell::new(0),
    lock_count: UnsafeCell::new(0),
    lock_owner: UnsafeCell::new(0),
    spinlock: UnsafeCell::new(0),
};

#[no_mangle]
pub static mut __winemu_vcpu_kernel_sp: [u64; MAX_VCPUS] = [0; MAX_VCPUS];

// 线程访问、内核上下文续点与栈迁移
include!("thread_context.rs");
// 就绪队列、拓扑、reschedule mask、状态机与 unlock-edge 切换准备
include!("topology.rs");
// 线程创建/销毁、用户线程栈与 TEB 初始化
include!("threads.rs");
// 调度入口与线程 0 初始化
include!("schedule.rs");
