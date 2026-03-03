// Guest kernel scheduler — EL1
// 多 vCPU：每个 vCPU 一个 KScheduler，共享全局就绪队列（自旋锁保护）。
// 借鉴 yuzu KAbstractSchedulerLock 的"延迟更新"模式。
// vCPU 空闲时执行 WFI → VM exit → VMM park 宿主线程。

mod lock;
mod continuation;
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
pub use continuation::{
    has_dispatch_continuation, has_kernel_continuation, reschedule_current_via_dispatch_continuation,
    save_current_dispatch_continuation, switch_kernel_continuation,
};
pub(crate) use thread_control::{boost_thread_priority_locked, set_thread_priority_locked};
pub use thread_control::{
    charge_current_runtime_locked, current_slice_remaining_100ns, resolve_thread_tid_from_handle,
    resume_thread_by_handle, rotate_current_on_quantum_expire_locked,
    set_thread_base_priority_by_handle, suspend_thread_by_handle,
};
pub(crate) use wait::{
    begin_wait_locked, cancel_wait_locked, clear_wait_tracking_locked, end_wait_locked,
    ensure_current_wait_continuation_locked, prepare_wait_tracking_locked,
};
pub use wait::{
    block_current_and_resched, check_timeouts, deadline_after_100ns, next_wait_deadline_locked,
    now_ticks, wait_current_pending_result,
};

// ── 常量 ─────────────────────────────────────────────────────

pub const MAX_VCPUS: usize = 8;
pub const IDLE_TID: u32 = 0;
pub const MAX_WAIT_HANDLES: usize = 64;
pub const KERNEL_STACK_SIZE: usize = 64 * 1024;

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
    pub dispatch_kctx: KernelContext,
    pub dispatch_valid: bool,

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
            dispatch_kctx: KernelContext {
                x19_x30: [0u64; 12],
                sp_el1: 0,
                lr_el1: 0,
            },
            dispatch_valid: false,
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
        self.dispatch_kctx = KernelContext::default();
        self.dispatch_valid = false;
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
        self.dispatch_kctx = KernelContext::default();
        self.dispatch_valid = false;
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
    lock_count: UnsafeCell::new(0),
    lock_owner: UnsafeCell::new(0),
    spinlock: UnsafeCell::new(0),
};

#[no_mangle]
pub static mut __winemu_vcpu_kernel_sp: [u64; MAX_VCPUS] = [0; MAX_VCPUS];

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

fn thread_ptr(tid: u32) -> *mut KThread {
    if tid == 0 {
        return core::ptr::null_mut();
    }
    thread_store_mut().get_ptr(tid)
}

#[inline(always)]
fn default_kernel_stack_top() -> u64 {
    crate::arch::vectors::default_kernel_stack_top()
}

#[inline(always)]
fn kstack_top_from_thread(t: &KThread) -> u64 {
    if t.kstack_base != 0 && t.kstack_size != 0 {
        t.kstack_base.saturating_add(t.kstack_size as u64)
    } else {
        default_kernel_stack_top()
    }
}

#[inline(always)]
fn set_vcpu_kernel_sp(vid: usize, sp: u64) {
    if vid < MAX_VCPUS {
        unsafe {
            __winemu_vcpu_kernel_sp[vid] = if sp != 0 { sp } else { default_kernel_stack_top() };
        }
    }
}

#[inline(always)]
fn set_vcpu_kernel_sp_for_tid(vid: usize, tid: u32) {
    if tid != 0 && thread_exists(tid) {
        let sp = with_thread(tid, kstack_top_from_thread);
        set_vcpu_kernel_sp(vid, sp);
    } else {
        set_vcpu_kernel_sp(vid, default_kernel_stack_top());
    }
}

pub fn current_thread_kernel_stack_top() -> u64 {
    let tid = current_tid();
    if tid == 0 || !thread_exists(tid) {
        return default_kernel_stack_top();
    }
    with_thread(tid, kstack_top_from_thread)
}

pub fn current_thread_kernel_stack_base() -> u64 {
    let tid = current_tid();
    if tid == 0 || !thread_exists(tid) {
        return 0;
    }
    with_thread(tid, |t| t.kstack_base)
}

pub fn migrate_svc_frame_to_current_kstack(frame_ptr: *mut u8, frame_size: usize) -> *mut u8 {
    if frame_ptr.is_null() || frame_size == 0 {
        return frame_ptr;
    }
    let tid = current_tid();
    if tid == 0 || !thread_exists(tid) {
        return frame_ptr;
    }
    let (base, top) = with_thread(tid, |t| (t.kstack_base, kstack_top_from_thread(t)));
    if base == 0 || top == 0 {
        return frame_ptr;
    }
    let base_usize = base as usize;
    let top_usize = top as usize;
    if top_usize <= base_usize || frame_size > top_usize.saturating_sub(base_usize) {
        return frame_ptr;
    }
    let new_frame_usize = top_usize.saturating_sub(frame_size);
    if new_frame_usize < base_usize {
        return frame_ptr;
    }
    let new_frame = new_frame_usize as *mut u8;
    if new_frame.is_null() || new_frame == frame_ptr {
        return frame_ptr;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(frame_ptr, new_frame, frame_size);
    }
    sched_lock_acquire();
    with_thread_mut(tid, |t| {
        t.kctx.sp_el1 = new_frame as u64;
        t.in_kernel = true;
    });
    sched_lock_release();
    new_frame
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

pub fn thread_count() -> u32 {
    unsafe {
        let Some(store) = (&*SCHED.threads.get()).as_ref() else {
            return 0;
        };
        let mut count = 0u32;
        store.for_each_live_id(|_| {
            count = count.saturating_add(1);
        });
        count
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
    // Read TPIDR_EL1 low 32 bits — set by svc_dispatch on entry.
    crate::arch::cpu::current_cpu_local() as u32
}

pub fn vcpu_id() -> usize {
    // High 32 bits of TPIDR_EL1 hold vcpu_id.
    (crate::arch::cpu::current_cpu_local() >> 32) as usize
}

pub fn set_current_cpu_thread(vcpu_id: usize, tid: u32) {
    let val = ((vcpu_id as u64) << 32) | (tid as u64);
    crate::arch::cpu::set_current_cpu_local(val);
}

pub(crate) fn set_thread_in_kernel_locked(tid: u32, in_kernel: bool) {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "set_thread_in_kernel_locked requires sched lock"
    );
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    with_thread_mut(tid, |t| {
        t.in_kernel = in_kernel;
        if !in_kernel {
            // Returning to EL0 invalidates any previously captured EL1
            // continuation resume target for this thread.
            t.kctx.x19_x30[11] = 0;
            t.kctx.lr_el1 = 0;
            t.kctx.sp_el1 = 0;
            t.dispatch_kctx.x19_x30[11] = 0;
            t.dispatch_valid = false;
            t.dispatch_kctx.lr_el1 = 0;
            t.dispatch_kctx.sp_el1 = 0;
        }
    });
}

pub fn set_thread_in_kernel(tid: u32, in_kernel: bool) {
    sched_lock_acquire();
    set_thread_in_kernel_locked(tid, in_kernel);
    sched_lock_release();
}

pub fn set_current_in_kernel(in_kernel: bool) {
    let tid = current_tid();
    if tid != 0 {
        set_thread_in_kernel(tid, in_kernel);
    }
}

#[inline(always)]
fn vcpu_bit(vid: usize) -> u32 {
    if vid >= 32 {
        0
    } else {
        1u32 << vid
    }
}

#[inline(always)]
fn ready_target_vcpu_hint(tid: u32) -> Option<usize> {
    let hint = with_thread(tid, |t| t.last_vcpu_hint as usize);
    if hint < MAX_VCPUS {
        Some(hint)
    } else {
        None
    }
}

fn ready_push_tid_locked(tid: u32) {
    unsafe {
        if let Some(vid) = ready_target_vcpu_hint(tid) {
            with_thread_mut(tid, |t| (*SCHED.ready_local.get())[vid].push(t));
        } else {
            with_thread_mut(tid, |t| (*SCHED.ready_global.get()).push(t));
        }
    }
}

fn ready_remove_tid_locked(tid: u32) {
    unsafe {
        (*SCHED.ready_global.get()).remove(tid);
        for vid in 0..MAX_VCPUS {
            (*SCHED.ready_local.get())[vid].remove(tid);
        }
    }
}

fn ready_highest_priority_locked() -> Option<u8> {
    unsafe {
        let mut highest = (*SCHED.ready_global.get()).highest_priority();
        for vid in 0..MAX_VCPUS {
            let cand = (*SCHED.ready_local.get())[vid].highest_priority();
            if cand.is_some() && (highest.is_none() || cand > highest) {
                highest = cand;
            }
        }
        highest
    }
}

fn ready_pop_for_vcpu_locked(vcpu_id: usize) -> u32 {
    unsafe {
        let local = &mut (*SCHED.ready_local.get())[vcpu_id];
        let local_prio = local.highest_priority();
        let global_prio = (*SCHED.ready_global.get()).highest_priority();
        let mut donor_vid = None;
        let mut donor_prio = None;
        for off in 1..=MAX_VCPUS {
            let vid = (vcpu_id + off) % MAX_VCPUS;
            let p = (*SCHED.ready_local.get())[vid].highest_priority();
            if p.is_some() && (donor_prio.is_none() || p > donor_prio) {
                donor_prio = p;
                donor_vid = Some(vid);
            }
        }

        let mut best = local_prio;
        if global_prio.is_some() && (best.is_none() || global_prio > best) {
            best = global_prio;
        }
        if donor_prio.is_some() && (best.is_none() || donor_prio > best) {
            best = donor_prio;
        }
        let Some(best_prio) = best else {
            return 0;
        };

        if local_prio == Some(best_prio) {
            return local.pop_highest_prefer_vcpu(vcpu_id);
        }
        if global_prio == Some(best_prio) {
            return (*SCHED.ready_global.get()).pop_highest_prefer_vcpu(vcpu_id);
        }
        if let Some(vid) = donor_vid {
            return (*SCHED.ready_local.get())[vid].pop_highest_prefer_vcpu(vcpu_id);
        }
        0
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

fn mark_reschedule_targeted_locked(changed_tid: u32, ready_prio: Option<u8>, ready_hint: Option<usize>) {
    let local_vid = vcpu_id().min(MAX_VCPUS - 1);
    let mut marked = vcpu_bit(local_vid);
    mark_vcpu_needs_scheduling_locked(local_vid);

    unsafe {
        if let Some(hint) = ready_hint {
            if hint < MAX_VCPUS && hint != local_vid {
                mark_vcpu_needs_scheduling_locked(hint);
                marked |= vcpu_bit(hint);
            }
        }
        let mut idle_target = None;
        let mut preempt_target = None;
        let mut preempt_prio = u8::MAX;
        let idle_mask = *SCHED.idle_vcpu_mask.get();
        for vid in 0..MAX_VCPUS {
            let bit = vcpu_bit(vid);
            if (marked & bit) != 0 {
                continue;
            }
            if (idle_mask & bit) != 0 {
                if idle_target.is_none() {
                    idle_target = Some(vid);
                }
                continue;
            }

            let running_tid = (*SCHED.vcpus.get())[vid].current_tid;
            if running_tid == changed_tid {
                mark_vcpu_needs_scheduling_locked(vid);
                continue;
            }

            if let Some(prio) = ready_prio {
                if running_tid != 0 && thread_exists(running_tid) {
                    let running_prio = with_thread(running_tid, |t| t.priority);
                    if running_prio < prio && running_prio < preempt_prio {
                        preempt_prio = running_prio;
                        preempt_target = Some(vid);
                    }
                }
            }
        }
        if let Some(vid) = idle_target {
            mark_vcpu_needs_scheduling_locked(vid);
        } else if let Some(vid) = preempt_target {
            mark_vcpu_needs_scheduling_locked(vid);
        }
    }
}

pub(crate) fn consume_pending_reschedule_locked(vid: usize) -> bool {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "consume_pending_reschedule_locked requires sched lock"
    );
    unsafe {
        let bit = vcpu_bit(vid);
        let pending = SCHED.pending_reschedule_mask.get();
        let hinted = SCHED.reschedule_mask.get();
        let had = ((*pending | *hinted) & bit) != 0;
        if !had {
            return false;
        }
        *pending &= !bit;
        *hinted &= !bit;
        true
    }
}

pub(crate) fn consume_idle_wakeup_mask_locked() -> u32 {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "consume_idle_wakeup_mask_locked requires sched lock"
    );
    unsafe {
        let hinted = SCHED.reschedule_mask.get();
        let idle = *SCHED.idle_vcpu_mask.get();
        let wake_mask = *hinted & idle;
        if wake_mask != 0 {
            *hinted &= !wake_mask;
        }
        wake_mask
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

#[inline(always)]
pub(crate) fn sched_lock_held_by_current_vcpu() -> bool {
    lock::sched_lock_held_by_current_vcpu()
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

    if old_state == ThreadState::Ready {
        ready_remove_tid_locked(tid);
    }

    with_thread_mut(tid, |t| {
        t.state = new_state;
        if new_state != ThreadState::Running {
            t.last_start_100ns = 0;
        }
        if new_state != ThreadState::Ready {
            t.sched_next = 0;
        }
    });

    if new_state == ThreadState::Ready {
        ready_push_tid_locked(tid);
    }
    let (ready_prio, ready_hint) = if new_state == ThreadState::Ready {
        (
            Some(with_thread(tid, |t| t.priority)),
            ready_target_vcpu_hint(tid),
        )
    } else {
        (None, None)
    };
    mark_reschedule_targeted_locked(tid, ready_prio, ready_hint);
}

// ── 线程创建 ──────────────────────────────────────────────────

/// 分配新 TID，初始化 KThread，加入就绪队列
pub fn spawn(
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
) -> u32 {
    sched_lock_acquire();
    let tid = thread_store_mut()
        .alloc_with(|id| {
            let mut t = KThread::zeroed();
            t.init_spawned(
                id,
                pid,
                pc,
                sp,
                arg,
                teb_va,
                stack_base,
                stack_size,
                kstack_base,
                kstack_size,
                priority,
            );
            t
        })
        .unwrap_or(0);
    if tid != 0 {
        set_thread_state_locked(tid, ThreadState::Ready);
    }
    sched_lock_release();
    tid
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateThreadError {
    InvalidParameter,
    NoMemory,
}

#[inline(always)]
fn normalize_stack_size(max_stack_size_arg: u64) -> u64 {
    if max_stack_size_arg == 0 {
        DEFAULT_THREAD_STACK_RESERVE
    } else {
        (max_stack_size_arg + (THREAD_STACK_ALIGN - 1)) & !(THREAD_STACK_ALIGN - 1)
    }
}

#[inline(always)]
fn alloc_kernel_stack() -> Option<(u64, u64)> {
    let ptr = crate::alloc::alloc_zeroed(KERNEL_STACK_SIZE, 16)?;
    Some((ptr as u64, KERNEL_STACK_SIZE as u64))
}

#[inline(always)]
fn free_kernel_stack(base: u64) {
    if base != 0 {
        crate::alloc::dealloc(base as *mut u8);
    }
}

#[inline(always)]
fn normalize_stack_commit_size(stack_size_arg: u64, stack_reserve: u64) -> u64 {
    let requested = if stack_size_arg == 0 {
        DEFAULT_THREAD_STACK_COMMIT
    } else {
        (stack_size_arg + (PAGE_SIZE_4K - 1)) & !(PAGE_SIZE_4K - 1)
    };
    let max_commit = stack_reserve.saturating_sub(PAGE_SIZE_4K);
    if max_commit == 0 {
        return PAGE_SIZE_4K;
    }
    requested.max(PAGE_SIZE_4K).min(max_commit)
}

#[inline(always)]
fn write_process_user_bytes(pid: u32, user_va: u64, src: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let mut done = 0usize;
    while done < len {
        let cur_va = user_va.saturating_add(done as u64);
        let page = cur_va & !(PAGE_SIZE_4K - 1);
        if !vm_handle_page_fault(pid, page, VM_ACCESS_WRITE) {
            return false;
        }
        let Some(dst_pa) = crate::process::with_process(pid, |p| {
            p.address_space
                .translate_user_va_for_access(cur_va, VM_ACCESS_WRITE)
        })
        .flatten()
        else {
            return false;
        };
        let page_off = (cur_va as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let chunk = core::cmp::min(len - done, (PAGE_SIZE_4K as usize) - page_off);
        unsafe {
            core::ptr::copy_nonoverlapping(src.add(done), dst_pa as *mut u8, chunk);
        }
        done += chunk;
    }
    true
}

#[inline(always)]
fn zero_process_user_bytes(pid: u32, user_va: u64, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let mut done = 0usize;
    while done < len {
        let cur_va = user_va.saturating_add(done as u64);
        let page = cur_va & !(PAGE_SIZE_4K - 1);
        if !vm_handle_page_fault(pid, page, VM_ACCESS_WRITE) {
            return false;
        }
        let Some(dst_pa) = crate::process::with_process(pid, |p| {
            p.address_space
                .translate_user_va_for_access(cur_va, VM_ACCESS_WRITE)
        })
        .flatten()
        else {
            return false;
        };
        let page_off = (cur_va as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let chunk = core::cmp::min(len - done, (PAGE_SIZE_4K as usize) - page_off);
        unsafe {
            core::ptr::write_bytes(dst_pa as *mut u8, 0, chunk);
        }
        done += chunk;
    }
    true
}

#[inline(always)]
fn write_teb_u64(pid: u32, teb_va: u64, offset: usize, value: u64) -> bool {
    let bytes = value.to_le_bytes();
    write_process_user_bytes(pid, teb_va + offset as u64, bytes.as_ptr(), bytes.len())
}

#[inline(never)]
pub fn create_user_thread(
    pid: u32,
    entry_va: u64,
    arg: u64,
    stack_size_arg: u64,
    max_stack_size_arg: u64,
    priority: u8,
) -> Result<u32, CreateThreadError> {
    if entry_va == 0 {
        return Err(CreateThreadError::InvalidParameter);
    }

    let stack_size = normalize_stack_size(max_stack_size_arg);
    let stack_commit = normalize_stack_commit_size(stack_size_arg, stack_size);
    let stack_base = vm_alloc_region_typed(pid, 0, stack_size, 0x04, VmaType::ThreadStack)
        .ok_or(CreateThreadError::NoMemory)?;
    let teb_va =
        vm_alloc_region_typed(pid, 0, PAGE_SIZE_4K, 0x04, VmaType::Private).map_or(0, |v| v);
    if teb_va == 0 {
        let _ = vm_free_region(pid, stack_base);
        return Err(CreateThreadError::NoMemory);
    }
    let (kstack_base, kstack_size) = match alloc_kernel_stack() {
        Some(v) => v,
        None => {
            let _ = vm_free_region(pid, stack_base);
            let _ = vm_free_region(pid, teb_va);
            return Err(CreateThreadError::NoMemory);
        }
    };
    let stack_top = stack_base + stack_size;
    let mut stack_limit = stack_top.saturating_sub(stack_commit);
    if stack_limit <= stack_base {
        stack_limit = stack_base.saturating_add(PAGE_SIZE_4K);
    }
    let guard_page = stack_limit.saturating_sub(PAGE_SIZE_4K);
    if guard_page < stack_base || !vm_make_guard_page(pid, guard_page) {
        let _ = vm_free_region(pid, stack_base);
        let _ = vm_free_region(pid, teb_va);
        free_kernel_stack(kstack_base);
        return Err(CreateThreadError::NoMemory);
    }

    let peb_va = crate::process::with_process(pid, |p| p.peb_va).unwrap_or(0);
    if !zero_process_user_bytes(pid, teb_va, PAGE_SIZE_4K as usize)
        || !write_teb_u64(pid, teb_va, teb_layout::EXCEPTION_LIST, u64::MAX)
        || !write_teb_u64(pid, teb_va, teb_layout::STACK_BASE, stack_top)
        || !write_teb_u64(pid, teb_va, teb_layout::STACK_LIMIT, stack_limit)
        || !write_teb_u64(pid, teb_va, teb_layout::SELF, teb_va)
        || !write_teb_u64(pid, teb_va, teb_layout::PEB, peb_va)
        || !write_teb_u64(pid, teb_va, teb_layout::CLIENT_ID, pid as u64)
    {
        let _ = vm_free_region(pid, stack_base);
        let _ = vm_free_region(pid, teb_va);
        free_kernel_stack(kstack_base);
        return Err(CreateThreadError::NoMemory);
    }

    let tid = spawn(
        pid,
        entry_va,
        stack_top,
        arg,
        teb_va,
        stack_base,
        stack_size,
        kstack_base,
        kstack_size,
        priority,
    );
    if tid == 0 {
        let _ = vm_free_region(pid, stack_base);
        let _ = vm_free_region(pid, teb_va);
        free_kernel_stack(kstack_base);
        return Err(CreateThreadError::NoMemory);
    }
    if !write_teb_u64(pid, teb_va, teb_layout::CLIENT_ID + 8, tid as u64) {
        let _ = terminate_thread_by_tid(tid);
        return Err(CreateThreadError::NoMemory);
    }
    crate::process::on_thread_created(pid, tid);
    Ok(tid)
}

pub fn terminate_thread_by_tid(tid: u32) -> bool {
    if tid == 0 || !thread_exists(tid) {
        return false;
    }
    sched_lock_acquire();
    let (state, pid, stack_base, teb_va, kstack_base) =
        with_thread(tid, |t| (t.state, t.pid, t.stack_base, t.teb_va, t.kstack_base));
    if state == ThreadState::Free || state == ThreadState::Terminated {
        sched_lock_release();
        return false;
    }
    if state == ThreadState::Waiting {
        debug_assert!(
            with_thread(tid, |t| t.wait_kind != WAIT_KIND_NONE),
            "waiting thread must carry wait metadata"
        );
        let _ = crate::sched::sync::cancel_wait_on_sync_objects_locked(
            tid,
            status::THREAD_IS_TERMINATING,
        );
    }
    with_thread_mut(tid, |t| {
        t.stack_base = 0;
        t.stack_size = 0;
        t.kstack_base = 0;
        t.kstack_size = 0;
        t.teb_va = 0;
        t.ctx.tpidr = 0;
    });
    set_thread_state_locked(tid, ThreadState::Terminated);
    sched_lock_release();

    let _ = vm_free_region(pid, stack_base);
    let _ = vm_free_region(pid, teb_va);
    free_kernel_stack(kstack_base);
    crate::process::on_thread_terminated(pid, tid);
    true
}

pub fn thread_basic_info(tid: u32) -> Option<[u8; THREAD_BASIC_INFORMATION_SIZE]> {
    if tid == 0 || !thread_exists(tid) {
        return None;
    }
    Some(with_thread(tid, |t| t.basic_info_record()))
}

pub fn thread_pid(tid: u32) -> Option<u32> {
    if tid == 0 || !thread_exists(tid) {
        return None;
    }
    Some(with_thread(tid, |t| t.pid))
}

pub fn thread_ids_by_pid(pid: u32) -> Vec<u32> {
    if pid == 0 {
        return Vec::new();
    }
    unsafe {
        let Some(store) = (&*SCHED.threads.get()).as_ref() else {
            return Vec::new();
        };
        let mut tids = Vec::new();
        store.for_each_live_ptr(|tid, ptr| {
            let t = &*ptr;
            if t.pid == pid && t.state != ThreadState::Free && t.state != ThreadState::Terminated {
                let _ = tids.try_reserve(1);
                tids.push(tid);
            }
        });
        tids
    }
}

// ── 调度核心 ──────────────────────────────────────────────────

/// 选取下一个线程并切换（在 trap 路径持锁调用）
/// 返回 (from_tid, to_tid)；若无需切换则 from == to；to == 0 表示 WFI idle
pub fn schedule(vcpu_id: usize, now_100ns: u64, quantum_100ns: u64) -> (u32, u32) {
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let mut cur_tid = vcpu.current_tid;
        if cur_tid != 0 && !thread_exists(cur_tid) {
            vcpu.current_tid = 0;
            set_current_cpu_thread(vcpu_id, 0);
            cur_tid = 0;
        }
        let cur_running = cur_tid != 0 && with_thread(cur_tid, |t| t.state == ThreadState::Running);

        // Strict priority preemption:
        // keep current running thread unless there exists a higher-priority ready thread.
        if cur_running {
            let cur_prio = with_thread(cur_tid, |t| t.priority);
            match ready_highest_priority_locked() {
                None => return (cur_tid, cur_tid),
                Some(ready_prio) if ready_prio <= cur_prio => return (cur_tid, cur_tid),
                _ => {}
            }
        }

        let next_tid = ready_pop_for_vcpu_locked(vcpu_id);

        if next_tid == 0 {
            // No ready threads — if current thread is still Running, keep it
            if cur_running {
                return (cur_tid, cur_tid);
            }
            // No runnable threads at all → WFI
            vcpu.current_tid = 0;
            set_current_cpu_thread(vcpu_id, 0);
            set_vcpu_kernel_sp(vcpu_id, default_kernel_stack_top());
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
                    t.last_vcpu_hint = vcpu_id as u8;
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
            t.last_vcpu_hint = vcpu_id as u8;
        });
        vcpu.current_tid = next_tid;
        set_current_cpu_thread(vcpu_id, next_tid);
        set_vcpu_kernel_sp_for_tid(vcpu_id, next_tid);

        (cur_tid, next_tid)
    }
}

/// 唤醒指定线程
pub fn wake(tid: u32, result: u32) {
    sched_lock_acquire();
    let _ = end_wait_locked(tid, result);
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
    let cur = current_tid();
    if cur != 0 {
        let _ = terminate_thread_by_tid(cur);
    }
}

/// Initialize the first thread on a vCPU (called from kernel_main).
pub fn set_initial_thread(vcpu_id: usize, tid: u32) {
    sched_lock_acquire();
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        vcpu.current_tid = tid;
        set_thread_state_locked(tid, ThreadState::Running);
        set_current_cpu_thread(vcpu_id, tid);
        set_vcpu_kernel_sp_for_tid(vcpu_id, tid);
        if let Some(pid) = thread_pid(tid) {
            crate::process::set_current_vcpu_pid(vcpu_id, pid);
        }
    }
    sched_lock_release();
}

/// Lazily register Thread 0 on first SVC entry.
/// Called at the top of svc_dispatch when current_tid() == 0.
pub fn register_thread0(teb_va: u64) {
    let pid = crate::process::boot_pid();
    let Some((kstack_base, kstack_size)) = alloc_kernel_stack() else {
        return;
    };
    let tid = thread_store_mut().alloc_with(|id| {
        let mut t = KThread::zeroed();
        t.init_thread0(id, pid, teb_va, kstack_base, kstack_size);
        t
    });
    let Some(tid) = tid else {
        free_kernel_stack(kstack_base);
        return;
    };
    crate::process::on_thread_created(pid, tid);
    unsafe {
        let vid = vcpu_id().min(MAX_VCPUS - 1);
        let vcpu = &mut (*SCHED.vcpus.get())[vid];
        vcpu.current_tid = tid;
        set_current_cpu_thread(vid, tid);
        set_vcpu_kernel_sp_for_tid(vid, tid);
        crate::process::set_current_vcpu_pid(vid, pid);
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
