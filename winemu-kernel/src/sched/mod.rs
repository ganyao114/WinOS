// Guest kernel scheduler — EL1
// 多 vCPU：每个 vCPU 一个 KScheduler，共享全局就绪队列（自旋锁保护）。
// 借鉴 yuzu KAbstractSchedulerLock 的"延迟更新"模式。
// vCPU 空闲时执行 WFI → VM exit → VMM park 宿主线程。

mod lock;
pub mod sync;

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

pub use lock::{sched_lock_acquire, sched_lock_release};

// ── 常量 ─────────────────────────────────────────────────────

pub const MAX_VCPUS: usize = 8;
pub const IDLE_TID: u32 = 0;
pub const MAX_WAIT_HANDLES: usize = 64;

pub const WAIT_KIND_NONE: u8 = 0;
pub const WAIT_KIND_SINGLE: u8 = 1;
pub const WAIT_KIND_MULTI_ANY: u8 = 2;
pub const WAIT_KIND_MULTI_ALL: u8 = 3;
pub const WAIT_KIND_DELAY: u8 = 4;
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

    pub ctx: ThreadContext,

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
            ctx: ThreadContext {
                x: [0u64; 31],
                sp: 0,
                pc: 0,
                pstate: 0,
                tpidr: 0,
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
        self.ctx = ThreadContext::default();
        self.ctx.pc = pc;
        self.ctx.sp = sp;
        self.ctx.x[0] = arg;
        self.ctx.x[18] = teb_va;
        self.ctx.pstate = 0x0; // EL0t
        self.ctx.tpidr = teb_va;
    }

    fn init_thread0(&mut self, tid: u32, pid: u32, teb_va: u64) {
        self.state = ThreadState::Running;
        self.priority = 8;
        self.base_priority = 8;
        self.suspend_count = 0;
        self.tid = tid;
        self.pid = pid;
        self.teb_va = teb_va;
        self.ctx = ThreadContext::default();
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

#[inline(always)]
pub(crate) fn sched_lock_held_by_current_vcpu() -> bool {
    lock::sched_lock_held_by_current_vcpu()
}

pub(crate) fn set_wait_deadline_locked(tid: u32, deadline: u64) -> bool {
    crate::hypercall::debug_u64(0xD101_0001);
    crate::hypercall::debug_u64(tid as u64);
    crate::hypercall::debug_u64(deadline);
    if tid == 0 || !thread_exists(tid) {
        crate::hypercall::debug_u64(0xD101_E001);
        return false;
    }
    let old_handle = with_thread_mut(tid, |t| {
        let prev = TimerTaskHandle {
            id: t.wait_timer_task_id,
            generation: t.wait_timer_generation,
        };
        t.wait_deadline = deadline;
        t.wait_timer_task_id = 0;
        t.wait_timer_generation = 0;
        prev
    });
    if deadline == 0 {
        if old_handle.is_valid() {
            let _ = timer::cancel_task(old_handle);
        }
        crate::hypercall::debug_u64(0xD101_0002);
        return true;
    }

    if old_handle.is_valid() {
        if let Some(handle) = timer::rearm_task(old_handle, deadline) {
            with_thread_mut(tid, |t| {
                t.wait_timer_task_id = handle.id;
                t.wait_timer_generation = handle.generation;
            });
            crate::hypercall::debug_u64(0xD101_0003);
            crate::hypercall::debug_u64(handle.id as u64);
            crate::hypercall::debug_u64(handle.generation as u64);
            return true;
        }
        let _ = timer::cancel_task(old_handle);
    }

    if let Some(handle) = timer::register_task(TimerTaskKind::ThreadTimeout, tid, deadline) {
        with_thread_mut(tid, |t| {
            t.wait_timer_task_id = handle.id;
            t.wait_timer_generation = handle.generation;
        });
        crate::hypercall::debug_u64(0xD101_0004);
        crate::hypercall::debug_u64(handle.id as u64);
        crate::hypercall::debug_u64(handle.generation as u64);
        return true;
    }

    with_thread_mut(tid, |t| {
        t.wait_deadline = 0;
        t.wait_timer_task_id = 0;
        t.wait_timer_generation = 0;
    });
    crate::hypercall::debug_u64(0xD101_E002);
    false
}

pub(crate) fn clear_wait_deadline_locked(tid: u32) {
    let _ = set_wait_deadline_locked(tid, 0);
}

fn apply_dynamic_wake_boost_locked(tid: u32) {
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    with_thread_mut(tid, |t| {
        if t.base_priority >= 16 || t.priority != t.base_priority {
            return;
        }
        let boosted = t
            .base_priority
            .saturating_add(DYNAMIC_BOOST_DELTA)
            .min(DYNAMIC_BOOST_MAX);
        if boosted > t.priority {
            t.priority = boosted;
            t.transient_boost = boosted.saturating_sub(t.base_priority);
        }
    });
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
    priority: u8,
) -> u32 {
    sched_lock_acquire();
    let tid = thread_store_mut()
        .alloc_with(|id| {
            let mut t = KThread::zeroed();
            t.init_spawned(
                id, pid, pc, sp, arg, teb_va, stack_base, stack_size, priority,
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
    let stack_top = stack_base + stack_size;
    let mut stack_limit = stack_top.saturating_sub(stack_commit);
    if stack_limit <= stack_base {
        stack_limit = stack_base.saturating_add(PAGE_SIZE_4K);
    }
    let guard_page = stack_limit.saturating_sub(PAGE_SIZE_4K);
    if guard_page < stack_base || !vm_make_guard_page(pid, guard_page) {
        let _ = vm_free_region(pid, stack_base);
        let _ = vm_free_region(pid, teb_va);
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
        return Err(CreateThreadError::NoMemory);
    }

    let tid = spawn(
        pid, entry_va, stack_top, arg, teb_va, stack_base, stack_size, priority,
    );
    if tid == 0 {
        let _ = vm_free_region(pid, stack_base);
        let _ = vm_free_region(pid, teb_va);
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
    let (state, pid, stack_base, teb_va) =
        with_thread(tid, |t| (t.state, t.pid, t.stack_base, t.teb_va));
    if state == ThreadState::Free || state == ThreadState::Terminated {
        sched_lock_release();
        return false;
    }
    with_thread_mut(tid, |t| {
        t.stack_base = 0;
        t.stack_size = 0;
        t.teb_va = 0;
        t.ctx.tpidr = 0;
    });
    set_thread_state_locked(tid, ThreadState::Terminated);
    sched_lock_release();

    let _ = vm_free_region(pid, stack_base);
    let _ = vm_free_region(pid, teb_va);
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

        (cur_tid, next_tid)
    }
}

/// 将当前线程置为 Waiting，立即调度下一个线程
pub fn block_current(vcpu_id: usize, deadline: u64) -> (u32, u32) {
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let mut cur_tid = vcpu.current_tid;
        if cur_tid != 0 && !thread_exists(cur_tid) {
            vcpu.current_tid = 0;
            set_current_cpu_thread(vcpu_id, 0);
            cur_tid = 0;
        }
        if cur_tid != 0 {
            set_thread_state_locked(cur_tid, ThreadState::Waiting);
            if !set_wait_deadline_locked(cur_tid, deadline) {
                set_thread_state_locked(cur_tid, ThreadState::Ready);
            }
        }

        let next_tid = ready_pop_for_vcpu_locked(vcpu_id);
        if next_tid == 0 {
            return (cur_tid, 0); // WFI
        }

        set_thread_state_locked(next_tid, ThreadState::Running);
        vcpu.current_tid = next_tid;
        set_current_cpu_thread(vcpu_id, next_tid);
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
    let should_boost = with_thread(tid, |t| {
        result == status::SUCCESS && t.wait_kind != WAIT_KIND_DELAY && t.base_priority < 16
    });
    if should_boost {
        apply_dynamic_wake_boost_locked(tid);
    }
    let _ = set_wait_deadline_locked(tid, 0);
    with_thread_mut(tid, |t| {
        t.wait_result = result;
        t.wait_kind = WAIT_KIND_NONE;
        t.wait_count = 0;
        t.wait_signaled = 0;
        t.wait_handles.fill(0);
        // Resume point for blocked NtWait* should return wake result in x0.
        t.ctx.x[0] = result as u64;
    });
    let suspended = with_thread(tid, |t| t.suspend_count != 0);
    if suspended {
        set_thread_state_locked(tid, ThreadState::Suspended);
    } else {
        set_thread_state_locked(tid, ThreadState::Ready);
    }
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
    let tid = thread_store_mut().alloc_with(|id| {
        let mut t = KThread::zeroed();
        t.init_thread0(id, pid, teb_va);
        t
    });
    let Some(tid) = tid else {
        return;
    };
    crate::process::on_thread_created(pid, tid);
    unsafe {
        let vid = vcpu_id().min(MAX_VCPUS - 1);
        let vcpu = &mut (*SCHED.vcpus.get())[vid];
        vcpu.current_tid = tid;
        set_current_cpu_thread(vid, tid);
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

/// Timeout dispatch hot path.
/// Caller must hold scheduler lock.
pub fn check_timeouts(now_ticks: u64) -> bool {
    let mut woke_any = false;

    let mut timeout_now = |tid: u32| {
        if tid == 0 || !thread_exists(tid) {
            return;
        }
        let still_waiting = with_thread(tid, |t| t.state == ThreadState::Waiting);
        if !still_waiting {
            return;
        }
        crate::sched::sync::cleanup_wait_registration_locked(tid);
        let _ = set_wait_deadline_locked(tid, 0);
        with_thread_mut(tid, |t| {
            let timeout_result = if t.wait_kind == WAIT_KIND_DELAY {
                status::SUCCESS
            } else {
                status::TIMEOUT
            };
            t.wait_result = timeout_result;
            t.wait_kind = WAIT_KIND_NONE;
            t.wait_count = 0;
            t.wait_signaled = 0;
            t.wait_handles.fill(0);
            t.ctx.x[0] = timeout_result as u64;
        });
        let suspended = with_thread(tid, |t| t.suspend_count != 0);
        if suspended {
            set_thread_state_locked(tid, ThreadState::Suspended);
        } else {
            set_thread_state_locked(tid, ThreadState::Ready);
        }
        woke_any = true;
    };

    loop {
        let Some(fired) = timer::pop_expired_task_locked(now_ticks) else {
            break;
        };
        if fired.kind != TimerTaskKind::ThreadTimeout {
            continue;
        }
        let tid = fired.target_id;
        if tid == 0 || !thread_exists(tid) {
            continue;
        }

        let still_waiting = with_thread(tid, |t| {
            t.state == ThreadState::Waiting
                && t.wait_deadline == fired.deadline_100ns
                && t.wait_timer_task_id == fired.handle.id
                && t.wait_timer_generation == fired.handle.generation
        });
        if !still_waiting {
            continue;
        }

        timeout_now(tid);
    }

    // Fallback scan: if timer task indexing becomes stale/corrupted, we still
    // honor absolute wait deadlines and avoid indefinite waits.
    unsafe {
        if let Some(store) = (&*SCHED.threads.get()).as_ref() {
            store.for_each_live_id(|tid| {
                if tid == 0 {
                    return;
                }
                let due = with_thread(tid, |t| {
                    t.state == ThreadState::Waiting && t.wait_deadline != 0 && t.wait_deadline <= now_ticks
                });
                if due {
                    timeout_now(tid);
                }
            });
        }
    }

    woke_any
}

/// Return the earliest waiting deadline (100ns), 0 if none.
/// Caller must hold scheduler lock.
pub fn next_wait_deadline_locked() -> u64 {
    let timer_deadline = timer::next_deadline_locked();
    if timer_deadline != 0 {
        return timer_deadline;
    }

    let mut best = 0u64;
    unsafe {
        if let Some(store) = (&*SCHED.threads.get()).as_ref() {
            store.for_each_live_ptr(|_tid, ptr| {
                let t = &*ptr;
                if t.state != ThreadState::Waiting || t.wait_deadline == 0 {
                    return;
                }
                if best == 0 || t.wait_deadline < best {
                    best = t.wait_deadline;
                }
            });
        }
    }
    best
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
        ready_remove_tid_locked(tid);
    }
    with_thread_mut(tid, |t| {
        t.priority = clamped;
        t.transient_boost = 0;
    });
    if state == ThreadState::Ready {
        ready_push_tid_locked(tid);
    }
    let (ready_prio, ready_hint) = if state == ThreadState::Ready {
        (Some(clamped), ready_target_vcpu_hint(tid))
    } else {
        (None, None)
    };
    mark_reschedule_targeted_locked(tid, ready_prio, ready_hint);
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

pub fn resolve_thread_tid_from_handle(thread_handle: u64) -> Option<u32> {
    if thread_handle == 0
        || thread_handle == PSEUDO_CURRENT_THREAD
        || thread_handle == PSEUDO_CURRENT_THREAD_ALT
    {
        return Some(current_tid());
    }
    if sync::handle_type(thread_handle) != sync::HANDLE_TYPE_THREAD {
        return None;
    }
    let tid = sync::handle_idx(thread_handle);
    if tid == 0 || !thread_exists(tid) {
        return None;
    }
    if !with_thread(tid, |t| t.state != ThreadState::Free) {
        return None;
    }
    Some(tid)
}

pub fn suspend_thread_by_tid(tid: u32) -> Result<u32, u32> {
    if tid == 0 || !thread_exists(tid) {
        return Err(status::INVALID_HANDLE);
    }

    sched_lock_acquire();
    let (state, prev_count) = with_thread(tid, |t| (t.state, t.suspend_count));
    if state == ThreadState::Free || state == ThreadState::Terminated {
        sched_lock_release();
        return Err(status::INVALID_HANDLE);
    }
    if prev_count == u8::MAX {
        sched_lock_release();
        return Err(status::INVALID_PARAMETER);
    }

    with_thread_mut(tid, |t| {
        t.suspend_count = t.suspend_count.saturating_add(1);
    });
    if prev_count == 0 {
        match state {
            ThreadState::Running | ThreadState::Ready => {
                set_thread_state_locked(tid, ThreadState::Suspended);
            }
            _ => {}
        }
    }

    sched_lock_release();
    Ok(prev_count as u32)
}

pub fn suspend_thread_by_handle(thread_handle: u64) -> Result<u32, u32> {
    let Some(tid) = resolve_thread_tid_from_handle(thread_handle) else {
        return Err(status::INVALID_HANDLE);
    };
    suspend_thread_by_tid(tid)
}

pub fn resume_thread_by_tid(tid: u32) -> Result<u32, u32> {
    if tid == 0 || !thread_exists(tid) {
        return Err(status::INVALID_HANDLE);
    }

    sched_lock_acquire();
    let (state, prev_count) = with_thread(tid, |t| (t.state, t.suspend_count));
    if state == ThreadState::Free || state == ThreadState::Terminated {
        sched_lock_release();
        return Err(status::INVALID_HANDLE);
    }

    if prev_count != 0 {
        with_thread_mut(tid, |t| {
            t.suspend_count -= 1;
        });
        if prev_count == 1 && state == ThreadState::Suspended {
            set_thread_state_locked(tid, ThreadState::Ready);
        }
    }

    sched_lock_release();
    Ok(prev_count as u32)
}

pub fn resume_thread_by_handle(thread_handle: u64) -> Result<u32, u32> {
    let Some(tid) = resolve_thread_tid_from_handle(thread_handle) else {
        return Err(status::INVALID_HANDLE);
    };
    resume_thread_by_tid(tid)
}

pub fn set_thread_base_priority_by_handle(thread_handle: u64, new_priority: i32) -> u32 {
    if new_priority < 0 {
        return status::INVALID_PARAMETER;
    }
    let Some(target_tid) = resolve_thread_tid_from_handle(thread_handle) else {
        return status::INVALID_HANDLE;
    };
    if !set_thread_base_priority(target_tid, new_priority as u8) {
        return status::INVALID_HANDLE;
    }
    status::SUCCESS
}

// ── 时间片记账（调用者必须持有 sched lock）──────────────────────

pub fn charge_current_runtime_locked(vcpu_id: usize, now_100ns: u64, quantum_100ns: u64) -> bool {
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let cur_tid = vcpu.current_tid;
        if cur_tid == 0 {
            return false;
        }
        if !thread_exists(cur_tid) {
            vcpu.current_tid = 0;
            set_current_cpu_thread(vcpu_id, 0);
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
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let cur_tid = vcpu.current_tid;
        if cur_tid == 0 {
            return;
        }
        if !thread_exists(cur_tid) {
            vcpu.current_tid = 0;
            set_current_cpu_thread(vcpu_id, 0);
            return;
        }
        let is_running = with_thread(cur_tid, |t| t.state == ThreadState::Running);
        if !is_running {
            return;
        }
        with_thread_mut(cur_tid, |t| {
            t.slice_remaining_100ns = quantum_100ns.max(1);
            t.last_start_100ns = 0;
            if t.transient_boost > 0 {
                t.transient_boost -= 1;
                let target = t.base_priority.saturating_add(t.transient_boost);
                if t.priority > target {
                    t.priority = target;
                }
            }
        });
        set_thread_state_locked(cur_tid, ThreadState::Ready);
    }
}

pub fn current_slice_remaining_100ns(vcpu_id: usize, default_100ns: u64) -> u64 {
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let cur_tid = vcpu.current_tid;
        if cur_tid == 0 {
            return default_100ns.max(1);
        }
        if !thread_exists(cur_tid) {
            vcpu.current_tid = 0;
            set_current_cpu_thread(vcpu_id, 0);
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
