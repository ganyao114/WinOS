// sched/types.rs — 核心类型定义
// KThread, ThreadState, ThreadContext, KernelContext, WaitState

use crate::nt::constants::{THREAD_BASIC_INFORMATION_SIZE};
use super::sync::WaitQueue;

pub const MAX_VCPUS: usize = 8;
pub const MAX_WAIT_HANDLES: usize = 64;
pub const KERNEL_STACK_SIZE: usize = 64 * 1024;
pub const IDLE_TID: u32 = 0;
pub const VCPU_HINT_NONE: u8 = u8::MAX;

pub const WAIT_KIND_NONE: u8 = 0;
pub const WAIT_KIND_SINGLE: u8 = 1;
pub const WAIT_KIND_MULTI_ANY: u8 = 2;
pub const WAIT_KIND_MULTI_ALL: u8 = 3;
pub const WAIT_KIND_DELAY: u8 = 4;
pub const WAIT_KIND_HOSTCALL: u8 = 5;

pub(crate) const DYNAMIC_BOOST_DELTA: u8 = 2;
pub(crate) const DYNAMIC_BOOST_MAX: u8 = 15;

pub const fn all_vcpu_affinity_mask() -> u32 {
    if MAX_VCPUS == 0 {
        0
    } else if MAX_VCPUS >= 32 {
        u32::MAX
    } else {
        (1u32 << MAX_VCPUS) - 1
    }
}

// ── ThreadState ───────────────────────────────────────────────

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
    pub pc: u64,      // ELR_EL1
    pub pstate: u64,  // SPSR_EL1
    pub tpidr: u64,   // TPIDR_EL0 (TEB pointer)
}

// ── EL1 内核上下文（callee-saved）────────────────────────────
// 布局与汇编严格对应：
//   [0x00] x19–x29 (11 × u64)  → x19_x29[0..11]
//   [0x58] x30 (lr)             → lr
//   [0x60] sp_el1               → sp_el1
// 注：去掉冗余 lr_el1 字段，x30 只保存一次。

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct KernelContext {
    pub x19_x29: [u64; 11], // x19–x29
    pub lr: u64,             // x30，continuation 入口
    pub sp_el1: u64,
}

impl KernelContext {
    #[inline(always)]
    pub fn has_continuation(&self) -> bool {
        self.sp_el1 != 0 && self.lr != 0
    }

    pub fn set_continuation(&mut self, sp_top: u64, entry: u64) {
        self.sp_el1 = sp_top;
        self.lr = entry;
        self.x19_x29 = [0; 11];
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

// ── KThread ───────────────────────────────────────────────────

#[repr(C)]
pub struct KThread {
    // 身份
    pub state: ThreadState,
    pub priority: u8,
    pub base_priority: u8,
    pub suspend_count: u8,
    pub tid: u32,
    pub pid: u32,
    pub teb_va: u64,

    // 栈
    pub stack_base: u64,
    pub stack_size: u64,
    pub kstack_base: u64,
    pub kstack_size: u64,

    // 标志
    pub in_kernel: bool,
    pub is_idle_thread: bool,

    // 上下文
    pub ctx: ThreadContext,
    pub kctx: KernelContext,

    // 等待信息
    pub wait_result: u32,
    pub wait_deadline: u64,
    pub wait_timer_task_id: u32,
    pub wait_timer_generation: u32,
    pub wait_kind: u8,
    pub wait_count: u8,
    pub wait_signaled: u64,

    // 时间片记账（100ns）
    pub slice_remaining_100ns: u64,
    pub last_start_100ns: u64,
    pub last_vcpu_hint: u8,
    pub affinity_mask: u32,
    pub transient_boost: u8,

    // 就绪队列链接
    pub sched_next: u32,
    pub wait_next: u32,

    // 等待此线程的 waiters
    pub waiters: WaitQueue,
    pub wait_handles: [u64; MAX_WAIT_HANDLES],
}

impl KThread {
    pub const fn zeroed() -> Self {
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
            is_idle_thread: false,
            ctx: ThreadContext {
                x: [0u64; 31],
                sp: 0,
                pc: 0,
                pstate: 0,
                tpidr: 0,
            },
            kctx: KernelContext {
                x19_x29: [0u64; 11],
                lr: 0,
                sp_el1: 0,
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
            last_vcpu_hint: VCPU_HINT_NONE,
            affinity_mask: all_vcpu_affinity_mask(),
            transient_boost: 0,
            sched_next: 0,
            wait_next: 0,
            waiters: WaitQueue::new(),
            wait_handles: [0u64; MAX_WAIT_HANDLES],
        }
    }

    pub fn init_spawned(
        &mut self,
        tid: u32, pid: u32,
        pc: u64, sp: u64, arg: u64,
        teb_va: u64,
        stack_base: u64, stack_size: u64,
        kstack_base: u64, kstack_size: u64,
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
        self.is_idle_thread = false;
        self.ctx = ThreadContext::default();
        self.kctx = KernelContext::default();
        self.last_vcpu_hint = VCPU_HINT_NONE;
        self.affinity_mask = all_vcpu_affinity_mask();
        self.ctx.pc = pc;
        self.ctx.sp = sp;
        self.ctx.x[0] = arg;
        self.ctx.x[18] = teb_va;
        self.ctx.pstate = 0x0;
        self.ctx.tpidr = teb_va;
    }

    pub fn init_thread0(
        &mut self,
        tid: u32, pid: u32,
        teb_va: u64,
        kstack_base: u64, kstack_size: u64,
    ) {
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
        self.is_idle_thread = false;
        self.ctx = ThreadContext::default();
        self.kctx = KernelContext::default();
        self.last_vcpu_hint = VCPU_HINT_NONE;
        self.affinity_mask = all_vcpu_affinity_mask();
        self.ctx.tpidr = teb_va;
    }

    pub fn init_idle_thread(
        &mut self,
        tid: u32, vcpu_id: usize,
        kstack_base: u64, kstack_size: u64,
    ) {
        self.state = ThreadState::Running;
        self.priority = 0;
        self.base_priority = 0;
        self.suspend_count = 0;
        self.tid = tid;
        self.pid = 0;
        self.teb_va = 0;
        self.stack_base = 0;
        self.stack_size = 0;
        self.kstack_base = kstack_base;
        self.kstack_size = kstack_size;
        self.in_kernel = true;
        self.is_idle_thread = true;
        self.ctx = ThreadContext::default();
        self.kctx = KernelContext::default();
        self.last_vcpu_hint = vcpu_id as u8;
        self.affinity_mask = if vcpu_id < 32 {
            1u32 << vcpu_id
        } else {
            all_vcpu_affinity_mask()
        };
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

    #[inline(always)]
    pub fn kstack_top(&self) -> u64 {
        if self.kstack_base != 0 && self.kstack_size != 0 {
            self.kstack_base.saturating_add(self.kstack_size)
        } else {
            0
        }
    }
}
