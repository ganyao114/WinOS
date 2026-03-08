// sched/types.rs — Core scheduler types: ThreadState, ThreadContext, KernelContext, KThread

use core::sync::atomic::{AtomicU32, Ordering};

pub const MAX_VCPUS: usize = 8;
pub const MAX_WAIT_HANDLES: usize = 64;
pub const KERNEL_STACK_SIZE: usize = 64 * 1024;

// ── ThreadState ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ThreadState {
    Free       = 0,
    Ready      = 1,
    Running    = 2,
    Waiting    = 3,
    Terminated = 4,
    Suspended  = 5,
}

// ── WaitKind flags ───────────────────────────────────────────────────────────

pub const WAIT_KIND_NONE:     u8 = 0;
pub const WAIT_KIND_SINGLE:   u8 = 1;
pub const WAIT_KIND_MULTIPLE: u8 = 2;
pub const WAIT_KIND_DELAY:    u8 = 3;

// ── WaitDeadline ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WaitDeadline {
    Infinite,
    Immediate,
    DeadlineTicks(u64),
}

impl WaitDeadline {
    pub fn to_ticks(self) -> u64 {
        match self {
            WaitDeadline::Infinite => u64::MAX,
            WaitDeadline::Immediate => 0,
            WaitDeadline::DeadlineTicks(t) => t,
        }
    }
}

// ── WaitState ────────────────────────────────────────────────────────────────

pub struct WaitState {
    pub kind:          u8,
    pub result:        u32,
    pub deadline:      u64,
    pub timer_task_id: u32,
    pub handles:       [u64; MAX_WAIT_HANDLES],
    pub handle_count:  u8,
    pub signaled_mask: u64,
    pub wait_all:      bool,
    /// intrusive wait-queue link (next TID in same wait queue)
    pub wait_next:     u32,
}

impl WaitState {
    pub const fn new() -> Self {
        Self {
            kind:          WAIT_KIND_NONE,
            result:        0,
            deadline:      u64::MAX,
            timer_task_id: 0,
            handles:       [0u64; MAX_WAIT_HANDLES],
            handle_count:  0,
            signaled_mask: 0,
            wait_all:      false,
            wait_next:     0,
        }
    }
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

// ── ThreadContext (EL0 registers) ────────────────────────────────────────────

/// EL0 user-mode register snapshot saved on SVC entry.
/// Layout must match arch/aarch64/context.rs __winemu_enter_user_thread_context.
#[repr(C)]
pub struct ThreadContext {
    pub x:      [u64; 31],  // x0–x30  @ 0x000
    pub sp:     u64,         // sp_el0  @ 0x0f8
    pub pc:     u64,         // elr_el1 @ 0x100
    pub pstate: u64,         // spsr_el1@ 0x108
    pub tpidr:  u64,         // tpidr_el0 @ 0x110
}

impl ThreadContext {
    pub const fn new() -> Self {
        Self {
            x:      [0u64; 31],
            sp:     0,
            pc:     0,
            pstate: 0,
            tpidr:  0,
        }
    }
}

// ── KernelContext (EL1 callee-saved) ─────────────────────────────────────────

/// EL1 kernel continuation context.
/// Layout must match arch/aarch64/context.rs assembly exactly:
///   [0x00] x19–x29 (11 × u64)
///   [0x58] x30 / lr  (continuation entry)
///   [0x60] sp_el1
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelContext {
    pub x19_x29: [u64; 11],  // x19–x29 @ 0x00
    pub lr:      u64,         // x30     @ 0x58
    pub sp_el1:  u64,         // sp_el1  @ 0x60
}

impl KernelContext {
    pub const fn new() -> Self {
        Self {
            x19_x29: [0u64; 11],
            lr:      0,
            sp_el1:  0,
        }
    }
    #[inline]
    pub fn has_continuation(&self) -> bool {
        self.sp_el1 != 0 && self.lr != 0
    }
    #[inline]
    pub fn set_continuation(&mut self, sp_top: u64, entry: u64) {
        self.sp_el1  = sp_top;
        self.lr      = entry;
        self.x19_x29 = [0u64; 11];
    }
    #[inline]
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

// ── KThread ──────────────────────────────────────────────────────────────────

pub struct KThread {
    // identity
    pub tid:            u32,
    pub pid:            u32,
    pub state:          ThreadState,
    pub priority:       u8,
    pub base_priority:  u8,
    pub is_idle_thread: bool,

    // EL0 context
    pub ctx:            ThreadContext,

    // EL1 kernel continuation context
    pub kctx:           KernelContext,
    /// true = kctx is valid / thread is executing in EL1
    pub in_kernel:      bool,

    // stacks
    pub stack_base:     u64,
    pub stack_size:     u64,
    pub kstack_base:    u64,
    pub kstack_size:    u64,
    pub teb_va:         u64,

    // scheduling
    pub affinity_mask:          u32,
    pub last_vcpu_hint:         u8,
    pub slice_remaining_100ns:  u64,
    pub last_start_100ns:       u64,
    pub suspend_count:          u32,
    pub transient_boost:        u8,

    // wait state
    pub wait:           WaitState,

    // ready-queue intrusive link
    pub sched_next:     u32,
    pub in_ready_queue: bool,
}

impl KThread {
    pub fn new(tid: u32, pid: u32) -> Self {
        Self {
            tid,
            pid,
            state:                   ThreadState::Free,
            priority:                8,
            base_priority:           8,
            is_idle_thread:          false,
            ctx:                     ThreadContext::new(),
            kctx:                    KernelContext::new(),
            in_kernel:               false,
            stack_base:              0,
            stack_size:              0,
            kstack_base:             0,
            kstack_size:             0,
            teb_va:                  0,
            affinity_mask:           0xFFFF_FFFF,
            last_vcpu_hint:          0,
            slice_remaining_100ns:   0,
            last_start_100ns:        0,
            suspend_count:           0,
            transient_boost:         0,
            wait:                    WaitState::new(),
            sched_next:              0,
            in_ready_queue:          false,
        }
    }
}

// ── Global TID counter ───────────────────────────────────────────────────────

static NEXT_TID: AtomicU32 = AtomicU32::new(1);

pub fn alloc_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::Relaxed)
}
