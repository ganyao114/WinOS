// sched/cpu.rs — Per-vCPU thread-local state via arch CPU-local register
//
// Each vCPU host thread stores a pointer to its KCpuLocal in the backend's
// CPU-local register.
// This gives O(1) access to current_tid and vcpu_id without touching
// the global scheduler lock.

use crate::sched::types::MAX_VCPUS;

// ── KCpuLocal ─────────────────────────────────────────────────────────────────

#[repr(C)]
pub struct KCpuLocal {
    pub vcpu_id: u32,
    pub current_tid: u32,
    pub idle_tid: u32,
    /// Local trap-safe-point reschedule request for the current vCPU.
    pub pending_trap_reschedule: bool,
    /// True while executing the idle loop.
    pub in_idle: bool,
    _pad: [u8; 2],
    /// Number of kernel-mode WFI/WFE traps safely skipped in idle wait path.
    pub wfx_skip_count: u32,
    /// Number of unexpected kernel-mode WFI/WFE traps (not in idle wait path).
    pub wfx_unexpected_count: u32,
}

impl KCpuLocal {
    pub const fn new(vcpu_id: u32) -> Self {
        Self {
            vcpu_id,
            current_tid: 0,
            idle_tid: 0,
            pending_trap_reschedule: false,
            in_idle: false,
            _pad: [0u8; 2],
            wfx_skip_count: 0,
            wfx_unexpected_count: 0,
        }
    }
}

// ── Static per-vCPU storage ───────────────────────────────────────────────────

static mut CPU_LOCALS: [KCpuLocal; MAX_VCPUS] = {
    // Can't use array repeat for non-Copy, so init manually.
    [
        KCpuLocal::new(0),
        KCpuLocal::new(1),
        KCpuLocal::new(2),
        KCpuLocal::new(3),
        KCpuLocal::new(4),
        KCpuLocal::new(5),
        KCpuLocal::new(6),
        KCpuLocal::new(7),
    ]
};

// ── CPU-local register accessors ─────────────────────────────────────────────

/// Install this vCPU's KCpuLocal pointer into the backend CPU-local register.
/// Must be called once per vCPU host thread before any scheduler use.
pub fn init_cpu_local(vcpu_id: u32) {
    debug_assert!((vcpu_id as usize) < MAX_VCPUS);
    let ptr = unsafe { &mut CPU_LOCALS[vcpu_id as usize] as *mut KCpuLocal };
    crate::arch::cpu::set_current_cpu_local(ptr as u64);
}

/// Read the current vCPU's KCpuLocal pointer from the backend CPU-local register.
#[inline(always)]
pub fn cpu_local() -> &'static mut KCpuLocal {
    let ptr = crate::arch::cpu::current_cpu_local();
    unsafe { &mut *(ptr as *mut KCpuLocal) }
}

/// Returns the current vCPU id (0-based).
#[inline(always)]
pub fn vcpu_id() -> u32 {
    cpu_local().vcpu_id
}

/// Returns the current vCPU index clamped to the scheduler's configured range.
#[inline(always)]
pub fn current_vcpu_index() -> usize {
    (vcpu_id() as usize).min(MAX_VCPUS - 1)
}

/// Returns the TID currently running on this vCPU (0 = idle/none).
#[inline(always)]
pub fn current_tid() -> u32 {
    cpu_local().current_tid
}

/// Update the current TID on this vCPU.
#[inline(always)]
pub fn set_current_tid(tid: u32) {
    cpu_local().current_tid = tid;
}

/// Mark whether this vCPU is inside the idle wait primitive.
#[inline(always)]
pub fn set_in_idle(in_idle: bool) {
    cpu_local().in_idle = in_idle;
}

#[inline(always)]
pub fn in_idle() -> bool {
    cpu_local().in_idle
}

#[inline(always)]
pub fn wfx_skip_count() -> u32 {
    cpu_local().wfx_skip_count
}

#[inline(always)]
pub fn wfx_unexpected_count() -> u32 {
    cpu_local().wfx_unexpected_count
}
