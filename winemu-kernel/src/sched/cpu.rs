// sched/cpu.rs — Per-vCPU thread-local state via TPIDR_EL1
//
// Each vCPU host thread stores a pointer to its KCpuLocal in TPIDR_EL1.
// This gives O(1) access to current_tid and vcpu_id without touching
// the global scheduler lock.

use crate::sched::types::MAX_VCPUS;

// ── KCpuLocal ─────────────────────────────────────────────────────────────────

#[repr(C)]
pub struct KCpuLocal {
    pub vcpu_id:     u32,
    pub current_tid: u32,
    pub idle_tid:    u32,
    /// Set when this vCPU should call schedule() at next safe point.
    pub needs_reschedule: bool,
    /// True while executing the idle loop.
    pub in_idle:     bool,
    _pad: [u8; 2],
    /// Number of EL1 WFI/WFE traps safely skipped in idle wait path.
    pub wfx_skip_count: u32,
    /// Number of unexpected EL1 WFI/WFE traps (not in idle wait path).
    pub wfx_unexpected_count: u32,
}

impl KCpuLocal {
    pub const fn new(vcpu_id: u32) -> Self {
        Self {
            vcpu_id,
            current_tid: 0,
            idle_tid: 0,
            needs_reschedule: false,
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
        KCpuLocal::new(0), KCpuLocal::new(1),
        KCpuLocal::new(2), KCpuLocal::new(3),
        KCpuLocal::new(4), KCpuLocal::new(5),
        KCpuLocal::new(6), KCpuLocal::new(7),
    ]
};

// ── TPIDR_EL1 accessors ───────────────────────────────────────────────────────

/// Install this vCPU's KCpuLocal pointer into TPIDR_EL1.
/// Must be called once per vCPU host thread before any scheduler use.
pub fn init_cpu_local(vcpu_id: u32) {
    debug_assert!((vcpu_id as usize) < MAX_VCPUS);
    let ptr = unsafe { &mut CPU_LOCALS[vcpu_id as usize] as *mut KCpuLocal };
    unsafe {
        core::arch::asm!(
            "msr tpidr_el1, {0}",
            in(reg) ptr as u64,
            options(nostack, nomem),
        );
    }
}

/// Read the current vCPU's KCpuLocal pointer from TPIDR_EL1.
#[inline(always)]
pub fn cpu_local() -> &'static mut KCpuLocal {
    let ptr: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, tpidr_el1",
            out(reg) ptr,
            options(nostack, readonly),
        );
        &mut *(ptr as *mut KCpuLocal)
    }
}

/// Returns the current vCPU id (0-based).
#[inline(always)]
pub fn vcpu_id() -> u32 {
    cpu_local().vcpu_id
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

/// Mark this vCPU as needing a reschedule.
#[inline(always)]
pub fn set_needs_reschedule() {
    cpu_local().needs_reschedule = true;
}

/// Clear and return the needs_reschedule flag.
#[inline(always)]
pub fn take_needs_reschedule() -> bool {
    let cl = cpu_local();
    let v = cl.needs_reschedule;
    cl.needs_reschedule = false;
    v
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
