use core::arch::global_asm;

#[no_mangle]
extern "C" fn timer_irq_el1_dispatch() {
    crate::hostcall::pump_completions();
    // Wake threads whose wait deadlines have expired.  This keeps timeout
    // wakeups prompt even when the IRQ fires during non-WFE EL1 execution.
    let woke = {
        let _lock = crate::sched::KSchedulerLock::lock();
        crate::sched::check_wait_timeouts_locked() > 0
    };
    // Signal sibling idle vCPUs so they notice the newly-ready threads
    // without waiting for their own timer deadline.
    if woke {
        super::cpu::send_event();
    }
}

// Guest EOI contract for HVF:
// clear CNTV_CTL_EL0.ENABLE in IRQ entry so host can observe end-of-interrupt
// and unmask vtimer for the next one-shot.
global_asm!(
    ".section .text.timer,\"ax\"",
    ".global __timer_irq_el1",
    "__timer_irq_el1:",
    "msr cntv_ctl_el0, xzr",
    "isb",
    // Save interrupted EL1 GPRs, dispatch IRQ side effects, then resume.
    "sub sp, sp, #0x100",
    "stp x0,  x1,  [sp, #0x000]",
    "stp x2,  x3,  [sp, #0x010]",
    "stp x4,  x5,  [sp, #0x020]",
    "stp x6,  x7,  [sp, #0x030]",
    "stp x8,  x9,  [sp, #0x040]",
    "stp x10, x11, [sp, #0x050]",
    "stp x12, x13, [sp, #0x060]",
    "stp x14, x15, [sp, #0x070]",
    "stp x16, x17, [sp, #0x080]",
    "stp x18, x19, [sp, #0x090]",
    "stp x20, x21, [sp, #0x0a0]",
    "stp x22, x23, [sp, #0x0b0]",
    "stp x24, x25, [sp, #0x0c0]",
    "stp x26, x27, [sp, #0x0d0]",
    "stp x28, x29, [sp, #0x0e0]",
    "str x30,      [sp, #0x0f0]",
    "bl timer_irq_el1_dispatch",
    "ldp x0,  x1,  [sp, #0x000]",
    "ldp x2,  x3,  [sp, #0x010]",
    "ldp x4,  x5,  [sp, #0x020]",
    "ldp x6,  x7,  [sp, #0x030]",
    "ldp x8,  x9,  [sp, #0x040]",
    "ldp x10, x11, [sp, #0x050]",
    "ldp x12, x13, [sp, #0x060]",
    "ldp x14, x15, [sp, #0x070]",
    "ldp x16, x17, [sp, #0x080]",
    "ldp x18, x19, [sp, #0x090]",
    "ldp x20, x21, [sp, #0x0a0]",
    "ldp x22, x23, [sp, #0x0b0]",
    "ldp x24, x25, [sp, #0x0c0]",
    "ldp x26, x27, [sp, #0x0d0]",
    "ldp x28, x29, [sp, #0x0e0]",
    "ldr x30,      [sp, #0x0f0]",
    "add sp, sp, #0x100",
    "eret",
);

// Lower-EL IRQ path:
// build SvcFrame and invoke Rust timer_irq_dispatch so timer IRQ can drive
// preempt scheduling without waiting for the next syscall.
global_asm!(
    ".section .text.timer,\"ax\"",
    ".global __timer_irq_el0",
    "__timer_irq_el0:",
    "msr cntv_ctl_el0, xzr",
    "isb",
    // Preserve interrupted user x16 before borrowing it as scratch.
    "msr tpidrro_el0, x16",
    "ldr x16, =__svc_stack_top",
    "mov sp, x16",
    "sub sp, sp, #0x120",
    // Save x0-x30 (SvcFrame.x[0..31))
    "stp x0,  x1,  [sp, #0x000]",
    "stp x2,  x3,  [sp, #0x010]",
    "stp x4,  x5,  [sp, #0x020]",
    "stp x6,  x7,  [sp, #0x030]",
    "stp x8,  x9,  [sp, #0x040]",
    "stp x10, x11, [sp, #0x050]",
    "stp x12, x13, [sp, #0x060]",
    "stp x14, x15, [sp, #0x070]",
    "mrs x16, tpidrro_el0",
    "str x16,      [sp, #0x080]",
    "str x17,      [sp, #0x088]",
    "stp x18, x19, [sp, #0x090]",
    "stp x20, x21, [sp, #0x0a0]",
    "stp x22, x23, [sp, #0x0b0]",
    "stp x24, x25, [sp, #0x0c0]",
    "stp x26, x27, [sp, #0x0d0]",
    "stp x28, x29, [sp, #0x0e0]",
    "str x30,      [sp, #0x0f0]",
    // Save extra SvcFrame fields.
    "mrs x16, sp_el0",
    "str x16, [sp, #0x0f8]",
    "mrs x16, elr_el1",
    "str x16, [sp, #0x100]",
    "mrs x16, spsr_el1",
    "str x16, [sp, #0x108]",
    "mrs x16, tpidr_el0",
    "str x16, [sp, #0x110]",
    "str xzr, [sp, #0x118]", // x8_orig is irrelevant for IRQ path
    // Migrate SvcFrame onto current thread's private EL1 kernel stack.
    "mov x0, sp",
    "mov x1, #0x120",
    "bl svc_migrate_frame_to_thread_stack",
    "mov sp, x0",
    // Call Rust dispatcher: timer_irq_dispatch(&mut frame)
    "mov x0, sp",
    "bl timer_irq_dispatch",
    // Restore ELR/SPSR/SP_EL0/TPIDR_EL0 from potentially modified frame.
    "ldr x16, [sp, #0x100]",
    "msr elr_el1, x16",
    "ldr x16, [sp, #0x108]",
    "msr spsr_el1, x16",
    "ldr x16, [sp, #0x0f8]",
    "msr sp_el0, x16",
    "ldr x16, [sp, #0x110]",
    "msr tpidr_el0, x16",
    // Restore x0-x30 and return to EL0.
    "ldp x0,  x1,  [sp, #0x000]",
    "ldp x2,  x3,  [sp, #0x010]",
    "ldp x4,  x5,  [sp, #0x020]",
    "ldp x6,  x7,  [sp, #0x030]",
    "ldp x8,  x9,  [sp, #0x040]",
    "ldp x10, x11, [sp, #0x050]",
    "ldp x12, x13, [sp, #0x060]",
    "ldp x14, x15, [sp, #0x070]",
    "ldp x16, x17, [sp, #0x080]",
    "ldp x18, x19, [sp, #0x090]",
    "ldp x20, x21, [sp, #0x0a0]",
    "ldp x22, x23, [sp, #0x0b0]",
    "ldp x24, x25, [sp, #0x0c0]",
    "ldp x26, x27, [sp, #0x0d0]",
    "ldp x28, x29, [sp, #0x0e0]",
    "ldr x30,      [sp, #0x0f0]",
    "add sp, sp, #0x120",
    "eret",
);

pub const DEFAULT_TIMESLICE_100NS: u64 = 150_000; // 15ms

#[inline(always)]
fn timer_frequency() -> u64 {
    let freq = super::cpu::read_cntfrq_el0();
    if freq == 0 {
        24_000_000
    } else {
        freq
    }
}

#[inline(always)]
fn arm_vtimer_oneshot_100ns(delta_100ns: u64) {
    let freq = timer_frequency();
    let now = super::cpu::read_cntvct_el0();
    let delta_ticks = (((delta_100ns.max(1) as u128) * (freq as u128)) / 10_000_000u128) as u64;
    let cval = now.saturating_add(delta_ticks.max(1));
    // ENABLE=1, IMASK=0
    super::cpu::write_cntv_cval_el0(cval);
    super::cpu::write_cntv_ctl_el0(1);
    super::cpu::isb();
}

#[inline(always)]
fn disarm_vtimer() {
    super::cpu::write_cntv_ctl_el0(0);
    super::cpu::isb();
}

#[inline(always)]
fn wait_for_timer_irq() {
    // Program one-shot timer, unmask IRQ, then sleep in WFE.
    // Cross-core scheduler kick uses SEV to wake idle vCPUs even before the
    // timer deadline, while timer IRQ still wakes the core for deadlines.
    super::cpu::daifclr_irq();
    super::cpu::wait_for_event();
    super::cpu::daifset_irq();
}

#[inline(always)]
pub fn arm_running_slice_100ns(now_100ns: u64, next_deadline_100ns: u64, quantum_100ns: u64) {
    let mut delta = quantum_100ns.max(1);
    if next_deadline_100ns > now_100ns {
        delta = delta.min(next_deadline_100ns - now_100ns).max(1);
    }
    arm_vtimer_oneshot_100ns(delta);
}

#[inline(always)]
pub fn schedule_running_slice_100ns(now_100ns: u64, next_deadline_100ns: u64, quantum_100ns: u64) {
    arm_running_slice_100ns(now_100ns, next_deadline_100ns, quantum_100ns);
}

#[inline(always)]
pub fn idle_wait_until_deadline_100ns(now_100ns: u64, next_deadline_100ns: u64) {
    if next_deadline_100ns > now_100ns {
        arm_vtimer_oneshot_100ns(next_deadline_100ns - now_100ns);
    } else {
        disarm_vtimer();
    }
    wait_for_timer_irq();
}
