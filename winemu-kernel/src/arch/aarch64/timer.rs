use core::arch::global_asm;

// Guest EOI contract for HVF:
// clear CNTV_CTL_EL0.ENABLE in IRQ entry so host can observe end-of-interrupt
// and unmask vtimer for the next one-shot.
global_asm!(
    ".section .text.timer,\"ax\"",
    ".global __timer_irq_el1",
    "__timer_irq_el1:",
    "msr cntv_ctl_el0, xzr",
    "isb",
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
    "stp x16, x17, [sp, #0x080]",
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
fn next_idle_sleep_100ns(now_100ns: u64, next_deadline_100ns: u64) -> u64 {
    if next_deadline_100ns > now_100ns {
        next_deadline_100ns - now_100ns
    } else {
        10_000 // 1ms fallback when there is no finite deadline.
    }
}

#[inline(always)]
fn arm_vtimer_oneshot_100ns(delta_100ns: u64) {
    let mut freq: u64;
    let mut now: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nostack, nomem));
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) now, options(nostack, nomem));
    }
    if freq == 0 {
        freq = 24_000_000;
    }
    let delta_ticks = (((delta_100ns.max(1) as u128) * (freq as u128)) / 10_000_000u128) as u64;
    let cval = now.saturating_add(delta_ticks.max(1));
    unsafe {
        // ENABLE=1, IMASK=0
        core::arch::asm!("msr cntv_cval_el0, {}", in(reg) cval, options(nostack));
        core::arch::asm!("msr cntv_ctl_el0, {}", in(reg) 1u64, options(nostack));
        core::arch::asm!("isb", options(nostack, nomem));
    }
}

#[inline(always)]
fn wait_for_timer_irq() {
    unsafe {
        core::arch::asm!(
            "msr daifclr, #2", // unmask IRQ while sleeping
            "wfi",
            "msr daifset, #2", // re-mask IRQ in scheduler critical path
            options(nostack)
        );
    }
}

#[inline(always)]
pub fn arm_running_slice_100ns(now_100ns: u64, next_deadline_100ns: u64, quantum_100ns: u64) {
    let mut delta = quantum_100ns.max(1);
    if next_deadline_100ns > now_100ns {
        let wait_delta = next_deadline_100ns - now_100ns;
        if wait_delta < delta {
            delta = wait_delta.max(1);
        }
    }
    arm_vtimer_oneshot_100ns(delta);
}

#[inline(always)]
pub fn schedule_running_slice_100ns(now_100ns: u64, next_deadline_100ns: u64, quantum_100ns: u64) {
    arm_running_slice_100ns(now_100ns, next_deadline_100ns, quantum_100ns);
}

#[inline(always)]
pub fn idle_wait_until_deadline_100ns(now_100ns: u64, next_deadline_100ns: u64) {
    // NOTE:
    // HVF WFI exits are currently handled in host vcpu loop that is still
    // coupled with legacy host-side scheduling state. Using WFI here can
    // deadlock delay wakeups when guest has no runnable thread.
    //
    // Keep running-thread preemption on vtimer IRQs, but use monotonic polling
    // in idle path so timeout wakeups remain correct.
    let target = if next_deadline_100ns > now_100ns {
        next_deadline_100ns
    } else {
        now_100ns.saturating_add(10_000) // 1ms fallback
    };
    while crate::hypercall::query_mono_time_100ns() < target {
        core::hint::spin_loop();
    }
}
