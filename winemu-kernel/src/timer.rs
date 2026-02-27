use core::arch::global_asm;

// EL1 timer IRQ fast-path.
//
// Guest EOI contract for HVF:
// we clear CNTV_CTL_EL0.ENABLE so host can observe that timer IRQ handling has
// completed and unmask vtimer for the next one-shot.
global_asm!(
    ".section .text.timer,\"ax\"",
    ".global __timer_irq",
    "__timer_irq:",
    "msr cntv_ctl_el0, xzr",
    "isb",
    "eret",
);

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
pub fn idle_wait_until_deadline_100ns(now_100ns: u64, next_deadline_100ns: u64) {
    let delta = next_idle_sleep_100ns(now_100ns, next_deadline_100ns);
    arm_vtimer_oneshot_100ns(delta);
    wait_for_timer_irq();
}
