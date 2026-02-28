#[inline(always)]
pub fn read_tpidr_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el1", out(reg) val, options(nostack, nomem));
    }
    val
}

#[inline(always)]
pub fn write_tpidr_el1(val: u64) {
    unsafe {
        core::arch::asm!("msr tpidr_el1, {}", in(reg) val, options(nostack, nomem));
    }
}

#[inline(always)]
pub fn read_esr_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, esr_el1", out(reg) val, options(nostack, nomem));
    }
    val
}

#[inline(always)]
pub fn read_far_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, far_el1", out(reg) val, options(nostack, nomem));
    }
    val
}

#[inline(always)]
pub fn read_cntfrq_el0() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) val, options(nostack, nomem));
    }
    val
}

#[inline(always)]
pub fn read_cntvct_el0() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) val, options(nostack, nomem));
    }
    val
}

#[inline(always)]
pub fn write_cntv_cval_el0(cval: u64) {
    unsafe {
        core::arch::asm!("msr cntv_cval_el0, {}", in(reg) cval, options(nostack));
    }
}

#[inline(always)]
pub fn write_cntv_ctl_el0(val: u64) {
    unsafe {
        core::arch::asm!("msr cntv_ctl_el0, {}", in(reg) val, options(nostack));
    }
}

#[inline(always)]
pub fn daifclr_irq() {
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nostack));
    }
}

#[inline(always)]
pub fn daifset_irq() {
    unsafe {
        core::arch::asm!("msr daifset, #2", options(nostack));
    }
}

#[inline(always)]
pub fn isb() {
    unsafe {
        core::arch::asm!("isb", options(nostack, nomem));
    }
}

#[inline(always)]
pub fn wfi() {
    unsafe {
        core::arch::asm!("wfi", options(nostack));
    }
}
