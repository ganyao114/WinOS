#[inline(always)]
pub fn read_mpidr_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, mpidr_el1", out(reg) val, options(nostack, nomem));
    }
    val
}

#[inline(always)]
pub fn boot_vcpu_id() -> u32 {
    let aff0 = (read_mpidr_el1() & 0xff) as u32;
    aff0.min((crate::sched::MAX_VCPUS - 1) as u32)
}

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

#[inline(always)]
pub fn wfe() {
    unsafe {
        core::arch::asm!("wfe", options(nostack));
    }
}

#[inline(always)]
pub fn sev() {
    unsafe {
        core::arch::asm!("sev", options(nostack));
    }
}

#[inline(always)]
pub fn cpu_local_read() -> u64 {
    read_tpidr_el1()
}

#[inline(always)]
pub fn cpu_local_write(value: u64) {
    write_tpidr_el1(value);
}

#[inline(always)]
pub fn fault_syndrome_read() -> u64 {
    read_esr_el1()
}

#[inline(always)]
pub fn fault_address_read() -> u64 {
    read_far_el1()
}

#[inline(always)]
pub fn wait_for_interrupt() {
    wfi();
}

#[inline(always)]
pub fn wait_for_event() {
    wfe();
}

#[inline(always)]
pub fn send_event() {
    sev();
}

#[inline(always)]
pub fn irq_enable() {
    daifclr_irq();
}

#[inline(always)]
pub fn irq_disable() {
    daifset_irq();
}
