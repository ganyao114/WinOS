#[inline(always)]
pub fn dsb_ishst() {
    unsafe {
        core::arch::asm!("dsb ishst", options(nostack));
    }
}

#[inline(always)]
pub fn tlbi_vmalle1is() {
    unsafe {
        core::arch::asm!("tlbi vmalle1is", options(nostack));
    }
}

#[inline(always)]
pub fn dsb_ish() {
    unsafe {
        core::arch::asm!("dsb ish", options(nostack));
    }
}

#[inline(always)]
pub fn isb() {
    unsafe {
        core::arch::asm!("isb", options(nostack));
    }
}

#[inline(always)]
pub fn write_mair_el1(mair: u64) {
    unsafe {
        core::arch::asm!("msr mair_el1, {}", in(reg) mair, options(nostack));
    }
}

#[inline(always)]
pub fn read_id_aa64mmfr0_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, id_aa64mmfr0_el1", out(reg) val, options(nostack));
    }
    val
}

#[inline(always)]
pub fn write_tcr_el1(tcr: u64) {
    unsafe {
        core::arch::asm!("msr tcr_el1, {}", in(reg) tcr, options(nostack));
    }
}

#[inline(always)]
pub fn write_ttbr0_el1(ttbr0: u64) {
    unsafe {
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) ttbr0, options(nostack));
    }
}

#[inline(always)]
pub fn read_sctlr_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) val, options(nostack));
    }
    val
}

#[inline(always)]
pub fn write_sctlr_el1(sctlr: u64) {
    unsafe {
        core::arch::asm!("msr sctlr_el1, {}", in(reg) sctlr, options(nostack));
    }
}
