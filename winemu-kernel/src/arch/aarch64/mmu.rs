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
pub fn read_ttbr0_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) val, options(nostack));
    }
    val
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

#[inline(always)]
pub fn memory_features_raw() -> u64 {
    read_id_aa64mmfr0_el1()
}

#[inline(always)]
pub fn physical_addr_range(features_raw: u64) -> u8 {
    (features_raw & 0xF) as u8
}

#[inline(always)]
pub fn supports_4k_granule(features_raw: u64) -> bool {
    ((features_raw >> 28) & 0xF) == 0
}

#[inline(always)]
pub fn supports_64k_granule(features_raw: u64) -> bool {
    ((features_raw >> 24) & 0xF) == 0
}

#[inline(always)]
pub fn current_user_table_root() -> u64 {
    read_ttbr0_el1()
}

#[inline(always)]
pub fn set_user_table_root(root: u64) {
    write_ttbr0_el1(root);
}

#[inline(always)]
pub fn flush_tlb_global() {
    dsb_ishst();
    tlbi_vmalle1is();
    dsb_ish();
    isb();
}

#[inline(always)]
pub fn apply_translation_config(memory_attrs: u64, translation_control: u64, user_table_root: u64) {
    write_mair_el1(memory_attrs);
    write_tcr_el1(translation_control);
    write_ttbr0_el1(user_table_root);
    dsb_ish();
    isb();
}

#[inline(always)]
pub fn read_system_control() -> u64 {
    read_sctlr_el1()
}

#[inline(always)]
pub fn write_system_control(value: u64) {
    write_sctlr_el1(value);
}

#[inline(always)]
pub fn instruction_barrier() {
    isb();
}
