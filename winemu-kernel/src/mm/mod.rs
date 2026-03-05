pub mod address_space;
pub mod areaset;
pub mod kmalloc;
pub mod phys;
pub mod range;
pub mod vaspace;
pub mod vm_area;

pub fn bootstrap_user_tables() -> (*const u64, *const u64, *const u64) {
    crate::arch::mmu::bootstrap_user_tables()
}

pub fn switch_process_ttbr0(new_ttbr0: u64) {
    if new_ttbr0 == 0 {
        return;
    }
    let cur = crate::arch::mmu::current_user_table_root();
    if (cur & !0xfff) == (new_ttbr0 & !0xfff) {
        return;
    }

    crate::arch::mmu::switch_user_table_root(new_ttbr0);
}

pub fn init_global_bootstrap() {
    crate::arch::mmu::init_global_bootstrap();
}

pub fn init_per_cpu() {
    crate::arch::mmu::init_per_cpu();
}

pub fn init() {
    init_global_bootstrap();
    init_per_cpu();
}
