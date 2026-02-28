#[derive(Clone, Copy)]
pub struct MemoryFeatures {
    pub raw: u64,
    pub physical_addr_range: u8,
    pub supports_4k_granule: bool,
    pub supports_64k_granule: bool,
}

#[derive(Clone, Copy)]
pub struct TranslationConfig {
    pub memory_attrs: u64,
    pub translation_control: u64,
    pub user_table_root: u64,
}

#[inline(always)]
pub fn memory_features() -> MemoryFeatures {
    let raw = super::backend::mmu::memory_features_raw();
    let parange = super::backend::mmu::physical_addr_range(raw);
    let tgran4_ok = super::backend::mmu::supports_4k_granule(raw);
    let tgran64_ok = super::backend::mmu::supports_64k_granule(raw);
    MemoryFeatures {
        raw,
        physical_addr_range: parange,
        supports_4k_granule: tgran4_ok,
        supports_64k_granule: tgran64_ok,
    }
}

#[inline(always)]
pub fn current_user_table_root() -> u64 {
    super::backend::mmu::current_user_table_root()
}

#[inline(always)]
pub fn set_user_table_root(root: u64) {
    super::backend::mmu::set_user_table_root(root);
}

#[inline(always)]
pub fn flush_tlb_global() {
    super::backend::mmu::flush_tlb_global();
}

#[inline(always)]
pub fn apply_translation_config(config: TranslationConfig) {
    super::backend::mmu::apply_translation_config(
        config.memory_attrs,
        config.translation_control,
        config.user_table_root,
    );
}

#[inline(always)]
pub fn mmu_init(config: TranslationConfig) {
    apply_translation_config(config);
}

#[inline(always)]
pub fn switch_user_table_root(root: u64) {
    set_user_table_root(root);
    flush_tlb_global();
}

#[inline(always)]
pub fn read_system_control() -> u64 {
    super::backend::mmu::read_system_control()
}

#[inline(always)]
pub fn write_system_control(value: u64) {
    super::backend::mmu::write_system_control(value);
}

#[inline(always)]
pub fn instruction_barrier() {
    super::backend::mmu::instruction_barrier();
}
