type Backend = super::backend::ArchBackend;

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
    let raw = <Backend as super::contract::MmuBackend>::memory_features_raw();
    let parange = <Backend as super::contract::MmuBackend>::physical_addr_range(raw);
    let tgran4_ok = <Backend as super::contract::MmuBackend>::supports_4k_granule(raw);
    let tgran64_ok = <Backend as super::contract::MmuBackend>::supports_64k_granule(raw);
    MemoryFeatures {
        raw,
        physical_addr_range: parange,
        supports_4k_granule: tgran4_ok,
        supports_64k_granule: tgran64_ok,
    }
}

#[inline(always)]
pub fn current_user_table_root() -> u64 {
    <Backend as super::contract::MmuBackend>::current_user_table_root()
}

#[inline(always)]
pub fn set_user_table_root(root: u64) {
    <Backend as super::contract::MmuBackend>::set_user_table_root(root);
}

#[inline(always)]
pub fn flush_tlb_global() {
    <Backend as super::contract::MmuBackend>::flush_tlb_global();
}

#[inline(always)]
pub fn apply_translation_config(config: TranslationConfig) {
    <Backend as super::contract::MmuBackend>::apply_translation_config(
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
    <Backend as super::contract::MmuBackend>::read_system_control()
}

#[inline(always)]
pub fn write_system_control(value: u64) {
    <Backend as super::contract::MmuBackend>::write_system_control(value);
}

#[inline(always)]
pub fn instruction_barrier() {
    <Backend as super::contract::MmuBackend>::instruction_barrier();
}
