type Backend = super::backend::ArchBackend;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PageTableEntryKind {
    Invalid,
    Block,
    TableOrPage,
    Reserved,
}

#[derive(Clone, Copy)]
pub enum UserDescLevel {
    L1Block,
    L2Block,
    L3Page,
}

pub const PAGE_TABLE_ENTRIES: usize = super::backend::mmu::PAGE_TABLE_ENTRIES;
pub const GUEST_PHYS_BASE: u64 = super::backend::mmu::GUEST_PHYS_BASE;
pub const GUEST_PHYS_LIMIT: u64 = super::backend::mmu::GUEST_PHYS_LIMIT;
pub const KERNEL_PHYSMAP_BASE: u64 = super::backend::mmu::KERNEL_PHYSMAP_BASE;
pub const KERNEL_PHYSMAP_LIMIT: u64 = super::backend::mmu::KERNEL_PHYSMAP_LIMIT;

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

#[inline(always)]
pub fn bootstrap_user_tables() -> (*const u64, *const u64, *const u64) {
    super::backend::mmu::bootstrap_user_tables()
}

#[inline(always)]
pub fn init_global_bootstrap() {
    super::backend::mmu::init_global_bootstrap();
}

#[inline(always)]
pub fn init_per_cpu() {
    super::backend::mmu::init_per_cpu();
}

#[inline(always)]
pub fn l0_index(va: u64) -> usize {
    super::backend::mmu::l0_index(va)
}

#[inline(always)]
pub fn l1_index(va: u64) -> usize {
    super::backend::mmu::l1_index(va)
}

#[inline(always)]
pub fn l2_index(va: u64) -> usize {
    super::backend::mmu::l2_index(va)
}

#[inline(always)]
pub fn l3_index(va: u64) -> usize {
    super::backend::mmu::l3_index(va)
}

#[inline(always)]
pub fn table_addr(desc: u64) -> u64 {
    super::backend::mmu::table_addr(desc)
}

#[inline(always)]
pub fn make_table_desc(table_pa: u64) -> u64 {
    super::backend::mmu::make_table_desc(table_pa)
}

#[inline(always)]
pub fn desc_kind(desc: u64) -> PageTableEntryKind {
    match super::backend::mmu::desc_kind_raw(desc) {
        0 => PageTableEntryKind::Invalid,
        1 => PageTableEntryKind::Block,
        3 => PageTableEntryKind::TableOrPage,
        _ => PageTableEntryKind::Reserved,
    }
}

#[inline(always)]
pub fn translate_user_desc(desc: u64, va: u64, level: UserDescLevel, access: u8) -> Option<u64> {
    let level_raw = match level {
        UserDescLevel::L1Block => 1,
        UserDescLevel::L2Block => 2,
        UserDescLevel::L3Page => 3,
    };
    super::backend::mmu::translate_user_desc(desc, va, level_raw, access)
}

#[inline(always)]
pub fn build_user_pte(pa: u64, prot: u32) -> u64 {
    super::backend::mmu::build_user_pte(pa, prot)
}

#[inline(always)]
pub fn split_l2_block_entry_to_l3_page(block_desc: u64, page_pa: u64) -> u64 {
    super::backend::mmu::split_l2_block_entry_to_l3_page(block_desc, page_pa)
}

#[inline(always)]
pub fn l2_index_in_user_window(user_va_base: u64, user_va_limit: u64, idx: usize) -> bool {
    super::backend::mmu::l2_index_in_user_window(user_va_base, user_va_limit, idx)
}

#[inline(always)]
pub unsafe fn install_process_root_tables(l0: *mut u64, l1: *mut u64, l2: *mut u64) {
    super::backend::mmu::install_process_root_tables(l0, l1, l2);
}
