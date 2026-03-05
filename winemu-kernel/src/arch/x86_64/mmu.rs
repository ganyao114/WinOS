#[inline(always)]
fn unsupported() -> ! {
    panic!("x86_64 backend is a stub");
}

pub const PAGE_TABLE_ENTRIES: usize = 512;

#[inline(always)]
pub fn memory_features_raw() -> u64 {
    unsupported()
}

#[inline(always)]
pub fn physical_addr_range(_features_raw: u64) -> u8 {
    unsupported()
}

#[inline(always)]
pub fn supports_4k_granule(_features_raw: u64) -> bool {
    unsupported()
}

#[inline(always)]
pub fn supports_64k_granule(_features_raw: u64) -> bool {
    unsupported()
}

#[inline(always)]
pub fn current_user_table_root() -> u64 {
    unsupported()
}

#[inline(always)]
pub fn set_user_table_root(_root: u64) {
    unsupported()
}

#[inline(always)]
pub fn flush_tlb_global() {
    unsupported()
}

#[inline(always)]
pub fn apply_translation_config(
    _memory_attrs: u64,
    _translation_control: u64,
    _user_table_root: u64,
) {
    unsupported()
}

#[inline(always)]
pub fn read_system_control() -> u64 {
    unsupported()
}

#[inline(always)]
pub fn write_system_control(_value: u64) {
    unsupported()
}

#[inline(always)]
pub fn instruction_barrier() {
    unsupported()
}

#[inline(always)]
pub fn bootstrap_user_tables() -> (*const u64, *const u64, *const u64) {
    unsupported()
}

#[inline(always)]
pub fn init_global_bootstrap() {
    unsupported()
}

#[inline(always)]
pub fn init_per_cpu() {
    unsupported()
}

#[inline(always)]
pub fn l0_index(_va: u64) -> usize {
    unsupported()
}

#[inline(always)]
pub fn l1_index(_va: u64) -> usize {
    unsupported()
}

#[inline(always)]
pub fn l2_index(_va: u64) -> usize {
    unsupported()
}

#[inline(always)]
pub fn l3_index(_va: u64) -> usize {
    unsupported()
}

#[inline(always)]
pub fn table_addr(_desc: u64) -> u64 {
    unsupported()
}

#[inline(always)]
pub fn make_table_desc(_table_pa: u64) -> u64 {
    unsupported()
}

#[inline(always)]
pub fn desc_kind_raw(_desc: u64) -> u8 {
    unsupported()
}

#[inline(always)]
pub fn translate_user_desc(_desc: u64, _va: u64, _level: u8, _access: u8) -> Option<u64> {
    unsupported()
}

#[inline(always)]
pub fn build_user_pte(_pa: u64, _prot: u32) -> u64 {
    unsupported()
}

#[inline(always)]
pub fn split_l2_block_entry_to_l3_page(_block_desc: u64, _page_pa: u64) -> u64 {
    unsupported()
}

#[inline(always)]
pub fn l2_index_in_user_window(_user_va_base: u64, _user_va_limit: u64, _idx: usize) -> bool {
    unsupported()
}

#[inline(always)]
pub unsafe fn install_process_root_tables(_l0: *mut u64, _l1: *mut u64, _l2: *mut u64) {
    unsupported()
}
