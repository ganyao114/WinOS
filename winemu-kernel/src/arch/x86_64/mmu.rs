#[inline(always)]
fn unsupported() -> ! {
    panic!("x86_64 backend is a stub");
}

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
