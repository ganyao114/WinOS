type Backend = super::backend::ArchBackend;

#[inline(always)]
pub fn lock_word(lock_ptr: *mut u32) {
    <Backend as super::contract::SpinBackend>::lock_word(lock_ptr);
}

#[inline(always)]
pub fn unlock_word(lock_ptr: *mut u32) {
    <Backend as super::contract::SpinBackend>::unlock_word(lock_ptr);
}
