#[inline(always)]
pub fn lock_word(lock_ptr: *mut u32) {
    super::backend::spin::lock_word(lock_ptr);
}

#[inline(always)]
pub fn unlock_word(lock_ptr: *mut u32) {
    super::backend::spin::unlock_word(lock_ptr);
}
