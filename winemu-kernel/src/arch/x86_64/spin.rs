#[inline(always)]
fn unsupported() -> ! {
    panic!("x86_64 backend is a stub");
}

#[inline(always)]
pub fn lock_word(_lock_ptr: *mut u32) {
    unsupported()
}

#[inline(always)]
pub fn unlock_word(_lock_ptr: *mut u32) {
    unsupported()
}
