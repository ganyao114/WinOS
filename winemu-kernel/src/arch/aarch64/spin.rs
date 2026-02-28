#[inline(always)]
pub fn lock_u32(spinlock_ptr: *mut u32) {
    unsafe {
        core::arch::asm!(
            "1: ldaxr {old:w}, [{p}]",
            "   cbnz  {old:w}, 1b",
            "   stxr  {old:w}, {one:w}, [{p}]",
            "   cbnz  {old:w}, 1b",
            p = in(reg) spinlock_ptr,
            old = out(reg) _,
            one = in(reg) 1u32,
            options(nostack)
        );
    }
}

#[inline(always)]
pub fn unlock_u32(spinlock_ptr: *mut u32) {
    unsafe {
        core::arch::asm!("stlr wzr, [{}]", in(reg) spinlock_ptr, options(nostack));
    }
}
