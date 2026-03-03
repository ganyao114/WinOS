#[inline(always)]
fn unsupported() -> ! {
    panic!("x86_64 backend is a stub");
}

#[inline(always)]
pub fn install_exception_vectors() {
    unsupported()
}

#[inline(always)]
pub fn default_kernel_stack_top() -> u64 {
    0
}
