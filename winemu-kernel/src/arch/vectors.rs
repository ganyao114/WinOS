type Backend = super::backend::ArchBackend;

#[inline(always)]
pub fn install_exception_vectors() {
    <Backend as super::contract::VectorsBackend>::install_exception_vectors();
}

#[inline(always)]
pub fn default_kernel_stack_top() -> u64 {
    <Backend as super::contract::VectorsBackend>::default_kernel_stack_top()
}
