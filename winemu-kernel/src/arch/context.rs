type Backend = super::backend::ArchBackend;

use crate::sched::KernelContext;

#[inline(always)]
pub unsafe fn save_kernel_context(ctx: *mut KernelContext) -> u64 {
    <Backend as super::contract::ContextBackend>::save_kernel_context(ctx)
}

#[inline(always)]
pub unsafe fn switch_kernel_context(from: *mut KernelContext, to: *const KernelContext) {
    <Backend as super::contract::ContextBackend>::switch_kernel_context(from, to);
}
