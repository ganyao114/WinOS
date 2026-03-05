type Backend = super::backend::ArchBackend;

use crate::sched::{KernelContext, ThreadContext};

#[inline(always)]
pub unsafe fn save_kernel_context(ctx: *mut KernelContext) -> u64 {
    <Backend as super::contract::ContextBackend>::save_kernel_context(ctx)
}

#[inline(always)]
pub unsafe fn switch_kernel_context(from: *mut KernelContext, to: *const KernelContext) {
    <Backend as super::contract::ContextBackend>::switch_kernel_context(from, to);
}

#[inline(always)]
pub unsafe fn enter_kernel_context(ctx: *const KernelContext) -> ! {
    <Backend as super::contract::ContextBackend>::enter_kernel_context(ctx)
}

#[inline(always)]
pub unsafe fn enter_user_thread_context(ctx: *const ThreadContext) -> ! {
    <Backend as super::contract::ContextBackend>::enter_user_thread_context(ctx)
}
