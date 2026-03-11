type Backend = super::backend::ArchBackend;

use crate::arch::trap::SvcFrame;

pub use super::context_types::{KernelContext, ThreadContext};

#[derive(Clone, Copy)]
pub struct UserThreadStart {
    pub program_counter: u64,
    pub stack_pointer: u64,
    pub thread_pointer: u64,
    pub arg0: u64,
    pub arg1: u64,
}

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

#[inline(always)]
pub fn restore_user_context_record(frame: &mut SvcFrame, context: &[u8]) -> bool {
    <Backend as super::contract::ContextBackend>::restore_user_context_record(frame, context)
}

#[inline(always)]
pub fn initialize_user_thread_context(ctx: &mut ThreadContext, start: UserThreadStart) {
    <Backend as super::contract::ContextBackend>::initialize_user_thread_context(
        ctx,
        start.program_counter,
        start.stack_pointer,
        start.thread_pointer,
        start.arg0,
        start.arg1,
    )
}
