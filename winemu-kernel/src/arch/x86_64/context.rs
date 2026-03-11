use crate::arch::trap::SvcFrame;
use crate::arch::context::{KernelContext, ThreadContext};

#[inline(always)]
pub unsafe fn save_kernel_context(_ctx: *mut KernelContext) -> u64 {
    // Stub backend to keep arch surface complete while x86_64 kernel execution
    // is not implemented in this tree yet.
    0
}

#[inline(always)]
pub unsafe fn switch_kernel_context(_from: *mut KernelContext, _to: *const KernelContext) {
    // Stub backend to keep arch surface complete while x86_64 kernel execution
    // is not implemented in this tree yet.
}

#[inline(always)]
pub unsafe fn enter_kernel_context(_ctx: *const KernelContext) -> ! {
    // Stub backend to keep arch surface complete while x86_64 kernel execution
    // is not implemented in this tree yet.
    loop {
        core::hint::spin_loop();
    }
}

#[inline(always)]
pub unsafe fn enter_user_thread_context(_ctx: *const ThreadContext) -> ! {
    // Stub backend to keep arch surface complete while x86_64 kernel execution
    // is not implemented in this tree yet.
    loop {
        core::hint::spin_loop();
    }
}

#[inline(always)]
pub fn restore_user_context_record(_frame: &mut SvcFrame, _context: &[u8]) -> bool {
    false
}

#[inline(always)]
pub fn initialize_user_thread_context(
    _ctx: &mut ThreadContext,
    _program_counter: u64,
    _stack_pointer: u64,
    _thread_pointer: u64,
    _arg0: u64,
    _arg1: u64,
) {
    unreachable!("x86_64 backend is a stub")
}
