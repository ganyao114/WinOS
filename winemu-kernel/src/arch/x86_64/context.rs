use crate::sched::KernelContext;

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
