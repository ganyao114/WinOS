use core::arch::global_asm;

use crate::sched::KernelContext;

global_asm!(
    ".section .text.context,\"ax\"",
    ".global __winemu_kernel_context_save",
    "__winemu_kernel_context_save:",
    // x0 = ctx (*mut KernelContext)
    "stp x19, x20, [x0, #0x00]",
    "stp x21, x22, [x0, #0x10]",
    "stp x23, x24, [x0, #0x20]",
    "stp x25, x26, [x0, #0x30]",
    "stp x27, x28, [x0, #0x40]",
    "stp x29, x30, [x0, #0x50]",
    "mov x9, sp",
    "str x9, [x0, #0x60]", // sp_el1
    "mov x0, xzr",
    "ret",
    ".global __winemu_kernel_context_switch",
    "__winemu_kernel_context_switch:",
    // x0 = from (*mut KernelContext), x1 = to (*const KernelContext)
    "stp x19, x20, [x0, #0x00]",
    "stp x21, x22, [x0, #0x10]",
    "stp x23, x24, [x0, #0x20]",
    "stp x25, x26, [x0, #0x30]",
    "stp x27, x28, [x0, #0x40]",
    "stp x29, x30, [x0, #0x50]",
    "mov x9, sp",
    "str x9, [x0, #0x60]", // sp_el1
    "ldp x19, x20, [x1, #0x00]",
    "ldp x21, x22, [x1, #0x10]",
    "ldp x23, x24, [x1, #0x20]",
    "ldp x25, x26, [x1, #0x30]",
    "ldp x27, x28, [x1, #0x40]",
    "ldp x29, x30, [x1, #0x50]",
    "ldr x9, [x1, #0x60]",
    "mov sp, x9",
    "mov x0, #1",
    "ret",
);

unsafe extern "C" {
    fn __winemu_kernel_context_save(ctx: *mut KernelContext) -> u64;
    fn __winemu_kernel_context_switch(from: *mut KernelContext, to: *const KernelContext);
}

#[inline(always)]
pub unsafe fn save_kernel_context(ctx: *mut KernelContext) -> u64 {
    __winemu_kernel_context_save(ctx)
}

#[inline(always)]
pub unsafe fn switch_kernel_context(from: *mut KernelContext, to: *const KernelContext) {
    __winemu_kernel_context_switch(from, to);
}
