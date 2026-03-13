use core::arch::global_asm;

use crate::arch::context::{KernelContext, ThreadContext};
use crate::arch::trap::SvcFrame;

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
    ".global __winemu_enter_kernel_context",
    "__winemu_enter_kernel_context:",
    // x0 = ctx (*const KernelContext)
    "ldp x19, x20, [x0, #0x00]",
    "ldp x21, x22, [x0, #0x10]",
    "ldp x23, x24, [x0, #0x20]",
    "ldp x25, x26, [x0, #0x30]",
    "ldp x27, x28, [x0, #0x40]",
    "ldp x29, x30, [x0, #0x50]",
    "ldr x9, [x0, #0x60]",
    "mov sp, x9",
    "mov x0, #1",
    "ret",
    ".global __winemu_enter_user_thread_context",
    "__winemu_enter_user_thread_context:",
    // x0 = ctx (*const ThreadContext)
    // Keep ctx pointer in x20 until all loads finish; restore x20 last.
    "mov x20, x0",
    // Program EL0 return state first.
    "ldr x9, [x20, #0x0f8]", // sp
    "msr sp_el0, x9",
    "ldr x9, [x20, #0x100]", // pc
    "msr elr_el1, x9",
    "ldr x9, [x20, #0x108]", // pstate
    "msr spsr_el1, x9",
    "ldr x9, [x20, #0x110]", // tpidr
    "msr tpidr_el0, x9",
    // Restore x0-x19 (skip x20 for now).
    "ldp x0,  x1,  [x20, #0x00]",
    "ldp x2,  x3,  [x20, #0x10]",
    "ldp x4,  x5,  [x20, #0x20]",
    "ldp x6,  x7,  [x20, #0x30]",
    "ldp x8,  x9,  [x20, #0x40]",
    "ldp x10, x11, [x20, #0x50]",
    "ldp x12, x13, [x20, #0x60]",
    "ldp x14, x15, [x20, #0x70]",
    "ldp x16, x17, [x20, #0x80]",
    "ldr x18, [x20, #0x90]",
    "ldr x19, [x20, #0x98]",
    // Restore x21-x30.
    "ldr x21, [x20, #0xA8]",
    "ldr x22, [x20, #0xB0]",
    "ldr x23, [x20, #0xB8]",
    "ldr x24, [x20, #0xC0]",
    "ldr x25, [x20, #0xC8]",
    "ldr x26, [x20, #0xD0]",
    "ldr x27, [x20, #0xD8]",
    "ldr x28, [x20, #0xE0]",
    "ldr x29, [x20, #0xE8]",
    "ldr x30, [x20, #0xF0]",
    // Restore x20 last because it carries ctx pointer.
    "ldr x20, [x20, #0xA0]",
    "eret",
);

unsafe extern "C" {
    fn __winemu_kernel_context_save(ctx: *mut KernelContext) -> u64;
    fn __winemu_kernel_context_switch(from: *mut KernelContext, to: *const KernelContext);
    fn __winemu_enter_kernel_context(ctx: *const KernelContext) -> !;
    fn __winemu_enter_user_thread_context(ctx: *const ThreadContext) -> !;
}

#[inline(always)]
pub unsafe fn save_kernel_context(ctx: *mut KernelContext) -> u64 {
    __winemu_kernel_context_save(ctx)
}

#[inline(always)]
pub unsafe fn switch_kernel_context(from: *mut KernelContext, to: *const KernelContext) {
    __winemu_kernel_context_switch(from, to);
}

#[inline(always)]
pub unsafe fn enter_kernel_context(ctx: *const KernelContext) -> ! {
    __winemu_enter_kernel_context(ctx)
}

#[inline(always)]
pub unsafe fn enter_user_thread_context(ctx: *const ThreadContext) -> ! {
    __winemu_enter_user_thread_context(ctx)
}

#[inline]
pub fn restore_user_context_record(frame: &mut SvcFrame, context: &[u8]) -> bool {
    if context.len() < 272 {
        return false;
    }

    // Guest ARM64 CONTEXT layout matches guest/ntdll/src/exception.c:
    // ContextFlags(4), Cpsr(4), X0..X30(31x8), Sp(8), Pc(8), ...
    let read_u64 = |off: usize| -> u64 {
        let bytes = &context[off..off + 8];
        u64::from_le_bytes(bytes.try_into().unwrap())
    };
    let read_u32 = |off: usize| -> u32 {
        let bytes = &context[off..off + 4];
        u32::from_le_bytes(bytes.try_into().unwrap())
    };

    for i in 0u64..31 {
        frame.x[i as usize] = read_u64(8 + i as usize * 8);
    }
    frame.set_user_sp(read_u64(256));
    frame.set_program_counter(read_u64(264));
    frame.set_processor_state(read_u32(4) as u64);
    true
}

#[inline]
pub fn initialize_user_thread_context(
    ctx: &mut ThreadContext,
    program_counter: u64,
    stack_pointer: u64,
    thread_pointer: u64,
    arg0: u64,
    arg1: u64,
) {
    *ctx = ThreadContext::new();
    ctx.set_program_counter(program_counter);
    ctx.set_user_sp(stack_pointer);
    ctx.set_processor_state(0);
    ctx.set_thread_pointer(thread_pointer);
    ctx.set_general_register(0, arg0);
    ctx.set_general_register(1, arg1);
    ctx.set_general_register(18, thread_pointer);
}
