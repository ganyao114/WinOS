// ARM64 EL1 异常向量表
// VBAR_EL1 必须 2KB 对齐（bit[10:0] = 0）
// 向量表布局（每个槽 128 字节 = 32 条指令）：
//   +0x000  Current EL, SP_EL0, Sync
//   +0x080  Current EL, SP_EL0, IRQ
//   +0x100  Current EL, SP_EL0, FIQ
//   +0x180  Current EL, SP_EL0, SError
//   +0x200  Current EL, SP_EL1, Sync   ← kernel fault
//   +0x280  Current EL, SP_EL1, IRQ
//   +0x300  Current EL, SP_EL1, FIQ
//   +0x380  Current EL, SP_EL1, SError
//   +0x400  Lower EL AArch64, Sync     ← SVC from EL0 (user syscall)
//   +0x480  Lower EL AArch64, IRQ
//   +0x500  Lower EL AArch64, FIQ
//   +0x580  Lower EL AArch64, SError
//   +0x600  Lower EL AArch32, Sync
//   ...

use core::arch::global_asm;

// Dedicated SVC stack in .bss — lives well below __heap_start,
// so it never overlaps with exe/dll images allocated from the heap.
global_asm!(
    ".bss",
    ".balign 16",
    ".global __svc_stack_bottom",
    "__svc_stack_bottom:",
    ".space 16384",
    ".global __svc_stack_top",
    "__svc_stack_top:",
);

global_asm!(
    // 2KB 对齐，放在 .text.vectors section
    ".section .text.vectors,\"ax\"",
    ".balign 2048",
    ".global __exception_vectors",
    "__exception_vectors:",

    // ── Slot 0: Current EL SP_EL0 Sync (128 bytes) ──────────
    "b .",   // hang
    ".balign 128",

    // ── Slot 1: Current EL SP_EL0 IRQ ───────────────────────
    "b .",
    ".balign 128",

    // ── Slot 2: Current EL SP_EL0 FIQ ───────────────────────
    "b .",
    ".balign 128",

    // ── Slot 3: Current EL SP_EL0 SError ────────────────────
    "b .",
    ".balign 128",

    // ── Slot 4: Current EL SP_EL1 Sync (kernel fault) ───────
    // 内核自身 fault — 打印调试信息后 hang
    "b .",
    ".balign 128",

    // ── Slot 5: Current EL SP_EL1 IRQ ───────────────────────
    "b .",
    ".balign 128",

    // ── Slot 6: Current EL SP_EL1 FIQ ───────────────────────
    "b .",
    ".balign 128",

    // ── Slot 7: Current EL SP_EL1 SError ────────────────────
    "b .",
    ".balign 128",

    // ── Slot 8: Lower EL AArch64 Sync ────────────────────────
    // Save x9 first, then use it for dispatch. x10 is NOT touched here.
    "msr tpidr_el1, x9",          // save user x9 before clobbering
    "mrs x9, esr_el1",
    "lsr x9, x9, #26",            // EC = bits[31:26]
    "cmp x9, #0x15",              // EC=0x15 → SVC from AArch64
    "b.eq __el0_svc",
    "cmp x9, #0x24",              // EC=0x24 → Data Abort from lower EL
    "b.eq __el0_da",
    "cmp x9, #0x20",              // EC=0x20 → Instruction Abort from lower EL
    "b.eq __el0_da",
    "b .",                          // unknown exception — hang
    ".balign 128",

    // ── Slot 9: Lower EL AArch64 IRQ ────────────────────────
    "b .",
    ".balign 128",

    // ── Slot 10: Lower EL AArch64 FIQ ───────────────────────
    "b .",
    ".balign 128",

    // ── Slot 11: Lower EL AArch64 SError ────────────────────
    "b .",
    ".balign 128",

    // ── Slot 12-15: Lower EL AArch32 ────────────────────────
    "b .",
    ".balign 128",
    "b .",
    ".balign 128",
    "b .",
    ".balign 128",
    "b .",
    ".balign 128",

    // ════════════════════════════════════════════════════════════
    // Out-of-line handlers (no 128-byte limit)
    // ════════════════════════════════════════════════════════════

    // ── SVC from EL0 ───────────────────────────────────────────
    // x9 was already saved to tpidr_el1 by the Slot 8 dispatch above.
    "__el0_svc:",
    "ldr x9, =__svc_stack_top",
    "mov sp, x9",
    "stp x29, x30, [sp, #-16]!",
    "mrs x9, tpidr_el1",
    "stp x9,  x10, [sp, #-16]!",
    "stp x11, x12, [sp, #-16]!",
    "mrs x9,  elr_el1",
    "mrs x10, spsr_el1",
    "stp x9,  x10, [sp, #-16]!",
    "and x9,  x8, #0xFFF",
    "lsr x10, x8, #12",
    "and x10, x10, #0x3",
    "mov x11, x0",
    "mov x0, #0x0700",
    "hvc #0",
    "ldp x9,  x10, [sp], #16",
    "msr elr_el1,  x9",
    "msr spsr_el1, x10",
    "ldp x11, x12, [sp], #16",
    "ldp x9,  x10, [sp], #16",
    "ldp x29, x30, [sp], #16",
    "eret",

    // ── Data Abort / Instruction Abort from EL0 ────────────────
    // x9 was already saved to tpidr_el1 by the Slot 8 dispatch above.
    "__el0_da:",
    "ldr x9, =__svc_stack_top",
    "mov sp, x9",
    "stp x29, x30, [sp, #-16]!",
    "mrs x9, tpidr_el1",
    "stp x9,  x10, [sp, #-16]!",
    // Save ELR/SPSR
    "mrs x9,  elr_el1",
    "mrs x10, spsr_el1",
    "stp x9,  x10, [sp, #-16]!",
    // Args for Rust handler
    "mrs x0, far_el1",
    "mrs x1, esr_el1",
    "mrs x2, elr_el1",
    "bl el0_page_fault",
    // Restore ELR/SPSR
    "ldp x9,  x10, [sp], #16",
    "msr elr_el1,  x9",
    "msr spsr_el1, x10",
    "ldp x9,  x10, [sp], #16",
    "ldp x29, x30, [sp], #16",
    // Check return value: x0 = 1 means resolved
    "cbnz x0, 1f",
    "b .",                          // unresolved fault — hang
    "1: eret",
);

extern "C" {
    pub static __exception_vectors: u8;
    pub static __svc_stack_top: u8;
    pub static __svc_stack_bottom: u8;
}

/// 安装异常向量表到 VBAR_EL1
pub fn install() {
    let vbar = core::ptr::addr_of!(__exception_vectors) as u64;
    unsafe {
        core::arch::asm!(
            "msr vbar_el1, {}",
            "isb",
            in(reg) vbar,
            options(nostack)
        );
    }
}
