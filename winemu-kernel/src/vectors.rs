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

global_asm!(
    // 2KB 对齐，放在 .text.vectors section
    ".section .text.vectors",
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

    // ── Slot 8: Lower EL AArch64 Sync (SVC from EL0) ────────
    // 约定：x8 = (table<<12)|syscall_nr, x0-x7 = args
    // HVC 约定（VMM 从 vCPU regs 读取）：
    //   x0  = NT_SYSCALL (0x0700)
    //   x9  = syscall_nr (x8 & 0xFFF)
    //   x10 = table_nr   (x8 >> 12 & 0x3)
    //   x11 = orig_x0    (FileHandle / arg0)
    //   x1-x7 = original syscall args 1-7 (untouched)
    // Reset SP_EL1 to fixed SVC stack top each entry (avoids SP_EL1 leak)
    // Use TPIDR_EL1 as per-CPU scratch to save x9 before overwriting it,
    // so ALL registers (x9/x10/x11/x12/x29/x30) are correctly preserved.
    "msr tpidr_el1, x9",               // save user's x9 to EL1 system register
    "adr x9, __kernel_svc_stack_top",  // x9 = SVC stack top
    "mov sp, x9",
    // Save scratch regs: all values correct at time of stp
    // Stack layout at SP_EL1 after all stps:
    //   [sp+0]=x11_orig, [sp+8]=x12_orig(correct)
    //   [sp+16]=x9_orig(correct), [sp+24]=x10_orig
    //   [sp+32]=x29_orig, [sp+40]=x30_orig
    "stp x29, x30, [sp, #-16]!",
    "mrs x9, tpidr_el1",               // restore user's x9 from system register
    "stp x9,  x10, [sp, #-16]!",
    "stp x11, x12, [sp, #-16]!",
    // Extract syscall_nr (x9) and table_nr (x10) from x8
    "and x9,  x8, #0xFFF",
    "lsr x10, x8, #12",
    "and x10, x10, #0x3",
    // x11 = orig_x0 (VMM reads from regs.x[11]); x1-x7 untouched
    "mov x11, x0",
    "mov x0, #0x0700",          // HVC x0 = NT_SYSCALL
    "hvc #0",
    // Restore scratch regs
    "ldp x11, x12, [sp], #16",
    "ldp x9,  x10, [sp], #16",
    "ldp x29, x30, [sp], #16",
    // Advance ELR_EL1 past the svc instruction
    "mrs x9, elr_el1",
    "add x9, x9, #4",
    "msr elr_el1, x9",
    "eret",
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
);

extern "C" {
    pub static __exception_vectors: u8;
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
