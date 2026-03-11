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

// Legacy bootstrap SVC stack in .bss. Normal EL0 trap paths should run on
// the current thread's EL1 stack (SP_EL1) to avoid cross-vCPU stack aliasing.
global_asm!(
    ".bss",
    ".balign 16",
    ".global __svc_stack_bottom",
    "__svc_stack_bottom:",
    // 64 KiB: process creation and VM clone paths can consume >16 KiB stack.
    ".space 65536",
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
    "b __el1_sync",
    ".balign 128",
    // ── Slot 1: Current EL SP_EL0 IRQ ───────────────────────
    "b __timer_irq_el1",
    ".balign 128",
    // ── Slot 2: Current EL SP_EL0 FIQ ───────────────────────
    "b .",
    ".balign 128",
    // ── Slot 3: Current EL SP_EL0 SError ────────────────────
    "b .",
    ".balign 128",
    // ── Slot 4: Current EL SP_EL1 Sync (kernel fault) ───────
    "b __el1_sync",
    ".balign 128",
    // ── Slot 5: Current EL SP_EL1 IRQ ───────────────────────
    "b __timer_irq_el1",
    ".balign 128",
    // ── Slot 6: Current EL SP_EL1 FIQ ───────────────────────
    "b .",
    ".balign 128",
    // ── Slot 7: Current EL SP_EL1 SError ────────────────────
    "b .",
    ".balign 128",
    // ── Slot 8: Lower EL AArch64 Sync ────────────────────────
    // Save x9 first, then use it for dispatch. x10 is NOT touched here.
    // Do NOT use TPIDR_EL1 here: scheduler stores vcpu_id/tid in TPIDR_EL1.
    "msr tpidrro_el0, x9", // save user x9 before clobbering
    "mrs x9, esr_el1",
    "lsr x9, x9, #26", // EC = bits[31:26]
    "cmp x9, #0x15",   // EC=0x15 → SVC from AArch64
    "b.ne 90f",
    "b __el0_svc",
    "90:",
    "cmp x9, #0x24", // EC=0x24 → Data Abort from lower EL
    "b.ne 91f",
    "b __el0_da",
    "91:",
    "cmp x9, #0x20", // EC=0x20 → Instruction Abort from lower EL
    "b.ne 92f",
    "b __el0_da",
    "92:",
    // Some user-mode probes trap as EC=0x00/0x18 on this platform
    // configuration. Keep this compat path for those EC values only; all
    // other unknown sync traps are treated as fatal and routed to diagnostics.
    "cmp x9, #0x18",
    "b.eq 93f",
    "cmp x9, #0x00",
    "b.eq 93f",
    "b __el0_undef",
    ".balign 128",
    // ── Slot 9: Lower EL AArch64 IRQ ────────────────────────
    "b __timer_irq_el0",
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

    // ── Sync exception from EL1 (kernel fault) ────────────────
    "__el1_sync:",
    // Check EC field (bits[31:26]).
    "stp x29, x30, [sp, #-16]!",
    "mrs x29, esr_el1",
    "lsr x29, x29, #26",
    "and x29, x29, #0x3f",
    "cmp x29, #0x01",
    "b.ne 1f",
    // EC=0x01 (WFI/WFE trap): allow skip only when this vCPU is in the idle
    // wait path and current_tid == idle_tid.
    // KCpuLocal offsets:
    //   +0x04 current_tid (u32)
    //   +0x08 idle_tid (u32)
    //   +0x0d in_idle (u8)
    //   +0x10 wfx_skip_count (u32)
    //   +0x14 wfx_unexpected_count (u32)
    "mrs x30, tpidr_el1",
    "cbz x30, 2f",
    "ldrb w29, [x30, #13]",
    "cbz w29, 2f",
    "ldr w29, [x30, #4]",
    "ldr w30, [x30, #8]",
    "cmp w29, w30",
    "b.ne 2f",
    // Allowed idle-path WFI/WFE trap: count and skip the instruction.
    "mrs x30, tpidr_el1",
    "ldr w29, [x30, #16]",
    "add w29, w29, #1",
    "str w29, [x30, #16]",
    "mrs x29, elr_el1",
    "add x29, x29, #4",
    "msr elr_el1, x29",
    "ldp x29, x30, [sp], #16",
    "eret",
    "2:",
    // Unexpected EL1 WFI/WFE trap: count it and continue fault diagnostics.
    "mrs x30, tpidr_el1",
    "cbz x30, 1f",
    "ldr w29, [x30, #20]",
    "add w29, w29, #1",
    "str w29, [x30, #20]",
    "1:",
    "ldp x29, x30, [sp], #16",
    "stp x29, x30, [sp, #-16]!",
    // Preserve faulting EL1 x0/x1/x2/x30 for diagnostics.
    "mov x4, x0",
    "mov x5, x1",
    "mov x6, x2",
    "mov x3, x30",
    "mrs x0, far_el1",
    "mrs x1, esr_el1",
    "mrs x2, elr_el1",
    "bl kernel_sync_fault_dispatch",
    "b .",
    // ── SVC from EL0 ───────────────────────────────────────────
    // Build SvcFrame on SVC stack and call guest EL1 dispatcher.
    // x9 was saved into tpidrro_el0 by Slot 8 dispatch above.
    "__el0_svc:",
    // Preserve user x16/x17 before borrowing them as scratch.
    "mov x9, x17",
    "mov x17, x16",
    "sub sp, sp, #0x120",
    // Save x0-x30 (SvcFrame.x[0..31))
    "stp x0,  x1,  [sp, #0x000]",
    "stp x2,  x3,  [sp, #0x010]",
    "stp x4,  x5,  [sp, #0x020]",
    "stp x6,  x7,  [sp, #0x030]",
    "stp x8,  x9,  [sp, #0x040]",
    "stp x10, x11, [sp, #0x050]",
    "stp x12, x13, [sp, #0x060]",
    "stp x14, x15, [sp, #0x070]",
    "str x17,      [sp, #0x080]",
    "str x9,       [sp, #0x088]",
    "stp x18, x19, [sp, #0x090]",
    "stp x20, x21, [sp, #0x0a0]",
    "stp x22, x23, [sp, #0x0b0]",
    "stp x24, x25, [sp, #0x0c0]",
    "stp x26, x27, [sp, #0x0d0]",
    "stp x28, x29, [sp, #0x0e0]",
    "str x30,      [sp, #0x0f0]",
    // Save extra SvcFrame fields.
    "mrs x16, sp_el0",
    "str x16, [sp, #0x0f8]",
    "mrs x16, elr_el1",
    "str x16, [sp, #0x100]",
    "mrs x16, spsr_el1",
    "str x16, [sp, #0x108]",
    "mrs x16, tpidr_el0",
    "str x16, [sp, #0x110]",
    "str x8,  [sp, #0x118]", // x8_orig syscall tag
    // Restore original user x9 from tpidrro_el0 shadow into frame.x[9].
    "mrs x16, tpidrro_el0",
    "str x16, [sp, #0x048]",
    // Migrate SVC frame onto current thread private EL1 kernel stack so
    // kernel continuations can safely resume after cross-thread switches.
    "mov x0, sp",
    "mov x1, #0x120",
    "bl svc_migrate_frame_to_thread_stack",
    // Keep frame base in x28 (callee-saved); run EL1 call stack below frame to avoid
    // overlap between continuation stack slots and mutable SvcFrame bytes.
    "mov x28, x0",
    "sub sp, x28, #0x10",
    // Call Rust dispatcher: syscall_dispatch(&mut frame)
    "mov x0, x28",
    "bl syscall_dispatch",
    // Restore ELR/SPSR/SP_EL0/TPIDR_EL0 from possibly modified frame.
    "ldr x16, [x28, #0x100]",
    "msr elr_el1, x16",
    "ldr x16, [x28, #0x108]",
    "msr spsr_el1, x16",
    "ldr x16, [x28, #0x0f8]",
    "msr sp_el0, x16",
    "ldr x16, [x28, #0x110]",
    "msr tpidr_el0, x16",
    // Restore x0-x30 and return to EL0.
    "ldp x0,  x1,  [x28, #0x000]",
    "ldp x2,  x3,  [x28, #0x010]",
    "ldp x4,  x5,  [x28, #0x020]",
    "ldp x6,  x7,  [x28, #0x030]",
    "ldp x8,  x9,  [x28, #0x040]",
    "ldp x10, x11, [x28, #0x050]",
    "ldp x12, x13, [x28, #0x060]",
    "ldp x14, x15, [x28, #0x070]",
    "ldp x16, x17, [x28, #0x080]",
    "ldp x18, x19, [x28, #0x090]",
    "ldp x20, x21, [x28, #0x0a0]",
    "ldp x22, x23, [x28, #0x0b0]",
    "ldp x24, x25, [x28, #0x0c0]",
    "ldp x26, x27, [x28, #0x0d0]",
    "ldr x30,      [x28, #0x0f0]",
    // Restore EL1 stack top for next trap entry (frame base + frame size).
    "add sp, x28, #0x120",
    "ldp x28, x29, [x28, #0x0e0]",
    "eret",
    // ── Data Abort / Instruction Abort from EL0 ────────────────
    // x9 was already saved to tpidrro_el0 by Slot 8 dispatch above.
    // Preserve full EL0 register context so demand-paging retries are transparent.
    "__el0_da:",
    // Preserve user x16/x17 before borrowing them as scratch.
    "mov x9, x17",
    "mov x17, x16",
    "sub sp, sp, #0x110",
    // Save x0-x30 (x31 is SP; not part of GPR save set).
    "stp x0,  x1,  [sp, #0x000]",
    "stp x2,  x3,  [sp, #0x010]",
    "stp x4,  x5,  [sp, #0x020]",
    "stp x6,  x7,  [sp, #0x030]",
    "stp x8,  x9,  [sp, #0x040]",
    "stp x10, x11, [sp, #0x050]",
    "stp x12, x13, [sp, #0x060]",
    "stp x14, x15, [sp, #0x070]",
    "str x17,      [sp, #0x080]",
    "str x9,       [sp, #0x088]",
    "stp x18, x19, [sp, #0x090]",
    "stp x20, x21, [sp, #0x0a0]",
    "stp x22, x23, [sp, #0x0b0]",
    "stp x24, x25, [sp, #0x0c0]",
    "stp x26, x27, [sp, #0x0d0]",
    "stp x28, x29, [sp, #0x0e0]",
    "str x30,      [sp, #0x0f0]",
    // Save ELR/SPSR, and recover original user x9 from tpidrro_el0.
    "mrs x16, elr_el1",
    "str x16, [sp, #0x0f8]",
    "mrs x16, spsr_el1",
    "str x16, [sp, #0x100]",
    "mrs x16, sp_el0",
    "str x16, [sp, #0x108]",
    "mrs x16, tpidrro_el0",
    "str x16, [sp, #0x048]",
    // Migrate fault frame onto current thread's private EL1 kernel stack.
    "mov x0, sp",
    "mov x1, #0x110",
    "bl svc_migrate_frame_to_thread_stack",
    "mov sp, x0",
    // Args for Rust handler: (far, esr, elr)
    "mrs x0, far_el1",
    "mrs x1, esr_el1",
    "ldr x2, [sp, #0x0f8]",
    "mov x3, sp",
    "bl user_page_fault_dispatch",
    // x0 == 0 => unresolved EL0 fault. For now, skip one A64 instruction.
    "cbz x0, 90f",
    // Restore ELR/SPSR
    "95:",
    "ldr x16, [sp, #0x0f8]",
    "msr elr_el1, x16",
    "ldr x16, [sp, #0x100]",
    "msr spsr_el1, x16",
    // Restore x0-x30 and return to EL0, retrying faulting instruction.
    "ldp x0,  x1,  [sp, #0x000]",
    "ldp x2,  x3,  [sp, #0x010]",
    "ldp x4,  x5,  [sp, #0x020]",
    "ldp x6,  x7,  [sp, #0x030]",
    "ldp x8,  x9,  [sp, #0x040]",
    "ldp x10, x11, [sp, #0x050]",
    "ldp x12, x13, [sp, #0x060]",
    "ldp x14, x15, [sp, #0x070]",
    "ldp x16, x17, [sp, #0x080]",
    "ldp x18, x19, [sp, #0x090]",
    "ldp x20, x21, [sp, #0x0a0]",
    "ldp x22, x23, [sp, #0x0b0]",
    "ldp x24, x25, [sp, #0x0c0]",
    "ldp x26, x27, [sp, #0x0d0]",
    "ldp x28, x29, [sp, #0x0e0]",
    "ldr x30,      [sp, #0x0f0]",
    "add sp, sp, #0x110",
    "1: eret",
    "90:",
    "ldr x16, [sp, #0x0f8]",
    "add x16, x16, #4",
    "str x16, [sp, #0x0f8]",
    "b 95b",
    // ── Unknown sync from EL0 (fatal) ─────────────────────────
    "__el0_undef:",
    "mrs x0, far_el1",
    "mrs x1, esr_el1",
    "mrs x2, elr_el1",
    "mov x3, xzr",
    "bl user_page_fault_dispatch",
    "b .",
    // ── EC=0x00 compat skip path ──────────────────────────────
    "93:",
    "__el0_undef_skip:",
    "mrs x16, elr_el1",
    "add x16, x16, #4",
    "msr elr_el1, x16",
    // restore user x9 saved by Slot 8 dispatch path
    "mrs x9, tpidrro_el0",
    "eret",
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

#[inline(always)]
pub fn install_exception_vectors() {
    install();
}

#[inline(always)]
pub fn default_kernel_stack_top() -> u64 {
    core::ptr::addr_of!(__svc_stack_top) as u64
}
