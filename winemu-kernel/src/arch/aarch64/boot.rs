use core::arch::global_asm;

global_asm!(
    ".bss",
    ".balign 16",
    ".global __secondary_kernel_stacks_bottom",
    "__secondary_kernel_stacks_bottom:",
    // 8 * 64KiB secondary boot stacks (vid 0..7)
    ".space (8 * 65536)",
    ".global __secondary_kernel_stacks_top",
    "__secondary_kernel_stacks_top:",
);

global_asm!(
    ".section .text.start,\"ax\"",
    ".global _start",
    "_start:",
    // Read MPIDR_EL1 affinity to distinguish bootstrap/secondary CPUs.
    "mrs x2, mpidr_el1",
    "and x2, x2, #0xff",
    // Secondary CPUs wait for primary boot completion.
    "cbz x2, 1f",
    // Clamp vid to [0, 7] for secondary stack index.
    "cmp x2, #7",
    "b.ls 0f",
    "mov x2, #0",
    "0:",
    "ldr x0, =__secondary_kernel_stacks_bottom",
    "movz x1, #0x1, lsl #16", // 64KiB
    "mul x4, x2, x1",
    "add x0, x0, x4",
    "add x0, x0, x1",
    "mov sp, x0",
    "2:",
    "ldr x4, =__boot_primary_ready",
    // Acquire load: observe bootstrap global init before secondary continue.
    "ldar w5, [x4]",
    "cbnz w5, 3f",
    "wfe",
    "b 2b",
    "3:",
    "bl kernel_secondary_main",
    "4: wfe",
    "   b 4b",
    // Primary CPU path.
    "1:",
    // 清零 BSS — 使用 literal pool 加载链接器符号地址
    "ldr x0, =__bss_start",
    "ldr x1, =__bss_end",
    "5: cmp x0, x1",
    "   b.ge 6f",
    "   str xzr, [x0], #8",
    "   b 5b",
    "6:",
    // 设置栈
    "ldr x0, =__kernel_stack_top",
    "mov sp, x0",
    // 跳转到 Rust 入口
    "bl kernel_main",
    // 不应返回
    "3: wfe",
    "   b 3b",
);
