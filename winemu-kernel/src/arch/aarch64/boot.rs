use core::arch::global_asm;

global_asm!(
    ".section .text.start,\"ax\"",
    ".global _start",
    "_start:",
    // 清零 BSS — 使用 literal pool 加载链接器符号地址
    "ldr x0, =__bss_start",
    "ldr x1, =__bss_end",
    "1: cmp x0, x1",
    "   b.ge 2f",
    "   str xzr, [x0], #8",
    "   b 1b",
    "2:",
    // 设置栈
    "ldr x0, =__kernel_stack_top",
    "mov sp, x0",
    // 跳转到 Rust 入口
    "bl kernel_main",
    // 不应返回
    "3: wfe",
    "   b 3b",
);
