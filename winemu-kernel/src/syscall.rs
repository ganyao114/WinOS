// syscall 分发器 — 替换 Wine 的 __wine_syscall_dispatcher
// Guest 程序调用 NT syscall 时跳到这里，通过 HVC 陷入 VMM
//
// 调用约定（与 Wine ARM64 兼容）：
//   x8  = syscall 号（低12位）+ 表号（位12-13）
//   x0-x7 = 参数
//   x9  = 调用者 LR（由 syscall stub 保存）
//   返回值在 x0

use core::arch::global_asm;

// ── syscall dispatcher 汇编 ──────────────────────────────────
// 布局：
//   1. 保存 x9（调用者 LR）到栈
//   2. 提取 syscall 号（x8 低12位）→ x1（hypercall arg0）
//   3. 提取表号（x8 位12-13）→ x2（hypercall arg1）
//   4. x0-x7 已是参数，打包 GPA 传给 VMM
//   5. HVC #0（nr = NT_SYSCALL）
//   6. 恢复 LR，ret
//
// 注意：VMM 侧 NT_SYSCALL hypercall 约定：
//   hypercall_nr = NT_SYSCALL (0x0700)
//   args[0] = syscall_nr (x8 & 0xFFF)
//   args[1] = table_nr  (x8 >> 12 & 0x3)
//   args[2] = arg0 (x0)
//   args[3] = arg1 (x1)
//   args[4] = arg2 (x2)
//   args[5] = arg3 (x3)
// 超过4个参数的部分由 VMM 从 guest 栈读取（args[4]=sp）

global_asm!(
    ".section .text,\"ax\"",
    ".global __winemu_syscall_dispatcher",
    ".balign 16",
    "__winemu_syscall_dispatcher:",
    // 保存调用者 LR（x9 由 syscall stub 设置为 LR）
    "stp x9, x30, [sp, #-16]!",
    // 构造 hypercall 参数
    // x0 = NT_SYSCALL hypercall 号
    "mov x16, #0x0700",        // NT_SYSCALL nr
    // 把 syscall 号和表号打包到 x17
    "and x17, x8, #0xFFF",     // x17 = syscall_nr
    "lsr x18, x8, #12",
    "and x18, x18, #0x3",      // x18 = table_nr
    // 参数 x0-x7 已就位，直接 HVC
    // HVC 约定：x0=nr, x1-x6=args
    // 需要把 syscall_nr/table_nr 插入，先移位参数
    // 实际约定：
    //   x0 = NT_SYSCALL (0x0700)
    //   x1 = syscall_nr
    //   x2 = table_nr
    //   x3 = original x0 (arg0)
    //   x4 = original x1 (arg1)
    //   x5 = original x2 (arg2)
    //   x6 = original x3 (arg3)
    // 超过4个参数：VMM 从 guest sp+16 读取
    "mov x6, x3",              // arg3
    "mov x5, x2",              // arg2
    "mov x4, x1",              // arg1
    "mov x3, x0",              // arg0
    "mov x2, x18",             // table_nr
    "mov x1, x17",             // syscall_nr
    "mov x0, x16",             // NT_SYSCALL
    "hvc #0",
    // 恢复 LR 并返回
    "ldp x9, x30, [sp], #16",
    "ret x9",
);

// ── syscall 表初始化 ─────────────────────────────────────────
// 把 __winemu_syscall_dispatcher 地址写入 TEB.syscall_table
// 这样 Wine 的 syscall stub（ldr x16, [x18, #0x2f8]; blr x16）
// 就会跳到我们的 dispatcher

extern "C" {
    fn __winemu_syscall_dispatcher();
}

/// 初始化 syscall 分发器
/// teb_va: 当前线程的 TEB 虚拟地址
pub fn init_dispatcher(teb_va: u64) {
    use winemu_shared::teb;
    let dispatcher_va = __winemu_syscall_dispatcher as u64;
    // 写入 TEB+0x2f8（SYSCALL_TABLE 字段）
    unsafe {
        let ptr = (teb_va + teb::SYSCALL_TABLE as u64) as *mut u64;
        ptr.write_volatile(dispatcher_va);
    }
}
