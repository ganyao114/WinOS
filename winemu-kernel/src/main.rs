#![no_std]
#![no_main]
#![allow(dead_code)]

mod alloc;
mod hypercall;
mod ldr;
mod mm;
mod teb;
mod vectors;

use core::arch::global_asm;

global_asm!(
    ".section .text.start",
    ".global _start",
    "_start:",
    // 清零 BSS
    "adr x0, __bss_start",
    "adr x1, __bss_end",
    "1: cmp x0, x1",
    "   b.ge 2f",
    "   str xzr, [x0], #8",
    "   b 1b",
    "2:",
    // 设置栈
    "adr x0, __kernel_stack_top",
    "mov sp, x0",
    // 跳转到 Rust 入口
    "bl kernel_main",
    // 不应返回
    "3: wfe",
    "   b 3b",
);

/// EXE 缓冲区固定放在内核基址 + 8MB 处，避免与堆冲突
/// VMM 映射了 512MB，此地址安全可用
const EXE_LOAD_BUF_GPA: u64   = 0x4080_0000;
const EXE_LOAD_BUF_SIZE: usize = 64 * 1024 * 1024;

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    mm::init();
    alloc::init();
    vectors::install();

    // ── 1. 请求 VMM 把 EXE 写入固定缓冲区 ───────────────────
    // LOAD_SYSCALL_TABLE nr 复用：args[0]=gpa, args[1]=max, args[2]=1(write)
    let exe_buf = EXE_LOAD_BUF_GPA as *mut u8;
    let written = hypercall::hypercall(
        winemu_shared::nr::LOAD_SYSCALL_TABLE,
        exe_buf as u64,
        EXE_LOAD_BUF_SIZE as u64,
        1,
    ) as usize;

    // debug: print written value as hex
    {
        let mut buf = [0u8; 32];
        let s = fmt_u64_hex(&mut buf, written as u64);
        hypercall::debug_print("kernel: written=0x");
        hypercall::debug_print(s);
        hypercall::debug_print("\n");
    }

    if written == 0 || written > EXE_LOAD_BUF_SIZE {
        hypercall::debug_print("kernel: no exe image\n");
        hypercall::kernel_ready(0, 0, 0, 0);
        loop { core::hint::spin_loop(); }
    }

    // ── 2. 加载 PE ───────────────────────────────────────────
    let exe_slice = unsafe { core::slice::from_raw_parts(exe_buf as *const u8, written) };

    hypercall::debug_print("kernel: before stack_reserve\n");

    // 读取 SizeOfStackReserve（PE OptionalHeader64 offset 72）
    let stack_reserve = if written >= 80 {
        let lfanew = u32::from_le_bytes([
            exe_slice[60], exe_slice[61], exe_slice[62], exe_slice[63]
        ]) as usize;
        let oh = lfanew + 24;
        if oh + 80 <= written {
            u64::from_le_bytes(exe_slice[oh+72..oh+80].try_into().unwrap_or([0;8]))
        } else { 0x10_0000 }
    } else { 0x10_0000 };

    hypercall::debug_print("kernel: calling ldr::load\n");

    let loaded = unsafe {
        ldr::load(exe_slice, |dll_name, imp| {
            let dll_base = hypercall::load_dll(dll_name);
            if dll_base == u64::MAX { return None; }
            match imp {
                ldr::ImportRef::Name(fn_name) => {
                    let va = hypercall::get_proc_address(dll_base, fn_name);
                    if va == 0 { None } else { Some(va) }
                }
                ldr::ImportRef::Ordinal(ord) => {
                    let mut buf = [0u8; 8];
                    let s = fmt_ordinal(&mut buf, ord);
                    let va = hypercall::get_proc_address(dll_base, s);
                    if va == 0 { None } else { Some(va) }
                }
            }
        })
    };

    let loaded = match loaded {
        Ok(img) => img,
        Err(_) => {
            hypercall::debug_print("kernel: PE load failed\n");
            hypercall::process_exit(1);
        }
    };

    // ── 3. 初始化 TEB / PEB / 栈 ────────────────────────────
    let teb_peb = match teb::init(loaded.base, 1, 1, stack_reserve, "C:\\app.exe", "app.exe") {
        Some(t) => t,
        None => {
            hypercall::debug_print("kernel: teb init failed\n");
            hypercall::process_exit(1);
        }
    };

    // ── 4. 通知 VMM 创建 Thread 0 ───────────────────────────
    let entry_va = loaded.base + loaded.entry_rva as u64;
    hypercall::debug_print("kernel: calling kernel_ready\n");
    hypercall::kernel_ready(entry_va, teb_peb.stack_base, teb_peb.teb_va, crate::alloc::heap_end());

    loop { core::hint::spin_loop(); }
}

fn fmt_u64_hex<'a>(buf: &'a mut [u8; 32], val: u64) -> &'a str {
    let hex = b"0123456789abcdef";
    for i in 0..16usize {
        let shift = (15 - i) * 4;
        buf[i] = hex[((val >> shift) & 0xF) as usize];
    }
    core::str::from_utf8(&buf[..16]).unwrap()
}

fn fmt_ordinal(buf: &mut [u8; 8], ord: u16) -> &str {
    buf[0] = b'#';
    let mut n = ord as u32;
    let mut digits = [0u8; 5];
    let mut len = 0usize;
    if n == 0 {
        digits[0] = b'0';
        len = 1;
    } else {
        while n > 0 {
            digits[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
        digits[..len].reverse();
    }
    buf[1..1 + len].copy_from_slice(&digits[..len]);
    core::str::from_utf8(&buf[..1 + len]).unwrap()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
