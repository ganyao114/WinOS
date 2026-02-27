#![no_std]
#![no_main]
#![allow(dead_code)]

mod alloc;
mod hypercall;
mod ldr;
mod mm;
mod nt;
mod sched;
mod teb;
mod vectors;

/// EL0 Data Abort / Instruction Abort handler.
/// Called from assembly with: far=faulting address, esr=syndrome, elr=faulting PC.
/// Returns 1 if fault resolved (demand paging), 0 if unresolvable.
#[no_mangle]
pub extern "C" fn el0_page_fault(far: u64, esr: u64, elr: u64) -> u64 {
    // ESR_EL1 fields
    let ec = (esr >> 26) & 0x3F;
    let iss = esr & 0x01FF_FFFF;
    let wnr = (iss >> 6) & 1; // 1=write, 0=read

    hypercall::debug_print("PAGE_FAULT: ");
    hypercall::debug_u64(far);
    hypercall::debug_print(" EC=");
    hypercall::debug_u64(ec);
    hypercall::debug_print(" WnR=");
    hypercall::debug_u64(wnr);
    hypercall::debug_print(" ELR=");
    hypercall::debug_u64(elr);
    hypercall::debug_print("\n");

    // TODO: When MMU is enabled, look up VMA and demand-page here.
    // For now, report and return unresolved.
    0
}

/// EL1 synchronous exception handler for kernel faults.
/// Called from vectors with: far=fault address, esr=syndrome, elr=faulting PC.
#[no_mangle]
pub extern "C" fn el1_sync_fault(far: u64, esr: u64, elr: u64) -> ! {
    hypercall::debug_print("KERNEL_FAULT: FAR=");
    hypercall::debug_u64(far);
    hypercall::debug_print(" ESR=");
    hypercall::debug_u64(esr);
    hypercall::debug_print(" ELR=");
    hypercall::debug_u64(elr);
    hypercall::debug_print("\n");
    loop { core::hint::spin_loop(); }
}

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

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    hypercall::debug_print("kernel_main: start\n");
    // Install vectors early so MMU-init faults can be diagnosed.
    vectors::install();
    mm::init();
    hypercall::debug_print("kernel_main: mmu ok\n");
    alloc::init();

    // ── 1. 通过 host fd 加载 EXE ─────────────────────────────
    let (exe_fd, exe_size) = hypercall::query_exe_info();
    if exe_fd == u64::MAX || exe_size == 0 {
        hypercall::debug_print("kernel: query_exe_info failed\n");
        hypercall::process_exit(1);
    }

    {
        let mut buf = [0u8; 32];
        let s = fmt_u64_hex(&mut buf, exe_size);
        hypercall::debug_print("kernel: exe_size=0x");
        hypercall::debug_print(s);
        hypercall::debug_print("\n");
    }

    // 读取 stack_reserve: 先读 DOS header 获取 lfanew
    let stack_reserve = {
        let mut hdr = [0u8; 512];
        let got = hypercall::host_read(exe_fd, hdr.as_mut_ptr(), 512, 0);
        if got >= 80 {
            let lfanew = u32::from_le_bytes([hdr[60], hdr[61], hdr[62], hdr[63]]) as usize;
            let oh = lfanew + 24;
            if oh + 80 <= got {
                u64::from_le_bytes(hdr[oh+72..oh+80].try_into().unwrap_or([0;8]))
            } else { 0x10_0000 }
        } else { 0x10_0000 }
    };

    hypercall::debug_print("kernel: calling ldr::load_from_fd\n");

    let loaded = unsafe {
        ldr::load_from_fd(exe_fd, exe_size, |dll_name, imp| {
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

    // 关闭 exe fd
    hypercall::host_close(exe_fd);

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
