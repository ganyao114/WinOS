#![no_std]
#![no_main]

use core::arch::asm;

const STDOUT: u64 = 0xFFFF_FFFF_FFFF_FFF5;

// NT syscall numbers (Windows 10 ARM64)
const NR_WRITE_FILE:          u64 = 0x0008;
const NR_TERMINATE_PROCESS:   u64 = 0x002C;
const NR_CREATE_SECTION:      u64 = 0x004A;
const NR_MAP_VIEW_OF_SECTION: u64 = 0x0028;
const NR_UNMAP_VIEW_OF_SECTION: u64 = 0x002A;

#[repr(C)]
struct IoStatusBlock { status: u64, info: u64 }

unsafe fn nt_write_file(handle: u64, buf: *const u8, len: u32) {
    let mut iosb = IoStatusBlock { status: 0, info: 0 };
    let iosb_ptr = &mut iosb as *mut _ as u64;
    let buf_ptr = buf as u64;
    let len_u64 = len as u64;
    asm!(
        "mov x0, {handle}",
        "mov x1, xzr",
        "mov x2, xzr",
        "mov x3, xzr",
        "mov x4, {iosb}",
        "mov x5, {buf}",
        "mov x6, {len}",
        "mov x7, xzr",
        "mov x8, {nr}",
        "str xzr, [sp, #-16]!",
        "svc #0",
        "add sp, sp, #16",
        nr     = in(reg) NR_WRITE_FILE,
        handle = in(reg) handle,
        iosb   = in(reg) iosb_ptr,
        buf    = in(reg) buf_ptr,
        len    = in(reg) len_u64,
        out("x0") _, out("x1") _, out("x2") _, out("x3") _,
        out("x4") _, out("x5") _, out("x6") _, out("x7") _,
        out("x8") _,
        options(nostack),
    );
}

unsafe fn nt_terminate_process(code: u32) -> ! {
    asm!(
        "mov x8, {nr}", "mov x0, xzr", "mov x1, {code}", "svc #0",
        nr = in(reg) NR_TERMINATE_PROCESS, code = in(reg) code as u64,
        options(noreturn, nostack),
    );
}

/// NtCreateSection(handle_out, access, oa=0, size*, prot, attrs, file=0)
unsafe fn nt_create_section(size: u64, prot: u32) -> u64 {
    let mut handle: u64 = 0;
    let mut sz = size;
    let hout = &mut handle as *mut u64 as u64;
    let szp  = &mut sz as *mut u64 as u64;
    let prot_u64 = prot as u64;
    asm!(
        "mov x0, {hout}",
        "mov x1, #0xF",
        "mov x2, xzr",
        "mov x3, {szp}",
        "mov x4, {prot}",
        "mov x5, #0x8000000",
        "mov x6, xzr",
        "mov x8, {nr}",
        "svc #0",
        nr   = in(reg) NR_CREATE_SECTION,
        hout = in(reg) hout,
        szp  = in(reg) szp,
        prot = in(reg) prot_u64,
        out("x0") _, out("x1") _, out("x2") _, out("x3") _,
        out("x4") _, out("x5") _, out("x6") _, out("x8") _,
        options(nostack),
    );
    handle
}

/// NtMapViewOfSection(section, process=-1, base_out*, 0, 0, offset*, size*, 1, 0, prot)
unsafe fn nt_map_view(section: u64, size: u64, prot: u32) -> u64 {
    let mut base: u64 = 0;
    let mut offset: u64 = 0;
    let mut view_size: u64 = size;
    let basep = &mut base as *mut u64 as u64;
    let offp  = &mut offset as *mut u64 as u64;
    let sizep = &mut view_size as *mut u64 as u64;
    let prot_u64 = prot as u64;
    let sec = section;
    let nr = NR_MAP_VIEW_OF_SECTION;
    asm!(
        "mov x0, {sec}",
        "mov x1, #-1",
        "mov x2, {basep}",
        "mov x3, xzr",
        "mov x4, xzr",
        "mov x5, {offp}",
        "mov x6, {sizep}",
        "mov x7, #1",
        "mov x8, {nr}",
        "str xzr, [sp, #-16]!",
        "mov x9, {prot}",
        "str x9, [sp, #8]",
        "svc #0",
        "add sp, sp, #16",
        nr    = in(reg) nr,
        sec   = in(reg) sec,
        basep = in(reg) basep,
        offp  = in(reg) offp,
        sizep = in(reg) sizep,
        prot  = in(reg) prot_u64,
        out("x0") _, out("x1") _, out("x2") _, out("x3") _,
        out("x4") _, out("x5") _, out("x6") _, out("x7") _,
        out("x8") _, out("x9") _,
        options(nostack),
    );
    base
}

unsafe fn nt_unmap_view(base: u64) {
    let b = base;
    let nr = NR_UNMAP_VIEW_OF_SECTION;
    asm!(
        "mov x8, {nr}",
        "mov x0, #-1",   // ProcessHandle
        "mov x1, {base}",
        "svc #0",
        nr   = in(reg) nr,
        base = in(reg) b,
        out("x0") _, out("x1") _, out("x8") _,
        options(nostack),
    );
}

fn write_str(s: &[u8]) {
    unsafe { nt_write_file(STDOUT, s.as_ptr(), s.len() as u32); }
}

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    write_str(b"Hello from WinEmu!\r\n");

    // ── Section test ──────────────────────────────────────────
    // 1. Create a 4096-byte pagefile-backed section (PAGE_READWRITE=4)
    let sec = unsafe { nt_create_section(4096, 4) };
    if sec == 0 {
        write_str(b"FAIL: NtCreateSection returned 0\r\n");
        unsafe { nt_terminate_process(1) };
    }

    // 2. Map it into our address space
    let base = unsafe { nt_map_view(sec, 4096, 4) };
    if base == 0 {
        write_str(b"FAIL: NtMapViewOfSection returned 0\r\n");
        unsafe { nt_terminate_process(1) };
    }

    // 3. Write a sentinel value and read it back
    unsafe {
        let ptr = base as *mut u64;
        ptr.write_volatile(0xDEAD_BEEF_CAFE_1234);
        let readback = ptr.read_volatile();
        if readback != 0xDEAD_BEEF_CAFE_1234 {
            write_str(b"FAIL: section memory readback mismatch\r\n");
            nt_terminate_process(1);
        }
    }

    // 4. Unmap
    unsafe { nt_unmap_view(base); }

    write_str(b"Section test PASSED\r\n");
    unsafe { nt_terminate_process(0) };
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { nt_terminate_process(1) }
}

