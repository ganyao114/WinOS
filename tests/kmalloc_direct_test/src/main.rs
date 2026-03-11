#![no_std]
#![no_main]

use core::arch::asm;

const STDOUT: u64 = 0xFFFF_FFFF_FFFF_FFF5;
const NR_WRITE_FILE: u64 = 0x0008;
const NR_TERMINATE_PROCESS: u64 = 0x002C;
const LARGE_BSS_SIZE: usize = 5 * 1024 * 1024;

static mut LARGE_BSS: [u8; LARGE_BSS_SIZE] = [0; LARGE_BSS_SIZE];

#[repr(C)]
struct IoStatusBlock {
    status: u64,
    info: u64,
}

unsafe fn nt_write_file(handle: u64, buf: *const u8, len: u32) {
    let mut iosb = IoStatusBlock { status: 0, info: 0 };
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
        nr = in(reg) NR_WRITE_FILE,
        handle = in(reg) handle,
        iosb = in(reg) (&mut iosb as *mut IoStatusBlock as u64),
        buf = in(reg) (buf as u64),
        len = in(reg) (len as u64),
        out("x0") _, out("x1") _, out("x2") _, out("x3") _,
        out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _,
        options(nostack),
    );
}

unsafe fn nt_terminate_process(code: u32) -> ! {
    asm!(
        "mov x0, xzr",
        "svc #0",
        in("x8") NR_TERMINATE_PROCESS,
        in("x1") (code as u64),
        options(noreturn, nostack),
    );
}

fn print(msg: &[u8]) {
    unsafe {
        nt_write_file(STDOUT, msg.as_ptr(), msg.len() as u32);
    }
}

unsafe fn touch_large_bss() -> bool {
    let slots = [
        0usize,
        0x1000,
        0x20_0000,
        LARGE_BSS_SIZE - 0x1000,
        LARGE_BSS_SIZE - 1,
    ];
    let values = [0x11u8, 0x22, 0x33, 0x44, 0x55];

    let base = core::ptr::addr_of_mut!(LARGE_BSS) as *mut u8;
    let mut i = 0usize;
    while i < slots.len() {
        base.add(slots[i]).write_volatile(values[i]);
        i += 1;
    }

    let mut checksum = 0u32;
    let mut j = 0usize;
    while j < slots.len() {
        checksum = checksum.wrapping_add(base.add(slots[j]).read_volatile() as u32);
        j += 1;
    }

    checksum == (0x11u32 + 0x22 + 0x33 + 0x44 + 0x55)
}

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    print(b"kmalloc direct test start\r\n");
    let ok = unsafe { touch_large_bss() };
    if ok {
        print(b"kmalloc direct test passed\r\n");
        unsafe { nt_terminate_process(0) };
    } else {
        print(b"kmalloc direct test failed\r\n");
        unsafe { nt_terminate_process(1) };
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { nt_terminate_process(1) }
}
