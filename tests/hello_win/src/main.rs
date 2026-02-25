#![no_std]
#![no_main]

// Minimal ARM64 Windows test — no CRT, direct NT syscalls via HVC
// NtWriteFile syscall number on Windows 10: 0x0008
// NtTerminateProcess: 0x002C

use core::arch::asm;

// NT pseudo-handle for stdout: -11 (0xFFFFFFFFFFFFFFF5)
const STDOUT: u64 = 0xFFFF_FFFF_FFFF_FFF5;

#[repr(C)]
struct IoStatusBlock {
    status: u64,
    info:   u64,
}

unsafe fn nt_write_file(handle: u64, buf: *const u8, len: u32) {
    let mut iosb = IoStatusBlock { status: 0, info: 0 };
    // NtWriteFile(handle, event=0, apc=0, apc_ctx=0, iosb, buf, len, offset=0, key=0)
    // syscall nr = 0x0008 on Win10 x64/arm64
    let nr: u64 = 0x0008;
    asm!(
        // x0..x7 = args, x8 = syscall number
        // NtWriteFile args:
        //   x0 = FileHandle
        //   x1 = Event (NULL)
        //   x2 = ApcRoutine (NULL)
        //   x3 = ApcContext (NULL)
        //   x4 = IoStatusBlock*
        //   x5 = Buffer*
        //   x6 = Length
        //   x7 = ByteOffset* (NULL = current position)
        // [sp+0] = Key* (NULL)  — 9th arg on stack
        "mov x8, {nr}",
        "mov x0, {handle}",
        "mov x1, xzr",
        "mov x2, xzr",
        "mov x3, xzr",
        "mov x4, {iosb}",
        "mov x5, {buf}",
        "mov x6, {len}",
        "mov x7, xzr",
        // push NULL for Key* (9th arg)
        "str xzr, [sp, #-16]!",
        "svc #0",
        "add sp, sp, #16",
        nr     = in(reg) nr,
        handle = in(reg) handle,
        iosb   = in(reg) &mut iosb as *mut _ as u64,
        buf    = in(reg) buf as u64,
        len    = in(reg) len as u64,
        out("x0") _,
        options(nostack),
    );
}

unsafe fn nt_terminate_process(exit_code: u32) -> ! {
    let nr: u64 = 0x002C;
    asm!(
        "mov x8, {nr}",
        "mov x0, xzr",   // ProcessHandle = NtCurrentProcess() = 0 (or -1)
        "mov x1, {code}",
        "svc #0",
        nr   = in(reg) nr,
        code = in(reg) exit_code as u64,
        options(noreturn, nostack),
    );
}

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    let msg = b"Hello from WinEmu!\r\n";
    unsafe {
        nt_write_file(STDOUT, msg.as_ptr(), msg.len() as u32);
        nt_terminate_process(0);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { nt_terminate_process(1) }
}
