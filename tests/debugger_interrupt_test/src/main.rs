#![no_std]
#![no_main]

use core::arch::asm;
use winemu_shared::nt_sysno::{nt_sysno_nr_for_build, NtHandlerId};

const WINDOWS_BUILD: u32 = 22631;
const STDOUT: u64 = 0xFFFF_FFFF_FFFF_FFF5;
const TICKS: u32 = 1000;
const DELAY_MS: u32 = 50;

#[repr(C)]
struct IoStatusBlock {
    status: u64,
    info: u64,
}

#[inline(always)]
fn nt_nr(handler: NtHandlerId) -> u64 {
    nt_sysno_nr_for_build(WINDOWS_BUILD, handler).expect("missing NT syscall") as u64
}

unsafe fn nt_write_file(handle: u64, buf: *const u8, len: u32) {
    let mut iosb = IoStatusBlock { status: 0, info: 0 };
    let iosb_ptr = &mut iosb as *mut _ as u64;
    let buf_ptr = buf as u64;
    let len_u64 = len as u64;
    asm!(
        "str xzr, [sp, #-16]!",
        "svc #0",
        "add sp, sp, #16",
        inlateout("x0") handle => _,
        inlateout("x1") 0u64 => _,
        inlateout("x2") 0u64 => _,
        inlateout("x3") 0u64 => _,
        inlateout("x4") iosb_ptr => _,
        inlateout("x5") buf_ptr => _,
        inlateout("x6") len_u64 => _,
        inlateout("x7") 0u64 => _,
        inlateout("x8") nt_nr(NtHandlerId::WriteFile) => _,
    );
}

unsafe fn nt_delay_execution_ms(ms: u32) {
    let mut rel_100ns: i64 = -((ms as i64) * 10_000);
    asm!(
        "svc #0",
        inlateout("x0") 0u64 => _,
        inlateout("x1") (&mut rel_100ns as *mut i64 as u64) => _,
        lateout("x2") _,
        lateout("x3") _,
        lateout("x4") _,
        lateout("x5") _,
        lateout("x6") _,
        lateout("x7") _,
        inlateout("x8") nt_nr(NtHandlerId::DelayExecution) => _,
        options(nostack),
    );
}

unsafe fn nt_terminate_process(code: u32) -> ! {
    asm!(
        "svc #0",
        in("x0") 0u64,
        in("x1") code as u64,
        in("x8") nt_nr(NtHandlerId::TerminateProcess),
        options(noreturn, nostack),
    );
}

fn write_str(text: &[u8]) {
    // SAFETY: The buffer is valid for the duration of the syscall and points to guest memory.
    unsafe { nt_write_file(STDOUT, text.as_ptr(), text.len() as u32) };
}

fn write_u32(mut value: u32) {
    let mut buf = [0u8; 16];
    let mut len = 0usize;
    if value == 0 {
        buf[0] = b'0';
        len = 1;
    } else {
        while value > 0 {
            buf[len] = b'0' + (value % 10) as u8;
            value /= 10;
            len += 1;
        }
        buf[..len].reverse();
    }
    write_str(&buf[..len]);
}

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    write_str(b"debugger_interrupt_test: start\r\n");
    for tick in 0..TICKS {
        if tick % 100 == 0 {
            write_str(b"debugger_interrupt_test: tick=");
            write_u32(tick);
            write_str(b"\r\n");
        }
        // SAFETY: Relative timeout is stack-local and valid for the duration of the syscall.
        unsafe { nt_delay_execution_ms(DELAY_MS) };
    }
    write_str(b"debugger_interrupt_test: PASS\r\n");
    // SAFETY: Exiting the current process is the terminal action of this test.
    unsafe { nt_terminate_process(0) };
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: Panic is fatal for this test process.
    unsafe { nt_terminate_process(1) }
}
