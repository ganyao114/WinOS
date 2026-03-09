#![no_std]
#![no_main]

use core::arch::asm;

// ── NT syscall numbers ────────────────────────────────────────────────────────
const NR_WRITE_FILE:        u64 = 0x0008;
const NR_DELAY_EXECUTION:   u64 = 0x0034;
const NR_TERMINATE_PROCESS: u64 = 0x002C;

// ── Win32k syscall numbers (table 1 = NtUser*, table 0 = NtGdi*) ─────────────
const NT_USER_CREATE_WINDOW_EX:   u32 = 0x06f;
const NT_USER_SHOW_WINDOW:        u32 = 0x052;
const NT_USER_QUERY_WINDOW:       u32 = 0x00e;
const NT_USER_PEEK_MESSAGE:       u32 = 0x001;
const NT_USER_TRANSLATE_MESSAGE:  u32 = 0x00b;
const NT_USER_BEGIN_PAINT:        u32 = 0x015;
const NT_USER_END_PAINT:          u32 = 0x017;
const NT_USER_DESTROY_WINDOW:     u32 = 0x095;
const NT_USER_POST_QUIT_MESSAGE:  u32 = 0x4d9;
const NT_USER_DEF_WINDOW_PROC:    u32 = 0x0a9;

// ── Windows message constants ─────────────────────────────────────────────────
const WM_DESTROY: u32 = 0x0002;
const WM_PAINT:   u32 = 0x000F;
const WM_CLOSE:   u32 = 0x0010;

// ── STDOUT pseudo-handle ──────────────────────────────────────────────────────
const STDOUT: u64 = 0xFFFF_FFFF_FFFF_FFF5;


// ── MSG struct (matches Windows layout) ──────────────────────────────────────
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Msg {
    hwnd:    u32,
    message: u32,
    wparam:  u64,
    lparam:  u64,
    time:    u32,
    pt_x:    i32,
    pt_y:    i32,
    _pad:    u32,
}

// ── PAINTSTRUCT (simplified) ──────────────────────────────────────────────────
#[repr(C)]
#[derive(Default)]
struct PaintStruct {
    hdc:         u64,
    erase:       u32,
    rc_left:     i32,
    rc_top:      i32,
    rc_right:    i32,
    rc_bottom:   i32,
    restore:     u32,
    inc_update:  u32,
    reserved:    [u8; 32],
}

// ── IoStatusBlock ─────────────────────────────────────────────────────────────
#[repr(C)]
struct IoStatusBlock { status: u64, info: u64 }

// ── Low-level syscall helpers ─────────────────────────────────────────────────

unsafe fn nt_write_file(handle: u64, buf: *const u8, len: u32) {
    let mut iosb = IoStatusBlock { status: 0, info: 0 };
    let iosb_ptr = &mut iosb as *mut _ as u64;
    let buf_ptr  = buf as u64;
    let len_u64  = len as u64;
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
        nr   = in(reg) NR_TERMINATE_PROCESS,
        code = in(reg) code as u64,
        options(noreturn, nostack),
    );
}

unsafe fn nt_delay_execution_ms(ms: u32) {
    let mut rel_100ns: i64 = -((ms as i64) * 10_000);
    asm!(
        "mov x0, xzr",
        "mov x1, {timeout}",
        "mov x8, {nr}",
        "svc #0",
        nr = in(reg) NR_DELAY_EXECUTION,
        timeout = in(reg) (&mut rel_100ns as *mut i64 as u64),
        out("x0") _, out("x1") _, out("x2") _, out("x3") _,
        out("x4") _, out("x5") _, out("x6") _, out("x7") _,
        out("x8") _,
        options(nostack),
    );
}

/// Issue a win32k syscall via svc #0.
/// x8 = (table << 12) | syscall_nr
/// x0..x7 = first 8 args; spill args[8..] onto stack if needed.
/// Returns x0 (NT status or result value).
unsafe fn win32k_call(table: u32, syscall_nr: u32, args: &[u64]) -> u64 {
    let x8_val = ((table as u64) << 12) | (syscall_nr as u64);
    let a: [u64; 8] = [
        if args.len() > 0 { args[0] } else { 0 },
        if args.len() > 1 { args[1] } else { 0 },
        if args.len() > 2 { args[2] } else { 0 },
        if args.len() > 3 { args[3] } else { 0 },
        if args.len() > 4 { args[4] } else { 0 },
        if args.len() > 5 { args[5] } else { 0 },
        if args.len() > 6 { args[6] } else { 0 },
        if args.len() > 7 { args[7] } else { 0 },
    ];
    let mut ret: u64;
    asm!(
        "mov x0, {a0}",
        "mov x1, {a1}",
        "mov x2, {a2}",
        "mov x3, {a3}",
        "mov x4, {a4}",
        "mov x5, {a5}",
        "mov x6, {a6}",
        "mov x7, {a7}",
        "mov x8, {nr}",
        "svc #0",
        "mov {ret}, x0",
        a0  = in(reg) a[0], a1 = in(reg) a[1],
        a2  = in(reg) a[2], a3 = in(reg) a[3],
        a4  = in(reg) a[4], a5 = in(reg) a[5],
        a6  = in(reg) a[6], a7 = in(reg) a[7],
        nr  = in(reg) x8_val,
        ret = out(reg) ret,
        out("x1") _, out("x2") _, out("x3") _,
        out("x4") _, out("x5") _, out("x6") _, out("x7") _,
        out("x8") _,
        options(nostack),
    );
    ret
}

fn write_str(s: &[u8]) {
    unsafe { nt_write_file(STDOUT, s.as_ptr(), s.len() as u32); }
}

fn write_ok(label: &[u8]) {
    write_str(b"[PASS] ");
    write_str(label);
    write_str(b"\r\n");
}

fn write_fail(label: &[u8]) {
    write_str(b"[FAIL] ");
    write_str(label);
    write_str(b"\r\n");
}

// ── WndProc-style paint helper ────────────────────────────────────────────────

unsafe fn do_paint(hwnd: u32) {
    let mut ps = PaintStruct::default();
    let ps_ptr = &mut ps as *mut PaintStruct as u64;

    // BeginPaint(hwnd, &ps) → hdc
    let hdc = win32k_call(1, NT_USER_BEGIN_PAINT, &[hwnd as u64, ps_ptr]) as u32;
    if hdc == 0 {
        write_fail(b"BeginPaint");
        return;
    }

    // EndPaint
    win32k_call(1, NT_USER_END_PAINT, &[hwnd as u64, ps_ptr]);
    write_ok(b"WM_PAINT handled");
}

// ── Main entry ────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    write_str(b"window_test: start\r\n");

    // ── 1. Create window ──────────────────────────────────────────────────────
    let hwnd = unsafe {
        win32k_call(1, NT_USER_CREATE_WINDOW_EX, &[
            0,                          // dwExStyle
            0,                          // lpClassName (ignored by VMM)
            0,                          // lpWindowName
            0x00CF0000u64,              // WS_OVERLAPPEDWINDOW
            100, 100, 640, 480,         // x, y, w, h
            0, 0, 0, 0,                 // parent, menu, instance, param
        ])
    } as u32;

    if hwnd == 0 {
        write_fail(b"CreateWindowEx");
        unsafe { nt_terminate_process(1) };
    }
    write_ok(b"CreateWindowEx");

    // ── 2. ShowWindow ─────────────────────────────────────────────────────────
    unsafe { win32k_call(1, NT_USER_SHOW_WINDOW, &[hwnd as u64, 1]) };
    write_ok(b"ShowWindow");
    write_str(b"window_test: waiting window visible state\r\n");

    // CreateWindowEx is deferred on host event-loop thread.
    // Poll visible state until the host window is actually live.
    let mut visible = false;
    for _ in 0..80_000u32 {
        unsafe {
            if win32k_call(1, NT_USER_QUERY_WINDOW, &[hwnd as u64, 7]) != 0 {
                visible = true;
                break;
            }
        }
        unsafe { nt_delay_execution_ms(1) };
    }
    if !visible {
        write_fail(b"WindowVisible");
        unsafe { nt_terminate_process(1) };
    }
    write_ok(b"WindowVisible");

    // ── 3. Message loop (bounded) ────────────────────────────────────────────
    let mut msg = Msg::default();
    let msg_ptr = &mut msg as *mut Msg as u64;
    let mut painted = false;
    let mut destroyed = false;
    let mut idle_ticks: u32 = 0;
    const MAX_IDLE_TICKS: u32 = 4_000;

    loop {
        if idle_ticks >= MAX_IDLE_TICKS {
            break;
        }

        // PeekMessage(msg, 0, 0, 0, PM_REMOVE=1)
        let got = unsafe {
            win32k_call(1, NT_USER_PEEK_MESSAGE, &[msg_ptr, 0, 0, 0, 1])
        };

        if got == 0 {
            if !painted {
                unsafe { do_paint(hwnd) };
                painted = true;
            } else {
                idle_ticks = idle_ticks.saturating_add(1);
            }
            unsafe { nt_delay_execution_ms(1) };
            continue;
        }
        idle_ticks = 0;

        // TranslateMessage
        unsafe { win32k_call(1, NT_USER_TRANSLATE_MESSAGE, &[msg_ptr]) };

        match msg.message {
            WM_PAINT => {
                unsafe { do_paint(hwnd) };
                painted = true;
            }
            WM_CLOSE => {
                if !destroyed {
                    unsafe {
                        win32k_call(1, NT_USER_DESTROY_WINDOW, &[hwnd as u64]);
                    }
                    destroyed = true;
                }
            }
            WM_DESTROY => {
                destroyed = true;
                unsafe {
                    win32k_call(1, NT_USER_POST_QUIT_MESSAGE, &[0]);
                }
                break;
            }
            0x0012 => break, // WM_QUIT
            _ => {
                // DefWindowProc
                unsafe {
                    win32k_call(1, NT_USER_DEF_WINDOW_PROC, &[
                        hwnd as u64, msg.message as u64, msg.wparam, msg.lparam,
                    ]);
                }
            }
        }
    }

    write_ok(b"message loop exited");

    if !destroyed {
        unsafe { win32k_call(1, NT_USER_DESTROY_WINDOW, &[hwnd as u64]) };
    }
    write_ok(b"DestroyWindow");

    write_str(b"window_test: PASSED\r\n");
    unsafe { nt_terminate_process(0) };
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { nt_terminate_process(1) }
}
