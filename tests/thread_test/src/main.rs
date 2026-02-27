#![no_std]
#![no_main]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

// ── NT syscall numbers (Windows 11 ARM64) ───────────────────
const STDOUT: u64 = 0xFFFF_FFFF_FFFF_FFF5;

const NR_WRITE_FILE: u64        = 0x0008;
const NR_WAIT_SINGLE: u64       = 0x0004;
const NR_SET_EVENT: u64         = 0x000E;
const NR_CLOSE: u64             = 0x000F;
const NR_TERMINATE_PROCESS: u64 = 0x002C;
const NR_TERMINATE_THREAD: u64  = 0x0053;
const NR_RESET_EVENT: u64       = 0x0034;
const NR_CREATE_EVENT: u64      = 0x0048;
const NR_YIELD_EXECUTION: u64   = 0x0046;
const NR_CREATE_THREAD_EX: u64  = 0x00C1;

const STATUS_SUCCESS: u64 = 0;
const STATUS_TIMEOUT: u64 = 0x0000_0102;

// ── Shared state ────────────────────────────────────────────
static COUNTER_A: AtomicU32 = AtomicU32::new(0);
static COUNTER_B: AtomicU32 = AtomicU32::new(0);
static DONE_A:    AtomicU32 = AtomicU32::new(0);
static DONE_B:    AtomicU32 = AtomicU32::new(0);

static mut PASS_COUNT: u32 = 0;
static mut FAIL_COUNT: u32 = 0;

// ── Low-level SVC wrappers ──────────────────────────────────

#[inline(always)]
unsafe fn svc(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64,
              a4: u64, a5: u64, a6: u64, a7: u64) -> u64 {
    let ret: u64;
    asm!(
        "svc #0",
        inout("x0") a0 => ret,
        in("x1") a1, in("x2") a2, in("x3") a3,
        in("x4") a4, in("x5") a5, in("x6") a6, in("x7") a7,
        in("x8") nr,
        options(nostack),
    );
    ret
}

#[inline(always)]
unsafe fn svc10(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64,
                a4: u64, a5: u64, a6: u64, a7: u64,
                s0: u64, s1: u64) -> u64 {
    let ret: u64;
    asm!(
        "stp {sa}, {sb}, [sp, #-16]!",
        "svc #0",
        "add sp, sp, #16",
        sa = in(reg) s0, sb = in(reg) s1,
        inout("x0") a0 => ret,
        in("x1") a1, in("x2") a2, in("x3") a3,
        in("x4") a4, in("x5") a5, in("x6") a6, in("x7") a7,
        in("x8") nr,
        options(nostack),
    );
    ret
}

/// SVC with 3 stack args (11 total params for NtCreateThreadEx)
#[inline(always)]
unsafe fn svc11(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64,
                a4: u64, a5: u64, a6: u64, a7: u64,
                s0: u64, s1: u64, s2: u64) -> u64 {
    let ret: u64;
    asm!(
        "stp {sb}, {sc}, [sp, #-16]!",
        "str {sa}, [sp, #-16]!",
        "svc #0",
        "add sp, sp, #32",
        sa = in(reg) s0, sb = in(reg) s1, sc = in(reg) s2,
        inout("x0") a0 => ret,
        in("x1") a1, in("x2") a2, in("x3") a3,
        in("x4") a4, in("x5") a5, in("x6") a6, in("x7") a7,
        in("x8") nr,
        options(nostack),
    );
    ret
}

// ── Output helpers ──────────────────────────────────────────

#[repr(C)]
struct IoStatusBlock { status: u64, info: u64 }

unsafe fn nt_write_stdout(buf: *const u8, len: u32) -> u64 {
    let mut iosb = IoStatusBlock { status: 0, info: 0 };
    svc10(
        NR_WRITE_FILE,
        STDOUT, 0, 0, 0,
        &mut iosb as *mut _ as u64,
        buf as u64, len as u64, 0,
        0, 0,
    )
}

fn print(s: &[u8]) {
    unsafe { nt_write_stdout(s.as_ptr(), s.len() as u32); }
}

fn print_u32(val: u32) {
    let mut buf = [0u8; 10];
    let mut n = val;
    let mut len = 0usize;
    if n == 0 { buf[0] = b'0'; len = 1; }
    else {
        while n > 0 { buf[len] = b'0' + (n % 10) as u8; n /= 10; len += 1; }
        buf[..len].reverse();
    }
    print(&buf[..len]);
}

unsafe fn check(name: &[u8], ok: bool) {
    if ok { print(b"  [PASS] "); PASS_COUNT += 1; }
    else  { print(b"  [FAIL] "); FAIL_COUNT += 1; }
    print(name);
    print(b"\r\n");
}

unsafe fn exit(code: u32) -> ! {
    svc(NR_TERMINATE_PROCESS, 0xFFFFFFFFFFFFFFFF, code as u64, 0, 0, 0, 0, 0, 0);
    loop { asm!("wfi", options(nostack)); }
}

unsafe fn exit_thread() -> ! {
    svc(NR_TERMINATE_THREAD, 0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0, 0, 0);
    loop { asm!("wfi", options(nostack)); }
}

unsafe fn yield_exec() {
    svc(NR_YIELD_EXECUTION, 0, 0, 0, 0, 0, 0, 0, 0);
}

// ── NtCreateThreadEx wrapper ────────────────────────────────
// NtCreateThreadEx(OUT PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE ProcessHandle,
//   PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits,
//   SIZE_T StackSize, SIZE_T MaxStackSize, PPS_ATTRIBUTE_LIST)
unsafe fn create_thread(entry: u64, arg: u64, stack_size: u64) -> (u64, u64) {
    let mut handle: u64 = 0;
    let st = svc11(
        NR_CREATE_THREAD_EX,
        &mut handle as *mut u64 as u64,  // x0: ThreadHandle out
        0x001FFFFF,                      // x1: THREAD_ALL_ACCESS
        0,                               // x2: ObjectAttributes (NULL)
        0xFFFFFFFFFFFFFFFF,              // x3: ProcessHandle (-1 = self)
        entry,                           // x4: StartRoutine
        arg,                             // x5: Argument
        0,                               // x6: CreateFlags (0 = run immediately)
        0,                               // x7: ZeroBits
        stack_size,                      // stack[0]: StackSize
        stack_size,                      // stack[1]: MaxStackSize
        0,                               // stack[2]: AttributeList (NULL)
    );
    (st, handle)
}

unsafe fn create_event(manual: bool, initial: bool) -> (u64, u64) {
    let mut handle: u64 = 0;
    let st = svc(
        NR_CREATE_EVENT,
        &mut handle as *mut u64 as u64,
        0x001F0003,
        0,
        if manual { 0 } else { 1 },
        if initial { 1 } else { 0 },
        0, 0, 0,
    );
    (st, handle)
}

unsafe fn set_event(handle: u64) -> u64 {
    svc(NR_SET_EVENT, handle, 0, 0, 0, 0, 0, 0, 0)
}

unsafe fn wait_single(handle: u64) -> u64 {
    svc(NR_WAIT_SINGLE, handle, 0, 0, 0, 0, 0, 0, 0)
}

unsafe fn wait_single_timeout_rel(handle: u64, rel_timeout_100ns: i64) -> u64 {
    let mut timeout = rel_timeout_100ns;
    svc(
        NR_WAIT_SINGLE,
        handle,
        0,
        &mut timeout as *mut i64 as u64,
        0,
        0,
        0,
        0,
        0,
    )
}

unsafe fn close(handle: u64) -> u64 {
    svc(NR_CLOSE, handle, 0, 0, 0, 0, 0, 0, 0)
}

// ── Worker thread functions ─────────────────────────────────

extern "C" fn thread_a(_arg: u64) -> ! {
    for _ in 0..10u32 {
        COUNTER_A.fetch_add(1, Ordering::Relaxed);
        unsafe { yield_exec(); }
    }
    DONE_A.store(1, Ordering::Release);
    unsafe { exit_thread() }
}

extern "C" fn thread_b(_arg: u64) -> ! {
    for _ in 0..10u32 {
        COUNTER_B.fetch_add(1, Ordering::Relaxed);
        unsafe { yield_exec(); }
    }
    DONE_B.store(1, Ordering::Release);
    unsafe { exit_thread() }
}

// Thread C: waits on an event, then signals done
static EVENT_FOR_C: AtomicU32 = AtomicU32::new(0);
static DONE_C: AtomicU32 = AtomicU32::new(0);

extern "C" fn thread_c(_arg: u64) -> ! {
    let ev = EVENT_FOR_C.load(Ordering::Acquire) as u64;
    unsafe { wait_single(ev); }
    DONE_C.store(1, Ordering::Release);
    unsafe { exit_thread() }
}

// Thread D: receives arg, stores it to prove arg passing works
static ARG_RECEIVED: AtomicU32 = AtomicU32::new(0);

extern "C" fn thread_d(arg: u64) -> ! {
    ARG_RECEIVED.store(arg as u32, Ordering::Release);
    unsafe { exit_thread() }
}

// ── Tests ───────────────────────────────────────────────────

unsafe fn test_basic_thread_create() {
    print(b"== Thread Create ==\r\n");

    let (st, h) = create_thread(thread_d as *const () as u64, 0x42, 0x10000);
    check(b"NtCreateThreadEx returns SUCCESS", st == STATUS_SUCCESS);
    check(b"Thread handle is valid", h != 0);

    // Yield to let thread_d run
    for _ in 0..5u32 { yield_exec(); }

    let arg = ARG_RECEIVED.load(Ordering::Acquire);
    check(b"Thread received correct argument (0x42)", arg == 0x42);

    close(h);
}

unsafe fn test_two_threads() {
    print(b"== Two Threads ==\r\n");

    COUNTER_A.store(0, Ordering::Relaxed);
    COUNTER_B.store(0, Ordering::Relaxed);
    DONE_A.store(0, Ordering::Relaxed);
    DONE_B.store(0, Ordering::Relaxed);

    let (st_a, h_a) = create_thread(thread_a as *const () as u64, 0, 0x10000);
    let (st_b, h_b) = create_thread(thread_b as *const () as u64, 0, 0x10000);
    check(b"Create thread_a", st_a == STATUS_SUCCESS);
    check(b"Create thread_b", st_b == STATUS_SUCCESS);

    // Spin-yield until both done
    let mut iters = 0u32;
    loop {
        if DONE_A.load(Ordering::Acquire) != 0 && DONE_B.load(Ordering::Acquire) != 0 {
            break;
        }
        yield_exec();
        iters += 1;
        if iters > 1000 { break; } // safety limit
    }

    let ca = COUNTER_A.load(Ordering::Relaxed);
    let cb = COUNTER_B.load(Ordering::Relaxed);
    check(b"counter_a == 10", ca == 10);
    check(b"counter_b == 10", cb == 10);
    check(b"Both threads completed", DONE_A.load(Ordering::Acquire) != 0 && DONE_B.load(Ordering::Acquire) != 0);

    close(h_a);
    close(h_b);
}

unsafe fn test_event_wake() {
    print(b"== Event Wake ==\r\n");

    DONE_C.store(0, Ordering::Relaxed);

    // Create auto-reset event (SynchronizationEvent=1), initially non-signaled
    let (st_ev, ev) = create_event(false, false);
    check(b"Create event", st_ev == STATUS_SUCCESS);

    // Store event handle for thread_c
    EVENT_FOR_C.store(ev as u32, Ordering::Release);

    // Spawn thread_c
    let (st_c, h_c) = create_thread(thread_c as *const () as u64, 0, 0x10000);
    check(b"Create thread_c", st_c == STATUS_SUCCESS);

    // Yield to let thread_c block on the event
    for _ in 0..5u32 { yield_exec(); }
    check(b"thread_c not done yet (blocked)", DONE_C.load(Ordering::Acquire) == 0);

    // Signal the event
    set_event(ev);

    // Yield to let thread_c wake and run
    for _ in 0..10u32 { yield_exec(); }
    check(b"thread_c woke and completed", DONE_C.load(Ordering::Acquire) != 0);

    close(h_c);
    close(ev);
}

unsafe fn test_wait_timeout_interrupt_wake() {
    print(b"== Wait Timeout (Timer IRQ) ==\r\n");

    // Create auto-reset event, initially non-signaled.
    let (st_ev, ev) = create_event(false, false);
    check(b"Create event for timeout wait", st_ev == STATUS_SUCCESS);

    // Relative timeout: -50_000 * 100ns = 5ms.
    let st = wait_single_timeout_rel(ev, -50_000);
    check(b"NtWaitForSingleObject times out", st == STATUS_TIMEOUT);

    close(ev);
}

// ── Entry point ─────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    print(b"========================================\r\n");
    print(b"  WinEmu Thread Test\r\n");
    print(b"========================================\r\n\r\n");

    unsafe {
        test_basic_thread_create();
        print(b"\r\n");

        test_two_threads();
        print(b"\r\n");

        test_event_wake();
        print(b"\r\n");

        test_wait_timeout_interrupt_wake();
        print(b"\r\n");

        // Summary
        print(b"========================================\r\n");
        print(b"  Results: ");
        print_u32(PASS_COUNT);
        print(b" passed, ");
        print_u32(FAIL_COUNT);
        print(b" failed\r\n");
        print(b"========================================\r\n");

        let code = if FAIL_COUNT == 0 { 0 } else { 1 };
        exit(code);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    print(b"PANIC!\r\n");
    unsafe { exit(99); }
}
