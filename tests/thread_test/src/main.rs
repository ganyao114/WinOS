#![no_std]
#![no_main]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

// ── NT syscall numbers (Windows 11 ARM64) ───────────────────
const STDOUT: u64 = 0xFFFF_FFFF_FFFF_FFF5;

const NR_WRITE_FILE: u64        = 0x0008;
const NR_WAIT_SINGLE: u64       = 0x0004;
const NR_WAIT_MULTIPLE: u64     = 0x0040;
const NR_SET_EVENT: u64         = 0x000E;
const NR_CLOSE: u64             = 0x000F;
const NR_SET_INFORMATION_THREAD: u64 = 0x000D;
const NR_TERMINATE_PROCESS: u64 = 0x002C;
const NR_TERMINATE_THREAD: u64  = 0x0053;
const NR_CREATE_EVENT: u64      = 0x0048;
const NR_CREATE_MUTEX: u64      = 0x00A9;
const NR_RELEASE_MUTANT: u64    = 0x001C;
const NR_YIELD_EXECUTION: u64   = 0x0046;
const NR_CREATE_THREAD_EX: u64  = 0x00C1;

const STATUS_SUCCESS: u64 = 0;
const STATUS_TIMEOUT: u64 = 0x0000_0102;
const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;

const PREEMPT_A_WORK: u32 = 12_000_000;
const PREEMPT_B_WORK: u32 = 500_000;
const PI_LOW_WORK: u32 = 500_000;
const PI_MED_WORK: u32 = 1_000_000;
const BURST_WAITERS: usize = 16;
const FAIR_WORKERS: usize = 8;
const FAIR_MAX_SPINS: u32 = 4_000_000;
const TIMEOUT_STORM_THREADS: usize = 24;
const MUTEX_STRESS_THREADS: usize = 8;
const MUTEX_STRESS_ITERS: u32 = 300;

// ── Shared state ────────────────────────────────────────────
static COUNTER_A: AtomicU32 = AtomicU32::new(0);
static COUNTER_B: AtomicU32 = AtomicU32::new(0);
static DONE_A:    AtomicU32 = AtomicU32::new(0);
static DONE_B:    AtomicU32 = AtomicU32::new(0);
static PREEMPT_SEEN: AtomicU32 = AtomicU32::new(0);
static PREEMPT_FLAG: AtomicU32 = AtomicU32::new(0);
static TIMEOUT_EVENT: AtomicU32 = AtomicU32::new(0);
static TIMEOUT_DONE: AtomicU32 = AtomicU32::new(0);
static TIMEOUT_STATUS: AtomicU32 = AtomicU32::new(0);
static SET_EVENT_PREEMPT_TARGET: AtomicU32 = AtomicU32::new(0);
static SET_EVENT_PREEMPT_READY: AtomicU32 = AtomicU32::new(0);
static SET_EVENT_PREEMPT_WOKE: AtomicU32 = AtomicU32::new(0);

static LOW_GO_EVENT: AtomicU32 = AtomicU32::new(0);
static HIGH_GO_EVENT: AtomicU32 = AtomicU32::new(0);
static MED_GO_EVENT: AtomicU32 = AtomicU32::new(0);
static TEST_MUTEX: AtomicU32 = AtomicU32::new(0);
static LOW_HAS_MUTEX: AtomicU32 = AtomicU32::new(0);
static LOW_DONE: AtomicU32 = AtomicU32::new(0);
static HIGH_DONE: AtomicU32 = AtomicU32::new(0);
static MED_DONE: AtomicU32 = AtomicU32::new(0);
static HIGH_BEFORE_MED_DONE: AtomicU32 = AtomicU32::new(0);
static BURST_EVENT: AtomicU32 = AtomicU32::new(0);
static BURST_DONE: AtomicU32 = AtomicU32::new(0);
static FAIR_START_EVENT: AtomicU32 = AtomicU32::new(0);
static FAIR_STOP: AtomicU32 = AtomicU32::new(0);
static FAIR_DONE: AtomicU32 = AtomicU32::new(0);
static FAIR_COUNTERS: [AtomicU32; FAIR_WORKERS] = [const { AtomicU32::new(0) }; FAIR_WORKERS];
static TIMEOUT_STORM_EVENT: AtomicU32 = AtomicU32::new(0);
static TIMEOUT_STORM_DONE: AtomicU32 = AtomicU32::new(0);
static TIMEOUT_STORM_TIMEOUTS: AtomicU32 = AtomicU32::new(0);
static MUTEX_STRESS_START: AtomicU32 = AtomicU32::new(0);
static MUTEX_STRESS_HANDLE: AtomicU32 = AtomicU32::new(0);
static MUTEX_STRESS_DONE: AtomicU32 = AtomicU32::new(0);
static MUTEX_STRESS_COUNTER: AtomicU32 = AtomicU32::new(0);
static DESTROY_WAIT_HANDLE: AtomicU32 = AtomicU32::new(0);
static DESTROY_WAIT_DONE: AtomicU32 = AtomicU32::new(0);
static DESTROY_WAIT_STATUS: AtomicU32 = AtomicU32::new(0);

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
        lateout("x20") _, lateout("x21") _, lateout("x22") _,
        lateout("x23") _, lateout("x24") _, lateout("x25") _, lateout("x26") _,
        lateout("x27") _, lateout("x28") _,
        clobber_abi("C"),
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
        "sub sp, sp, #16",
        "str {sa}, [sp, #0]",
        "str {sb}, [sp, #8]",
        "svc #0",
        "add sp, sp, #16",
        sa = in(reg) s0, sb = in(reg) s1,
        inout("x0") a0 => ret,
        in("x1") a1, in("x2") a2, in("x3") a3,
        in("x4") a4, in("x5") a5, in("x6") a6, in("x7") a7,
        in("x8") nr,
        lateout("x20") _, lateout("x21") _, lateout("x22") _,
        lateout("x23") _, lateout("x24") _, lateout("x25") _, lateout("x26") _,
        lateout("x27") _, lateout("x28") _,
        clobber_abi("C"),
        options(),
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
        "sub sp, sp, #32",
        "str {sa}, [sp, #0]",
        "str {sb}, [sp, #8]",
        "str {sc}, [sp, #16]",
        "svc #0",
        "add sp, sp, #32",
        sa = in(reg) s0, sb = in(reg) s1, sc = in(reg) s2,
        inout("x0") a0 => ret,
        in("x1") a1, in("x2") a2, in("x3") a3,
        in("x4") a4, in("x5") a5, in("x6") a6, in("x7") a7,
        in("x8") nr,
        lateout("x20") _, lateout("x21") _, lateout("x22") _,
        lateout("x23") _, lateout("x24") _, lateout("x25") _, lateout("x26") _,
        lateout("x27") _, lateout("x28") _,
        clobber_abi("C"),
        options(),
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

unsafe fn create_mutex(initial_owner: bool) -> (u64, u64) {
    let mut handle: u64 = 0;
    let st = svc(
        NR_CREATE_MUTEX,
        &mut handle as *mut u64 as u64,
        0x001F0001,
        0,
        if initial_owner { 1 } else { 0 },
        0, 0, 0, 0,
    );
    (st, handle)
}

unsafe fn release_mutant(handle: u64) -> u64 {
    svc(NR_RELEASE_MUTANT, handle, 0, 0, 0, 0, 0, 0, 0)
}

unsafe fn set_thread_priority(thread_handle: u64, prio: i32) -> u64 {
    let mut p = prio;
    // ThreadPriority = 2
    svc(
        NR_SET_INFORMATION_THREAD,
        thread_handle,
        2,
        &mut p as *mut i32 as u64,
        core::mem::size_of::<i32>() as u64,
        0,
        0,
        0,
        0,
    )
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

unsafe fn wait_multiple_timeout_rel(handles: &[u64], wait_all: bool, rel_timeout_100ns: i64) -> u64 {
    let mut timeout = rel_timeout_100ns;
    svc(
        NR_WAIT_MULTIPLE,
        handles.len() as u64,
        handles.as_ptr() as u64,
        if wait_all { 0 } else { 1 },
        0,
        &mut timeout as *mut i64 as u64,
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

extern "C" fn thread_preempt_a(_arg: u64) -> ! {
    let mut seen = 0u32;
    for _ in 0..PREEMPT_A_WORK {
        COUNTER_A.fetch_add(1, Ordering::Relaxed);
        if PREEMPT_FLAG.load(Ordering::Acquire) != 0 {
            seen = 1;
            break;
        }
    }
    PREEMPT_SEEN.store(seen, Ordering::Release);
    DONE_A.store(1, Ordering::Release);
    unsafe { exit_thread() }
}

extern "C" fn thread_preempt_b(_arg: u64) -> ! {
    PREEMPT_FLAG.store(1, Ordering::Release);
    for _ in 0..PREEMPT_B_WORK {
        COUNTER_B.fetch_add(1, Ordering::Relaxed);
    }
    DONE_B.store(1, Ordering::Release);
    unsafe { exit_thread() }
}

extern "C" fn thread_pi_low(_arg: u64) -> ! {
    let go = LOW_GO_EVENT.load(Ordering::Acquire) as u64;
    unsafe { wait_single(go); }
    let mutex = TEST_MUTEX.load(Ordering::Acquire) as u64;
    if unsafe { wait_single(mutex) } == STATUS_SUCCESS {
        LOW_HAS_MUTEX.store(1, Ordering::Release);
        for _ in 0..PI_LOW_WORK {
            COUNTER_A.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { release_mutant(mutex); }
    }
    LOW_DONE.store(1, Ordering::Release);
    unsafe { exit_thread() }
}

extern "C" fn thread_pi_high(_arg: u64) -> ! {
    let go = HIGH_GO_EVENT.load(Ordering::Acquire) as u64;
    unsafe { wait_single(go); }
    let mutex = TEST_MUTEX.load(Ordering::Acquire) as u64;
    if unsafe { wait_single(mutex) } == STATUS_SUCCESS {
        if MED_DONE.load(Ordering::Acquire) == 0 {
            HIGH_BEFORE_MED_DONE.store(1, Ordering::Release);
        }
        unsafe { release_mutant(mutex); }
    }
    HIGH_DONE.store(1, Ordering::Release);
    unsafe { exit_thread() }
}

extern "C" fn thread_pi_medium(_arg: u64) -> ! {
    let go = MED_GO_EVENT.load(Ordering::Acquire) as u64;
    unsafe { wait_single(go); }
    for _ in 0..PI_MED_WORK {
        COUNTER_B.fetch_add(1, Ordering::Relaxed);
    }
    MED_DONE.store(1, Ordering::Release);
    unsafe { exit_thread() }
}

extern "C" fn thread_timeout_wait(_arg: u64) -> ! {
    let ev = TIMEOUT_EVENT.load(Ordering::Acquire) as u64;
    let st = unsafe { wait_single_timeout_rel(ev, -50_000) };
    TIMEOUT_STATUS.store(st as u32, Ordering::Release);
    TIMEOUT_DONE.store(1, Ordering::Release);
    unsafe { exit_thread() }
}

extern "C" fn thread_set_event_preempt_waiter(_arg: u64) -> ! {
    SET_EVENT_PREEMPT_READY.store(1, Ordering::Release);
    let ev = SET_EVENT_PREEMPT_TARGET.load(Ordering::Acquire) as u64;
    let st = unsafe { wait_single(ev) };
    if st == STATUS_SUCCESS {
        SET_EVENT_PREEMPT_WOKE.store(1, Ordering::Release);
    }
    unsafe { exit_thread() }
}

extern "C" fn thread_burst_waiter(_arg: u64) -> ! {
    let ev = BURST_EVENT.load(Ordering::Acquire) as u64;
    if unsafe { wait_single(ev) } == STATUS_SUCCESS {
        BURST_DONE.fetch_add(1, Ordering::AcqRel);
    }
    unsafe { exit_thread() }
}

extern "C" fn thread_fair_worker(arg: u64) -> ! {
    let idx = (arg as usize) % FAIR_WORKERS;
    let ev = FAIR_START_EVENT.load(Ordering::Acquire) as u64;
    unsafe { wait_single(ev); }

    let mut spins = 0u32;
    loop {
        FAIR_COUNTERS[idx].fetch_add(1, Ordering::Relaxed);
        spins = spins.wrapping_add(1);
        if (spins & 0x3fff) == 0 {
            if FAIR_STOP.load(Ordering::Acquire) != 0 || spins >= FAIR_MAX_SPINS {
                break;
            }
        }
    }
    FAIR_DONE.fetch_add(1, Ordering::AcqRel);
    unsafe { exit_thread() }
}

extern "C" fn thread_timeout_storm_waiter(_arg: u64) -> ! {
    let ev = TIMEOUT_STORM_EVENT.load(Ordering::Acquire) as u64;
    let st = unsafe { wait_single_timeout_rel(ev, -20_000) };
    if st == STATUS_TIMEOUT {
        TIMEOUT_STORM_TIMEOUTS.fetch_add(1, Ordering::AcqRel);
    }
    TIMEOUT_STORM_DONE.fetch_add(1, Ordering::AcqRel);
    unsafe { exit_thread() }
}

extern "C" fn thread_mutex_stress(_arg: u64) -> ! {
    let go = MUTEX_STRESS_START.load(Ordering::Acquire) as u64;
    unsafe { wait_single(go); }
    let mutex = MUTEX_STRESS_HANDLE.load(Ordering::Acquire) as u64;
    let mut i = 0u32;
    while i < MUTEX_STRESS_ITERS {
        if unsafe { wait_single(mutex) } == STATUS_SUCCESS {
            MUTEX_STRESS_COUNTER.fetch_add(1, Ordering::AcqRel);
            unsafe { release_mutant(mutex); }
        }
        if (i & 31) == 0 {
            unsafe { yield_exec(); }
        }
        i += 1;
    }
    MUTEX_STRESS_DONE.fetch_add(1, Ordering::AcqRel);
    unsafe { exit_thread() }
}

extern "C" fn thread_destroy_waiter(_arg: u64) -> ! {
    let h = DESTROY_WAIT_HANDLE.load(Ordering::Acquire) as u64;
    let st = unsafe { wait_single(h) };
    DESTROY_WAIT_STATUS.store(st as u32, Ordering::Release);
    DESTROY_WAIT_DONE.store(1, Ordering::Release);
    unsafe { exit_thread() }
}

// ── Tests ───────────────────────────────────────────────────

unsafe fn wait_flag_with_yield(flag: &AtomicU32, max_iters: u32) -> bool {
    for _ in 0..max_iters {
        if flag.load(Ordering::Acquire) != 0 {
            return true;
        }
        yield_exec();
    }
    false
}

unsafe fn wait_counter_at_least(counter: &AtomicU32, target: u32, max_iters: u32) -> bool {
    for _ in 0..max_iters {
        if counter.load(Ordering::Acquire) >= target {
            return true;
        }
        yield_exec();
    }
    false
}

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

unsafe fn test_set_event_wake_preemption() {
    print(b"== SetEvent Wake Preemption ==\r\n");

    SET_EVENT_PREEMPT_READY.store(0, Ordering::Relaxed);
    SET_EVENT_PREEMPT_WOKE.store(0, Ordering::Relaxed);

    let (st_target, target) = create_event(false, false);
    check(b"Create preempt target event", st_target == STATUS_SUCCESS && target != 0);
    SET_EVENT_PREEMPT_TARGET.store(target as u32, Ordering::Release);

    let (st_waiter, h_waiter) = create_thread(
        thread_set_event_preempt_waiter as *const () as u64,
        0,
        0x10000,
    );
    check(
        b"Create preempt waiter thread",
        st_waiter == STATUS_SUCCESS && h_waiter != 0,
    );

    let st_prio_waiter = set_thread_priority(h_waiter, 20);
    check(b"Set preempt waiter priority", st_prio_waiter == STATUS_SUCCESS);

    let waiter_ready = wait_flag_with_yield(&SET_EVENT_PREEMPT_READY, 20_000);
    check(b"Preempt waiter reached wait site", waiter_ready);
    for _ in 0..64u32 {
        yield_exec();
    }

    let st_set = set_event(target);
    check(b"SetEvent returns SUCCESS", st_set == STATUS_SUCCESS);
    let woke_immediately = SET_EVENT_PREEMPT_WOKE.load(Ordering::Acquire) != 0;
    check(b"SetEvent caller yields to waiter before return", woke_immediately);

    let waiter_woke = wait_flag_with_yield(&SET_EVENT_PREEMPT_WOKE, 20_000);
    check(b"Preempt waiter thread woke", waiter_woke);

    close(h_waiter);
    close(target);
}

unsafe fn test_wait_timeout_edges() {
    print(b"== NtWait Timeout Edge Cases ==\r\n");

    let (st_unsig, ev_unsig) = create_event(false, false);
    let (st_sig, ev_sig) = create_event(true, true);
    check(
        b"Create unsignaled timeout event",
        st_unsig == STATUS_SUCCESS && ev_unsig != 0,
    );
    check(
        b"Create signaled timeout event",
        st_sig == STATUS_SUCCESS && ev_sig != 0,
    );

    let st_single_imm_to = wait_single_timeout_rel(ev_unsig, 0);
    check(
        b"NtWaitForSingleObject immediate timeout on unsignaled event",
        st_single_imm_to == STATUS_TIMEOUT,
    );
    let st_single_imm_ok = wait_single_timeout_rel(ev_sig, 0);
    check(
        b"NtWaitForSingleObject immediate succeeds on signaled event",
        st_single_imm_ok == STATUS_SUCCESS,
    );

    let handles_any_timeout = [ev_unsig, ev_unsig];
    let st_multi_any_to = wait_multiple_timeout_rel(&handles_any_timeout, false, 0);
    check(
        b"NtWaitForMultipleObjects(Any) immediate timeout on unsignaled set",
        st_multi_any_to == STATUS_TIMEOUT,
    );

    let handles_any_hit = [ev_unsig, ev_sig];
    let st_multi_any_hit = wait_multiple_timeout_rel(&handles_any_hit, false, 0);
    check(
        b"NtWaitForMultipleObjects(Any) returns signaled index",
        st_multi_any_hit == STATUS_SUCCESS + 1,
    );

    let st_single_rel_to = wait_single_timeout_rel(ev_unsig, -30_000);
    check(
        b"NtWaitForSingleObject relative timeout returns TIMEOUT",
        st_single_rel_to == STATUS_TIMEOUT,
    );
    let st_multi_rel_to = wait_multiple_timeout_rel(&handles_any_timeout, false, -30_000);
    check(
        b"NtWaitForMultipleObjects(Any) relative timeout returns TIMEOUT",
        st_multi_rel_to == STATUS_TIMEOUT,
    );

    close(ev_sig);
    close(ev_unsig);
}

unsafe fn test_wait_timeout_interrupt_wake() {
    print(b"== Wait Timeout (Timer IRQ) ==\r\n");

    TIMEOUT_DONE.store(0, Ordering::Relaxed);
    TIMEOUT_STATUS.store(0, Ordering::Relaxed);

    // Create auto-reset event, initially non-signaled.
    let (st_ev, ev) = create_event(false, false);
    check(b"Create event for timeout wait", st_ev == STATUS_SUCCESS);
    TIMEOUT_EVENT.store(ev as u32, Ordering::Release);

    let (st_t, h_t) = create_thread(thread_timeout_wait as *const () as u64, 0, 0x10000);
    check(b"Create timeout waiter thread", st_t == STATUS_SUCCESS);

    let done = wait_flag_with_yield(&TIMEOUT_DONE, 10_000);
    check(b"Timeout waiter thread completed", done);
    if done {
        let st = TIMEOUT_STATUS.load(Ordering::Acquire) as u64;
        check(b"NtWaitForSingleObject times out", st == STATUS_TIMEOUT);
    } else {
        check(b"NtWaitForSingleObject times out", false);
    }

    close(h_t);
    close(ev);
}

unsafe fn test_timer_preemption_without_yield() {
    print(b"== Timer Preemption (No Yield) ==\r\n");

    COUNTER_A.store(0, Ordering::Relaxed);
    COUNTER_B.store(0, Ordering::Relaxed);
    DONE_A.store(0, Ordering::Relaxed);
    DONE_B.store(0, Ordering::Relaxed);
    PREEMPT_SEEN.store(0, Ordering::Relaxed);
    PREEMPT_FLAG.store(0, Ordering::Relaxed);

    let (st_a, h_a) = create_thread(thread_preempt_a as *const () as u64, 0, 0x10000);
    let (st_b, h_b) = create_thread(thread_preempt_b as *const () as u64, 0, 0x10000);
    check(b"Create preempt thread A", st_a == STATUS_SUCCESS);
    check(b"Create preempt thread B", st_b == STATUS_SUCCESS);

    let a_done = wait_flag_with_yield(&DONE_A, 20_000);
    let b_done = wait_flag_with_yield(&DONE_B, 20_000);
    check(b"preempt thread A completed", a_done);
    check(b"preempt thread B completed", b_done);
    check(
        b"thread A observed thread B before exit (requires timer preemption)",
        PREEMPT_SEEN.load(Ordering::Acquire) != 0,
    );

    close(h_a);
    close(h_b);
}

unsafe fn test_mutex_priority_inheritance() {
    print(b"== Mutex Priority Inheritance ==\r\n");

    COUNTER_A.store(0, Ordering::Relaxed);
    COUNTER_B.store(0, Ordering::Relaxed);
    LOW_HAS_MUTEX.store(0, Ordering::Relaxed);
    LOW_DONE.store(0, Ordering::Relaxed);
    HIGH_DONE.store(0, Ordering::Relaxed);
    MED_DONE.store(0, Ordering::Relaxed);
    HIGH_BEFORE_MED_DONE.store(0, Ordering::Relaxed);

    let (st_low_go, low_go) = create_event(false, false);
    let (st_high_go, high_go) = create_event(false, false);
    let (st_med_go, med_go) = create_event(false, false);
    check(b"Create low-go event", st_low_go == STATUS_SUCCESS);
    check(b"Create high-go event", st_high_go == STATUS_SUCCESS);
    check(b"Create med-go event", st_med_go == STATUS_SUCCESS);

    let (st_mutex, mutex) = create_mutex(false);
    check(b"Create mutex", st_mutex == STATUS_SUCCESS);
    TEST_MUTEX.store(mutex as u32, Ordering::Release);
    LOW_GO_EVENT.store(low_go as u32, Ordering::Release);
    HIGH_GO_EVENT.store(high_go as u32, Ordering::Release);
    MED_GO_EVENT.store(med_go as u32, Ordering::Release);

    let (st_low, h_low) = create_thread(thread_pi_low as *const () as u64, 0, 0x10000);
    let (st_med, h_med) = create_thread(thread_pi_medium as *const () as u64, 0, 0x10000);
    let (st_high, h_high) = create_thread(thread_pi_high as *const () as u64, 0, 0x10000);
    check(b"Create low thread", st_low == STATUS_SUCCESS);
    check(b"Create medium thread", st_med == STATUS_SUCCESS);
    check(b"Create high thread", st_high == STATUS_SUCCESS);

    let st_prio_low = set_thread_priority(h_low, 8);
    let st_prio_med = set_thread_priority(h_med, 12);
    let st_prio_high = set_thread_priority(h_high, 20);
    check(b"Set low thread priority", st_prio_low == STATUS_SUCCESS);
    check(b"Set medium thread priority", st_prio_med == STATUS_SUCCESS);
    check(b"Set high thread priority", st_prio_high == STATUS_SUCCESS);

    set_event(low_go);
    let low_has_mutex = wait_flag_with_yield(&LOW_HAS_MUTEX, 20_000);
    check(b"Low thread acquired mutex first", low_has_mutex);

    set_event(high_go);
    for _ in 0..20u32 {
        yield_exec();
    }

    set_event(med_go);

    let high_done = wait_flag_with_yield(&HIGH_DONE, 20_000);
    let med_done = wait_flag_with_yield(&MED_DONE, 20_000);
    let low_done = wait_flag_with_yield(&LOW_DONE, 20_000);
    check(b"High thread completed", high_done);
    check(b"Medium thread completed", med_done);
    check(b"Low thread completed", low_done);
    check(
        b"High acquired mutex before medium completed (priority inheritance)",
        HIGH_BEFORE_MED_DONE.load(Ordering::Acquire) != 0,
    );

    close(h_low);
    close(h_med);
    close(h_high);
    close(mutex);
    close(low_go);
    close(high_go);
    close(med_go);
}

unsafe fn test_wait_wake_burst() {
    print(b"== Wait/Wake Burst ==\r\n");

    BURST_DONE.store(0, Ordering::Relaxed);
    let (st_ev, ev) = create_event(true, false);
    check(b"Create burst event", st_ev == STATUS_SUCCESS);
    BURST_EVENT.store(ev as u32, Ordering::Release);

    let mut handles = [0u64; BURST_WAITERS];
    let mut ok_create = true;
    let mut i = 0usize;
    while i < BURST_WAITERS {
        let (st, h) = create_thread(thread_burst_waiter as *const () as u64, 0, 0x10000);
        if st != STATUS_SUCCESS || h == 0 {
            ok_create = false;
        }
        handles[i] = h;
        i += 1;
    }
    check(b"Burst waiter threads created", ok_create);

    for _ in 0..64u32 {
        yield_exec();
    }

    let st_set = set_event(ev);
    check(b"Set burst event", st_set == STATUS_SUCCESS);
    let all_done = wait_flag_with_yield(&BURST_DONE, 40_000);
    check(
        b"All burst waiters woke",
        all_done && BURST_DONE.load(Ordering::Acquire) == BURST_WAITERS as u32,
    );

    let _ = handles;
}

unsafe fn test_cpu_contention_fairness() {
    print(b"== CPU Contention Fairness ==\r\n");

    FAIR_STOP.store(0, Ordering::Relaxed);
    FAIR_DONE.store(0, Ordering::Relaxed);
    for i in 0..FAIR_WORKERS {
        FAIR_COUNTERS[i].store(0, Ordering::Relaxed);
    }

    let (st_ev, ev) = create_event(true, false);
    check(b"Create fairness start event", st_ev == STATUS_SUCCESS);
    FAIR_START_EVENT.store(ev as u32, Ordering::Release);

    let mut ok_create = true;
    for i in 0..FAIR_WORKERS {
        let (st, h) = create_thread(thread_fair_worker as *const () as u64, i as u64, 0x10000);
        if st != STATUS_SUCCESS || h == 0 {
            ok_create = false;
        }
    }
    check(b"Fairness workers created", ok_create);

    let st_set = set_event(ev);
    check(b"Start fairness workers", st_set == STATUS_SUCCESS);
    for _ in 0..4_000u32 {
        yield_exec();
    }
    FAIR_STOP.store(1, Ordering::Release);

    let done = wait_counter_at_least(&FAIR_DONE, FAIR_WORKERS as u32, 200_000);
    check(b"Fairness workers completed", done);

    let mut all_progress = true;
    let mut min = u32::MAX;
    let mut max = 0u32;
    for i in 0..FAIR_WORKERS {
        let v = FAIR_COUNTERS[i].load(Ordering::Acquire);
        if v == 0 {
            all_progress = false;
        }
        if v < min {
            min = v;
        }
        if v > max {
            max = v;
        }
    }
    check(b"All fairness workers made progress", all_progress);
    let bounded_skew = min > 0 && max / min < 200;
    check(b"Fairness skew is bounded", bounded_skew);
}

unsafe fn test_timeout_storm() {
    print(b"== Timeout Storm ==\r\n");

    TIMEOUT_STORM_DONE.store(0, Ordering::Relaxed);
    TIMEOUT_STORM_TIMEOUTS.store(0, Ordering::Relaxed);
    let (st_ev, ev) = create_event(false, false);
    check(b"Create timeout storm event", st_ev == STATUS_SUCCESS);
    TIMEOUT_STORM_EVENT.store(ev as u32, Ordering::Release);

    let mut ok_create = true;
    for _ in 0..TIMEOUT_STORM_THREADS {
        let (st, h) = create_thread(thread_timeout_storm_waiter as *const () as u64, 0, 0x10000);
        if st != STATUS_SUCCESS || h == 0 {
            ok_create = false;
        }
    }
    check(b"Timeout storm waiters created", ok_create);

    let done = wait_counter_at_least(&TIMEOUT_STORM_DONE, TIMEOUT_STORM_THREADS as u32, 220_000);
    check(b"Timeout storm waiters completed", done);
    check(
        b"Timeout storm all timed out",
        done && TIMEOUT_STORM_TIMEOUTS.load(Ordering::Acquire) == TIMEOUT_STORM_THREADS as u32,
    );
}

unsafe fn test_mutex_contention_stress() {
    print(b"== Mutex Contention Stress ==\r\n");

    MUTEX_STRESS_DONE.store(0, Ordering::Relaxed);
    MUTEX_STRESS_COUNTER.store(0, Ordering::Relaxed);
    let (st_start, start_ev) = create_event(true, false);
    let (st_mutex, mutex) = create_mutex(false);
    check(b"Create mutex stress start event", st_start == STATUS_SUCCESS);
    check(b"Create mutex stress mutex", st_mutex == STATUS_SUCCESS);
    MUTEX_STRESS_START.store(start_ev as u32, Ordering::Release);
    MUTEX_STRESS_HANDLE.store(mutex as u32, Ordering::Release);

    let mut ok_create = true;
    for _ in 0..MUTEX_STRESS_THREADS {
        let (st, h) = create_thread(thread_mutex_stress as *const () as u64, 0, 0x10000);
        if st != STATUS_SUCCESS || h == 0 {
            ok_create = false;
        }
    }
    check(b"Mutex stress workers created", ok_create);

    let st_set = set_event(start_ev);
    check(b"Start mutex stress workers", st_set == STATUS_SUCCESS);
    let done = wait_counter_at_least(&MUTEX_STRESS_DONE, MUTEX_STRESS_THREADS as u32, 220_000);
    check(b"Mutex stress workers completed", done);
    let expected = (MUTEX_STRESS_THREADS as u32) * MUTEX_STRESS_ITERS;
    let actual = MUTEX_STRESS_COUNTER.load(Ordering::Acquire);
    check(b"Mutex stress protected counter exact", done && actual == expected);
}

unsafe fn test_waiter_woken_by_event_destroy() {
    print(b"== Waiter Wake On Event Destroy ==\r\n");

    DESTROY_WAIT_DONE.store(0, Ordering::Relaxed);
    DESTROY_WAIT_STATUS.store(0, Ordering::Relaxed);

    let (st_ev, ev) = create_event(false, false);
    check(b"Create event for destroy wake", st_ev == STATUS_SUCCESS && ev != 0);
    DESTROY_WAIT_HANDLE.store(ev as u32, Ordering::Release);

    let (st_t, h_t) = create_thread(thread_destroy_waiter as *const () as u64, 0, 0x10000);
    check(b"Create destroy waiter thread (event)", st_t == STATUS_SUCCESS && h_t != 0);

    for _ in 0..64u32 {
        yield_exec();
    }
    let st_close = close(ev);
    check(b"Close waited event returns SUCCESS", st_close == STATUS_SUCCESS);

    let done = wait_flag_with_yield(&DESTROY_WAIT_DONE, 20_000);
    check(b"Destroy waiter thread completed (event)", done);
    if done {
        let st = DESTROY_WAIT_STATUS.load(Ordering::Acquire) as u64;
        check(
            b"Waiter returns STATUS_INVALID_HANDLE after event destroy",
            st == STATUS_INVALID_HANDLE,
        );
    }

    close(h_t);
}

unsafe fn test_waiter_woken_by_mutex_destroy() {
    print(b"== Waiter Wake On Mutex Destroy ==\r\n");

    DESTROY_WAIT_DONE.store(0, Ordering::Relaxed);
    DESTROY_WAIT_STATUS.store(0, Ordering::Relaxed);

    // Main thread owns mutex so waiter must block.
    let (st_mx, mutex) = create_mutex(true);
    check(
        b"Create owned mutex for destroy wake",
        st_mx == STATUS_SUCCESS && mutex != 0,
    );
    DESTROY_WAIT_HANDLE.store(mutex as u32, Ordering::Release);

    let (st_t, h_t) = create_thread(thread_destroy_waiter as *const () as u64, 0, 0x10000);
    check(b"Create destroy waiter thread (mutex)", st_t == STATUS_SUCCESS && h_t != 0);

    for _ in 0..64u32 {
        yield_exec();
    }
    let st_close = close(mutex);
    check(b"Close waited mutex returns SUCCESS", st_close == STATUS_SUCCESS);

    let done = wait_flag_with_yield(&DESTROY_WAIT_DONE, 20_000);
    check(b"Destroy waiter thread completed (mutex)", done);
    if done {
        let st = DESTROY_WAIT_STATUS.load(Ordering::Acquire) as u64;
        check(
            b"Waiter returns STATUS_INVALID_HANDLE after mutex destroy",
            st == STATUS_INVALID_HANDLE,
        );
    }

    close(h_t);
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

        test_set_event_wake_preemption();
        print(b"\r\n");

        test_wait_timeout_edges();
        print(b"\r\n");

        test_wait_timeout_interrupt_wake();
        print(b"\r\n");

        test_timer_preemption_without_yield();
        print(b"\r\n");

        test_mutex_priority_inheritance();
        print(b"\r\n");

        test_wait_wake_burst();
        print(b"\r\n");

        test_cpu_contention_fairness();
        print(b"\r\n");

        test_timeout_storm();
        print(b"\r\n");

        test_mutex_contention_stress();
        print(b"\r\n");

        test_waiter_woken_by_event_destroy();
        print(b"\r\n");

        test_waiter_woken_by_mutex_destroy();
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
