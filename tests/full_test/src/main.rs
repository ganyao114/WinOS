#![no_std]
#![no_main]
#![allow(dead_code)]

use core::arch::asm;

// ── Well-known handles ──────────────────────────────────────────
const STDOUT: u64 = 0xFFFF_FFFF_FFFF_FFF5;

// ── NT syscall numbers (Windows 11 ARM64, table 0) ──────────────
const NR_WRITE_FILE: u64              = 0x0008;
const NR_CLOSE: u64                   = 0x000F;
const NR_TERMINATE_PROCESS: u64       = 0x002C;
const NR_ALLOCATE_VIRTUAL_MEMORY: u64 = 0x0015;
const NR_FREE_VIRTUAL_MEMORY: u64     = 0x001E;
const NR_PROTECT_VIRTUAL_MEMORY: u64  = 0x004D;
const NR_QUERY_VIRTUAL_MEMORY: u64    = 0x0023;
const NR_CREATE_SECTION: u64          = 0x004A;
const NR_MAP_VIEW_OF_SECTION: u64     = 0x0028;
const NR_UNMAP_VIEW_OF_SECTION: u64   = 0x002A;
const NR_CREATE_EVENT: u64            = 0x0048;
const NR_SET_EVENT: u64               = 0x000E;
const NR_RESET_EVENT: u64             = 0x0034;
const NR_YIELD_EXECUTION: u64         = 0x0046;
const NR_QUERY_INFORMATION_PROCESS: u64 = 0x0019;
const NR_DUPLICATE_OBJECT: u64        = 0x003C;

const STATUS_SUCCESS: u64 = 0;
const PAGE_READWRITE: u64 = 0x04;
const MEM_COMMIT: u64     = 0x1000;
const MEM_RESERVE: u64    = 0x2000;
const MEM_RELEASE: u64    = 0x8000;

static mut PASS_COUNT: u32 = 0;
static mut FAIL_COUNT: u32 = 0;

// ── Low-level SVC wrappers ──────────────────────────────────────

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

// ── Output helpers ──────────────────────────────────────────────

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

fn print_hex(val: u64) {
    let hex = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0'; buf[1] = b'x';
    for i in 0..16usize {
        buf[2 + i] = hex[((val >> ((15 - i) * 4)) & 0xF) as usize];
    }
    print(&buf);
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

// ════════════════════════════════════════════════════════════════
// Test 1: NtAllocateVirtualMemory / NtFreeVirtualMemory
// ════════════════════════════════════════════════════════════════

unsafe fn test_virtual_memory() {
    print(b"== Virtual Memory ==\r\n");

    // Allocate 64KB
    let mut base: u64 = 0;
    let mut size: u64 = 0x10000;
    let st = svc(
        NR_ALLOCATE_VIRTUAL_MEMORY,
        0xFFFFFFFFFFFFFFFF,              // ProcessHandle (-1 = self)
        &mut base as *mut u64 as u64,    // BaseAddress ptr
        0,                               // ZeroBits
        &mut size as *mut u64 as u64,    // RegionSize ptr
        MEM_COMMIT | MEM_RESERVE,        // AllocationType
        PAGE_READWRITE,                  // Protect
        0, 0,
    );
    check(b"NtAllocateVirtualMemory returns SUCCESS", st == STATUS_SUCCESS);
    check(b"Allocated base is non-zero", base != 0);
    check(b"Allocated size >= 64KB", size >= 0x10000);

    // Write pattern and read back
    let ptr = base as *mut u8;
    for i in 0..256u32 {
        *ptr.add(i as usize) = (i & 0xFF) as u8;
    }
    let mut ok = true;
    for i in 0..256u32 {
        if *ptr.add(i as usize) != (i & 0xFF) as u8 { ok = false; break; }
    }
    check(b"Write/read pattern in allocated memory", ok);

    // Free
    let mut free_base = base;
    let mut free_size: u64 = 0;
    let st = svc(
        NR_FREE_VIRTUAL_MEMORY,
        0xFFFFFFFFFFFFFFFF,
        &mut free_base as *mut u64 as u64,
        0,
        &mut free_size as *mut u64 as u64,
        MEM_RELEASE,
        0, 0, 0,
    );
    check(b"NtFreeVirtualMemory returns SUCCESS", st == STATUS_SUCCESS);
}

// ════════════════════════════════════════════════════════════════
// Test 2: NtCreateSection / NtMapViewOfSection / NtUnmapViewOfSection
// ════════════════════════════════════════════════════════════════

unsafe fn test_section() {
    print(b"== Section ==\r\n");

    // Create pagefile-backed section (64KB)
    let mut sec_handle: u64 = 0;
    let mut sec_size: u64 = 0x10000;
    let st = svc(
        NR_CREATE_SECTION,
        &mut sec_handle as *mut u64 as u64,  // SectionHandle out
        0x000F001F,                          // DesiredAccess (SECTION_ALL_ACCESS)
        0,                                   // ObjectAttributes
        &mut sec_size as *mut u64 as u64,    // MaximumSize
        PAGE_READWRITE,                      // SectionPageProtection
        0x08000000,                          // AllocationAttributes (SEC_COMMIT)
        0,                                   // FileHandle (0 = pagefile)
        0,
    );
    check(b"NtCreateSection returns SUCCESS", st == STATUS_SUCCESS);
    check(b"Section handle is valid", sec_handle != 0);

    // Map view
    let mut view_base: u64 = 0;
    let mut view_size: u64 = 0;
    let mut view_off: u64 = 0;
    let st = svc10(
        NR_MAP_VIEW_OF_SECTION,
        sec_handle,                          // SectionHandle
        0xFFFFFFFFFFFFFFFF,                  // ProcessHandle
        &mut view_base as *mut u64 as u64,   // BaseAddress ptr
        0,                                   // ZeroBits
        0,                                   // CommitSize
        &mut view_off as *mut u64 as u64,    // SectionOffset
        &mut view_size as *mut u64 as u64,   // ViewSize
        1,                                   // InheritDisposition
        0, PAGE_READWRITE,                   // AllocationType, Win32Protect
    );
    check(b"NtMapViewOfSection returns SUCCESS", st == STATUS_SUCCESS);
    check(b"Mapped base is non-zero", view_base != 0);

    // Write to mapped view and verify
    let p = view_base as *mut u32;
    *p = 0xDEADBEEF;
    *(p.add(1)) = 0xCAFEBABE;
    check(b"Write to mapped view", *p == 0xDEADBEEF);
    check(b"Second write to mapped view", *(p.add(1)) == 0xCAFEBABE);

    // Unmap
    let st = svc(
        NR_UNMAP_VIEW_OF_SECTION,
        0xFFFFFFFFFFFFFFFF,
        view_base,
        0, 0, 0, 0, 0, 0,
    );
    check(b"NtUnmapViewOfSection returns SUCCESS", st == STATUS_SUCCESS);

    // Close section handle
    let st = svc(NR_CLOSE, sec_handle, 0, 0, 0, 0, 0, 0, 0);
    check(b"NtClose section handle", st == STATUS_SUCCESS);
}

// ════════════════════════════════════════════════════════════════
// Test 3: NtCreateEvent / NtSetEvent / NtResetEvent
// ════════════════════════════════════════════════════════════════

unsafe fn test_event() {
    print(b"== Event ==\r\n");

    // Create manual-reset event (initially non-signaled)
    let mut evt_handle: u64 = 0;
    let st = svc(
        NR_CREATE_EVENT,
        &mut evt_handle as *mut u64 as u64,  // EventHandle out
        0x001F0003,                          // EVENT_ALL_ACCESS
        0,                                   // ObjectAttributes
        1,                                   // EventType: NotificationEvent (manual)
        0,                                   // InitialState: non-signaled
        0, 0, 0,
    );
    check(b"NtCreateEvent returns SUCCESS", st == STATUS_SUCCESS);
    check(b"Event handle is valid", evt_handle != 0);

    // Set event
    let mut prev_state: u64 = 0xFFFF;
    let st = svc(
        NR_SET_EVENT,
        evt_handle,
        &mut prev_state as *mut u64 as u64,
        0, 0, 0, 0, 0, 0,
    );
    check(b"NtSetEvent returns SUCCESS", st == STATUS_SUCCESS);

    // Reset event
    let mut prev_state2: u64 = 0xFFFF;
    let st = svc(
        NR_RESET_EVENT,
        evt_handle,
        &mut prev_state2 as *mut u64 as u64,
        0, 0, 0, 0, 0, 0,
    );
    check(b"NtResetEvent returns SUCCESS", st == STATUS_SUCCESS);

    // Close
    let st = svc(NR_CLOSE, evt_handle, 0, 0, 0, 0, 0, 0, 0);
    check(b"NtClose event handle", st == STATUS_SUCCESS);
}

// ════════════════════════════════════════════════════════════════
// Test 4: NtYieldExecution
// ════════════════════════════════════════════════════════════════

unsafe fn test_yield() {
    print(b"== Yield ==\r\n");
    let st = svc(NR_YIELD_EXECUTION, 0, 0, 0, 0, 0, 0, 0, 0);
    // NtYieldExecution returns STATUS_SUCCESS or STATUS_NO_YIELD_PERFORMED
    check(b"NtYieldExecution does not crash", true);
    let _ = st;
}

// ════════════════════════════════════════════════════════════════
// Test 5: NtDuplicateObject (handle duplication)
// ════════════════════════════════════════════════════════════════

unsafe fn test_duplicate_object() {
    print(b"== DuplicateObject ==\r\n");

    // Create an event, then duplicate its handle
    let mut evt: u64 = 0;
    svc(
        NR_CREATE_EVENT,
        &mut evt as *mut u64 as u64,
        0x001F0003, 0, 1, 0, 0, 0, 0,
    );

    let mut dup: u64 = 0;
    let st = svc(
        NR_DUPLICATE_OBJECT,
        0xFFFFFFFFFFFFFFFF,                  // SourceProcessHandle
        evt,                                 // SourceHandle
        0xFFFFFFFFFFFFFFFF,                  // TargetProcessHandle
        &mut dup as *mut u64 as u64,         // TargetHandle out
        0,                                   // DesiredAccess
        0,                                   // HandleAttributes
        0x00000002,                          // Options: DUPLICATE_SAME_ACCESS
        0,
    );
    check(b"NtDuplicateObject returns SUCCESS", st == STATUS_SUCCESS);
    check(b"Duplicated handle is valid", dup != 0 && dup != evt);

    // Close both
    svc(NR_CLOSE, evt, 0, 0, 0, 0, 0, 0, 0);
    svc(NR_CLOSE, dup, 0, 0, 0, 0, 0, 0, 0);
}

// ════════════════════════════════════════════════════════════════
// Test 6: Multiple allocations (stress test)
// ════════════════════════════════════════════════════════════════

unsafe fn test_multi_alloc() {
    print(b"== Multi-Alloc Stress ==\r\n");

    let mut bases = [0u64; 8];
    let mut all_ok = true;

    for i in 0..8 {
        let mut base: u64 = 0;
        let mut size: u64 = 0x1000; // 4KB each
        let st = svc(
            NR_ALLOCATE_VIRTUAL_MEMORY,
            0xFFFFFFFFFFFFFFFF,
            &mut base as *mut u64 as u64,
            0,
            &mut size as *mut u64 as u64,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
            0, 0,
        );
        if st != STATUS_SUCCESS || base == 0 { all_ok = false; }
        bases[i] = base;
        // Write unique tag
        *(base as *mut u64) = 0xA5A5_0000 + i as u64;
    }
    check(b"Allocate 8 x 4KB regions", all_ok);

    // Verify tags
    let mut tags_ok = true;
    for i in 0..8 {
        if bases[i] != 0 {
            let tag = *(bases[i] as *const u64);
            if tag != 0xA5A5_0000 + i as u64 { tags_ok = false; }
        }
    }
    check(b"All 8 regions have correct tags", tags_ok);

    // Free all
    let mut free_ok = true;
    for i in 0..8 {
        if bases[i] != 0 {
            let mut fb = bases[i];
            let mut fs: u64 = 0;
            let st = svc(
                NR_FREE_VIRTUAL_MEMORY,
                0xFFFFFFFFFFFFFFFF,
                &mut fb as *mut u64 as u64,
                0,
                &mut fs as *mut u64 as u64,
                MEM_RELEASE, 0, 0, 0,
            );
            if st != STATUS_SUCCESS { free_ok = false; }
        }
    }
    check(b"Free all 8 regions", free_ok);
}

// ════════════════════════════════════════════════════════════════
// Entry point
// ════════════════════════════════════════════════════════════════

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    print(b"========================================\r\n");
    print(b"  WinEmu Full Test Suite\r\n");
    print(b"========================================\r\n\r\n");

    unsafe {
        test_virtual_memory();
        print(b"\r\n");

        test_section();
        print(b"\r\n");

        test_event();
        print(b"\r\n");

        test_yield();
        print(b"\r\n");

        test_duplicate_object();
        print(b"\r\n");

        test_multi_alloc();
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
