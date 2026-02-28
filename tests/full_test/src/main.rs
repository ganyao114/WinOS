#![no_std]
#![no_main]
#![allow(dead_code)]

use core::arch::asm;

// ── Well-known handles ──────────────────────────────────────────
const STDOUT: u64 = 0xFFFF_FFFF_FFFF_FFF5;

// ── NT syscall numbers (Windows 11 ARM64, table 0) ──────────────
const NR_WRITE_FILE: u64 = 0x0008;
const NR_CLOSE: u64 = 0x000F;
const NR_TERMINATE_PROCESS: u64 = 0x002C;
const NR_ALLOCATE_VIRTUAL_MEMORY: u64 = 0x0015;
const NR_FREE_VIRTUAL_MEMORY: u64 = 0x001E;
const NR_PROTECT_VIRTUAL_MEMORY: u64 = 0x004D;
const NR_QUERY_VIRTUAL_MEMORY: u64 = 0x0023;
const NR_CREATE_SECTION: u64 = 0x004A;
const NR_MAP_VIEW_OF_SECTION: u64 = 0x0028;
const NR_UNMAP_VIEW_OF_SECTION: u64 = 0x002A;
const NR_CREATE_EVENT: u64 = 0x0048;
const NR_SET_EVENT: u64 = 0x000E;
const NR_RESET_EVENT: u64 = 0x0034;
const NR_YIELD_EXECUTION: u64 = 0x0046;
const NR_QUERY_INFORMATION_PROCESS: u64 = 0x0019;
const NR_DUPLICATE_OBJECT: u64 = 0x003C;

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xC000000D;
const PAGE_READWRITE: u64 = 0x04;
const PAGE_WRITECOPY: u64 = 0x08;
const PAGE_READONLY: u64 = 0x02;
const PAGE_EXECUTE_READ: u64 = 0x20;
const PAGE_EXECUTE_READWRITE: u64 = 0x40;
const MEM_COMMIT: u64 = 0x1000;
const MEM_RESERVE: u64 = 0x2000;
const MEM_DECOMMIT: u64 = 0x4000;
const MEM_RELEASE: u64 = 0x8000;
const SEC_COMMIT: u64 = 0x08000000;
const SEC_IMAGE: u64 = 0x01000000;

static mut PASS_COUNT: u32 = 0;
static mut FAIL_COUNT: u32 = 0;

// ── Low-level SVC wrappers ──────────────────────────────────────

#[inline(always)]
unsafe fn svc(
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
) -> u64 {
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
unsafe fn svc10(
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    s0: u64,
    s1: u64,
) -> u64 {
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
struct IoStatusBlock {
    status: u64,
    info: u64,
}

unsafe fn nt_write_stdout(buf: *const u8, len: u32) -> u64 {
    let mut iosb = IoStatusBlock { status: 0, info: 0 };
    svc10(
        NR_WRITE_FILE,
        STDOUT,
        0,
        0,
        0,
        &mut iosb as *mut _ as u64,
        buf as u64,
        len as u64,
        0,
        0,
        0,
    )
}

fn print(s: &[u8]) {
    unsafe {
        nt_write_stdout(s.as_ptr(), s.len() as u32);
    }
}

fn print_hex(val: u64) {
    let hex = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16usize {
        buf[2 + i] = hex[((val >> ((15 - i) * 4)) & 0xF) as usize];
    }
    print(&buf);
}

fn print_u32(val: u32) {
    let mut buf = [0u8; 10];
    let mut n = val;
    let mut len = 0usize;
    if n == 0 {
        buf[0] = b'0';
        len = 1;
    } else {
        while n > 0 {
            buf[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
        buf[..len].reverse();
    }
    print(&buf[..len]);
}

unsafe fn check(name: &[u8], ok: bool) {
    if ok {
        print(b"  [PASS] ");
        PASS_COUNT += 1;
    } else {
        print(b"  [FAIL] ");
        FAIL_COUNT += 1;
    }
    print(name);
    print(b"\r\n");
}

unsafe fn exit(code: u32) -> ! {
    svc(
        NR_TERMINATE_PROCESS,
        0xFFFFFFFFFFFFFFFF,
        code as u64,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    loop {
        asm!("wfi", options(nostack));
    }
}

#[inline(always)]
unsafe fn nt_query_virtual(addr: u64, out: &mut [u8; 48]) -> u64 {
    let mut ret_len: u64 = 0;
    svc(
        NR_QUERY_VIRTUAL_MEMORY,
        0xFFFF_FFFF_FFFF_FFFF,
        addr,
        0,
        out.as_mut_ptr() as u64,
        out.len() as u64,
        &mut ret_len as *mut u64 as u64,
        0,
        0,
    )
}

fn rd_u32(buf: &[u8], off: usize) -> u32 {
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&buf[off..off + 4]);
    u32::from_le_bytes(tmp)
}

// ════════════════════════════════════════════════════════════════
// Test 1: NtAllocateVirtualMemory / NtFreeVirtualMemory
// ════════════════════════════════════════════════════════════════

unsafe fn test_virtual_memory() {
    print(b"== Virtual Memory ==\r\n");

    // Reserve 64KB only
    let mut base: u64 = 0;
    let mut size: u64 = 0x10000;
    let st = svc(
        NR_ALLOCATE_VIRTUAL_MEMORY,
        0xFFFFFFFFFFFFFFFF,           // ProcessHandle (-1 = self)
        &mut base as *mut u64 as u64, // BaseAddress ptr
        0,                            // ZeroBits
        &mut size as *mut u64 as u64, // RegionSize ptr
        MEM_RESERVE,                  // AllocationType
        PAGE_READWRITE,               // Protect
        0,
        0,
    );
    check(
        b"NtAllocateVirtualMemory reserve returns SUCCESS",
        st == STATUS_SUCCESS,
    );
    check(b"Allocated base is non-zero", base != 0);
    check(b"Allocated size >= 64KB", size >= 0x10000);

    let mut mbi = [0u8; 48];
    let st = nt_query_virtual(base, &mut mbi);
    check(
        b"NtQueryVirtualMemory on reserved page returns SUCCESS",
        st == STATUS_SUCCESS,
    );
    check(
        b"Reserved page reports MEM_RESERVE",
        rd_u32(&mbi, 32) as u64 == MEM_RESERVE,
    );

    // Commit 8KB from reserved region
    let mut commit_base = base;
    let mut commit_size: u64 = 0x2000;
    let st = svc(
        NR_ALLOCATE_VIRTUAL_MEMORY,
        0xFFFFFFFFFFFFFFFF,
        &mut commit_base as *mut u64 as u64,
        0,
        &mut commit_size as *mut u64 as u64,
        MEM_COMMIT,
        PAGE_READWRITE,
        0,
        0,
    );
    check(
        b"NtAllocateVirtualMemory commit-in-reserve returns SUCCESS",
        st == STATUS_SUCCESS,
    );

    // First touch should fault-in pages, then read back
    let p0 = base as *mut u64;
    let p1 = (base + 0x1000) as *mut u64;
    *p0 = 0x1122_3344_5566_7788;
    *p1 = 0x8877_6655_4433_2211;
    check(
        b"Write/read pattern in committed pages",
        *p0 == 0x1122_3344_5566_7788 && *p1 == 0x8877_6655_4433_2211,
    );

    // Query committed state
    let mut mbi = [0u8; 48];
    let st = nt_query_virtual(base, &mut mbi);
    check(
        b"NtQueryVirtualMemory on committed page returns SUCCESS",
        st == STATUS_SUCCESS,
    );
    check(
        b"Committed page reports MEM_COMMIT",
        rd_u32(&mbi, 32) as u64 == MEM_COMMIT,
    );

    // Protect first page to READONLY
    let mut prot_base = base;
    let mut prot_size: u64 = 0x1000;
    let mut old_prot: u32 = 0;
    let st = svc(
        NR_PROTECT_VIRTUAL_MEMORY,
        0xFFFFFFFFFFFFFFFF,
        &mut prot_base as *mut u64 as u64,
        &mut prot_size as *mut u64 as u64,
        PAGE_READONLY,
        &mut old_prot as *mut u32 as u64,
        0,
        0,
        0,
    );
    check(
        b"NtProtectVirtualMemory returns SUCCESS",
        st == STATUS_SUCCESS,
    );
    check(
        b"NtProtectVirtualMemory old protection is PAGE_READWRITE",
        old_prot as u64 == PAGE_READWRITE,
    );

    let mut wx_base = base;
    let mut wx_size: u64 = 0x1000;
    let mut wx_old: u32 = 0;
    let st = svc(
        NR_PROTECT_VIRTUAL_MEMORY,
        0xFFFFFFFFFFFFFFFF,
        &mut wx_base as *mut u64 as u64,
        &mut wx_size as *mut u64 as u64,
        PAGE_EXECUTE_READWRITE,
        &mut wx_old as *mut u32 as u64,
        0,
        0,
        0,
    );
    check(
        b"NtProtectVirtualMemory RWX request returns SUCCESS",
        st == STATUS_SUCCESS,
    );
    check(
        b"RWX request reports previous protection PAGE_READONLY",
        wx_old as u64 == PAGE_READONLY,
    );
    let mut wx_mbi = [0u8; 48];
    let st = nt_query_virtual(base, &mut wx_mbi);
    check(
        b"Query after RWX protect returns SUCCESS",
        st == STATUS_SUCCESS,
    );
    check(
        b"W^X enforced: effective protect downgraded to PAGE_EXECUTE_READ",
        rd_u32(&wx_mbi, 36) as u64 == PAGE_EXECUTE_READ,
    );

    // Convert second page to WRITECOPY, write should trigger COW and promote to RW.
    let cow_addr = base + 0x1000;
    let mut cow_base = cow_addr;
    let mut cow_size: u64 = 0x1000;
    let mut cow_old: u32 = 0;
    let st = svc(
        NR_PROTECT_VIRTUAL_MEMORY,
        0xFFFFFFFFFFFFFFFF,
        &mut cow_base as *mut u64 as u64,
        &mut cow_size as *mut u64 as u64,
        PAGE_WRITECOPY,
        &mut cow_old as *mut u32 as u64,
        0,
        0,
        0,
    );
    check(
        b"NtProtectVirtualMemory WRITECOPY request returns SUCCESS",
        st == STATUS_SUCCESS,
    );
    check(
        b"WRITECOPY request reports previous protection PAGE_READWRITE",
        cow_old as u64 == PAGE_READWRITE,
    );
    let mut cow_mbi = [0u8; 48];
    let st = nt_query_virtual(cow_addr, &mut cow_mbi);
    check(
        b"Query WRITECOPY page returns SUCCESS",
        st == STATUS_SUCCESS,
    );
    check(
        b"Effective protect is PAGE_WRITECOPY before write",
        rd_u32(&cow_mbi, 36) as u64 == PAGE_WRITECOPY,
    );
    let cow_ptr = cow_addr as *mut u8;
    core::ptr::write_volatile(cow_ptr, 0x5A);
    check(
        b"Write to WRITECOPY page succeeds",
        core::ptr::read_volatile(cow_ptr) == 0x5A,
    );
    let mut cow_after_mbi = [0u8; 48];
    let st = nt_query_virtual(cow_addr, &mut cow_after_mbi);
    check(
        b"Query WRITECOPY page after write returns SUCCESS",
        st == STATUS_SUCCESS,
    );
    check(
        b"WRITECOPY page promoted to PAGE_READWRITE after COW",
        rd_u32(&cow_after_mbi, 36) as u64 == PAGE_READWRITE,
    );

    // Decommit second page
    let mut decommit_base = base + 0x1000;
    let mut decommit_size: u64 = 0x1000;
    let st = svc(
        NR_FREE_VIRTUAL_MEMORY,
        0xFFFFFFFFFFFFFFFF,
        &mut decommit_base as *mut u64 as u64,
        &mut decommit_size as *mut u64 as u64,
        MEM_DECOMMIT,
        0,
        0,
        0,
        0,
    );
    check(
        b"NtFreeVirtualMemory MEM_DECOMMIT returns SUCCESS",
        st == STATUS_SUCCESS,
    );

    let mut mbi = [0u8; 48];
    let st = nt_query_virtual(base + 0x1000, &mut mbi);
    check(
        b"Query decommitted page returns SUCCESS",
        st == STATUS_SUCCESS,
    );
    check(
        b"Decommitted page reports MEM_RESERVE",
        rd_u32(&mbi, 32) as u64 == MEM_RESERVE,
    );

    // Re-commit decommitted page and touch again
    let mut recommit_base = base + 0x1000;
    let mut recommit_size: u64 = 0x1000;
    let st = svc(
        NR_ALLOCATE_VIRTUAL_MEMORY,
        0xFFFFFFFFFFFFFFFF,
        &mut recommit_base as *mut u64 as u64,
        0,
        &mut recommit_size as *mut u64 as u64,
        MEM_COMMIT,
        PAGE_READWRITE,
        0,
        0,
    );
    check(
        b"Re-commit after decommit returns SUCCESS",
        st == STATUS_SUCCESS,
    );
    let p1 = (base + 0x1000) as *mut u64;
    *p1 = 0xAABB_CCDD_EEFF_0011;
    check(b"Re-committed page writable", *p1 == 0xAABB_CCDD_EEFF_0011);

    // Overlapping reserve at fixed base should fail
    let mut overlap_base = base;
    let mut overlap_size: u64 = 0x1000;
    let st = svc(
        NR_ALLOCATE_VIRTUAL_MEMORY,
        0xFFFFFFFFFFFFFFFF,
        &mut overlap_base as *mut u64 as u64,
        0,
        &mut overlap_size as *mut u64 as u64,
        MEM_RESERVE,
        PAGE_READWRITE,
        0,
        0,
    );
    check(b"Overlapping MEM_RESERVE fails", st != STATUS_SUCCESS);

    // Release region
    let mut free_base = base;
    let mut free_size: u64 = 0;
    let st = svc(
        NR_FREE_VIRTUAL_MEMORY,
        0xFFFFFFFFFFFFFFFF,
        &mut free_base as *mut u64 as u64,
        &mut free_size as *mut u64 as u64,
        MEM_RELEASE,
        0,
        0,
        0,
        0,
    );
    check(b"NtFreeVirtualMemory returns SUCCESS", st == STATUS_SUCCESS);

    // Commit without reserve should fail
    let mut bad_commit_base = base;
    let mut bad_commit_size: u64 = 0x1000;
    let st = svc(
        NR_ALLOCATE_VIRTUAL_MEMORY,
        0xFFFFFFFFFFFFFFFF,
        &mut bad_commit_base as *mut u64 as u64,
        0,
        &mut bad_commit_size as *mut u64 as u64,
        MEM_COMMIT,
        PAGE_READWRITE,
        0,
        0,
    );
    check(
        b"MEM_COMMIT without reserve fails",
        st == STATUS_INVALID_PARAMETER || st != STATUS_SUCCESS,
    );
}

// ════════════════════════════════════════════════════════════════
// Test 2: NtCreateSection / NtMapViewOfSection / NtUnmapViewOfSection
// ════════════════════════════════════════════════════════════════

unsafe fn test_section() {
    print(b"== Section ==\r\n");

    // SEC_IMAGE requires a file-backed section.
    let mut bad_sec: u64 = 0;
    let mut bad_size: u64 = 0x1000;
    let st = svc(
        NR_CREATE_SECTION,
        &mut bad_sec as *mut u64 as u64,
        0x000F001F,
        0,
        &mut bad_size as *mut u64 as u64,
        PAGE_EXECUTE_READ,
        SEC_IMAGE,
        0,
        0,
    );
    check(
        b"NtCreateSection SEC_IMAGE without file fails",
        st == STATUS_INVALID_PARAMETER,
    );
    check(b"SEC_IMAGE failure does not return handle", bad_sec == 0);

    // Create pagefile-backed section (64KB)
    let mut sec_handle: u64 = 0;
    let mut sec_size: u64 = 0x10000;
    let st = svc(
        NR_CREATE_SECTION,
        &mut sec_handle as *mut u64 as u64, // SectionHandle out
        0x000F001F,                         // DesiredAccess (SECTION_ALL_ACCESS)
        0,                                  // ObjectAttributes
        &mut sec_size as *mut u64 as u64,   // MaximumSize
        PAGE_READWRITE,                     // SectionPageProtection
        SEC_COMMIT,                         // AllocationAttributes (SEC_COMMIT)
        0,                                  // FileHandle (0 = pagefile)
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
        sec_handle,                        // SectionHandle
        0xFFFFFFFFFFFFFFFF,                // ProcessHandle
        &mut view_base as *mut u64 as u64, // BaseAddress ptr
        0,                                 // ZeroBits
        0,                                 // CommitSize
        &mut view_off as *mut u64 as u64,  // SectionOffset
        &mut view_size as *mut u64 as u64, // ViewSize
        1,                                 // InheritDisposition
        0,
        PAGE_READWRITE, // AllocationType, Win32Protect
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
        0,
        0,
        0,
        0,
        0,
        0,
    );
    check(
        b"NtUnmapViewOfSection returns SUCCESS",
        st == STATUS_SUCCESS,
    );

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
        &mut evt_handle as *mut u64 as u64, // EventHandle out
        0x001F0003,                         // EVENT_ALL_ACCESS
        0,                                  // ObjectAttributes
        1,                                  // EventType: NotificationEvent (manual)
        0,                                  // InitialState: non-signaled
        0,
        0,
        0,
    );
    check(b"NtCreateEvent returns SUCCESS", st == STATUS_SUCCESS);
    check(b"Event handle is valid", evt_handle != 0);

    // Set event
    let mut prev_state: u64 = 0xFFFF;
    let st = svc(
        NR_SET_EVENT,
        evt_handle,
        &mut prev_state as *mut u64 as u64,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    check(b"NtSetEvent returns SUCCESS", st == STATUS_SUCCESS);

    // Reset event
    let mut prev_state2: u64 = 0xFFFF;
    let st = svc(
        NR_RESET_EVENT,
        evt_handle,
        &mut prev_state2 as *mut u64 as u64,
        0,
        0,
        0,
        0,
        0,
        0,
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
        0x001F0003,
        0,
        1,
        0,
        0,
        0,
        0,
    );

    let mut dup: u64 = 0;
    let st = svc(
        NR_DUPLICATE_OBJECT,
        0xFFFFFFFFFFFFFFFF,          // SourceProcessHandle
        evt,                         // SourceHandle
        0xFFFFFFFFFFFFFFFF,          // TargetProcessHandle
        &mut dup as *mut u64 as u64, // TargetHandle out
        0,                           // DesiredAccess
        0,                           // HandleAttributes
        0x00000002,                  // Options: DUPLICATE_SAME_ACCESS
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
            0,
            0,
        );
        if st != STATUS_SUCCESS || base == 0 {
            all_ok = false;
        }
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
            if tag != 0xA5A5_0000 + i as u64 {
                tags_ok = false;
            }
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
                &mut fs as *mut u64 as u64,
                MEM_RELEASE,
                0,
                0,
                0,
                0,
            );
            if st != STATUS_SUCCESS {
                free_ok = false;
            }
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
    unsafe {
        exit(99);
    }
}
