#![no_std]
#![no_main]

use core::arch::asm;

const STDOUT: u64 = 0xFFFF_FFFF_FFFF_FFF5;

const NR_WRITE_FILE: u64            = 0x0008;
const NR_DELETE_KEY: u64            = 0x00DA;
const NR_DELETE_VALUE_KEY: u64      = 0x00DD;
const NR_ENUMERATE_VALUE_KEY: u64   = 0x0013;
const NR_CLOSE: u64                 = 0x000F;
const NR_OPEN_KEY: u64              = 0x0012;
const NR_QUERY_VALUE_KEY: u64       = 0x0017;
const NR_CREATE_KEY: u64            = 0x001D;
const NR_TERMINATE_PROCESS: u64     = 0x002C;
const NR_ENUMERATE_KEY: u64         = 0x0032;
const NR_SET_VALUE_KEY: u64         = 0x0060;

const STATUS_SUCCESS: u64 = 0x0000_0000;
const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xC000_0034;

const REG_DWORD: u32 = 4;

static mut PASS_COUNT: u32 = 0;
static mut FAIL_COUNT: u32 = 0;
static mut PARENT_PATH_BUF: [u16; 96] = [0; 96];
static mut SUB_PATH_BUF: [u16; 32] = [0; 32];
static mut VALUE_NAME_BUF: [u16; 32] = [0; 32];
static mut EMPTY_VALUE_NAME_BUF: [u16; 2] = [0; 2];
static mut KEY_INFO_BUF: [u8; 128] = [0; 128];
static mut VALUE_INFO_BUF: [u8; 64] = [0; 64];
static mut ENUM_VALUE_INFO_BUF: [u8; 128] = [0; 128];

#[repr(C)]
struct IoStatusBlock {
    status: u64,
    info: u64,
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    _pad: u32,
    buffer: u64,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    _pad0: u32,
    root_directory: u64,
    object_name: u64,
    attributes: u32,
    _pad1: u32,
    security_descriptor: u64,
    security_qos: u64,
}

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
        in("x1") a1,
        in("x2") a2,
        in("x3") a3,
        in("x4") a4,
        in("x5") a5,
        in("x6") a6,
        in("x7") a7,
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
        sa = in(reg) s0,
        sb = in(reg) s1,
        inout("x0") a0 => ret,
        in("x1") a1,
        in("x2") a2,
        in("x3") a3,
        in("x4") a4,
        in("x5") a5,
        in("x6") a6,
        in("x7") a7,
        in("x8") nr,
        options(nostack),
    );
    ret
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
    unsafe { nt_write_stdout(s.as_ptr(), s.len() as u32) };
}

fn print_u32(mut val: u32) {
    let mut buf = [0u8; 10];
    let mut len = 0usize;
    if val == 0 {
        buf[0] = b'0';
        len = 1;
    } else {
        while val > 0 {
            buf[len] = b'0' + (val % 10) as u8;
            val /= 10;
            len += 1;
        }
        buf[..len].reverse();
    }
    print(&buf[..len]);
}

unsafe fn check(name: &[u8], ok: bool) {
    if ok {
        PASS_COUNT += 1;
        print(b"  [PASS] ");
    } else {
        FAIL_COUNT += 1;
        print(b"  [FAIL] ");
    }
    print(name);
    print(b"\r\n");
}

unsafe fn exit(code: u32) -> ! {
    svc(
        NR_TERMINATE_PROCESS,
        0xFFFF_FFFF_FFFF_FFFF,
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

fn ascii_lower(b: u8) -> u8 {
    if (b'A'..=b'Z').contains(&b) {
        b + 32
    } else {
        b
    }
}

fn utf16le_ascii_eq_ignore_case(utf16: &[u8], ascii: &[u8]) -> bool {
    if utf16.len() != ascii.len() * 2 {
        return false;
    }
    for i in 0..ascii.len() {
        let lo = utf16[i * 2];
        let hi = utf16[i * 2 + 1];
        if hi != 0 {
            return false;
        }
        if ascii_lower(lo) != ascii_lower(ascii[i]) {
            return false;
        }
    }
    true
}

fn init_unicode<const N: usize>(buf: &mut [u16; N], s: &str) -> UnicodeString {
    let mut len = 0usize;
    for b in s.as_bytes() {
        if len + 1 >= N {
            break;
        }
        buf[len] = *b as u16;
        len += 1;
    }
    buf[len] = 0;
    UnicodeString {
        length: (len * 2) as u16,
        maximum_length: ((len + 1) * 2) as u16,
        _pad: 0,
        buffer: buf.as_ptr() as u64,
    }
}

fn init_oa(name: &mut UnicodeString, root: u64) -> ObjectAttributes {
    ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        _pad0: 0,
        root_directory: root,
        object_name: name as *mut _ as u64,
        attributes: 0x40,
        _pad1: 0,
        security_descriptor: 0,
        security_qos: 0,
    }
}

unsafe fn nt_close(handle: u64) -> u64 {
    svc(NR_CLOSE, handle, 0, 0, 0, 0, 0, 0, 0)
}

unsafe fn test_registry_syscalls() {
    print(b"== Registry NT Syscalls ==\r\n");

    let mut parent_us = init_unicode(
        &mut PARENT_PATH_BUF,
        "\\Registry\\Machine\\Software\\WinEmuRegTest",
    );
    let mut parent_oa = init_oa(&mut parent_us, 0);

    let mut parent_handle: u64 = 0;
    let mut disposition: u32 = 0;
    let st = svc(
        NR_CREATE_KEY,
        &mut parent_handle as *mut u64 as u64,
        0,
        &mut parent_oa as *mut _ as u64,
        0,
        0,
        0,
        &mut disposition as *mut u32 as u64,
        0,
    );
    check(b"NtCreateKey(parent) returns SUCCESS", st == STATUS_SUCCESS);
    check(b"Parent handle is valid", parent_handle != 0);
    check(
        b"Create disposition is valid",
        disposition == 1 || disposition == 2,
    );

    let mut parent_open_handle: u64 = 0;
    let st = svc(
        NR_OPEN_KEY,
        &mut parent_open_handle as *mut u64 as u64,
        0,
        &mut parent_oa as *mut _ as u64,
        0,
        0,
        0,
        0,
        0,
    );
    check(b"NtOpenKey(parent) returns SUCCESS", st == STATUS_SUCCESS);
    check(
        b"Opened parent handle is valid",
        parent_open_handle != 0,
    );

    let mut sub_us = init_unicode(&mut SUB_PATH_BUF, "SubA");
    let mut sub_oa = init_oa(&mut sub_us, parent_handle);

    let mut sub_handle: u64 = 0;
    let mut sub_disp: u32 = 0;
    let st = svc(
        NR_CREATE_KEY,
        &mut sub_handle as *mut u64 as u64,
        0,
        &mut sub_oa as *mut _ as u64,
        0,
        0,
        0,
        &mut sub_disp as *mut u32 as u64,
        0,
    );
    check(b"NtCreateKey(subkey) returns SUCCESS", st == STATUS_SUCCESS);
    check(b"Subkey handle is valid", sub_handle != 0);

    let mut key_ret_len: u32 = 0;
    let st = svc(
        NR_ENUMERATE_KEY,
        parent_handle,
        0,
        0,
        KEY_INFO_BUF.as_mut_ptr() as u64,
        KEY_INFO_BUF.len() as u64,
        &mut key_ret_len as *mut u32 as u64,
        0,
        0,
    );
    check(b"NtEnumerateKey returns SUCCESS", st == STATUS_SUCCESS);
    let key_name_ok = if st == STATUS_SUCCESS {
        let name_len =
            u32::from_le_bytes([KEY_INFO_BUF[12], KEY_INFO_BUF[13], KEY_INFO_BUF[14], KEY_INFO_BUF[15]])
            as usize;
        let name_end = 16 + name_len;
        name_end <= KEY_INFO_BUF.len()
            && utf16le_ascii_eq_ignore_case(&KEY_INFO_BUF[16..name_end], b"SubA")
    } else {
        false
    };
    check(b"Enumerated subkey name matches SubA", key_name_ok);

    let mut value_us = init_unicode(&mut VALUE_NAME_BUF, "Answer");
    let value_data: u32 = 0x1234_5678;

    let st = svc(
        NR_DELETE_VALUE_KEY,
        0xFFFF_FFFF_FFFF_FF00,
        &mut value_us as *mut _ as u64,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    check(
        b"NtDeleteValueKey(invalid handle) returns INVALID_HANDLE",
        st == STATUS_INVALID_HANDLE,
    );

    let st = svc(
        NR_SET_VALUE_KEY,
        sub_handle,
        &mut value_us as *mut _ as u64,
        0,
        REG_DWORD as u64,
        &value_data as *const u32 as u64,
        4,
        0,
        0,
    );
    check(b"NtSetValueKey(REG_DWORD) returns SUCCESS", st == STATUS_SUCCESS);

    let mut value_ret_len: u32 = 0;
    let st = svc(
        NR_QUERY_VALUE_KEY,
        sub_handle,
        &mut value_us as *mut _ as u64,
        2,
        VALUE_INFO_BUF.as_mut_ptr() as u64,
        VALUE_INFO_BUF.len() as u64,
        &mut value_ret_len as *mut u32 as u64,
        0,
        0,
    );
    check(b"NtQueryValueKey(partial) returns SUCCESS", st == STATUS_SUCCESS);
    let query_ok = if st == STATUS_SUCCESS {
        let ty = u32::from_le_bytes([
            VALUE_INFO_BUF[4],
            VALUE_INFO_BUF[5],
            VALUE_INFO_BUF[6],
            VALUE_INFO_BUF[7],
        ]);
        let data_len =
            u32::from_le_bytes([VALUE_INFO_BUF[8], VALUE_INFO_BUF[9], VALUE_INFO_BUF[10], VALUE_INFO_BUF[11]]) as usize;
        let val = if data_len >= 4 {
            u32::from_le_bytes([
                VALUE_INFO_BUF[12],
                VALUE_INFO_BUF[13],
                VALUE_INFO_BUF[14],
                VALUE_INFO_BUF[15],
            ])
        } else {
            0
        };
        ty == REG_DWORD && data_len == 4 && val == value_data
    } else {
        false
    };
    check(b"Queried DWORD value matches 0x12345678", query_ok);

    let mut enum_value_ret_len: u32 = 0;
    let st = svc(
        NR_ENUMERATE_VALUE_KEY,
        sub_handle,
        0,
        0,
        ENUM_VALUE_INFO_BUF.as_mut_ptr() as u64,
        ENUM_VALUE_INFO_BUF.len() as u64,
        &mut enum_value_ret_len as *mut u32 as u64,
        0,
        0,
    );
    check(
        b"NtEnumerateValueKey(class=0) returns SUCCESS",
        st == STATUS_SUCCESS,
    );
    let enum_value_ok = if st == STATUS_SUCCESS {
        let ty = u32::from_le_bytes([
            ENUM_VALUE_INFO_BUF[4],
            ENUM_VALUE_INFO_BUF[5],
            ENUM_VALUE_INFO_BUF[6],
            ENUM_VALUE_INFO_BUF[7],
        ]);
        let name_len = u32::from_le_bytes([
            ENUM_VALUE_INFO_BUF[8],
            ENUM_VALUE_INFO_BUF[9],
            ENUM_VALUE_INFO_BUF[10],
            ENUM_VALUE_INFO_BUF[11],
        ]) as usize;
        let name_end = 12 + name_len;
        ty == REG_DWORD
            && name_end <= ENUM_VALUE_INFO_BUF.len()
            && utf16le_ascii_eq_ignore_case(&ENUM_VALUE_INFO_BUF[12..name_end], b"Answer")
    } else {
        false
    };
    check(b"Enumerated value name/type are correct", enum_value_ok);

    let st = svc(
        NR_DELETE_VALUE_KEY,
        sub_handle,
        &mut value_us as *mut _ as u64,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    check(b"NtDeleteValueKey returns SUCCESS", st == STATUS_SUCCESS);

    let mut deleted_value_ret_len: u32 = 0;
    let st = svc(
        NR_QUERY_VALUE_KEY,
        sub_handle,
        &mut value_us as *mut _ as u64,
        2,
        VALUE_INFO_BUF.as_mut_ptr() as u64,
        VALUE_INFO_BUF.len() as u64,
        &mut deleted_value_ret_len as *mut u32 as u64,
        0,
        0,
    );
    check(
        b"NtQueryValueKey after delete returns OBJECT_NAME_NOT_FOUND",
        st == STATUS_OBJECT_NAME_NOT_FOUND,
    );

    let st = svc(
        NR_DELETE_VALUE_KEY,
        sub_handle,
        &mut value_us as *mut _ as u64,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    check(
        b"NtDeleteValueKey(nonexistent) returns OBJECT_NAME_NOT_FOUND",
        st == STATUS_OBJECT_NAME_NOT_FOUND,
    );

    let mut empty_value_us = init_unicode(&mut EMPTY_VALUE_NAME_BUF, "");
    let default_value_data: u32 = 0xA55A_5AA5;

    let st = svc(
        NR_SET_VALUE_KEY,
        sub_handle,
        &mut empty_value_us as *mut _ as u64,
        0,
        REG_DWORD as u64,
        &default_value_data as *const u32 as u64,
        4,
        0,
        0,
    );
    check(
        b"NtSetValueKey(empty name) returns SUCCESS",
        st == STATUS_SUCCESS,
    );

    let st = svc(
        NR_DELETE_VALUE_KEY,
        sub_handle,
        &mut empty_value_us as *mut _ as u64,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    check(
        b"NtDeleteValueKey(empty name) returns SUCCESS",
        st == STATUS_SUCCESS,
    );

    let mut empty_value_ret_len: u32 = 0;
    let st = svc(
        NR_QUERY_VALUE_KEY,
        sub_handle,
        &mut empty_value_us as *mut _ as u64,
        2,
        VALUE_INFO_BUF.as_mut_ptr() as u64,
        VALUE_INFO_BUF.len() as u64,
        &mut empty_value_ret_len as *mut u32 as u64,
        0,
        0,
    );
    check(
        b"NtQueryValueKey(empty name) after delete returns OBJECT_NAME_NOT_FOUND",
        st == STATUS_OBJECT_NAME_NOT_FOUND,
    );

    let st = svc(
        NR_DELETE_VALUE_KEY,
        sub_handle,
        &mut empty_value_us as *mut _ as u64,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    check(
        b"NtDeleteValueKey(empty name, nonexistent) returns OBJECT_NAME_NOT_FOUND",
        st == STATUS_OBJECT_NAME_NOT_FOUND,
    );

    let st = nt_close(sub_handle);
    check(b"NtClose(subkey handle) returns SUCCESS", st == STATUS_SUCCESS);

    let mut sub_delete_handle: u64 = 0;
    let st = svc(
        NR_OPEN_KEY,
        &mut sub_delete_handle as *mut u64 as u64,
        0,
        &mut sub_oa as *mut _ as u64,
        0,
        0,
        0,
        0,
        0,
    );
    check(b"NtOpenKey(subkey) before delete returns SUCCESS", st == STATUS_SUCCESS);

    let st = svc(NR_DELETE_KEY, sub_delete_handle, 0, 0, 0, 0, 0, 0, 0);
    check(b"NtDeleteKey(subkey) returns SUCCESS", st == STATUS_SUCCESS);

    let mut sub_reopen: u64 = 0;
    let st = svc(
        NR_OPEN_KEY,
        &mut sub_reopen as *mut u64 as u64,
        0,
        &mut sub_oa as *mut _ as u64,
        0,
        0,
        0,
        0,
        0,
    );
    check(
        b"NtOpenKey(subkey) after delete returns OBJECT_NAME_NOT_FOUND",
        st == STATUS_OBJECT_NAME_NOT_FOUND,
    );

    let st = nt_close(parent_open_handle);
    check(b"NtClose(parent open handle) returns SUCCESS", st == STATUS_SUCCESS);

    let st = svc(NR_DELETE_KEY, parent_handle, 0, 0, 0, 0, 0, 0, 0);
    check(b"NtDeleteKey(parent) returns SUCCESS", st == STATUS_SUCCESS);

    let mut parent_reopen: u64 = 0;
    let st = svc(
        NR_OPEN_KEY,
        &mut parent_reopen as *mut u64 as u64,
        0,
        &mut parent_oa as *mut _ as u64,
        0,
        0,
        0,
        0,
        0,
    );
    check(
        b"NtOpenKey(parent) after delete returns OBJECT_NAME_NOT_FOUND",
        st == STATUS_OBJECT_NAME_NOT_FOUND,
    );
}

#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    print(b"========================================\r\n");
    print(b"  WinEmu Registry Syscall Test\r\n");
    print(b"========================================\r\n\r\n");

    unsafe {
        test_registry_syscalls();

        print(b"\r\n========================================\r\n");
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
    unsafe { exit(99) }
}
