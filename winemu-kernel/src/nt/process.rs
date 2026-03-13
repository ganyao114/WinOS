use winemu_shared::status;

use super::user_args::{UserInPtr, UserOutPtr};
use super::SvcFrame;
use crate::mm::usercopy::read_user_at;
use crate::mm::UserVa;

pub(crate) const CPP_EH_EXCEPTION_CODE: u32 = 0xE06D_7363;
const EXCEPTION_NAME_MAX: usize = 128;
const STATUS_INVALID_CRUNTIME_PARAMETER: u32 = 0xC000_0417;
const EXCEPTION_WINE_STUB: u32 = 0x8000_0100;

#[repr(C)]
#[derive(Clone, Copy)]
struct ClientId {
    unique_process: u64,
    unique_thread: u64,
}

fn read_user_u8(pid: u32, va: u64) -> Option<u8> {
    read_user_at(pid, UserVa::new(va))
}

fn read_user_u32(pid: u32, va: u64) -> Option<u32> {
    let b0 = read_user_u8(pid, va)? as u32;
    let b1 = read_user_u8(pid, va.saturating_add(1))? as u32;
    let b2 = read_user_u8(pid, va.saturating_add(2))? as u32;
    let b3 = read_user_u8(pid, va.saturating_add(3))? as u32;
    Some(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
}

fn read_user_u64(pid: u32, va: u64) -> Option<u64> {
    let mut out = 0u64;
    for i in 0..8u64 {
        out |= (read_user_u8(pid, va.saturating_add(i))? as u64) << (i * 8);
    }
    Some(out)
}

fn read_user_ascii_cstr(pid: u32, ptr: u64, out: &mut [u8]) -> Option<usize> {
    if ptr == 0 || out.is_empty() {
        return None;
    }
    let mut len = 0usize;
    while len < out.len() {
        let b = read_user_u8(pid, ptr.saturating_add(len as u64))?;
        if b == 0 {
            return if len == 0 { None } else { Some(len) };
        }
        if !(0x20..=0x7E).contains(&b) {
            return None;
        }
        out[len] = b;
        len += 1;
    }
    None
}

fn image_rel_or_abs(image_base: u64, value: u32) -> u64 {
    if value == 0 {
        return 0;
    }
    // MSVC x64/ARM64 C++ EH metadata usually stores 32-bit image-relative RVAs.
    // Keep a conservative absolute fallback for non-standard layouts.
    if image_base != 0 && value < 0x1000_0000 {
        image_base.saturating_add(value as u64)
    } else {
        value as u64
    }
}

fn trace_loaded_module_for_addr(prefix: &str, addr: u64) {
    crate::log::debug_print(prefix);
    crate::log::debug_u64(addr);
    let mut found = false;
    crate::dll::for_each_loaded(|name, base, size, _entry| {
        if found {
            return;
        }
        let end = base.saturating_add(size as u64);
        if addr < base || addr >= end {
            return;
        }
        found = true;
        crate::log::debug_print(" module=");
        crate::log::debug_print(name);
        crate::log::debug_print("+");
        crate::log::debug_u64(addr.saturating_sub(base));
    });
    if !found {
        crate::log::debug_print(" module=<unknown>");
    }
    crate::log::debug_print("\n");
}

pub(crate) fn trace_cpp_exception_type_name(pid: u32, throw_info: u64, image_base: u64) {
    if throw_info == 0 {
        return;
    }
    crate::log::debug_print("nt: cpp throw_info=");
    crate::log::debug_u64(throw_info);
    crate::log::debug_print(" image_base=");
    crate::log::debug_u64(image_base);
    crate::log::debug_print("\n");

    // Try MSVC ThrowInfo -> CatchableTypeArray -> TypeDescriptor chain.
    if image_base != 0 {
        let cta_rva = read_user_u32(pid, throw_info.saturating_add(0x0c)).unwrap_or(0);
        let cta = image_rel_or_abs(image_base, cta_rva);
        crate::log::debug_print("nt: cpp cta_rva=");
        crate::log::debug_u64(cta_rva as u64);
        crate::log::debug_print(" cta=");
        crate::log::debug_u64(cta);
        crate::log::debug_print("\n");
        if cta != 0 {
            let count = read_user_u32(pid, cta).unwrap_or(0);
            crate::log::debug_print("nt: cpp catchable_count=");
            crate::log::debug_u64(count as u64);
            crate::log::debug_print("\n");
            if (1..=32).contains(&count) {
                for i in 0..count {
                    let ct_rva =
                        read_user_u32(pid, cta.saturating_add(4 + (i as u64) * 4)).unwrap_or(0);
                    let ct = image_rel_or_abs(image_base, ct_rva);
                    if ct == 0 {
                        continue;
                    }
                    let td_rva = read_user_u32(pid, ct.saturating_add(4)).unwrap_or(0);
                    let td = image_rel_or_abs(image_base, td_rva);
                    crate::log::debug_print("nt: cpp ct=");
                    crate::log::debug_u64(ct);
                    crate::log::debug_print(" td=");
                    crate::log::debug_u64(td);
                    crate::log::debug_print("\n");
                    if td == 0 {
                        continue;
                    }
                    for off in [16u64, 8, 24, 0, 32] {
                        let mut buf = [0u8; EXCEPTION_NAME_MAX];
                        let Some(len) = read_user_ascii_cstr(pid, td.saturating_add(off), &mut buf)
                        else {
                            continue;
                        };
                        if len < 3 {
                            continue;
                        }
                        if let Ok(name) = core::str::from_utf8(&buf[..len]) {
                            crate::log::debug_print("nt: cpp exception type=");
                            crate::log::debug_print(name);
                            crate::log::debug_print("\n");
                            return;
                        }
                    }
                }
            }
        }
    }

    // Fallback for legacy pointer-like payloads.
    let mut buf = [0u8; EXCEPTION_NAME_MAX];
    let candidates = [
        throw_info,
        throw_info.saturating_add(16),
        throw_info.saturating_add(24),
        throw_info.saturating_add(32),
    ];
    for ptr in candidates {
        let Some(len) = read_user_ascii_cstr(pid, ptr, &mut buf) else {
            continue;
        };
        if len < 3 {
            continue;
        }
        if let Ok(name) = core::str::from_utf8(&buf[..len]) {
            crate::log::debug_print("nt: cpp exception type=");
            crate::log::debug_print(name);
            crate::log::debug_print("\n");
            return;
        }
    }
    crate::log::debug_print("nt: cpp exception type=<unresolved>\n");
}

// x0=ProcessHandle, x1=ProcessInformationClass, x2=Buffer, x3=BufferLength, x4=*ReturnLength
pub(crate) fn handle_query_information_process(frame: &mut SvcFrame) {
    let process_handle = frame.x[0];
    let info_class = frame.x[1] as u32;
    let buf = frame.x[2] as *mut u8;
    let buf_len = frame.x[3] as usize;
    let ret_len = frame.x[4] as *mut u32;

    frame.x[0] = crate::process::query_information_process(
        process_handle,
        info_class,
        buf,
        buf_len,
        ret_len,
    ) as u64;
}

pub(crate) fn should_dispatch_set_information_process(frame: &SvcFrame) -> bool {
    // `NtReleaseMutant(handle, previous_count*)` uses a mutex handle in x0.
    // `NtSetInformationProcess(handle, class, info, len)` uses a process handle in x0.
    if crate::process::resolve_process_handle(frame.x[0]).is_none() {
        return false;
    }
    if frame.x[2] != 0 || frame.x[3] != 0 {
        return true;
    }
    (frame.x[1] as u32) <= 0x0200
}

// x0=ProcessHandle, x1=ProcessInformationClass, x2=ProcessInformation, x3=ProcessInformationLength
pub(crate) fn handle_set_information_process(frame: &mut SvcFrame) {
    let process_handle = frame.x[0];
    let info_class = frame.x[1] as u32;
    let info = frame.x[2] as *const u8;
    let info_len = frame.x[3] as usize;

    frame.x[0] =
        crate::process::set_information_process(process_handle, info_class, info, info_len) as u64;
}

// NtOpenProcess:
// x0=*ProcessHandle, x1=DesiredAccess, x2=ObjectAttributes, x3=ClientId
pub(crate) fn handle_open_process(frame: &mut SvcFrame) {
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    let _obj_attr = frame.x[2];
    let client_id_ptr = UserInPtr::from_raw(frame.x[3] as *const ClientId);

    if out_ptr.is_null() || client_id_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Some(cid) = client_id_ptr.read_current() else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    let target_pid = cid.unique_process as u32;
    if target_pid == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let meta = super::kobject::object_type_meta_for_kind(crate::process::KObjectKind::Process);
    if (desired_access & !meta.valid_access_mask) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }

    match crate::process::open_process(target_pid, desired_access) {
        Ok(handle) => {
            if !out_ptr.write_current(handle) {
                let _ = super::kobject::close_handle_for_current(handle);
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        Err(st) => {
            frame.x[0] = st as u64;
        }
    }
}

// NtCreateProcessEx:
// x0=*ProcessHandle, x1=DesiredAccess, x3=ParentProcess, x4=Flags, x5=SectionHandle
pub(crate) fn handle_create_process(frame: &mut SvcFrame) {
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    let parent_handle = frame.x[3];
    let flags = frame.x[4] as u32;
    let section_handle = frame.x[5];

    let meta = super::kobject::object_type_meta_for_kind(crate::process::KObjectKind::Process);
    if (desired_access & !meta.valid_access_mask) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    match crate::process::create_process(parent_handle, section_handle, flags) {
        Ok(pid) => {
            let owner_pid = crate::process::current_pid();
            match super::kobject::install_handle_for_pid(
                owner_pid,
                crate::process::KObjectRef::process(pid),
                out_ptr,
            ) {
                Ok(_) => {
                    frame.x[0] = status::SUCCESS as u64;
                }
                Err(st) => {
                    if st == status::NO_MEMORY {
                        crate::process::destroy_unpublished_process(pid);
                    }
                    frame.x[0] = st as u64;
                }
            }
        }
        Err(st) => {
            frame.x[0] = st as u64;
        }
    }
}

// x0 = ProcessHandle, x1 = ExitStatus
pub(crate) fn handle_terminate_process(frame: &mut SvcFrame) {
    let process_handle = frame.x[0];
    let exit_status = frame.x[1] as u32;
    let Some(pid) = crate::process::resolve_process_handle(process_handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    let terminate_self = pid == crate::process::current_pid();
    if terminate_self
        && matches!(exit_status, 0 | EXCEPTION_WINE_STUB)
        && crate::log::log_enabled(crate::log::LogLevel::Trace)
    {
        crate::log::debug_print("nt: TerminateProcess self exit_status=");
        crate::log::debug_u64(exit_status as u64);
        crate::log::debug_print(" pc=");
        crate::log::debug_u64(frame.program_counter());
        crate::log::debug_print(" lr=");
        crate::log::debug_u64(frame.x[30]);
        crate::log::debug_print(" fp=");
        crate::log::debug_u64(frame.x[29]);
        crate::log::debug_print("\n");
        trace_loaded_module_for_addr("nt: TerminateProcess pc=", frame.program_counter());
        trace_loaded_module_for_addr("nt: TerminateProcess lr=", frame.x[30]);
        let mut fp = frame.x[29];
        for depth in 0..4u64 {
            if fp == 0 {
                break;
            }
            let Some(next_fp) = read_user_u64(pid, fp) else {
                break;
            };
            let Some(saved_lr) = read_user_u64(pid, fp.saturating_add(8)) else {
                break;
            };
            crate::log::debug_print("nt: TerminateProcess fp depth=");
            crate::log::debug_u64(depth);
            crate::log::debug_print(" saved_lr=");
            crate::log::debug_u64(saved_lr);
            crate::log::debug_print(" next_fp=");
            crate::log::debug_u64(next_fp);
            crate::log::debug_print("\n");
            trace_loaded_module_for_addr("nt: TerminateProcess caller=", saved_lr);
            if next_fp <= fp {
                break;
            }
            fp = next_fp;
        }
    }
    if matches!(
        exit_status,
        CPP_EH_EXCEPTION_CODE | STATUS_INVALID_CRUNTIME_PARAMETER | EXCEPTION_WINE_STUB
    ) && crate::log::log_enabled(crate::log::LogLevel::Trace)
    {
        crate::log::debug_print("nt: TerminateProcess exception code=");
        crate::log::debug_u64(exit_status as u64);
        crate::log::debug_print(" info2=");
        crate::log::debug_u64(frame.x[2]);
        crate::log::debug_print(" info3=");
        crate::log::debug_u64(frame.x[3]);
        crate::log::debug_print(" diag4=");
        crate::log::debug_u64(frame.x[4]);
        crate::log::debug_print(" diag5=");
        crate::log::debug_u64(frame.x[5]);
        crate::log::debug_print("\n");

        let handler_count = (frame.x[5] >> 48) & 0xFFFF;
        let last_result = (frame.x[5] >> 40) & 0xFF;
        let heap_fail_count = (frame.x[5] >> 32) & 0xFF;
        let dispatch_status = frame.x[5] as u32;
        crate::log::debug_print("nt: TerminateProcess dispatch_status=");
        crate::log::debug_u64(dispatch_status as u64);
        crate::log::debug_print(" handler_count=");
        crate::log::debug_u64(handler_count);
        crate::log::debug_print(" last_result=");
        crate::log::debug_u64(last_result);
        crate::log::debug_print(" heap_fail_count=");
        crate::log::debug_u64(heap_fail_count);
        crate::log::debug_print("\n");

        trace_loaded_module_for_addr("nt: TerminateProcess diag4=", frame.x[4]);
    }
    if exit_status == CPP_EH_EXCEPTION_CODE {
        trace_cpp_exception_type_name(pid, frame.x[2], frame.x[3]);
    }

    let st = crate::process::terminate_process(pid, exit_status);
    if terminate_self && st == status::SUCCESS {
        crate::nt::thread::terminate_current_thread();
    }
    frame.x[0] = st as u64;
}
