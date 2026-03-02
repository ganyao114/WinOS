use winemu_shared::status;

use super::SvcFrame;

const PAGE_SIZE_4K: u64 = 0x1000;
const PAGE_MASK_4K: u64 = !(PAGE_SIZE_4K - 1);
const CPP_EH_EXCEPTION_CODE: u32 = 0xE06D_7363;
const EXCEPTION_NAME_MAX: usize = 128;

#[repr(C)]
struct ClientId {
    unique_process: u64,
    unique_thread: u64,
}

fn read_user_u8(pid: u32, va: u64) -> Option<u8> {
    if va >= crate::process::USER_VA_LIMIT {
        return None;
    }
    if let Some(pa) = crate::process::with_process(pid, |p| {
        p.address_space
            .translate_user_va_for_access(va, super::state::VM_ACCESS_READ)
    })
    .flatten()
    {
        return Some(unsafe { (pa as *const u8).read_volatile() });
    }

    let page = va & PAGE_MASK_4K;
    if !super::state::vm_handle_page_fault(pid, page, super::state::VM_ACCESS_READ) {
        return Some(unsafe { (va as *const u8).read_volatile() });
    }
    let pa = crate::process::with_process(pid, |p| {
        p.address_space
            .translate_user_va_for_access(va, super::state::VM_ACCESS_READ)
    })
    .flatten()?;
    Some(unsafe { (pa as *const u8).read_volatile() })
}

fn read_user_u32(pid: u32, va: u64) -> Option<u32> {
    let b0 = read_user_u8(pid, va)? as u32;
    let b1 = read_user_u8(pid, va.saturating_add(1))? as u32;
    let b2 = read_user_u8(pid, va.saturating_add(2))? as u32;
    let b3 = read_user_u8(pid, va.saturating_add(3))? as u32;
    Some(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
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

fn trace_cpp_exception_type_name(pid: u32, throw_info: u64, image_base: u64) {
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
                    let ct_rva = read_user_u32(pid, cta.saturating_add(4 + (i as u64) * 4)).unwrap_or(0);
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
                        let Some(len) =
                            read_user_ascii_cstr(pid, td.saturating_add(off), &mut buf)
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

    frame.x[0] =
        crate::process::query_information_process(process_handle, info_class, buf, buf_len, ret_len)
            as u64;
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
    let out_ptr = frame.x[0] as *mut u64;
    let desired_access = frame.x[1] as u32;
    let _obj_attr = frame.x[2];
    let client_id_ptr = frame.x[3] as *const ClientId;

    if out_ptr.is_null() || client_id_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let cid = unsafe { &*client_id_ptr };
    let target_pid = cid.unique_process as u32;
    if target_pid == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Some(meta) = super::kobject::object_type_meta(crate::sched::sync::HANDLE_TYPE_PROCESS) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    if (desired_access & !meta.valid_access_mask) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }

    match crate::process::open_process(target_pid, desired_access) {
        Ok(handle) => {
            unsafe { out_ptr.write_volatile(handle) };
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
    crate::log::debug_u64(0xC501_0001);
    let out_ptr = frame.x[0] as *mut u64;
    let desired_access = frame.x[1] as u32;
    let parent_handle = frame.x[3];
    let flags = frame.x[4] as u32;
    let section_handle = frame.x[5];

    let Some(meta) = super::kobject::object_type_meta(crate::sched::sync::HANDLE_TYPE_PROCESS) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    if (desired_access & !meta.valid_access_mask) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }

    match crate::process::create_process(parent_handle, section_handle, flags) {
        Ok(handle) => {
            crate::log::debug_u64(0xC501_0002);
            if !out_ptr.is_null() {
                unsafe { out_ptr.write_volatile(handle) };
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        Err(st) => {
            crate::log::debug_u64(0xC501_1000 | st as u64);
            frame.x[0] = st as u64;
        }
    }
}

// x0 = ProcessHandle, x1 = ExitStatus
pub(crate) fn handle_terminate_process(frame: &mut SvcFrame) {
    let process_handle = frame.x[0];
    let exit_status = frame.x[1] as u32;
    let dbg2 = frame.x[2];
    let dbg3 = frame.x[3];
    let dbg4 = frame.x[4];
    let dbg5 = frame.x[5];
    crate::log::debug_print("nt: NtTerminateProcess enter h=");
    crate::log::debug_u64(process_handle);
    crate::log::debug_print(" status=");
    crate::log::debug_u64(exit_status as u64);
    crate::log::debug_print(" d2=");
    crate::log::debug_u64(dbg2);
    crate::log::debug_print(" d3=");
    crate::log::debug_u64(dbg3);
    crate::log::debug_print(" d4=");
    crate::log::debug_u64(dbg4);
    crate::log::debug_print(" d5=");
    crate::log::debug_u64(dbg5);
    crate::log::debug_print(" elr=");
    crate::log::debug_u64(frame.elr);
    crate::log::debug_print(" fp=");
    crate::log::debug_u64(frame.x[29]);
    crate::log::debug_print(" lr=");
    crate::log::debug_u64(frame.x[30]);
    crate::log::debug_print("\n");

    let Some(pid) = crate::process::resolve_process_handle(process_handle) else {
        crate::log::debug_print("nt: NtTerminateProcess invalid handle\n");
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    crate::log::debug_print("nt: NtTerminateProcess pid=");
    crate::log::debug_u64(pid as u64);
    crate::log::debug_print("\n");
    if exit_status == CPP_EH_EXCEPTION_CODE {
        trace_cpp_exception_type_name(pid, dbg2, dbg3);
    }

    frame.x[0] = crate::process::terminate_process(pid, exit_status) as u64;
}
