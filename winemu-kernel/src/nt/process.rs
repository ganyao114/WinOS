use winemu_shared::status;

use super::SvcFrame;

#[repr(C)]
struct ClientId {
    unique_process: u64,
    unique_thread: u64,
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
// x0=*ProcessHandle, x3=ParentProcess, x4=Flags, x5=SectionHandle
pub(crate) fn handle_create_process(frame: &mut SvcFrame) {
    crate::hypercall::debug_u64(0xC501_0001);
    let out_ptr = frame.x[0] as *mut u64;
    let parent_handle = frame.x[3];
    let flags = frame.x[4] as u32;
    let section_handle = frame.x[5];

    match crate::process::create_process(parent_handle, section_handle, flags) {
        Ok(handle) => {
            crate::hypercall::debug_u64(0xC501_0002);
            if !out_ptr.is_null() {
                unsafe { out_ptr.write_volatile(handle) };
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        Err(st) => {
            crate::hypercall::debug_u64(0xC501_1000 | st as u64);
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

    frame.x[0] = crate::process::terminate_process(pid, exit_status) as u64;
}
