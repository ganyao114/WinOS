use crate::sched::sync::{
    close_handle_info, destroy_object_by_type, duplicate_handle_between, HANDLE_TYPE_EVENT,
    HANDLE_TYPE_FILE, HANDLE_TYPE_KEY, HANDLE_TYPE_MUTEX, HANDLE_TYPE_SECTION,
    HANDLE_TYPE_SEMAPHORE, HANDLE_TYPE_THREAD, HANDLE_TYPE_PROCESS, STATUS_SUCCESS,
};
use winemu_shared::status;

use super::common::{STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use super::file;
use super::registry;
use super::section;
use super::SvcFrame;

// x0=SourceProcessHandle, x1=SourceHandle, x2=TargetProcessHandle, x3=*TargetHandle
pub(crate) fn handle_duplicate_object(frame: &mut SvcFrame) {
    let source_process = frame.x[0];
    let src = frame.x[1];
    let target_process = frame.x[2];
    let out_ptr = frame.x[3] as *mut u64;

    let Some(source_pid) = crate::process::resolve_process_handle(source_process) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    let Some(target_pid) = crate::process::resolve_process_handle(target_process) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let dup = match duplicate_handle_between(source_pid, src, target_pid) {
        Ok(v) => v,
        Err(st) => {
            frame.x[0] = st as u64;
            return;
        }
    };
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(dup) };
    }
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_close(frame: &mut SvcFrame) -> bool {
    let h = frame.x[0];
    if h == STD_INPUT_HANDLE || h == STD_OUTPUT_HANDLE || h == STD_ERROR_HANDLE {
        frame.x[0] = STATUS_SUCCESS as u64;
        return true;
    }

    let Some(info) = close_handle_info(h) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return true;
    };

    if !info.destroy_object {
        frame.x[0] = STATUS_SUCCESS as u64;
        return true;
    }

    let htype = info.htype;
    if htype == HANDLE_TYPE_EVENT
        || htype == HANDLE_TYPE_MUTEX
        || htype == HANDLE_TYPE_SEMAPHORE
        || htype == HANDLE_TYPE_THREAD
        || htype == HANDLE_TYPE_PROCESS
    {
        frame.x[0] = destroy_object_by_type(htype, info.obj_idx) as u64;
        return true;
    }
    if htype == HANDLE_TYPE_FILE {
        file::close_file_idx(info.obj_idx);
        frame.x[0] = STATUS_SUCCESS as u64;
        return true;
    }
    if htype == HANDLE_TYPE_SECTION {
        section::close_section_idx(info.obj_idx);
        frame.x[0] = STATUS_SUCCESS as u64;
        return true;
    }
    if htype == HANDLE_TYPE_KEY {
        if registry::close_key_idx(info.obj_idx) {
            frame.x[0] = STATUS_SUCCESS as u64;
            return true;
        }
        frame.x[0] = status::INVALID_HANDLE as u64;
        return true;
    }

    frame.x[0] = status::INVALID_HANDLE as u64;
    true
}
