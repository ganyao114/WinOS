use crate::sched::sync::{
    self, close_handle_info, destroy_object_by_type, duplicate_handle, HANDLE_TYPE_EVENT,
    HANDLE_TYPE_FILE, HANDLE_TYPE_KEY, HANDLE_TYPE_MUTEX, HANDLE_TYPE_SECTION,
    HANDLE_TYPE_SEMAPHORE, HANDLE_TYPE_THREAD, HANDLE_TYPE_PROCESS, STATUS_SUCCESS,
};
use winemu_shared::status;

use super::common::{STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use super::file;
use super::registry;
use super::section;
use super::SvcFrame;

// x1=SourceHandle, x3=*TargetHandle
pub(crate) fn handle_duplicate_object(frame: &mut SvcFrame) {
    let src = frame.x[1];
    let out_ptr = frame.x[3] as *mut u64;
    let htype = sync::handle_type(src);
    if htype == 0 {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
    let Some(dup) = duplicate_handle(src) else {
        frame.x[0] = status::NO_MEMORY as u64;
        return;
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
