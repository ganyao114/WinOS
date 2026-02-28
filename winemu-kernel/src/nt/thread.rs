use crate::sched::sync::{
    make_new_handle, thread_notify_terminated, HANDLE_TYPE_THREAD, STATUS_SUCCESS,
};
use crate::sched::{
    create_user_thread, current_tid, resolve_thread_tid_from_handle,
    set_thread_base_priority_by_handle, terminate_current_thread, terminate_thread_by_tid,
    thread_basic_info, CreateThreadError,
};
use winemu_shared::status;

use super::constants::{
    THREAD_BASIC_INFORMATION_SIZE, THREAD_INFO_CLASS_BASE_PRIORITY, THREAD_INFO_CLASS_PRIORITY,
};
use super::SvcFrame;

// x1=ThreadInformationClass, x2=Buffer, x3=BufferLength, x4=*ReturnLength
pub(crate) fn handle_query_information_thread(frame: &mut SvcFrame) {
    let thread_handle = frame.x[0];
    let info_class = frame.x[1] as u32;
    let buf = frame.x[2] as *mut u8;
    let buf_len = frame.x[3] as usize;
    let ret_len = frame.x[4] as *mut u32;
    match info_class {
        0 => {
            if buf.is_null() || buf_len < THREAD_BASIC_INFORMATION_SIZE {
                if !ret_len.is_null() {
                    unsafe { ret_len.write_volatile(THREAD_BASIC_INFORMATION_SIZE as u32) };
                }
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            let Some(target_tid) = resolve_thread_tid_from_handle(thread_handle) else {
                frame.x[0] = status::INVALID_HANDLE as u64;
                return;
            };
            let Some(tbi) = thread_basic_info(target_tid) else {
                frame.x[0] = status::INVALID_HANDLE as u64;
                return;
            };
            unsafe {
                core::ptr::copy_nonoverlapping(tbi.as_ptr(), buf, THREAD_BASIC_INFORMATION_SIZE)
            };
            if !ret_len.is_null() {
                unsafe { ret_len.write_volatile(THREAD_BASIC_INFORMATION_SIZE as u32) };
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

pub(crate) fn handle_set_information_thread(frame: &mut SvcFrame) {
    // x0=ThreadHandle, x1=ThreadInformationClass, x2=ThreadInformation, x3=Length
    let thread_handle = frame.x[0];
    let info_class = frame.x[1] as u32;
    let info_ptr = frame.x[2] as *const u8;
    let info_len = frame.x[3] as usize;

    if info_class != THREAD_INFO_CLASS_PRIORITY && info_class != THREAD_INFO_CLASS_BASE_PRIORITY {
        // Keep compatibility with previous behavior: unhandled classes are no-op success.
        frame.x[0] = status::SUCCESS as u64;
        return;
    }

    if info_ptr.is_null() || info_len < core::mem::size_of::<i32>() {
        frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
        return;
    }

    let prio = unsafe { (info_ptr as *const i32).read_volatile() };
    frame.x[0] = set_thread_base_priority_by_handle(thread_handle, prio) as u64;
}

pub(crate) fn handle_yield(frame: &mut SvcFrame) {
    crate::sched::yield_current_thread();
    frame.x[0] = STATUS_SUCCESS as u64;
}

// x0=ThreadHandle*(out), x4=StartRoutine, x5=Argument, x6=CreateFlags
// stack[0]=StackSize, stack[1]=MaxStackSize, stack[2]=AttributeList
pub(crate) fn handle_create_thread(frame: &mut SvcFrame) {
    let out_ptr = frame.x[0] as *mut u64;
    let entry_va = frame.x[4];
    let arg = frame.x[5];
    let create_flags = frame.x[6] as u32;
    let _stack_size_arg = unsafe { (frame.sp_el0 as *const u64).read_volatile() };
    let max_stack_size_arg = unsafe { (frame.sp_el0 as *const u64).add(1).read_volatile() };
    let tid = match create_user_thread(entry_va, arg, max_stack_size_arg, 8) {
        Ok(tid) => tid,
        Err(CreateThreadError::InvalidParameter) => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
        Err(CreateThreadError::NoMemory) => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };
    let Some(handle) = make_new_handle(HANDLE_TYPE_THREAD, tid) else {
        let _ = terminate_thread_by_tid(tid);
        thread_notify_terminated(tid);
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(handle) };
    }
    let _ = create_flags;
    frame.x[0] = STATUS_SUCCESS as u64;
}

pub(crate) fn handle_terminate_thread(frame: &mut SvcFrame) {
    let cur = current_tid();
    terminate_current_thread();
    thread_notify_terminated(cur);
    frame.x[0] = STATUS_SUCCESS as u64;
}
