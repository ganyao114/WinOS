use winemu_shared::status;

use crate::mm::usercopy::{read_current_user_bytes, read_current_user_value};

use super::{resolve_process_handle, with_process_mut};

const PROCESS_INFO_CLASS_ACCESS_TOKEN: u32 = 9;
const PROCESS_INFO_CLASS_DEFAULT_HARD_ERROR_MODE: u32 = 12;
const PROCESS_INFO_CLASS_PRIORITY_CLASS: u32 = 18;
const PROCESS_INFO_CLASS_AFFINITY_MASK: u32 = 21;
const PROCESS_INFO_CLASS_PRIORITY_BOOST: u32 = 22;
const PROCESS_INFO_CLASS_BREAK_ON_TERMINATION: u32 = 29;
const PROCESS_INFO_CLASS_DEBUG_FLAGS: u32 = 31;
const PROCESS_INFO_CLASS_EXECUTE_FLAGS: u32 = 34;
const PROCESS_INFO_CLASS_INSTRUMENTATION_CALLBACK: u32 = 40;

const PROCESS_ACCESS_TOKEN_SIZE: usize = 16;
const PROCESS_PRIORITY_CLASS_SIZE: usize = 2;

pub fn set_information_process(
    process_handle: u64,
    info_class: u32,
    info: *const u8,
    info_len: usize,
) -> u32 {
    let Some(pid) = resolve_process_handle(process_handle) else {
        return status::INVALID_HANDLE;
    };

    match info_class {
        PROCESS_INFO_CLASS_ACCESS_TOKEN => set_access_token(pid, info, info_len),
        PROCESS_INFO_CLASS_DEFAULT_HARD_ERROR_MODE => {
            set_default_hard_error_mode(pid, info, info_len)
        }
        PROCESS_INFO_CLASS_PRIORITY_CLASS => set_priority_class(pid, info, info_len),
        PROCESS_INFO_CLASS_AFFINITY_MASK => set_affinity_mask(pid, info, info_len),
        PROCESS_INFO_CLASS_PRIORITY_BOOST => set_u32_field(pid, info, info_len),
        PROCESS_INFO_CLASS_BREAK_ON_TERMINATION => set_u32_field(pid, info, info_len),
        PROCESS_INFO_CLASS_DEBUG_FLAGS => set_u32_field(pid, info, info_len),
        PROCESS_INFO_CLASS_EXECUTE_FLAGS => set_u32_field(pid, info, info_len),
        PROCESS_INFO_CLASS_INSTRUMENTATION_CALLBACK => {
            if info_len < core::mem::size_of::<u64>() {
                status::INFO_LENGTH_MISMATCH
            } else {
                status::SUCCESS
            }
        }
        _ => status::NOT_IMPLEMENTED,
    }
}

fn set_default_hard_error_mode(pid: u32, info: *const u8, info_len: usize) -> u32 {
    if info.is_null() || info_len != core::mem::size_of::<u32>() {
        return status::INVALID_PARAMETER;
    }
    let Some(mode) = read_current_user_value(info.cast::<u32>()) else {
        return status::INVALID_PARAMETER;
    };
    let Some(()) = with_process_mut(pid, |p| {
        p.default_hard_error_mode = mode;
    }) else {
        return status::INVALID_HANDLE;
    };
    status::SUCCESS
}

fn set_u32_field(pid: u32, info: *const u8, info_len: usize) -> u32 {
    let _ = pid;
    if info.is_null() || info_len != core::mem::size_of::<u32>() {
        return status::INVALID_PARAMETER;
    }
    let Some(_) = read_current_user_value(info.cast::<u32>()) else {
        return status::INVALID_PARAMETER;
    };
    status::SUCCESS
}

fn set_priority_class(pid: u32, info: *const u8, info_len: usize) -> u32 {
    let _ = pid;
    if info.is_null() || info_len != PROCESS_PRIORITY_CLASS_SIZE {
        return status::INVALID_PARAMETER;
    }

    let Some(_) = read_current_user_bytes(info, PROCESS_PRIORITY_CLASS_SIZE) else {
        return status::INVALID_PARAMETER;
    };
    status::SUCCESS
}

fn set_affinity_mask(pid: u32, info: *const u8, info_len: usize) -> u32 {
    if info.is_null() || info_len != core::mem::size_of::<u64>() {
        return status::INVALID_PARAMETER;
    }
    let Some(requested_mask) = read_current_user_value(info.cast::<u64>()) else {
        return status::INVALID_PARAMETER;
    };
    if requested_mask == 0 {
        return status::INVALID_PARAMETER;
    }

    let _lock = crate::sched::KSchedulerLock::lock();
    let tids = crate::sched::thread_ids_by_pid(pid);
    if tids.is_empty() {
        return status::INVALID_PARAMETER;
    }

    let mut changed = false;
    for tid in tids {
        if crate::sched::set_thread_affinity_mask_locked(tid, requested_mask) {
            changed = true;
        }
    }
    if !changed {
        return status::INVALID_PARAMETER;
    }

    status::SUCCESS
}

fn set_access_token(_pid: u32, info: *const u8, info_len: usize) -> u32 {
    if info.is_null() || info_len != PROCESS_ACCESS_TOKEN_SIZE {
        return status::INFO_LENGTH_MISMATCH;
    }

    let Some(raw) = read_current_user_bytes(info, PROCESS_ACCESS_TOKEN_SIZE) else {
        return status::INVALID_PARAMETER;
    };
    let mut token_bytes = [0u8; 8];
    token_bytes.copy_from_slice(&raw[0..8]);
    let token_handle = u64::from_le_bytes(token_bytes);
    let mut thread_bytes = [0u8; 8];
    thread_bytes.copy_from_slice(&raw[8..16]);
    let thread_handle = u64::from_le_bytes(thread_bytes);
    if thread_handle != 0 {
        return status::NOT_IMPLEMENTED;
    }
    if token_handle != 0 && !crate::nt::token::is_valid_token_handle(token_handle) {
        return status::INVALID_HANDLE;
    }

    status::SUCCESS
}
