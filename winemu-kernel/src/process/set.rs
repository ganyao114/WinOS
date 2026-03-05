use winemu_shared::status;

use super::resolve_process_handle;

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
        PROCESS_INFO_CLASS_DEFAULT_HARD_ERROR_MODE => set_u32_field(pid, info, info_len),
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

fn set_u32_field(pid: u32, info: *const u8, info_len: usize) -> u32 {
    let _ = pid;
    if info.is_null() || info_len != core::mem::size_of::<u32>() {
        return status::INVALID_PARAMETER;
    }
    let _ = unsafe { (info as *const u32).read_volatile() };
    status::SUCCESS
}

fn set_priority_class(pid: u32, info: *const u8, info_len: usize) -> u32 {
    let _ = pid;
    if info.is_null() || info_len != PROCESS_PRIORITY_CLASS_SIZE {
        return status::INVALID_PARAMETER;
    }

    let _ = unsafe { info.add(1).read_volatile() };
    status::SUCCESS
}

fn set_affinity_mask(pid: u32, info: *const u8, info_len: usize) -> u32 {
    let _ = pid;
    if info.is_null() || info_len != core::mem::size_of::<u64>() {
        return status::INVALID_PARAMETER;
    }
    let mask = unsafe { (info as *const u64).read_volatile() };
    if mask != 1 {
        return status::INVALID_PARAMETER;
    }

    status::SUCCESS
}

fn set_access_token(_pid: u32, info: *const u8, info_len: usize) -> u32 {
    if info.is_null() || info_len != PROCESS_ACCESS_TOKEN_SIZE {
        return status::INFO_LENGTH_MISMATCH;
    }

    let token_handle = unsafe { (info as *const u64).read_volatile() };
    let thread_handle = unsafe { (info as *const u64).add(1).read_volatile() };
    if thread_handle != 0 {
        return status::NOT_IMPLEMENTED;
    }
    if token_handle != 0 && !crate::nt::token::is_valid_token_handle(token_handle) {
        return status::INVALID_HANDLE;
    }

    status::SUCCESS
}
