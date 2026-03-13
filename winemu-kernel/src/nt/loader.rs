use core::str;

use winemu_shared::status;

use crate::mm::usercopy::{read_current_user_bytes, write_current_user_value};

use super::SvcFrame;

pub(crate) fn handle_load_dll(frame: &mut SvcFrame) {
    let name_ptr = frame.x[0] as *const u8;
    let name_len = frame.x[1] as usize;
    let out_handle = frame.x[2] as *mut u64;

    if name_ptr.is_null() || name_len == 0 || out_handle.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Some(mut bytes) = read_current_user_bytes(name_ptr, name_len) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };

    while matches!(bytes.last(), Some(0)) {
        let _ = bytes.pop();
    }
    if bytes.is_empty() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Ok(name) = str::from_utf8(&bytes) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    if name.bytes().any(|b| b == 0) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    match crate::dll::load_module(name) {
        Ok(module) => {
            if !write_current_user_value(out_handle, module.base) {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        Err(st) => frame.x[0] = st as u64,
    }
}
