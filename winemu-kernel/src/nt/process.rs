use crate::hypercall;
use winemu_shared::status;

use super::SvcFrame;

// x1=ProcessInformationClass, x2=Buffer, x3=BufferLength, x4=*ReturnLength
pub(crate) fn handle_query_information_process(frame: &mut SvcFrame) {
    let info_class = frame.x[1] as u32;
    let buf = frame.x[2] as *mut u8;
    let buf_len = frame.x[3] as usize;
    let ret_len = frame.x[4] as *mut u32;

    match info_class {
        0 => {
            if buf.is_null() || buf_len < 48 {
                if !ret_len.is_null() {
                    unsafe { ret_len.write_volatile(48) };
                }
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            let mut pbi = [0u8; 48];
            pbi[8..16].copy_from_slice(&0u64.to_le_bytes());
            pbi[16..24].copy_from_slice(&1u64.to_le_bytes());
            pbi[24..28].copy_from_slice(&8i32.to_le_bytes());
            pbi[32..40].copy_from_slice(&1u64.to_le_bytes());
            pbi[40..48].copy_from_slice(&0u64.to_le_bytes());
            unsafe { core::ptr::copy_nonoverlapping(pbi.as_ptr(), buf, 48) };
            if !ret_len.is_null() {
                unsafe { ret_len.write_volatile(48) };
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        27 => {
            if buf.is_null() || buf_len < 16 {
                if !ret_len.is_null() {
                    unsafe { ret_len.write_volatile(16) };
                }
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            unsafe { core::ptr::write_bytes(buf, 0, 16) };
            if !ret_len.is_null() {
                unsafe { ret_len.write_volatile(16) };
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

pub(crate) fn handle_create_process(frame: &mut SvcFrame) {
    let _ = frame.x[0];
    frame.x[0] = status::NOT_IMPLEMENTED as u64;
}

// x0 = ProcessHandle, x1 = ExitStatus
pub(crate) fn handle_terminate_process(frame: &mut SvcFrame) {
    let code = frame.x[1] as u32;
    hypercall::process_exit(code);
}
