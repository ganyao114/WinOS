use crate::sched::{current_tid, spawn, with_thread, with_thread_mut, ThreadState};
use crate::sched::sync::{make_handle, HANDLE_TYPE_THREAD, STATUS_SUCCESS};
use winemu_shared::status;

use super::SvcFrame;

// x1=ThreadInformationClass, x2=Buffer, x3=BufferLength, x4=*ReturnLength
pub(crate) fn handle_query_information_thread(frame: &mut SvcFrame) {
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
            let tid = current_tid() as u64;
            let teb = with_thread(current_tid(), |t| t.teb_va);
            let mut tbi = [0u8; 48];
            tbi[8..16].copy_from_slice(&teb.to_le_bytes());
            tbi[16..24].copy_from_slice(&1u64.to_le_bytes());
            tbi[24..32].copy_from_slice(&tid.to_le_bytes());
            tbi[32..40].copy_from_slice(&1u64.to_le_bytes());
            tbi[40..44].copy_from_slice(&8i32.to_le_bytes());
            tbi[44..48].copy_from_slice(&8i32.to_le_bytes());
            unsafe { core::ptr::copy_nonoverlapping(tbi.as_ptr(), buf, 48) };
            if !ret_len.is_null() {
                unsafe { ret_len.write_volatile(48) };
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

pub(crate) fn handle_set_information_thread(frame: &mut SvcFrame) {
    let _ = frame.x[1];
    frame.x[0] = status::SUCCESS as u64;
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
    let max_stack_size_arg = unsafe { (frame.sp_el0 as *const u64).add(2).read_volatile() };
    let stack_size = if max_stack_size_arg == 0 {
        0x10000u64
    } else {
        (max_stack_size_arg + 0xFFFF) & !0xFFFF
    };

    if entry_va == 0 {
        frame.x[0] = 0xC000_000Du64;
        return;
    }

    let stack_base = match crate::alloc::alloc_zeroed(stack_size as usize, 0x10000) {
        Some(p) => p as u64,
        None => {
            frame.x[0] = 0xC000_0017u64;
            return;
        }
    };
    let stack_top = stack_base + stack_size;
    let teb_va = crate::alloc::alloc_zeroed(0x1000, 0x1000).map_or(0, |p| p as u64);

    let tid = spawn(entry_va, stack_top, arg, teb_va, 8);
    if tid == 0 {
        frame.x[0] = 0xC000_0017u64;
        return;
    }
    let handle = make_handle(HANDLE_TYPE_THREAD, tid as u16);
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(handle) };
    }
    let _ = create_flags;
    frame.x[0] = STATUS_SUCCESS as u64;
}

pub(crate) fn handle_terminate_thread(frame: &mut SvcFrame) {
    let cur = current_tid();
    with_thread_mut(cur, |t| t.state = ThreadState::Terminated);
    frame.x[0] = STATUS_SUCCESS as u64;
}
