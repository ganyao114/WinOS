use crate::sched::sync::{
    handle_idx, handle_type, make_handle, thread_notify_terminated, HANDLE_TYPE_THREAD,
    STATUS_SUCCESS,
};
use crate::sched::{
    current_tid, set_thread_base_priority, spawn, terminate_current_thread, with_thread,
};
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
            let (teb, prio, base_prio) =
                with_thread(current_tid(), |t| (t.teb_va, t.priority as i32, t.base_priority as i32));
            let mut tbi = [0u8; 48];
            tbi[8..16].copy_from_slice(&teb.to_le_bytes());
            tbi[16..24].copy_from_slice(&1u64.to_le_bytes());
            tbi[24..32].copy_from_slice(&tid.to_le_bytes());
            tbi[32..40].copy_from_slice(&1u64.to_le_bytes());
            tbi[40..44].copy_from_slice(&prio.to_le_bytes());
            tbi[44..48].copy_from_slice(&base_prio.to_le_bytes());
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
    // x0=ThreadHandle, x1=ThreadInformationClass, x2=ThreadInformation, x3=Length
    let thread_handle = frame.x[0];
    let info_class = frame.x[1] as u32;
    let info_ptr = frame.x[2] as *const u8;
    let info_len = frame.x[3] as usize;

    // ThreadPriority / ThreadBasePriority: i32 in [0, 31]
    const THREAD_PRIORITY_CLASS: u32 = 2;
    const THREAD_BASE_PRIORITY_CLASS: u32 = 3;

    if info_class != THREAD_PRIORITY_CLASS && info_class != THREAD_BASE_PRIORITY_CLASS {
        // Keep compatibility with previous behavior: unhandled classes are no-op success.
        frame.x[0] = status::SUCCESS as u64;
        return;
    }

    if info_ptr.is_null() || info_len < core::mem::size_of::<i32>() {
        frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
        return;
    }

    let target_tid = if thread_handle == 0
        || thread_handle == 0xFFFF_FFFF_FFFF_FFFF
        || thread_handle == 0xFFFF_FFFF_FFFF_FFFE
    {
        current_tid()
    } else if handle_type(thread_handle) == HANDLE_TYPE_THREAD {
        handle_idx(thread_handle)
    } else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let prio = unsafe { (info_ptr as *const i32).read_volatile() };
    if prio < 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    if !set_thread_base_priority(target_tid, prio as u8) {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
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

    let tid = spawn(entry_va, stack_top, arg, teb_va, stack_base, stack_size, 8);
    if tid == 0 {
        crate::alloc::dealloc(stack_base as *mut u8);
        if teb_va != 0 {
            crate::alloc::dealloc(teb_va as *mut u8);
        }
        frame.x[0] = 0xC000_0017u64;
        return;
    }
    let handle = make_handle(HANDLE_TYPE_THREAD, tid);
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
