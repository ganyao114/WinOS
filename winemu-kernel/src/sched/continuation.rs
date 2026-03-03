use super::*;

pub fn has_dispatch_continuation(tid: u32) -> bool {
    if tid == 0 || !thread_exists(tid) {
        return false;
    }
    with_thread(tid, |t| {
        t.in_kernel
            && t.dispatch_valid
            && t.dispatch_kctx.sp_el1 != 0
            && t.dispatch_kctx.x19_x30[11] != 0
    })
}

pub unsafe fn save_current_dispatch_continuation() -> u64 {
    let tid = current_tid();
    if tid == 0 || !thread_exists(tid) {
        return 0;
    }
    let ptr = thread_ptr(tid);
    if ptr.is_null() {
        return 0;
    }
    unsafe {
        (*ptr).in_kernel = true;
        (*ptr).dispatch_valid = true;
        crate::arch::context::save_kernel_context(&mut (*ptr).dispatch_kctx as *mut KernelContext)
    }
}

pub fn reschedule_current_via_dispatch_continuation() -> bool {
    let tid = current_tid();
    if tid == 0 || !thread_exists(tid) {
        return false;
    }
    let ptr = thread_ptr(tid);
    if ptr.is_null() {
        return false;
    }
    let has_dispatch = unsafe {
        (*ptr).dispatch_valid
            && (*ptr).dispatch_kctx.sp_el1 != 0
            && (*ptr).dispatch_kctx.x19_x30[11] != 0
    };
    if !has_dispatch {
        return false;
    }
    let from_kctx = unsafe { &mut (*ptr).kctx as *mut KernelContext };
    let to_kctx = unsafe { &(*ptr).dispatch_kctx as *const KernelContext };
    unsafe {
        crate::arch::context::switch_kernel_context(from_kctx, to_kctx);
    }
    true
}

pub fn has_kernel_continuation(tid: u32) -> bool {
    if tid == 0 || !thread_exists(tid) {
        return false;
    }
    with_thread(tid, |t| t.in_kernel && t.kctx.sp_el1 != 0 && t.kctx.x19_x30[11] != 0)
}

pub unsafe fn switch_kernel_continuation(from_tid: u32, to_tid: u32) -> bool {
    if from_tid == 0 || to_tid == 0 || from_tid == to_tid {
        return false;
    }
    if !thread_exists(from_tid) || !thread_exists(to_tid) {
        return false;
    }
    let can_switch = with_thread(from_tid, |t| {
        t.in_kernel
            && t.dispatch_valid
            && t.dispatch_kctx.sp_el1 != 0
            && t.dispatch_kctx.x19_x30[11] != 0
    }) && has_kernel_continuation(to_tid);
    if !can_switch {
        return false;
    }
    let from_ptr = thread_ptr(from_tid);
    let to_ptr = thread_ptr(to_tid);
    if from_ptr.is_null() || to_ptr.is_null() {
        return false;
    }
    // schedule_from_trap runs on dispatch continuation. Save current EL1 state
    // back into from.dispatch_kctx, then restore target thread's kernel continuation.
    let from_kctx = unsafe { &mut (*from_ptr).dispatch_kctx as *mut KernelContext };
    let to_kctx = unsafe { &(*to_ptr).kctx as *const KernelContext };
    unsafe {
        crate::arch::context::switch_kernel_context(from_kctx, to_kctx);
    }
    true
}
