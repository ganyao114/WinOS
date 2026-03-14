// Trap carrier helpers.
//
// Centralizes the bridge between a trap-time `SvcFrame` and a schedulable
// thread carrier (`ThreadContext` or `KernelContext`).

use crate::sched::{
    bind_running_thread_to_vcpu, current_tid, set_thread_in_kernel_locked, with_thread,
    with_thread_mut, ThreadState,
};

use super::SvcFrame;

pub enum TrapResumeTarget {
    KernelContinuation,
    UserFrame,
}

/// Mark the current thread as executing on a trap-owned kernel carrier before
/// syscall/IRQ-side scheduling begins.
pub fn begin_current_trap_carrier() -> u32 {
    let cur = current_tid();
    if cur != 0 {
        crate::sched::lock::with_sched_raw_lock(|| {
            set_thread_in_kernel_locked(cur, true);
        });
    }
    cur
}

/// Restore the current thread to the normal user-return carrier after trap-side
/// dispatch completes.
pub fn finish_current_trap_carrier(tid: u32) {
    if tid != 0 {
        crate::sched::lock::with_sched_raw_lock(|| {
            set_thread_in_kernel_locked(tid, false);
        });
    }
}

/// Save the trap frame into `tid`'s persistent user context.
pub fn save_user_frame_for_thread(tid: u32, frame: &SvcFrame) {
    if tid == 0 || !crate::sched::thread_exists(tid) {
        return;
    }
    with_thread_mut(tid, |t| {
        t.ctx.copy_general_registers_from(&frame.x);
        t.ctx.set_user_sp(frame.user_sp());
        t.ctx.set_program_counter(frame.program_counter());
        t.ctx.set_processor_state(frame.processor_state());
        t.ctx.set_thread_pointer(frame.thread_pointer());
    });
}

/// Restore `tid`'s persistent user context into the trap frame.
pub fn restore_user_frame_for_thread(tid: u32, frame: &mut SvcFrame) {
    if tid == 0 || !crate::sched::thread_exists(tid) {
        return;
    }
    with_thread_mut(tid, |t| {
        frame.x.copy_from_slice(t.ctx.general_registers());
        frame.set_user_sp(t.ctx.user_sp());
        frame.set_program_counter(t.ctx.program_counter());
        frame.set_processor_state(t.ctx.processor_state());
        frame.set_thread_pointer(t.ctx.thread_pointer());
    });
}

/// Mark `tid` as running on `vid` while reusing the current trap frame as the
/// active user carrier.
pub fn bind_current_frame_thread_on_vcpu(tid: u32, vid: usize) {
    bind_running_thread_to_vcpu(vid, tid);
    crate::process::switch_to_thread_process(tid);
}

/// Restore `tid` into the current trap frame and bind it as the running thread
/// on `vid`.
pub fn resume_user_frame_thread_on_vcpu(tid: u32, frame: &mut SvcFrame, vid: usize) {
    bind_current_frame_thread_on_vcpu(tid, vid);
    restore_user_frame_for_thread(tid, frame);
}

#[inline]
fn clear_stale_kernel_carrier_from_terminated(from_tid: u32, current_not_running: bool) {
    if current_not_running
        && with_thread(from_tid, |t| t.state == ThreadState::Terminated).unwrap_or(false)
    {
        set_thread_in_kernel_locked(from_tid, false);
    }
}

/// Resolve whether trap-side switching to `to_tid` must enter a kernel
/// continuation or can restore a user frame directly.
///
/// Requires the scheduler lock to be held.
pub fn resolve_trap_resume_target(
    from_tid: u32,
    to_tid: u32,
    current_not_running: bool,
) -> TrapResumeTarget {
    let target_has_continuation =
        with_thread(to_tid, |t| t.has_kernel_continuation()).unwrap_or(false);
    let mut target_in_kernel = with_thread(to_tid, |t| t.in_kernel).unwrap_or(false);

    if current_not_running && target_in_kernel && !target_has_continuation {
        set_thread_in_kernel_locked(to_tid, false);
        target_in_kernel = false;
    }
    clear_stale_kernel_carrier_from_terminated(from_tid, current_not_running);

    if target_has_continuation {
        TrapResumeTarget::KernelContinuation
    } else if target_in_kernel {
        panic!(
            "sched: in-kernel target missing continuation from={} to={}",
            from_tid, to_tid
        );
    } else {
        TrapResumeTarget::UserFrame
    }
}

/// Returns whether trap-side scheduling should reuse the current `SvcFrame`
/// carrier for `to_tid` instead of entering a kernel continuation.
pub fn should_restore_target_user_frame(
    from_tid: u32,
    to_tid: u32,
    pending_trap_reschedule: bool,
    timeout_woke: bool,
    current_not_running: bool,
) -> bool {
    from_tid == 0
        || (from_tid == to_tid
            && (current_not_running || pending_trap_reschedule || timeout_woke))
}
