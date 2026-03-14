// Trap scheduling adapter.
// Owns SvcFrame save/restore and trap-side ScheduleDecision application.

use crate::sched::{
    current_tid, drain_deferred_kstacks,
    enter_kernel_continuation_noreturn, execute_kernel_continuation_switch, schedule_core_locked,
    set_thread_in_kernel_locked, vcpu_id, with_thread, ScheduleDecision, ScheduleReason,
    SCHED_LOCK,
};
use crate::sched::resched::{local_trap_reschedule_pending, request_local_trap_reschedule};
use crate::timer;

use super::trap_carrier::{
    begin_current_trap_carrier, bind_current_frame_thread_on_vcpu, finish_current_trap_carrier,
    resolve_trap_resume_target, resume_user_frame_thread_on_vcpu, save_user_frame_for_thread,
    should_restore_target_user_frame, TrapResumeTarget,
};
use super::SvcFrame;

const DEFERRED_RESCHED_RETRY_100NS: u64 = 10_000; // 1ms

#[derive(Clone, Copy)]
pub struct TrapScheduleRequest {
    pub allow_idle_wait: bool,
    pub drain_hostcall: bool,
    pub quantum_100ns: u64,
    pub reason: ScheduleReason,
}

impl TrapScheduleRequest {
    #[inline]
    pub fn user_irq(reason: ScheduleReason, quantum_100ns: u64) -> Self {
        Self {
            allow_idle_wait: false,
            drain_hostcall: true,
            quantum_100ns,
            reason,
        }
    }
}

#[inline]
fn prepare_current_thread_for_trap_schedule() -> u32 {
    let cur = begin_current_trap_carrier();
    drain_deferred_kstacks();
    cur
}

#[inline]
pub fn begin_syscall_dispatch() -> u32 {
    prepare_current_thread_for_trap_schedule()
}

#[inline]
pub fn finish_syscall_dispatch(tid: u32) {
    finish_current_trap_carrier(tid);
}

#[inline]
fn schedule_trap_timeslice(now_100ns: u64, next_deadline_100ns: u64, slice_remaining_100ns: u64) {
    timer::schedule_running_slice_100ns(now_100ns, next_deadline_100ns, slice_remaining_100ns);
}

struct TrapScheduleContext<'a> {
    frame: &'a mut SvcFrame,
    vid: usize,
    saved_tid: u32,
}

impl<'a> TrapScheduleContext<'a> {
    #[inline]
    fn new(frame: &'a mut SvcFrame, vid: usize) -> Self {
        Self {
            frame,
            vid,
            saved_tid: 0,
        }
    }

    #[inline]
    fn save_frame_for(&mut self, tid: u32) {
        if tid == 0 || self.saved_tid == tid {
            return;
        }
        save_user_frame_for_thread(tid, self.frame);
        self.saved_tid = tid;
    }

    #[inline]
    fn apply_continue_current(
        &mut self,
        now_100ns: u64,
        next_deadline_100ns: u64,
        slice_remaining_100ns: u64,
    ) -> bool {
        let cur = current_tid();
        if cur != 0 {
            bind_current_frame_thread_on_vcpu(cur, self.vid);
            set_thread_in_kernel_locked(cur, false);
        }
        crate::sched::lock::unlock_after_raw_or_scoped(self.vid);
        schedule_trap_timeslice(now_100ns, next_deadline_100ns, slice_remaining_100ns);
        false
    }

    #[inline]
    fn apply_kctx_switch(
        &mut self,
        from_tid: u32,
        to_tid: u32,
        now_100ns: u64,
        next_deadline_100ns: u64,
        slice_remaining_100ns: u64,
    ) -> bool {
        self.save_frame_for(from_tid);
        execute_kernel_continuation_switch(from_tid, to_tid);

        let cur = current_tid();
        if cur != 0 {
            resume_user_frame_thread_on_vcpu(cur, self.frame, self.vid);
            set_thread_in_kernel_locked(cur, false);
        }
        schedule_trap_timeslice(now_100ns, next_deadline_100ns, slice_remaining_100ns);
        cur != from_tid
    }

    #[inline]
    fn apply_user_switch(
        &mut self,
        from_tid: u32,
        to_tid: u32,
        current_not_running: bool,
        now_100ns: u64,
        next_deadline_100ns: u64,
        slice_remaining_100ns: u64,
    ) -> bool {
        self.save_frame_for(from_tid);
        resume_user_frame_thread_on_vcpu(to_tid, self.frame, self.vid);
        crate::sched::lock::unlock_after_raw_or_scoped(self.vid);
        if !current_not_running {
            set_thread_in_kernel_locked(from_tid, false);
        }
        set_thread_in_kernel_locked(to_tid, false);
        schedule_trap_timeslice(now_100ns, next_deadline_100ns, slice_remaining_100ns);
        true
    }

    #[inline]
    fn apply_switch(
        &mut self,
        from_tid: u32,
        to_tid: u32,
        pending_resched: bool,
        timeout_woke: bool,
        current_not_running: bool,
        now_100ns: u64,
        next_deadline_100ns: u64,
        slice_remaining_100ns: u64,
    ) -> bool {
        if from_tid != 0 && from_tid != to_tid {
            return match resolve_trap_resume_target(from_tid, to_tid, current_not_running) {
                TrapResumeTarget::KernelContinuation => self.apply_kctx_switch(
                    from_tid,
                    to_tid,
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns,
                ),
                TrapResumeTarget::UserFrame => self.apply_user_switch(
                    from_tid,
                    to_tid,
                    current_not_running,
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns,
                ),
            };
        }

        if from_tid == 0 && with_thread(to_tid, |t| t.is_idle_thread).unwrap_or(false) {
            // SAFETY: `to_tid` is an idle thread continuation chosen by the
            // scheduler while the scheduler lock is held.
            unsafe { enter_kernel_continuation_noreturn(to_tid) }
        }

        if should_restore_target_user_frame(
            from_tid,
            to_tid,
            pending_resched,
            timeout_woke,
            current_not_running,
        ) {
            resume_user_frame_thread_on_vcpu(to_tid, self.frame, self.vid);
        }

        set_thread_in_kernel_locked(to_tid, false);
        crate::sched::lock::unlock_after_raw_or_scoped(self.vid);
        schedule_trap_timeslice(now_100ns, next_deadline_100ns, slice_remaining_100ns);
        from_tid != to_tid
    }

    #[inline]
    fn apply_enter_idle(
        &mut self,
        allow_idle_wait: bool,
        quantum_100ns: u64,
        from_tid: &mut u32,
        from_sched: u32,
        now_100ns: u64,
        next_deadline_100ns: u64,
    ) -> Option<bool> {
        if !allow_idle_wait {
            crate::sched::lock::unlock_after_raw_or_scoped(self.vid);
            schedule_trap_timeslice(now_100ns, next_deadline_100ns, quantum_100ns);
            return Some(false);
        }
        if from_sched != 0 {
            self.save_frame_for(from_sched);
            *from_tid = 0;
        }
        crate::sched::lock::unlock_after_raw_or_scoped(self.vid);
        crate::sched::schedule::idle_wait_or_exit(self.vid, now_100ns, next_deadline_100ns);
        None
    }
}

pub fn schedule_from_trap(frame: &mut SvcFrame, request: TrapScheduleRequest) -> bool {
    let vid = vcpu_id() as usize;
    let mut trap_ctx = TrapScheduleContext::new(frame, vid);
    let mut from = current_tid();
    if from != 0 {
        trap_ctx.save_frame_for(from);
    }
    loop {
        if request.drain_hostcall {
            crate::hostcall::pump_completions();
        }
        SCHED_LOCK.acquire();
        let decision =
            schedule_core_locked(vid as u32, from, request.quantum_100ns, request.reason);
        match decision {
            ScheduleDecision::ContinueCurrent {
                now_100ns,
                next_deadline_100ns,
                slice_remaining_100ns,
            } => {
                return trap_ctx.apply_continue_current(
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns,
                );
            }
            ScheduleDecision::SwitchToThread {
                now_100ns,
                next_deadline_100ns,
                slice_remaining_100ns,
                from_tid: from_sched,
                to_tid: to,
                pending_resched,
                timeout_woke,
                current_not_running,
            } => {
                return trap_ctx.apply_switch(
                    from_sched,
                    to,
                    pending_resched,
                    timeout_woke,
                    current_not_running,
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns,
                );
            }
            ScheduleDecision::EnterIdle {
                now_100ns,
                next_deadline_100ns,
                from_tid: from_sched,
            } => {
                if let Some(result) = trap_ctx.apply_enter_idle(
                    request.allow_idle_wait,
                    request.quantum_100ns,
                    &mut from,
                    from_sched,
                    now_100ns,
                    next_deadline_100ns,
                ) {
                    return result;
                }
            }
        }
    }
}

#[inline]
fn should_defer_user_irq_schedule(frame: &SvcFrame) -> bool {
    // EL0 timer/IRQ traps are the immediate preemption path. Only defer when
    // the IRQ interrupted kernel execution, because that path has no user
    // frame we can switch away from directly.
    !crate::arch::trap::interrupted_user_mode(frame)
}

#[inline]
fn schedule_deferred_user_irq_retry_slice() {
    request_local_trap_reschedule();
    let now = crate::sched::wait::current_ticks();
    // Nested-trap / in-kernel IRQ path cannot switch immediately.
    // Re-arm a short retry slice so deferred preemption is observed before
    // CPU-bound user code can run to completion.
    timer::schedule_running_slice_100ns(now, u64::MAX, DEFERRED_RESCHED_RETRY_100NS);
}

#[inline]
fn user_irq_schedule_reason() -> ScheduleReason {
    if local_trap_reschedule_pending() {
        ScheduleReason::Ipi
    } else {
        ScheduleReason::TimerPreempt
    }
}

#[no_mangle]
pub extern "C" fn user_irq_dispatch(frame: &mut SvcFrame) {
    if should_defer_user_irq_schedule(frame) {
        schedule_deferred_user_irq_retry_slice();
        return;
    }
    prepare_current_thread_for_trap_schedule();
    let reason = user_irq_schedule_reason();
    schedule_from_trap(
        frame,
        TrapScheduleRequest::user_irq(reason, timer::DEFAULT_TIMESLICE_100NS),
    );
}
