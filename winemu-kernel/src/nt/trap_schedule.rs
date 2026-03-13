// Trap scheduling adapter.
// Owns SvcFrame save/restore and trap-side ScheduleDecision application.

use crate::sched::{
    bind_running_thread_to_vcpu, current_tid, drain_deferred_kstacks,
    enter_kernel_continuation_noreturn, execute_kernel_continuation_switch,
    schedule_core_locked, set_needs_reschedule, set_thread_in_kernel_locked, vcpu_id,
    with_thread, with_thread_mut, ScheduleDecision, ScheduleReason, ThreadState, MAX_VCPUS,
    SCHED_LOCK,
};
use crate::timer;
use core::sync::atomic::{AtomicU32, Ordering};

use super::sysno_table::NtHandlerId;
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
    pub fn syscall(reason: ScheduleReason) -> Self {
        Self {
            allow_idle_wait: true,
            drain_hostcall: true,
            quantum_100ns: 0,
            reason,
        }
    }

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
    let cur = current_tid();
    if cur != 0 {
        set_thread_in_kernel_locked(cur, true);
    }
    drain_deferred_kstacks();
    cur
}

#[inline]
pub fn begin_syscall_trap() -> u32 {
    prepare_current_thread_for_trap_schedule()
}

#[inline]
pub fn schedule_syscall_unlock_edge(frame: &mut SvcFrame) -> bool {
    schedule_from_trap(frame, TrapScheduleRequest::syscall(ScheduleReason::UnlockEdge))
}

#[inline]
fn is_wait_completion_handler(handler_id: u8) -> bool {
    use NtHandlerId::*;
    handler_id == WaitForSingleObject as u8
        || handler_id == WaitForMultipleObjects as u8
        || handler_id == WaitForAlertByThreadId as u8
}

#[inline]
fn is_wakeup_handler(handler_id: u8) -> bool {
    use NtHandlerId::*;
    handler_id == SetEvent as u8
        || handler_id == ReleaseMutant as u8
        || handler_id == ReleaseSemaphore as u8
        || handler_id == ResumeThread as u8
        || handler_id == CreateThreadEx as u8
}

#[inline]
fn current_thread_is_waiting(current_tid: u32) -> bool {
    current_tid != 0
        && with_thread(current_tid, |t| t.state == ThreadState::Waiting).unwrap_or(false)
}

fn reason_for_nt_handler(
    handler_id: u8,
    frame: &SvcFrame,
    current_tid: u32,
    is_delay_execution: bool,
) -> ScheduleReason {
    use NtHandlerId::*;
    if handler_id == YieldExecution as u8 {
        return ScheduleReason::Yield;
    }
    if is_wait_completion_handler(handler_id) {
        return if current_thread_is_waiting(current_tid) {
            ScheduleReason::Timeout
        } else {
            ScheduleReason::UnlockEdge
        };
    }
    if is_wakeup_handler(handler_id) {
        return if frame.x[0] as u32 == crate::sched::STATUS_SUCCESS {
            ScheduleReason::Wakeup
        } else {
            ScheduleReason::UnlockEdge
        };
    }
    if handler_id == ResetEvent as u8 || handler_id == DelayExecution as u8 {
        return if is_delay_execution {
            ScheduleReason::Timeout
        } else {
            ScheduleReason::UnlockEdge
        };
    }
    ScheduleReason::UnlockEdge
}

#[inline]
pub fn finish_nt_syscall_trap(
    frame: &mut SvcFrame,
    handler_id: u8,
    current_tid: u32,
    is_delay_execution: bool,
) -> bool {
    let reason = reason_for_nt_handler(handler_id, frame, current_tid, is_delay_execution);
    schedule_from_trap(frame, TrapScheduleRequest::syscall(reason))
}

static TRAP_SCHED_ACTIVE: [AtomicU32; MAX_VCPUS] = [
    const { AtomicU32::new(0) };
    MAX_VCPUS
];

struct TrapSchedGuard {
    vid: usize,
    active: bool,
}

impl TrapSchedGuard {
    #[inline]
    fn enter(vid: usize) -> Self {
        TRAP_SCHED_ACTIVE[vid].fetch_add(1, Ordering::AcqRel);
        Self { vid, active: true }
    }

    #[inline]
    fn suspend(&mut self) {
        if self.active {
            TRAP_SCHED_ACTIVE[self.vid].fetch_sub(1, Ordering::AcqRel);
            self.active = false;
        }
    }

    #[inline]
    fn resume(&mut self) {
        if !self.active {
            TRAP_SCHED_ACTIVE[self.vid].fetch_add(1, Ordering::AcqRel);
            self.active = true;
        }
    }
}

impl Drop for TrapSchedGuard {
    #[inline]
    fn drop(&mut self) {
        if self.active {
            TRAP_SCHED_ACTIVE[self.vid].fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn save_ctx_for(tid: u32, frame: &SvcFrame) {
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

fn restore_ctx_to_frame(tid: u32, frame: &mut SvcFrame) {
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

#[inline]
fn schedule_trap_timeslice(now_100ns: u64, next_deadline_100ns: u64, slice_remaining_100ns: u64) {
    timer::schedule_running_slice_100ns(now_100ns, next_deadline_100ns, slice_remaining_100ns);
}

#[inline]
fn mark_running_thread_on_vcpu(tid: u32, vid: usize) {
    bind_running_thread_to_vcpu(vid, tid);
}

#[inline]
fn resume_user_thread_to_frame(tid: u32, frame: &mut SvcFrame, vid: usize) {
    mark_running_thread_on_vcpu(tid, vid);
    crate::process::switch_to_thread_process(tid);
    restore_ctx_to_frame(tid, frame);
}

#[inline]
fn clear_stale_in_kernel_from_terminated(from_tid: u32, current_not_running: bool) {
    if current_not_running
        && with_thread(from_tid, |t| t.state == ThreadState::Terminated).unwrap_or(false)
    {
        set_thread_in_kernel_locked(from_tid, false);
    }
}

enum TrapSwitchTarget {
    KernelContinuation,
    UserFrame,
}

fn classify_trap_switch_target(
    from_tid: u32,
    to_tid: u32,
    current_not_running: bool,
) -> TrapSwitchTarget {
    let target_has_continuation =
        with_thread(to_tid, |t| t.has_kernel_continuation()).unwrap_or(false);
    let mut target_in_kernel = with_thread(to_tid, |t| t.in_kernel).unwrap_or(false);

    if current_not_running && target_in_kernel && !target_has_continuation {
        set_thread_in_kernel_locked(to_tid, false);
        target_in_kernel = false;
    }
    clear_stale_in_kernel_from_terminated(from_tid, current_not_running);

    if target_has_continuation {
        TrapSwitchTarget::KernelContinuation
    } else if target_in_kernel {
        panic!(
            "sched: in-kernel target missing continuation from={} to={}",
            from_tid, to_tid
        );
    } else {
        TrapSwitchTarget::UserFrame
    }
}

#[inline]
fn should_resume_user_frame(
    from_tid: u32,
    to_tid: u32,
    pending_resched: bool,
    timeout_woke: bool,
    current_not_running: bool,
) -> bool {
    from_tid == 0
        || (from_tid == to_tid && (current_not_running || pending_resched || timeout_woke))
}

struct TrapScheduleContext<'a> {
    frame: &'a mut SvcFrame,
    vid: usize,
    saved_tid: u32,
    active_guard: TrapSchedGuard,
}

impl<'a> TrapScheduleContext<'a> {
    #[inline]
    fn new(frame: &'a mut SvcFrame, vid: usize) -> Self {
        Self {
            frame,
            vid,
            saved_tid: 0,
            active_guard: TrapSchedGuard::enter(vid),
        }
    }

    #[inline]
    fn save_frame_for(&mut self, tid: u32) {
        if tid == 0 || self.saved_tid == tid {
            return;
        }
        save_ctx_for(tid, self.frame);
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
            mark_running_thread_on_vcpu(cur, self.vid);
            crate::process::switch_to_thread_process(cur);
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
        self.active_guard.suspend();
        execute_kernel_continuation_switch(
            from_tid,
            to_tid,
            now_100ns,
            next_deadline_100ns,
            slice_remaining_100ns,
            "trap",
        );
        self.active_guard.resume();

        let cur = current_tid();
        if cur != 0 {
            resume_user_thread_to_frame(cur, self.frame, self.vid);
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
        resume_user_thread_to_frame(to_tid, self.frame, self.vid);
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
            return match classify_trap_switch_target(from_tid, to_tid, current_not_running) {
                TrapSwitchTarget::KernelContinuation => self.apply_kctx_switch(
                    from_tid,
                    to_tid,
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns,
                ),
                TrapSwitchTarget::UserFrame => self.apply_user_switch(
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
            self.active_guard.suspend();
            // SAFETY: `to_tid` is an idle thread continuation chosen by the
            // scheduler while the scheduler lock is held.
            unsafe { enter_kernel_continuation_noreturn(to_tid) }
        }

        if should_resume_user_frame(
            from_tid,
            to_tid,
            pending_resched,
            timeout_woke,
            current_not_running,
        ) {
            resume_user_thread_to_frame(to_tid, self.frame, self.vid);
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
        match schedule_core_locked(vid as u32, from, request.quantum_100ns, request.reason) {
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
fn trap_schedule_is_active(vid: usize) -> bool {
    TRAP_SCHED_ACTIVE[vid].load(Ordering::Acquire) != 0
}

#[inline]
fn should_defer_user_irq_schedule(frame: &SvcFrame, vid: usize) -> bool {
    trap_schedule_is_active(vid) || !crate::arch::trap::interrupted_user_mode(frame)
}

#[inline]
fn schedule_deferred_user_irq_retry_slice() {
    set_needs_reschedule();
    let now = crate::sched::wait::current_ticks();
    // Nested-trap / in-kernel IRQ path cannot switch immediately.
    // Re-arm a short retry slice so deferred preemption is observed before
    // CPU-bound user code can run to completion.
    timer::schedule_running_slice_100ns(now, u64::MAX, DEFERRED_RESCHED_RETRY_100NS);
}

#[inline]
fn user_irq_schedule_reason() -> ScheduleReason {
    if crate::sched::cpu::cpu_local().needs_reschedule {
        ScheduleReason::Ipi
    } else {
        ScheduleReason::TimerPreempt
    }
}

#[no_mangle]
pub extern "C" fn user_irq_dispatch(frame: &mut SvcFrame) {
    let vid = vcpu_id() as usize;
    if should_defer_user_irq_schedule(frame, vid) {
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
