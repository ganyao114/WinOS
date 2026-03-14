// sched/schedule.rs — Core scheduler decision + context-switch dispatch
//
// schedule_core_locked(vid, from_tid, quantum_100ns, reason) → ScheduleDecision
// execute_kernel_continuation_switch(from, to, ...)
// enter_kernel_continuation_noreturn(to) → !

use crate::arch::context::{self, KernelContext};
use crate::sched::context::drain_deferred_kstacks;
use crate::sched::cpu::vcpu_id;
use crate::sched::global::{with_thread, with_thread_mut, SCHED};
use crate::sched::ready::{
    commit_ready_candidate_for_vcpu_locked, peek_next_ready_thread_for_vcpu_locked,
    peek_ready_candidate_for_vcpu_locked,
};
use crate::sched::resched::{
    clear_remote_vcpu_reschedule_locked, remote_vcpu_reschedule_pending_locked,
    request_remote_vcpu_reschedule_locked, take_local_trap_reschedule,
    take_local_unlock_edge_schedule_reason_locked,
};
use crate::sched::thread_control::reset_quantum_locked;
use crate::sched::threads::free_terminated_threads_locked;
use crate::sched::topology::{bind_running_thread_to_vcpu, set_thread_state_locked};
use crate::sched::types::{CpuMask, ThreadState, MAX_VCPUS};
use crate::sched::wait::check_wait_timeouts_locked;

// ── ScheduleDecision ──────────────────────────────────────────────────────────

pub enum ScheduleDecision {
    ContinueCurrent {
        now_100ns: u64,
        next_deadline_100ns: u64,
        slice_remaining_100ns: u64,
    },
    SwitchToThread {
        now_100ns: u64,
        next_deadline_100ns: u64,
        slice_remaining_100ns: u64,
        from_tid: u32,
        to_tid: u32,
        pending_resched: bool,
        timeout_woke: bool,
        current_not_running: bool,
    },
    EnterIdle {
        now_100ns: u64,
        next_deadline_100ns: u64,
        from_tid: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleReason {
    UnlockEdge,
    Yield,
    TimerPreempt,
    Wakeup,
    Ipi,
    Timeout,
}

pub enum LocalSchedulePlan {
    None,
    ContinueCurrent { tid: u32 },
    SwitchKernelContext { from_tid: u32, to_tid: u32 },
    EnterContinuation { to_tid: u32 },
}

pub(crate) struct UnlockEdgeDispatch {
    remote_reschedule_mask: CpuMask,
    local_plan: LocalSchedulePlan,
}

impl LocalSchedulePlan {
    pub(crate) fn from_decision(vid: usize, decision: ScheduleDecision) -> Self {
        match decision {
            ScheduleDecision::SwitchToThread {
                from_tid, to_tid, ..
            } => {
                if from_tid == 0 {
                    Self::EnterContinuation { to_tid }
                } else if from_tid == to_tid {
                    Self::ContinueCurrent { tid: to_tid }
                } else {
                    Self::SwitchKernelContext { from_tid, to_tid }
                }
            }
            ScheduleDecision::EnterIdle { from_tid, .. } => {
                let idle_tid = unsafe { SCHED.vcpu_raw(vid) }.idle_tid;
                if idle_tid == 0 {
                    Self::None
                } else if from_tid == 0 {
                    Self::EnterContinuation { to_tid: idle_tid }
                } else if from_tid == idle_tid {
                    Self::ContinueCurrent { tid: idle_tid }
                } else {
                    Self::SwitchKernelContext {
                        from_tid,
                        to_tid: idle_tid,
                    }
                }
            }
            ScheduleDecision::ContinueCurrent { .. } => Self::None,
        }
    }

    pub(crate) fn apply(self, vid: usize) {
        match self {
            Self::None => {}
            Self::ContinueCurrent { tid } => {
                if tid != 0 {
                    bind_running_thread_to_vcpu(vid, tid);
                }
            }
            Self::SwitchKernelContext { from_tid, to_tid } => {
                execute_kernel_continuation_switch(from_tid, to_tid);
            }
            Self::EnterContinuation { to_tid } => {
                schedule_thread_timeslice_locked(to_tid);
                // SAFETY: `to_tid` was selected by `schedule_core_locked` while the
                // scheduler lock was held, and this path is entered only after the
                // lock is released for the transfer of control.
                unsafe { enter_kernel_continuation_noreturn(to_tid) }
            }
        }
    }

    pub(crate) fn apply_noreturn(self, vid: usize, label: &str) -> ! {
        match self {
            Self::SwitchKernelContext { from_tid, to_tid } => {
                bind_running_thread_to_vcpu(vid, to_tid);

                let to_kctx = with_thread(to_tid, |t| &t.kctx as *const KernelContext as usize)
                    .unwrap_or(0) as *const u8;
                let from_kctx =
                    with_thread_mut(from_tid, |t| &mut t.kctx as *mut KernelContext as usize)
                        .unwrap_or(0) as *mut u8;

                crate::process::switch_to_thread_process(to_tid);
                schedule_thread_timeslice_locked(to_tid);
                crate::sched::lock::unlock_after_raw_or_scoped(vid);
                // SAFETY: both contexts were chosen by the scheduler while holding the
                // scheduler lock; `from_tid` is the current non-returning execution
                // context and `to_tid` is the selected continuation target.
                unsafe { crate::sched::context::__sched_switch_kernel_context(from_kctx, to_kctx) }
                panic!(
                    "{}: switched back to non-runnable thread tid={}",
                    label, from_tid
                );
            }
            Self::EnterContinuation { to_tid } => {
                schedule_thread_timeslice_locked(to_tid);
                // SAFETY: `to_tid` was selected by the scheduler while holding the
                // scheduler lock, and this path is entered only to transfer control.
                unsafe { enter_kernel_continuation_noreturn(to_tid) }
            }
            Self::ContinueCurrent { tid } => {
                panic!(
                    "{}: unexpected continue-current on non-returning path tid={}",
                    label, tid
                );
            }
            Self::None => {
                panic!("{}: scheduler produced no runnable target", label);
            }
        }
    }
}

impl UnlockEdgeDispatch {
    #[inline]
    fn new(remote_reschedule_mask: CpuMask, local_plan: LocalSchedulePlan) -> Self {
        Self {
            remote_reschedule_mask,
            local_plan,
        }
    }

    pub(crate) fn apply_after_unlock(self, current_vid: usize) {
        enable_scheduling(self.remote_reschedule_mask, current_vid);
        self.local_plan.apply(current_vid);
    }
}

fn continue_current_decision(
    now_100ns: u64,
    next_deadline_100ns: u64,
    slice_remaining_100ns: u64,
) -> ScheduleDecision {
    ScheduleDecision::ContinueCurrent {
        now_100ns,
        next_deadline_100ns,
        slice_remaining_100ns,
    }
}

fn enter_idle_decision(
    now_100ns: u64,
    next_deadline_100ns: u64,
    from_tid: u32,
) -> ScheduleDecision {
    ScheduleDecision::EnterIdle {
        now_100ns,
        next_deadline_100ns,
        from_tid,
    }
}

#[inline]
fn current_thread_state(from_tid: u32) -> ThreadState {
    if from_tid == 0 {
        ThreadState::Terminated
    } else {
        with_thread(from_tid, |t| t.state).unwrap_or(ThreadState::Terminated)
    }
}

fn continue_current_without_ready_candidate(
    from_tid: u32,
    now_100ns: u64,
    next_deadline_100ns: u64,
    slice_remaining_100ns: u64,
    from_state: ThreadState,
    vid: u32,
) -> Option<ScheduleDecision> {
    if from_tid == 0 {
        return None;
    }
    if from_state != ThreadState::Running && from_state != ThreadState::Ready {
        return None;
    }
    // Current running thread is not kept in ready queue; if there is no
    // ready candidate, continue current instead of falling into idle wait.
    if from_state == ThreadState::Ready {
        with_thread_mut(from_tid, |t| {
            t.state = ThreadState::Running;
            t.last_vcpu_hint = vid;
            t.ready_home_vcpu_hint = vid;
        });
    }
    Some(continue_current_decision(
        now_100ns,
        next_deadline_100ns,
        slice_remaining_100ns,
    ))
}

fn should_switch_to_ready_candidate(
    reason: ScheduleReason,
    from_tid: u32,
    to_tid: u32,
    current_not_running: bool,
    slice_remaining_100ns: u64,
    pending_resched: bool,
    timeout_woke: bool,
) -> bool {
    if from_tid == 0 || to_tid == 0 || to_tid == from_tid || current_not_running {
        return true;
    }

    let from_prio = with_thread(from_tid, |t| t.priority).unwrap_or(31);
    let to_prio = with_thread(to_tid, |t| t.priority).unwrap_or(31);
    let higher_priority = to_prio < from_prio;
    let same_priority = to_prio == from_prio;
    let slice_expired = slice_remaining_100ns == 0;

    match reason {
        ScheduleReason::Yield => true,
        ScheduleReason::Wakeup | ScheduleReason::Timeout => higher_priority || same_priority,
        ScheduleReason::TimerPreempt => higher_priority || same_priority,
        ScheduleReason::Ipi => {
            higher_priority || (same_priority && (pending_resched || timeout_woke || slice_expired))
        }
        ScheduleReason::UnlockEdge => higher_priority,
    }
}

// ── schedule_core_locked ──────────────────────────────────────────────────────

pub fn schedule_core_locked(
    vid: u32,
    from_tid: u32,
    quantum_100ns: u64,
    reason: ScheduleReason,
) -> ScheduleDecision {
    clear_remote_vcpu_reschedule_locked(vid as usize);
    drain_deferred_kstacks();
    let timeout_woke = check_wait_timeouts_locked() > 0;
    free_terminated_threads_locked();
    let reason = if reason == ScheduleReason::UnlockEdge && timeout_woke {
        ScheduleReason::Timeout
    } else {
        reason
    };

    let now_100ns = crate::sched::wait::current_ticks();
    let next_deadline_100ns = next_wait_deadline_locked();

    let (slice_remaining, pending_resched) = if from_tid != 0 {
        let rem = with_thread(from_tid, |t| t.slice_remaining_100ns)
            .unwrap_or(0)
            .saturating_sub(quantum_100ns);
        with_thread_mut(from_tid, |t| t.slice_remaining_100ns = rem);
        let pending = take_local_trap_reschedule();
        (rem, pending)
    } else {
        (0u64, false)
    };

    let from_state = current_thread_state(from_tid);
    let cur_not_running = from_tid == 0 || from_state != ThreadState::Running;

    let candidate = peek_ready_candidate_for_vcpu_locked(vid);
    let mut to_tid = candidate.map(|next| next.tid).unwrap_or(0);

    if to_tid == 0 {
        if let Some(decision) = continue_current_without_ready_candidate(
            from_tid,
            now_100ns,
            next_deadline_100ns,
            slice_remaining,
            from_state,
            vid,
        ) {
            return decision;
        }
        return enter_idle_decision(now_100ns, next_deadline_100ns, from_tid);
    }

    if !should_switch_to_ready_candidate(
        reason,
        from_tid,
        to_tid,
        cur_not_running,
        slice_remaining,
        pending_resched,
        timeout_woke,
    ) {
        return continue_current_decision(now_100ns, next_deadline_100ns, slice_remaining);
    }

    if to_tid == from_tid && !cur_not_running {
        return continue_current_decision(now_100ns, next_deadline_100ns, slice_remaining);
    }

    // Commit selection only after policy decided so the queue topology is
    // updated exactly once, including any required cross-core migration.
    if to_tid != 0 {
        to_tid = candidate
            .and_then(|next| {
                let committed = commit_ready_candidate_for_vcpu_locked(next, vid);
                (committed != 0).then_some(committed)
            })
            .unwrap_or(0);
        if to_tid == 0 {
            if from_tid != 0 && !cur_not_running {
                return continue_current_decision(now_100ns, next_deadline_100ns, slice_remaining);
            }
            return enter_idle_decision(now_100ns, next_deadline_100ns, from_tid);
        }
    }

    // Preempted running thread must be returned to ready queue when we switch
    // away from it. Blocked/terminated threads are handled by their own state
    // transitions and must not be re-queued here.
    if from_tid != 0 && to_tid != from_tid && !cur_not_running {
        set_thread_state_locked(from_tid, ThreadState::Ready);
    }

    reset_quantum_locked(to_tid);
    let slice_remaining_100ns = with_thread(to_tid, |t| t.slice_remaining_100ns).unwrap_or(0);

    ScheduleDecision::SwitchToThread {
        now_100ns,
        next_deadline_100ns,
        slice_remaining_100ns,
        from_tid,
        to_tid,
        pending_resched,
        timeout_woke,
        current_not_running: cur_not_running,
    }
}

// ── next_wait_deadline_locked ─────────────────────────────────────────────────

pub fn next_wait_deadline_locked() -> u64 {
    let store = unsafe { SCHED.threads_raw() };
    let mut min = u64::MAX;
    store.for_each(|_tid, t| {
        if t.state == ThreadState::Waiting && t.wait.deadline != u64::MAX {
            if t.wait.deadline < min {
                min = t.wait.deadline;
            }
        }
    });
    min
}

/// Common idle path: if the process layer requested VM shutdown, only vCPU0
/// performs PROCESS_EXIT; otherwise this vCPU waits until the next deadline.
pub fn idle_wait_or_exit(vid: usize, now_100ns: u64, next_deadline_100ns: u64) {
    if let Some(code) = crate::process::take_kernel_shutdown_exit_code(vid) {
        crate::hypercall::process_exit(code);
    }
    crate::timer::idle_wait_until_deadline_100ns(now_100ns, next_deadline_100ns);
}

fn schedule_thread_timeslice_locked(tid: u32) {
    if tid == 0 {
        return;
    }
    if with_thread(tid, |t| t.is_idle_thread).unwrap_or(true) {
        return;
    }
    let now = crate::sched::wait::current_ticks();
    let next_deadline = next_wait_deadline_locked();
    let slice = with_thread(tid, |t| t.slice_remaining_100ns)
        .unwrap_or(crate::timer::DEFAULT_TIMESLICE_100NS)
        .max(1);
    crate::timer::schedule_running_slice_100ns(now, next_deadline, slice);
}

// ── execute_kernel_continuation_switch ───────────────────────────────────────

/// Switch from `from_tid` to `to_tid` via kernel context switch.
/// This is typically entered from a pre-built local scheduling plan.
pub fn execute_kernel_continuation_switch(
    from_tid: u32,
    to_tid: u32,
) {
    use crate::sched::context::__sched_switch_kernel_context;

    let vid = vcpu_id() as usize;
    bind_running_thread_to_vcpu(vid, to_tid);

    let to_kctx =
        with_thread(to_tid, |t| &t.kctx as *const KernelContext as usize).unwrap_or(0) as *const u8;
    let from_kctx = with_thread_mut(from_tid, |t| &mut t.kctx as *mut KernelContext as usize)
        .unwrap_or(0) as *mut u8;

    crate::process::switch_to_thread_process(to_tid);
    schedule_thread_timeslice_locked(to_tid);
    crate::sched::lock::unlock_after_raw_or_scoped(vid);

    unsafe { __sched_switch_kernel_context(from_kctx, to_kctx) }

    // When this call returns we have been switched back in as the current
    // thread. Restore a coherent running-state view for unlock-edge callers
    // that do not have an explicit post-switch epilogue.
    let cur = crate::sched::cpu::current_tid();
    if cur != 0 {
        bind_running_thread_to_vcpu(vid, cur);
        crate::process::switch_to_thread_process(cur);
    }
}

// ── enter_kernel_continuation_noreturn ───────────────────────────────────────

/// Jump directly into `to_tid`'s kernel continuation (no from-context save).
/// # Safety: `to_tid` must denote a valid continuation selected by the scheduler.
pub unsafe fn enter_kernel_continuation_noreturn(to_tid: u32) -> ! {
    let vid = vcpu_id() as usize;
    bind_running_thread_to_vcpu(vid, to_tid);

    let kctx = with_thread(to_tid, |t| &t.kctx as *const KernelContext)
        .unwrap_or_else(|| panic!("enter_kernel_continuation_noreturn: missing tid={}", to_tid));
    crate::process::switch_to_thread_process(to_tid);
    crate::sched::lock::unlock_after_raw_or_scoped(vid);

    // SAFETY: `kctx` points to the selected thread's kernel continuation,
    // chosen while holding the scheduler lock. Control is being transferred
    // after unlocking, and the arch backend owns the restore sequence.
    unsafe { context::enter_kernel_context(kctx) }
}

// ── peek_next_thread_for_vcpu ─────────────────────────────────────────────────

/// Non-destructive: peek at the highest-priority thread runnable on `vid`
/// without popping it from the queue. Used by compute_remote_reschedule_mask_locked.
fn peek_next_thread_for_vcpu(vid: u32) -> u32 {
    peek_next_ready_thread_for_vcpu_locked(vid)
}

fn should_reschedule_remote_vcpu_locked(vid: usize, candidate_tid: u32) -> bool {
    if candidate_tid == 0 {
        return false;
    }
    let current_tid = unsafe { SCHED.vcpu_raw(vid) }.current_tid;
    if current_tid == 0 {
        return true;
    }
    if current_tid == candidate_tid {
        return false;
    }
    let current_is_idle = with_thread(current_tid, |t| t.is_idle_thread).unwrap_or(true);
    if current_is_idle {
        return true;
    }
    let current_prio = with_thread(current_tid, |t| t.priority).unwrap_or(31);
    let candidate_prio = with_thread(candidate_tid, |t| t.priority).unwrap_or(31);
    candidate_prio < current_prio
}

// ── compute_remote_reschedule_mask_locked ────────────────────────────────────

fn collect_explicit_reschedule_mask_locked() -> CpuMask {
    let mut cores_needing_scheduling = CpuMask::empty();
    for vid in 0..MAX_VCPUS {
        let vs = unsafe { SCHED.vcpu_raw(vid) };
        if vs.idle_tid != 0 && remote_vcpu_reschedule_pending_locked(vid) {
            cores_needing_scheduling.insert(vid);
        }
    }
    cores_needing_scheduling
}

fn refresh_remote_reschedule_mask_locked(mut mask: CpuMask) -> CpuMask {
    for vid in 0..MAX_VCPUS {
        let idle_tid = unsafe { SCHED.vcpu_raw(vid) }.idle_tid;
        if idle_tid == 0 {
            continue;
        }
        let candidate = peek_next_thread_for_vcpu(vid as u32);
        if should_reschedule_remote_vcpu_locked(vid, candidate) {
            request_remote_vcpu_reschedule_locked(vid);
            mask.insert(vid);
        }
    }

    mask
}

/// Build a cross-core reschedule mask from:
/// 1) explicit remote-reschedule flags already raised by state transitions, and
/// 2) a global ready-queue snapshot that detects higher-priority remote work.
///
/// Must be called with the scheduler spinlock held.
fn compute_remote_reschedule_mask_locked() -> CpuMask {
    let cores_needing_scheduling = collect_explicit_reschedule_mask_locked();

    // Fast path: no scheduler topology update is pending; keep explicit flags.
    if !SCHED
        .scheduler_update_needed
        .swap(false, core::sync::atomic::Ordering::AcqRel)
    {
        return cores_needing_scheduling;
    }

    refresh_remote_reschedule_mask_locked(cores_needing_scheduling)
}

// ── reschedule_other_cores ────────────────────────────────────────────────────

/// Send a reschedule IPI to every vCPU in `mask` except `current_vid`.
/// Mirrors Atmosphere's RescheduleOtherCores / KInterruptManager::SendIpi.
///
/// Uses the per-vCPU kick hypercall which the VMM translates into a virtual
/// SGI / wakeup for each target vCPU.
fn reschedule_other_cores(mask: CpuMask, current_vid: usize) {
    for vid in mask.iter_set() {
        if vid != current_vid {
            crate::hypercall::kick_vcpu(vid);
        }
    }
}

// ── enable_scheduling ─────────────────────────────────────────────────────────

/// Mirrors the remote-wakeup part of Atmosphere's EnableScheduling.
///
/// Called after the spinlock has been released to notify other vCPUs that they
/// should re-enter the scheduler.
pub(crate) fn enable_scheduling(cores_needing_scheduling: CpuMask, current_vid: usize) {
    reschedule_other_cores(cores_needing_scheduling, current_vid);
}

// ── build_unlock_edge_dispatch_locked ─────────────────────────────────────────

/// Called by KSchedulerLock::Drop (depth 1→0) while the spinlock is still held.
///
/// 1. Runs the current-vCPU scheduler round (handles timeouts, frees, etc.).
/// 2. Calls compute_remote_reschedule_mask_locked() to compute cross-core
///    reschedule
///    mask and wake peers that should re-enter schedule_core_locked.
///
/// Returns the remote reschedule mask plus the local unlock-edge execution
/// plan. The spinlock is released by the caller immediately after.
pub(crate) fn build_unlock_edge_dispatch_locked(vid: usize) -> UnlockEdgeDispatch {
    // Run the full round for the current vCPU: drain kstacks, expire timeouts,
    // free terminated threads, and pop the next thread from the ready queue.
    // This also handles the ContinueCurrent / EnterIdle cases for this vCPU.
    let from_tid = unsafe { SCHED.vcpu_raw(vid) }.current_tid;
    let reason = take_local_unlock_edge_schedule_reason_locked(vid);
    let decision = schedule_core_locked(vid as u32, from_tid, 0, reason);

    // Apply the round result to the current vCPU's state.
    match decision {
        ScheduleDecision::SwitchToThread { .. } => {
            // Mark update needed so other vCPUs are also re-evaluated.
            SCHED
                .scheduler_update_needed
                .store(true, core::sync::atomic::Ordering::Relaxed);
        }
        ScheduleDecision::EnterIdle { .. } | ScheduleDecision::ContinueCurrent { .. } => {}
    }

    // Collect remote-core reschedule mask from scheduler update flags and
    // current queue snapshot.
    let mut mask = compute_remote_reschedule_mask_locked();
    mask.remove(vid);
    clear_remote_vcpu_reschedule_locked(vid);

    let plan = LocalSchedulePlan::from_decision(vid, decision);

    UnlockEdgeDispatch::new(mask, plan)
}

pub fn run_local_scheduler_iteration(
    vid: usize,
    from_tid: u32,
    quantum_100ns: u64,
    reason: ScheduleReason,
) {
    match schedule_core_locked(vid as u32, from_tid, quantum_100ns, reason) {
        decision @ ScheduleDecision::SwitchToThread { .. } => {
            let plan = LocalSchedulePlan::from_decision(vid, decision);
            crate::sched::lock::unlock_after_raw_or_scoped(vid);
            plan.apply(vid);
        }
        ScheduleDecision::ContinueCurrent {
            now_100ns,
            next_deadline_100ns,
            ..
        }
        | ScheduleDecision::EnterIdle {
            now_100ns,
            next_deadline_100ns,
            ..
        } => {
            crate::sched::lock::unlock_after_raw_or_scoped(vid);
            idle_wait_or_exit(vid, now_100ns, next_deadline_100ns);
        }
    }
}

// ── schedule_noreturn_locked ──────────────────────────────────────────────────

/// Called by exit_thread_locked after marking the thread Terminated.
/// Picks the next thread and switches to it. Does not return.
/// Caller must hold the scheduler lock.
pub fn schedule_noreturn_locked(from_tid: u32) -> ! {
    let vid = vcpu_id() as usize;
    let reason = take_local_unlock_edge_schedule_reason_locked(vid);
    let decision = schedule_core_locked(vid as u32, from_tid, 0, reason);
    let plan = LocalSchedulePlan::from_decision(vid, decision);
    plan.apply_noreturn(vid, "schedule_noreturn_locked")
}

// ── enter_core_scheduler_entry ────────────────────────────────────────────────

/// Main scheduler entry point for a vCPU.
/// Called once per vCPU after boot setup. Does not return.
pub fn enter_core_scheduler_entry(vid: usize) -> ! {
    use crate::sched::lock::SCHED_LOCK;

    loop {
        SCHED_LOCK.acquire();
        run_local_scheduler_iteration(vid, 0, 0, ScheduleReason::Ipi);
    }
}

/// Common boot/idle handoff for the current vCPU.
/// Ensures the local idle thread exists, then enters the shared scheduler loop.
pub fn enter_current_core_scheduler() -> ! {
    let vid = crate::sched::cpu::current_vcpu_index();
    // Bootstrap entry must not trigger unlock-edge scheduling before the first
    // real scheduler loop iteration. At this point `current_tid` may still
    // describe a synthetic boot binding rather than a live continuation.
    crate::sched::lock::with_sched_raw_lock(|| {
        crate::sched::threads::ensure_idle_thread_for_vcpu_locked(vid as u32);
    });
    enter_core_scheduler_entry(vid)
}
