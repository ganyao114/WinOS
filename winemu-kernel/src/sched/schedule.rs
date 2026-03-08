// sched/schedule.rs — Core scheduler round + context-switch dispatch
//
// scheduler_round_locked(vid, from_tid, quantum_100ns, reason) → SchedulerRoundAction
// execute_kernel_continuation_switch(from, to, ...)
// enter_kernel_continuation_noreturn(to) → !

use core::arch::asm;

use crate::sched::config::{
    SCHED_ENABLE_MESO_SHADOW, SCHED_ENABLE_STATE_SANITIZER, SCHED_USE_MESO_PICK,
};
use crate::sched::context::drain_deferred_kstacks;
use crate::sched::cpu::{set_current_tid, take_needs_reschedule, vcpu_id};
use crate::sched::global::{with_thread, with_thread_mut, SCHED};
use crate::sched::priority_queue::{
    mark_shadow_priority_queue_dirty_locked, rebuild_shadow_priority_queue_if_dirty_locked,
    shadow_pick_for_vcpu,
};
use crate::sched::thread_control::reset_quantum_locked;
use crate::sched::threads::free_terminated_threads_locked;
use crate::sched::topology::set_thread_state_locked;
use crate::sched::types::{KernelContext, ThreadState, WAIT_KIND_NONE};
use crate::sched::wait::check_wait_timeouts_locked;

// ── SchedulerRoundAction ──────────────────────────────────────────────────────

pub enum SchedulerRoundAction {
    ContinueCurrent {
        now_100ns:             u64,
        next_deadline_100ns:   u64,
        slice_remaining_100ns: u64,
    },
    RunThread {
        now_100ns:             u64,
        next_deadline_100ns:   u64,
        slice_remaining_100ns: u64,
        from_tid:              u32,
        to_tid:                u32,
        pending_resched:       bool,
        timeout_woke:          bool,
        cur_not_running:       bool,
    },
    IdleWait {
        now_100ns:           u64,
        next_deadline_100ns: u64,
        from_tid:            u32,
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

// ── pick_next_thread_locked ───────────────────────────────────────────────────

fn pick_next_thread_locked(vid: u32) -> u32 {
    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw() };
    queue.pop_highest_matching(
        &|id| store.get_ptr(id),
        &|t| {
            !t.is_idle_thread
                && (t.affinity_mask & (1u32 << vid)) != 0
                && (!t.in_kernel || t.last_vcpu_hint as u32 == vid)
        },
    )
}

fn peek_next_thread_locked(vid: u32) -> u32 {
    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw() };
    queue.peek_highest_matching(
        &|id| store.get_ptr(id).map(|p| p as *const _),
        &|t| {
            !t.is_idle_thread
                && (t.affinity_mask & (1u32 << vid)) != 0
                && (!t.in_kernel || t.last_vcpu_hint as u32 == vid)
        },
    )
}

fn dequeue_ready_tid_locked(tid: u32) -> bool {
    let Some(prio) = with_thread(tid, |t| t.priority) else {
        return false;
    };
    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw() };
    queue.remove(tid, prio, &|id| store.get_ptr(id))
}

fn purge_tid_from_ready_queue_locked(tid: u32) {
    if tid == 0 {
        return;
    }
    let Some(prio) = with_thread(tid, |t| t.priority) else {
        return;
    };
    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw() };
    while queue.remove(tid, prio, &|id| store.get_ptr(id)) {}
    if SCHED_ENABLE_STATE_SANITIZER {
        for p in 0..32u8 {
            if p != prio {
                while queue.remove(tid, p, &|id| store.get_ptr(id)) {}
            }
        }
    }
}

fn sanitize_invalid_thread_states_locked() -> bool {
    let mut bad = [0u32; 64];
    let mut count = 0usize;
    {
        let store = unsafe { SCHED.threads_raw() };
        store.for_each(|tid, t| {
            if (t.state as u8) > (ThreadState::Suspended as u8) && count < bad.len() {
                bad[count] = tid;
                count += 1;
            }
        });
    }
    for tid in bad.iter().take(count).copied() {
        with_thread_mut(tid, |t| {
            let old = t.state as u8;
            t.state = if t.suspend_count > 0 {
                ThreadState::Suspended
            } else if t.wait.kind != WAIT_KIND_NONE {
                ThreadState::Waiting
            } else if t.is_idle_thread {
                ThreadState::Ready
            } else {
                ThreadState::Running
            };
            crate::kerror!(
                "sched: repaired invalid state tid={} old={} new={}",
                tid,
                old,
                t.state as u8
            );
        });
    }
    count != 0
}

// ── scheduler_round_locked ────────────────────────────────────────────────────

pub fn scheduler_round_locked(
    vid: u32,
    from_tid: u32,
    quantum_100ns: u64,
    reason: ScheduleReason,
) -> SchedulerRoundAction {
    if SCHED_ENABLE_STATE_SANITIZER && sanitize_invalid_thread_states_locked() {
        mark_shadow_priority_queue_dirty_locked();
    }
    drain_deferred_kstacks();
    let timeout_woke = check_wait_timeouts_locked() > 0;
    free_terminated_threads_locked();

    let now_100ns = crate::sched::wait::current_ticks();
    let next_deadline_100ns = next_wait_deadline_locked();

    let (slice_remaining, pending_resched) = if from_tid != 0 {
        let rem = with_thread(from_tid, |t| t.slice_remaining_100ns)
            .unwrap_or(0)
            .saturating_sub(quantum_100ns);
        with_thread_mut(from_tid, |t| t.slice_remaining_100ns = rem);
        let pending = take_needs_reschedule();
        (rem, pending)
    } else {
        (0u64, false)
    };

    let cur_not_running = from_tid == 0 || {
        with_thread(from_tid, |t| t.state).unwrap_or(ThreadState::Terminated) != ThreadState::Running
    };
    if from_tid != 0 && !cur_not_running {
        // Running threads must never remain linked in the ready queue.
        purge_tid_from_ready_queue_locked(from_tid);
    }

    let mut to_tid = peek_next_thread_locked(vid);

    if to_tid == 0 {
        // Current running thread is not kept in ready queue; if there is no
        // ready candidate, continue current instead of falling into idle wait.
        if from_tid != 0 {
            let from_state = with_thread(from_tid, |t| t.state).unwrap_or(ThreadState::Terminated);
            if from_state == ThreadState::Running || from_state == ThreadState::Ready {
                // Robustness: if current thread temporarily appears as Ready while
                // no ready-queue candidate exists, keep running it instead of
                // dropping into idle and losing forward progress.
                if from_state == ThreadState::Ready {
                    with_thread_mut(from_tid, |t| {
                        t.state = ThreadState::Running;
                        t.last_vcpu_hint = vid as u8;
                    });
                }
                return SchedulerRoundAction::ContinueCurrent {
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns: slice_remaining,
                };
            }
        }
        return SchedulerRoundAction::IdleWait {
            now_100ns,
            next_deadline_100ns,
            from_tid,
        };
    }

    if from_tid != 0 && to_tid != from_tid && !cur_not_running {
        let from_prio = with_thread(from_tid, |t| t.priority).unwrap_or(31);
        let to_prio = with_thread(to_tid, |t| t.priority).unwrap_or(31);
        let higher_priority = to_prio < from_prio;
        let same_priority = to_prio == from_prio;
        let slice_expired = slice_remaining == 0;
        let should_switch = match reason {
            ScheduleReason::Yield => true,
            ScheduleReason::Wakeup | ScheduleReason::Timeout => {
                // Wake/timeout should only preempt current when candidate is at
                // least as urgent as current.
                higher_priority || same_priority
            }
            ScheduleReason::TimerPreempt => {
                // Periodic timer preemption should rotate equal-priority peers
                // without requiring an extra reschedule hint.
                higher_priority || same_priority
            }
            ScheduleReason::Ipi => {
                // IPI-driven preemption can rotate equal-priority peers when
                // the target core has explicit reschedule pressure.
                higher_priority
                    || (same_priority && (pending_resched || timeout_woke || slice_expired))
            }
            ScheduleReason::UnlockEdge => {
                // Ordinary syscall unlock-edge keeps current unless a strictly
                // higher-priority candidate becomes runnable.
                higher_priority
            }
        };
        if !should_switch {
            return SchedulerRoundAction::ContinueCurrent {
                now_100ns,
                next_deadline_100ns,
                slice_remaining_100ns: slice_remaining,
            };
        }
    }

    if to_tid == from_tid && !cur_not_running {
        return SchedulerRoundAction::ContinueCurrent {
            now_100ns,
            next_deadline_100ns,
            slice_remaining_100ns: slice_remaining,
        };
    }

    // Commit selection: dequeue chosen ready thread only after policy decided.
    if to_tid != 0 && !dequeue_ready_tid_locked(to_tid) {
        to_tid = pick_next_thread_locked(vid);
        if to_tid == 0 {
            if from_tid != 0 && !cur_not_running {
                return SchedulerRoundAction::ContinueCurrent {
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns: slice_remaining,
                };
            }
            return SchedulerRoundAction::IdleWait {
                now_100ns,
                next_deadline_100ns,
                from_tid,
            };
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

    SchedulerRoundAction::RunThread {
        now_100ns,
        next_deadline_100ns,
        slice_remaining_100ns,
        from_tid,
        to_tid,
        pending_resched,
        timeout_woke,
        cur_not_running,
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

fn arm_target_running_slice_locked(tid: u32) {
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
/// Caller must hold the scheduler lock; this function releases it.
pub fn execute_kernel_continuation_switch(
    from_tid: u32,
    to_tid: u32,
    _now_100ns: u64,
    _next_deadline_100ns: u64,
    _slice_remaining_100ns: u64,
    _label: &str,
) {
    use crate::sched::topology::set_vcpu_current_thread;
    use crate::sched::context::__sched_switch_kernel_context;

    let vid = vcpu_id() as usize;
    set_vcpu_current_thread(vid, to_tid);
    set_current_tid(to_tid);
    with_thread_mut(to_tid, |t| {
        t.state = ThreadState::Running;
        t.last_vcpu_hint = vid as u8;
    });

    let to_kctx = with_thread(to_tid, |t| &t.kctx as *const KernelContext as usize)
        .unwrap_or(0) as *const u8;
    let from_kctx = with_thread_mut(from_tid, |t| &mut t.kctx as *mut KernelContext as usize)
        .unwrap_or(0) as *mut u8;

    arm_target_running_slice_locked(to_tid);
    crate::sched::lock::unlock_after_raw_or_scoped(vid);

    unsafe { __sched_switch_kernel_context(from_kctx, to_kctx) }

    // When this call returns we have been switched back in as the current
    // thread. Restore a coherent running-state view for unlock-edge callers
    // that do not have an explicit post-switch epilogue.
    let cur = crate::sched::cpu::current_tid();
    if cur != 0 {
        with_thread_mut(cur, |t| {
            t.state = ThreadState::Running;
            t.last_vcpu_hint = vid as u8;
        });
        crate::process::switch_to_thread_process(cur);
    }
}

// ── enter_kernel_continuation_noreturn ───────────────────────────────────────

/// Jump directly into `to_tid`'s kernel continuation (no from-context save).
/// # Safety: caller must hold the scheduler lock.
pub unsafe fn enter_kernel_continuation_noreturn(to_tid: u32) -> ! {
    use crate::sched::topology::set_vcpu_current_thread;

    let vid = vcpu_id() as usize;
    set_vcpu_current_thread(vid, to_tid);
    set_current_tid(to_tid);
    with_thread_mut(to_tid, |t| {
        t.state = ThreadState::Running;
        t.last_vcpu_hint = vid as u8;
    });

    let kctx = with_thread(to_tid, |t| t.kctx).unwrap_or_else(KernelContext::new);
    crate::sched::lock::unlock_after_raw_or_scoped(vid);

    unsafe {
        asm!(
            "mov sp, {sp}",
            "br  {lr}",
            sp = in(reg) kctx.sp_el1,
            lr = in(reg) kctx.lr,
            options(noreturn),
        );
    }
}

// ── peek_next_thread_for_vcpu ─────────────────────────────────────────────────

/// Non-destructive: peek at the highest-priority thread runnable on `vid`
/// without popping it from the queue.  Used by update_highest_priority_threads.
fn peek_next_thread_for_vcpu(vid: u32) -> u32 {
    let queue = unsafe { SCHED.queue_raw_mut() };
    let store = unsafe { SCHED.threads_raw() };
    queue.peek_highest_matching(
        &|id| store.get_ptr(id).map(|p| p as *const _),
        &|t| {
            !t.is_idle_thread
                && (t.affinity_mask & (1u32 << vid)) != 0
                && (!t.in_kernel || t.last_vcpu_hint as u32 == vid)
        },
    )
}

fn peek_next_thread_for_vcpu_meso_shadow(vid: u32) -> u32 {
    let idle_tid = unsafe { SCHED.vcpu_raw(vid as usize) }.idle_tid;
    shadow_pick_for_vcpu(vid as usize, idle_tid)
}

// ── update_highest_priority_threads ──────────────────────────────────────────

/// Mirrors Atmosphere's UpdateHighestPriorityThreadsImpl().
///
/// Iterates every active vCPU, peeks at the highest-priority runnable thread
/// for each, and updates `vcpu[v].highest_priority_tid` + `needs_scheduling`.
///
/// Returns a bitmask of vCPUs whose `highest_priority_tid` changed and
/// therefore need a reschedule (either inline or via IPI).
///
/// Must be called with the scheduler spinlock held.
pub fn update_highest_priority_threads() -> u32 {
    use crate::sched::types::MAX_VCPUS;

    let use_meso_pick = SCHED_USE_MESO_PICK && SCHED_ENABLE_MESO_SHADOW;

    if SCHED_ENABLE_MESO_SHADOW {
        rebuild_shadow_priority_queue_if_dirty_locked();
    }

    // Fast path: if nothing changed since last call, skip the scan.
    if !SCHED.scheduler_update_needed.swap(false, core::sync::atomic::Ordering::AcqRel) {
        return 0;
    }

    let mut cores_needing_scheduling: u32 = 0;

    for vid in 0..MAX_VCPUS {
        // Only consider vCPUs that have been initialised (have an idle thread).
        let idle_tid = unsafe { SCHED.vcpu_raw(vid) }.idle_tid;
        if idle_tid == 0 {
            continue;
        }

        let legacy_tid = peek_next_thread_for_vcpu(vid as u32);
        let shadow_tid = if SCHED_ENABLE_MESO_SHADOW {
            peek_next_thread_for_vcpu_meso_shadow(vid as u32)
        } else {
            0
        };

        let top_tid = if use_meso_pick {
            if shadow_tid != 0 { shadow_tid } else { legacy_tid }
        } else {
            legacy_tid
        };
        // Fall back to idle if no real thread is runnable on this vCPU.
        let candidate = if top_tid != 0 { top_tid } else { idle_tid };

        let vs = unsafe { SCHED.vcpu_raw_mut(vid) };
        let prev = vs.highest_priority_tid;
        if prev != candidate {
            vs.highest_priority_tid = candidate;
            vs.needs_scheduling = true;
            cores_needing_scheduling |= 1u32 << vid;
        }
    }

    cores_needing_scheduling
}

// ── reschedule_other_cores ────────────────────────────────────────────────────

/// Send a reschedule IPI to every vCPU in `mask` except `current_vid`.
/// Mirrors Atmosphere's RescheduleOtherCores / KInterruptManager::SendIpi.
///
/// Uses the KICK_VCPU_MASK hypercall (nr=0x0003) which the VMM translates
/// into a virtual SGI to the target vCPUs.
fn reschedule_other_cores(mask: u32, current_vid: usize) {
    let other_mask = mask & !(1u32 << current_vid);
    if other_mask != 0 {
        crate::hypercall::kick_vcpu_mask(other_mask);
    }
}

// ── enable_scheduling ─────────────────────────────────────────────────────────

/// Mirrors Atmosphere's EnableScheduling(cores_needing_scheduling).
///
/// Called after the spinlock has been released:
///   1. Send IPI to other cores that need rescheduling.
///   2. Reschedule the current core inline.
pub fn enable_scheduling(cores_needing_scheduling: u32, current_vid: usize) {
    reschedule_other_cores(cores_needing_scheduling, current_vid);
    reschedule_current_core(current_vid);
}

// ── flush_unlock_edge ─────────────────────────────────────────────────────────

/// Called by KSchedulerLock::Drop (depth 1→0) while the spinlock is still held.
///
/// 1. Runs the current-vCPU scheduler round (handles timeouts, frees, etc.).
/// 2. Calls update_highest_priority_threads() to select the next thread for
///    every active vCPU and compute the reschedule bitmask.
///
/// Returns the bitmask of vCPUs that need rescheduling (for enable_scheduling).
/// The spinlock is released by the caller immediately after.
pub fn flush_unlock_edge(vid: usize) -> u32 {
    // Run the full round for the current vCPU: drain kstacks, expire timeouts,
    // free terminated threads, and pop the next thread from the ready queue.
    // This also handles the ContinueCurrent / IdleWait cases for this vCPU.
    let from_tid = unsafe { SCHED.vcpu_raw(vid) }.current_tid;
    let action = scheduler_round_locked(vid as u32, from_tid, 0, ScheduleReason::UnlockEdge);

    // Apply the round result to the current vCPU's state.
    match action {
        SchedulerRoundAction::RunThread { .. } => {
            // Mark update needed so other vCPUs are also re-evaluated.
            SCHED.scheduler_update_needed
                .store(true, core::sync::atomic::Ordering::Relaxed);
        }
        SchedulerRoundAction::IdleWait { .. } | SchedulerRoundAction::ContinueCurrent { .. } => {}
    }

    // Now do the full multi-core scan (UpdateHighestPriorityThreads).
    // This may add the current vCPU back into the mask if its candidate changed.
    let mut mask = update_highest_priority_threads();

    // Keep the current-vCPU decision from scheduler_round_locked authoritative.
    // update_highest_priority_threads() scans ready queues and must not override
    // the already-popped current candidate with idle.
    {
        let vs = unsafe { SCHED.vcpu_raw_mut(vid) };
        match action {
            SchedulerRoundAction::RunThread { to_tid, .. } => {
                vs.highest_priority_tid = to_tid;
                vs.needs_scheduling = true;
                mask |= 1u32 << vid;
            }
            SchedulerRoundAction::IdleWait { .. } => {
                let idle = vs.idle_tid;
                vs.highest_priority_tid = idle;
                vs.needs_scheduling = idle != 0;
                if idle != 0 {
                    mask |= 1u32 << vid;
                } else {
                    mask &= !(1u32 << vid);
                }
            }
            SchedulerRoundAction::ContinueCurrent { .. } => {
                vs.highest_priority_tid = 0;
                vs.needs_scheduling = false;
                mask &= !(1u32 << vid);
            }
        }
    }

    mask
}

// ── reschedule_current_core ───────────────────────────────────────────────────

/// Called by KSchedulerLock::Drop after the spinlock has been released.
///
/// If `vcpu[vid].needs_scheduling` is set, performs the actual context switch
/// to `highest_priority_tid`.  This is the "EnableScheduling" step.
pub fn reschedule_current_core(vid: usize) {
    let (needs, to_tid, from_tid) = {
        let vs = unsafe { SCHED.vcpu_raw(vid) };
        (vs.needs_scheduling, vs.highest_priority_tid, vs.current_tid)
    };

    if !needs || to_tid == 0 {
        return;
    }

    // Re-acquire the lock for the context switch (release_raw will drop it).
    use crate::sched::lock::SCHED_LOCK;
    SCHED_LOCK.acquire();

    // Clear the flag before switching.
    unsafe { SCHED.vcpu_raw_mut(vid) }.needs_scheduling = false;

    if from_tid == 0 {
        // No current thread or same thread — just jump in.
        arm_target_running_slice_locked(to_tid);
        unsafe { enter_kernel_continuation_noreturn(to_tid) }
    } else if from_tid == to_tid {
        // No actual switch needed on unlock-edge. Keep running in the current
        // kernel control flow and just restore the running state.
        with_thread_mut(to_tid, |t| {
            t.state = ThreadState::Running;
            t.last_vcpu_hint = vid as u8;
        });
        crate::sched::lock::unlock_after_raw_or_scoped(vid);
        return;
    } else {
        execute_kernel_continuation_switch(from_tid, to_tid, 0, u64::MAX, 0, "unlock-edge");
    }
}

// ── schedule_noreturn_locked ──────────────────────────────────────────────────

/// Called by exit_thread_locked after marking the thread Terminated.
/// Picks the next thread and switches to it. Does not return.
/// Caller must hold the scheduler lock.
pub fn schedule_noreturn_locked(from_tid: u32) -> ! {
    let vid = vcpu_id() as usize;
    use crate::sched::topology::set_vcpu_current_thread;

    let to_tid = pick_next_thread_locked(vid as u32);
    let idle_tid = unsafe { SCHED.vcpu_raw(vid) }.idle_tid;
    let target = if to_tid != 0 { to_tid } else if idle_tid != 0 { idle_tid } else {
        panic!("schedule_noreturn_locked: no thread to run");
    };

    set_vcpu_current_thread(vid, target);
    set_current_tid(target);
    with_thread_mut(target, |t| {
        t.state = ThreadState::Running;
        t.last_vcpu_hint = vid as u8;
    });

    if from_tid != 0 && from_tid != target {
        let to_kctx = with_thread(target, |t| &t.kctx as *const KernelContext as usize)
            .unwrap_or(0) as *const u8;
        let from_kctx = with_thread_mut(from_tid, |t| &mut t.kctx as *mut KernelContext as usize)
            .unwrap_or(0) as *mut u8;
        arm_target_running_slice_locked(target);
        crate::sched::lock::unlock_after_raw_or_scoped(vid);
        unsafe { crate::sched::context::__sched_switch_kernel_context(from_kctx, to_kctx) }
        panic!(
            "schedule_noreturn_locked: switched back to terminated/non-runnable thread tid={}",
            from_tid
        );
    } else {
        unsafe { enter_kernel_continuation_noreturn(target) }
    }
}

// ── enter_core_scheduler_entry ────────────────────────────────────────────────

/// Main scheduler entry point for a vCPU.
/// Called once per vCPU after boot setup. Does not return.
pub fn enter_core_scheduler_entry(vid: usize) -> ! {
    use crate::sched::topology::set_vcpu_current_thread;
    use crate::sched::lock::SCHED_LOCK;

    loop {
        SCHED_LOCK.acquire();
        drain_deferred_kstacks();
        let _ = check_wait_timeouts_locked();
        free_terminated_threads_locked();

        let to_tid = pick_next_thread_locked(vid as u32);
        let idle_tid = unsafe { SCHED.vcpu_raw(vid) }.idle_tid;
        let target = if to_tid != 0 { to_tid } else if idle_tid != 0 { idle_tid } else {
            crate::sched::lock::unlock_after_raw_or_scoped(vid);
            idle_wait_or_exit(vid, crate::sched::wait::current_ticks(), u64::MAX);
            continue;
        };

        set_vcpu_current_thread(vid, target);
        set_current_tid(target);
        with_thread_mut(target, |t| {
            t.state = ThreadState::Running;
            t.last_vcpu_hint = vid as u8;
        });
        arm_target_running_slice_locked(target);

        unsafe { enter_kernel_continuation_noreturn(target) }
    }
}
