// sched/resched.rs — Reschedule intent helpers
//
// Separates three distinct scheduling intents:
// 1. Local trap-safe-point reschedule requests
// 2. Local unlock-edge schedule reasons
// 3. Remote vCPU reschedule requests

use crate::sched::cpu::cpu_local;
use crate::sched::global::SCHED;
use crate::sched::lock::KSchedulerLock;
use crate::sched::schedule::ScheduleReason;
use crate::sched::types::MAX_VCPUS;
use crate::sched::vcpu_id;

const PENDING_UNLOCK_EDGE_REASON_NONE: u8 = 0;

#[inline]
fn schedule_reason_priority(reason: ScheduleReason) -> u8 {
    match reason {
        ScheduleReason::UnlockEdge => 0,
        ScheduleReason::Ipi => 1,
        ScheduleReason::TimerPreempt => 2,
        ScheduleReason::Wakeup | ScheduleReason::Timeout => 3,
        ScheduleReason::Yield => 4,
    }
}

#[inline]
fn encode_unlock_edge_reason(reason: ScheduleReason) -> u8 {
    match reason {
        ScheduleReason::UnlockEdge => PENDING_UNLOCK_EDGE_REASON_NONE,
        ScheduleReason::Yield => 1,
        ScheduleReason::TimerPreempt => 2,
        ScheduleReason::Wakeup => 3,
        ScheduleReason::Ipi => 4,
        ScheduleReason::Timeout => 5,
    }
}

#[inline]
fn decode_unlock_edge_reason(code: u8) -> Option<ScheduleReason> {
    match code {
        1 => Some(ScheduleReason::Yield),
        2 => Some(ScheduleReason::TimerPreempt),
        3 => Some(ScheduleReason::Wakeup),
        4 => Some(ScheduleReason::Ipi),
        5 => Some(ScheduleReason::Timeout),
        _ => None,
    }
}

#[inline]
fn choose_unlock_edge_reason_code(current: u8, incoming: ScheduleReason) -> u8 {
    let incoming_code = encode_unlock_edge_reason(incoming);
    if incoming_code == PENDING_UNLOCK_EDGE_REASON_NONE {
        return current;
    }

    let current_reason = decode_unlock_edge_reason(current);
    if current_reason
        .map(|reason| schedule_reason_priority(reason) >= schedule_reason_priority(incoming))
        .unwrap_or(false)
    {
        current
    } else {
        incoming_code
    }
}

/// Request that the current vCPU re-enters the trap scheduler at the next safe
/// point on the currently running thread.
#[inline]
pub fn request_local_trap_reschedule() {
    cpu_local().pending_trap_reschedule = true;
}

/// Returns true when the current vCPU still owes a trap-safe-point scheduler
/// re-entry to the currently running thread.
#[inline]
pub fn local_trap_reschedule_pending() -> bool {
    cpu_local().pending_trap_reschedule
}

/// Consume and clear the current vCPU's trap-safe-point reschedule request.
#[inline]
pub fn take_local_trap_reschedule() -> bool {
    let cl = cpu_local();
    let pending = cl.pending_trap_reschedule;
    cl.pending_trap_reschedule = false;
    pending
}

/// Record a local unlock-edge scheduling reason for the current vCPU.
/// Caller must hold the scheduler lock.
pub fn request_local_unlock_edge_schedule(reason: ScheduleReason) {
    debug_assert!(KSchedulerLock::is_held());
    let vid = vcpu_id() as usize;
    // SAFETY: caller holds the scheduler lock, so per-vCPU scheduler state is
    // exclusively mutable here.
    let vcpu = unsafe { SCHED.vcpu_raw_mut(vid) };
    vcpu.pending_unlock_edge_reason_code = choose_unlock_edge_reason_code(
        vcpu.pending_unlock_edge_reason_code,
        reason,
    );
}

/// Consume the deferred unlock-edge scheduling reason for `vid`.
/// Caller must hold the scheduler lock.
pub fn take_local_unlock_edge_schedule_reason_locked(vid: usize) -> ScheduleReason {
    // SAFETY: caller holds the scheduler lock and is consuming the selected
    // vCPU's deferred local unlock-edge reason.
    let vcpu = unsafe { SCHED.vcpu_raw_mut(vid) };
    let code = vcpu.pending_unlock_edge_reason_code;
    vcpu.pending_unlock_edge_reason_code = PENDING_UNLOCK_EDGE_REASON_NONE;
    decode_unlock_edge_reason(code).unwrap_or(ScheduleReason::UnlockEdge)
}

/// Request that a remote vCPU rerun its scheduler core.
/// Caller must hold the scheduler lock.
#[inline]
pub fn request_remote_vcpu_reschedule_locked(vid: usize) {
    if vid < MAX_VCPUS {
        // SAFETY: caller holds the scheduler lock, so per-vCPU scheduler state
        // is exclusively mutable here.
        unsafe { SCHED.vcpu_raw_mut(vid) }.pending_remote_reschedule = true;
    }
}

/// Returns whether `vid` has an explicit remote reschedule request pending.
/// Caller must hold the scheduler lock.
#[inline]
pub fn remote_vcpu_reschedule_pending_locked(vid: usize) -> bool {
    if vid >= MAX_VCPUS {
        return false;
    }
    // SAFETY: caller holds the scheduler lock and is only reading stable
    // per-vCPU scheduling intent state.
    unsafe { SCHED.vcpu_raw(vid) }.pending_remote_reschedule
}

/// Clear the explicit remote reschedule request for `vid`.
/// Caller must hold the scheduler lock.
#[inline]
pub fn clear_remote_vcpu_reschedule_locked(vid: usize) {
    if vid < MAX_VCPUS {
        // SAFETY: caller holds the scheduler lock, so per-vCPU scheduler state
        // is exclusively mutable here.
        unsafe { SCHED.vcpu_raw_mut(vid) }.pending_remote_reschedule = false;
    }
}

/// Wake one idle vCPU if possible; otherwise request a remote reschedule on
/// every online vCPU so preemption can occur.
/// Caller must hold the scheduler lock.
pub fn request_remote_reschedule_for_ready_work_locked(
    mut is_idle: impl FnMut(usize) -> bool,
) {
    for vid in 0..MAX_VCPUS {
        if is_idle(vid) {
            request_remote_vcpu_reschedule_locked(vid);
            return;
        }
    }
    for vid in 0..MAX_VCPUS {
        request_remote_vcpu_reschedule_locked(vid);
    }
}
