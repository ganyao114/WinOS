// sched/mod.rs — Scheduler module: pub use exports

pub mod context;
pub mod cpu;
pub mod global;
pub mod lock;
pub mod queue;
pub mod schedule;
pub mod sync;
pub mod thread_control;
pub mod thread_store;
pub mod threads;
pub mod topology;
pub mod types;
pub mod wait;

// ── Re-exports ────────────────────────────────────────────────────────────────

// Types
pub use types::{ThreadState, WaitDeadline, MAX_VCPUS};

// Global scheduler
pub use global::{init_scheduler, thread_exists, with_thread, with_thread_mut, SCHED};

// Per-vCPU TLS
pub use cpu::{current_tid, init_cpu_local, set_needs_reschedule, vcpu_id};

// Scheduler lock
pub use lock::{KSchedulerLock, SCHED_LOCK};

// Topology / state transitions
pub use topology::{
    bind_running_thread_to_vcpu, set_thread_affinity_mask_locked,
};

// Context switch
pub use context::{drain_deferred_kstacks, set_thread_in_kernel_locked};

// Wait / unblock
pub use wait::{
    block_thread_locked, check_wait_timeouts_locked, current_ticks, timeout_to_deadline,
    unblock_thread_locked, STATUS_PENDING, STATUS_SUCCESS,
};

// Thread control
pub use thread_control::{
    resume_thread_locked, set_thread_priority_locked, suspend_thread_locked,
    terminate_thread_locked,
};

// Thread lifecycle
pub use threads::{
    create_boot_thread_for_current_vcpu_locked, create_user_thread_locked, exit_thread_locked,
    prepare_boot_thread_user_entry_locked, terminate_thread_by_tid, thread_ids_by_pid,
    UserThreadParams,
};

// Scheduler core
pub use schedule::{
    enter_current_core_scheduler, enter_kernel_continuation_noreturn,
    execute_kernel_continuation_switch, schedule_core_locked, ScheduleDecision, ScheduleReason,
};

// Sync objects
pub use sync::init_sync_state;

// ── Convenience helpers ───────────────────────────────────────────────────────

/// Wake a waiting thread with the given result code.
/// Convenience wrapper around unblock_thread_locked (requires sched lock).
#[inline]
pub fn wake(tid: u32, result: u32) {
    unblock_thread_locked(tid, result);
}

/// Compute an absolute deadline from a relative timeout in 100ns units.
/// Negative = relative, positive = absolute (Windows convention).
#[inline]
pub fn deadline_after_100ns(timeout_100ns: i64) -> WaitDeadline {
    timeout_to_deadline(timeout_100ns)
}

/// Get the PID of a thread.
pub fn thread_pid(tid: u32) -> u32 {
    with_thread(tid, |t| t.pid).unwrap_or(0)
}

/// Block the current thread and yield to the scheduler.
/// Returns STATUS_PENDING if successfully blocked.
/// Requires sched lock to be held on entry; releases it internally via
/// the caller's lock guard.
pub fn block_current_and_resched(
    wait_kind: u8,
    _handles: &[u64],
    deadline_ticks: u64,
    _pending_status: u32,
) -> u32 {
    let tid = current_tid();
    if tid == 0 {
        return winemu_shared::status::INVALID_PARAMETER;
    }
    let deadline = if deadline_ticks == 0 {
        WaitDeadline::Infinite
    } else {
        WaitDeadline::DeadlineTicks(deadline_ticks)
    };
    with_thread_mut(tid, |t| {
        t.wait.kind = wait_kind;
    });
    block_thread_locked(tid, deadline);
    STATUS_PENDING
}

/// WAIT_KIND constant for hostcall waits.
pub const WAIT_KIND_HOSTCALL: u8 = 4;

/// WAIT_KIND constant for alert waits (NtWaitForAlertByThreadId).
pub const WAIT_KIND_ALERT: u8 = 5;

/// Alert a thread by TID (NtAlertThreadByThreadId).
/// If the thread is waiting in WAIT_KIND_ALERT, wake it with STATUS_ALERTED.
/// Otherwise set its alerted flag so the next wait returns immediately.
pub fn alert_thread_by_tid(tid: u32) -> u32 {
    let _lock = KSchedulerLock::lock();
    let is_waiting = with_thread(tid, |t| {
        t.state == ThreadState::Waiting && t.wait.kind == WAIT_KIND_ALERT
    })
    .unwrap_or(false);
    if is_waiting {
        unblock_thread_locked(tid, winemu_shared::status::ALERTED);
    } else {
        with_thread_mut(tid, |t| {
            t.alerted = true;
        });
    }
    winemu_shared::status::SUCCESS
}

/// Wait for an alert on the current thread (NtWaitForAlertByThreadId).
/// Returns STATUS_ALERTED if already alerted, otherwise blocks.
pub fn wait_for_alert_by_tid(timeout: WaitDeadline) -> u32 {
    use crate::sched::lock::SchedLockAndSleep;
    let tid = current_tid();
    if tid == 0 {
        return winemu_shared::status::INVALID_PARAMETER;
    }
    let status = {
        let mut slp = SchedLockAndSleep::new();
        let already = with_thread(tid, |t| t.alerted).unwrap_or(false);
        if already {
            with_thread_mut(tid, |t| {
                t.alerted = false;
            });
            slp.cancel();
            winemu_shared::status::ALERTED
        } else {
            with_thread_mut(tid, |t| {
                t.wait.kind = WAIT_KIND_ALERT;
            });
            block_thread_locked(tid, timeout);
            STATUS_PENDING
        }
    };
    if status == STATUS_PENDING {
        loop {
            let (state, r) = with_thread(tid, |t| (t.state, t.wait.result))
                .unwrap_or((ThreadState::Terminated, winemu_shared::status::ALERTED));
            if state != ThreadState::Waiting {
                break r;
            }
            let mut slp = SchedLockAndSleep::new();
            let state2 = with_thread(tid, |t| t.state).unwrap_or(ThreadState::Terminated);
            if state2 != ThreadState::Waiting {
                slp.cancel();
            }
            drop(slp);
        }
    } else {
        status
    }
}
