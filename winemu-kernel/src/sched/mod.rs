// sched/mod.rs — Scheduler module: pub use exports

pub mod types;
pub mod thread_store;
pub mod global;
pub mod cpu;
pub mod lock;
pub mod queue;
pub mod topology;
pub mod context;
pub mod wait;
pub mod thread_control;
pub mod threads;
pub mod schedule;
pub mod sync;

// ── Re-exports ────────────────────────────────────────────────────────────────

// Types
pub use types::{
    ThreadState, ThreadContext, KernelContext, KThread, WaitState, WaitDeadline,
    alloc_tid, MAX_VCPUS, KERNEL_STACK_SIZE,
    WAIT_KIND_NONE, WAIT_KIND_SINGLE, WAIT_KIND_MULTIPLE, WAIT_KIND_DELAY,
};

// Global scheduler
pub use global::{
    SCHED, init_scheduler, with_thread, with_thread_mut, thread_exists,
    KGlobalScheduler, KVcpuState,
};

// Per-vCPU TLS
pub use cpu::{
    init_cpu_local, cpu_local, vcpu_id, current_tid, set_current_tid,
    set_needs_reschedule, take_needs_reschedule,
};

// Scheduler lock
pub use lock::{
    KSchedulerLock, SchedSpinlock, SCHED_LOCK,
    with_sched_lock, with_sched_lock_vid0,
    SchedLockAndSleep,
};

// Ready queue
pub use queue::KReadyQueue;

// Topology / state transitions
pub use topology::{
    set_thread_state_locked, request_reschedule_self, request_reschedule_vcpu,
    hint_reschedule_any_idle, thread_can_run_on, pick_vcpu_for_thread,
    set_vcpu_current_thread, get_vcpu_current_thread,
    any_thread_running, all_threads_done,
};

// Context switch
pub use context::{
    ensure_user_entry_continuation_locked, setup_idle_thread_continuation_locked,
    set_thread_in_kernel_locked, alloc_kstack, free_kstack,
    defer_kstack_free, drain_deferred_kstacks,
};

// Wait / unblock
pub use wait::{
    block_thread_locked, block_thread_delay_locked,
    unblock_thread_locked, timeout_thread_locked,
    check_wait_timeouts_locked, current_ticks, timeout_to_deadline,
    STATUS_SUCCESS, STATUS_PENDING, STATUS_TIMEOUT,
    STATUS_ABANDONED_WAIT_0, STATUS_USER_APC,
};

// Thread control
pub use thread_control::{
    set_thread_priority_locked, boost_thread_priority_locked,
    decay_priority_boost_locked, suspend_thread_locked, resume_thread_locked,
    terminate_thread_locked, reset_quantum_locked, consume_quantum_locked,
    DEFAULT_QUANTUM_100NS,
};

// Thread lifecycle
pub use threads::{
    spawn_locked, create_user_thread_locked, register_idle_thread_for_vcpu,
    exit_thread_locked, free_terminated_threads_locked, UserThreadParams,
};

// Scheduler core
pub use schedule::{
    scheduler_round_locked, run_selected_thread_noreturn,
    schedule_noreturn_locked, schedule_from_trap,
    enter_core_scheduler_entry, idle_thread_fn_impl,
    flush_unlock_edge, reschedule_current_core,
    enable_scheduling, update_highest_priority_threads,
    enter_kernel_continuation_noreturn,
};

// Sync objects
pub use sync::{
    WaitQueue, KEvent, KMutex, KSemaphore, SyncObject,
    init_sync_state,
    create_event, set_event, reset_event,
    create_mutex, release_mutex,
    create_semaphore, release_semaphore,
    wait_for_single_object, wait_for_multiple_objects,
    close_handle,
};
