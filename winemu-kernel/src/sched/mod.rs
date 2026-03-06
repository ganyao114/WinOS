// sched/mod.rs — 调度器根模块

pub mod sync;
pub mod types;
pub mod global;
pub mod queue;
pub mod thread_store;
pub mod cpu;
pub mod lock;
pub mod context;
pub mod topology;
pub mod wait;
pub mod thread_control;
pub mod threads;
pub mod schedule;

// ── 重新导出公共 API ──────────────────────────────────────────

pub use types::{
    KernelContext, ThreadContext, ThreadState,
    MAX_VCPUS, MAX_WAIT_HANDLES, WAIT_KIND_HOSTCALL,
};

pub use thread_store::{thread_exists, with_thread, with_thread_mut};

pub use cpu::{current_tid, vcpu_id};

pub use lock::{sched_lock_acquire, sched_lock_release, ScopedSchedulerLock};

pub use context::{
    has_kernel_continuation, set_thread_in_kernel, set_current_in_kernel,
    migrate_svc_frame_to_current_kstack, execute_kernel_continuation_switch,
    enter_kernel_continuation_noreturn,
};

// pub(crate) re-exports used by dispatch.rs and other nt/ callers
pub(crate) use topology::{
    set_thread_state_locked, set_vcpu_idle_locked,
    record_schedule_event_trap,
};
pub(crate) use wait::next_wait_deadline_locked;
pub(crate) use schedule::{SchedulerRoundAction, scheduler_round_locked};

pub use wait::{block_current_and_resched, check_timeouts, deadline_after_100ns, now_ticks};

pub use thread_control::{
    resolve_thread_tid_from_handle, resume_thread_by_handle,
    set_thread_base_priority_by_handle, suspend_thread_by_handle,
};

pub use threads::{
    create_user_thread, terminate_thread_by_tid,
    thread_basic_info, thread_pid, thread_ids_by_pid,
    reclaim_deferred_kernel_stacks, CreateThreadError,
};

pub use self::schedule::{
    wake, yield_current_thread, terminate_current_thread,
    register_thread0, set_current_thread_teb,
    enter_core_scheduler_entry, all_threads_done, register_idle_thread_for_vcpu,
};
