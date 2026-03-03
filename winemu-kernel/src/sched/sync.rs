// Guest kernel 同步原语 — EL1
// KEvent, KMutex, KSemaphore, Thread waiters, HandleTable
// 所有状态机在 guest 内完成，不走 HVC。

use crate::kobj::{ObjectStore, SlabPool};
use crate::nt::constants::{
    HANDLE_SLOT_BITS, HANDLE_SLOT_MASK, HANDLE_TYPE_MASK, NTSTATUS_ERROR_BIT,
};
use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use winemu_shared::status;

use super::{
    begin_wait_locked, boost_thread_priority_locked, cancel_wait_locked, clear_wait_tracking_locked,
    current_tid, end_wait_locked, ensure_current_wait_preconditions_locked, prepare_wait_tracking_locked,
    sched_lock_acquire, sched_lock_release, set_thread_priority_locked, set_thread_state_locked, thread_count,
    thread_exists, with_thread, with_thread_mut, ScopedSchedulerLock, ThreadState, MAX_WAIT_HANDLES,
    WAIT_KIND_DELAY, WAIT_KIND_MULTI_ALL, WAIT_KIND_MULTI_ANY, WAIT_KIND_SINGLE,
};

// ── NTSTATUS 常量 ─────────────────────────────────────────────

pub const STATUS_SUCCESS: u32 = status::SUCCESS;
pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_TIMEOUT: u32 = status::TIMEOUT;
pub const STATUS_ABANDONED: u32 = status::ABANDONED_WAIT_0;
pub const STATUS_INVALID_HANDLE: u32 = status::INVALID_HANDLE;
pub const STATUS_INVALID_PARAMETER: u32 = status::INVALID_PARAMETER;
pub const STATUS_MUTANT_NOT_OWNED: u32 = status::MUTANT_NOT_OWNED;
pub const STATUS_SEMAPHORE_LIMIT_EXCEEDED: u32 = status::SEMAPHORE_LIMIT_EXCEEDED;
pub const STATUS_NO_MEMORY: u32 = status::NO_MEMORY;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WaitDeadline {
    Infinite,
    Immediate,
    DeadlineTicks(u64),
}

// ── 拆分实现（按职责）────────────────────────────────────────
// 等待队列节点与按优先级队列操作
include!("sync/wait_queue.rs");
// 同步对象定义与全局状态存储
include!("sync/state.rs");
// HandleTable 与对象引用计数
include!("sync/handles.rs");
// Wait 注册/撤销/唤醒与等待入口
include!("sync/wait_path.rs");
// Event/Mutex/Semaphore 对外 API
include!("sync/primitives_api.rs");
