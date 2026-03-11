// sched/sync/primitives_api.rs — KEvent, KMutex, KSemaphore
//
// All methods require the scheduler lock to be held.

use crate::sched::global::with_thread;
use crate::sched::sync::wait_queue::WaitQueue;
use crate::sched::thread_control::{boost_thread_priority_locked, set_thread_priority_locked};
use crate::sched::types::WaitDeadline;
use crate::sched::wait::{
    block_thread_locked, unblock_thread_locked, STATUS_ABANDONED_WAIT_0, STATUS_PENDING,
    STATUS_SUCCESS, STATUS_TIMEOUT,
};

pub const STATUS_MUTANT_NOT_OWNED: u32 = 0xC000_0046;
pub const STATUS_SEMAPHORE_LIMIT_EXCEEDED: u32 = 0xC000_0047;

// ── KEvent ────────────────────────────────────────────────────────────────────

pub struct KEvent {
    pub signaled: bool,
    pub auto_reset: bool,
    pub waiters: WaitQueue,
}

impl KEvent {
    pub const fn new(auto_reset: bool, initial_state: bool) -> Self {
        Self {
            signaled: initial_state,
            auto_reset,
            waiters: WaitQueue::new(),
        }
    }

    /// Signal the event. Wakes waiters according to reset mode.
    pub fn signal(&mut self) {
        self.signaled = true;
        if self.auto_reset {
            // Wake exactly one waiter and consume the signal.
            if let Some(tid) = self.waiters.dequeue_highest() {
                unblock_thread_locked(tid, STATUS_SUCCESS);
                self.signaled = false;
            }
            // If no waiters, signal stays set for the next wait().
        } else {
            // Manual-reset: wake all waiters, signal stays set.
            self.waiters.wake_all();
        }
    }

    /// Clear the event (NtResetEvent).
    pub fn clear(&mut self) {
        self.signaled = false;
    }

    /// Wait on the event. Returns STATUS_SUCCESS if already signaled,
    /// STATUS_TIMEOUT if deadline==Immediate, or STATUS_PENDING if the thread
    /// was enqueued — the caller must read wait.result after being unblocked.
    pub fn wait(&mut self, tid: u32, deadline: WaitDeadline) -> u32 {
        if self.signaled {
            if self.auto_reset {
                self.signaled = false;
            }
            return STATUS_SUCCESS;
        }
        if deadline == WaitDeadline::Immediate {
            return STATUS_TIMEOUT;
        }
        self.waiters.enqueue(tid);
        block_thread_locked(tid, deadline);
        STATUS_PENDING
    }

    pub fn is_signaled(&self) -> bool {
        self.signaled
    }
}

// ── KMutex ────────────────────────────────────────────────────────────────────

pub struct KMutex {
    pub owner_tid: u32,
    pub recursion: u32,
    pub waiters: WaitQueue,
    /// Priority the owner had before any inheritance boost.
    saved_owner_priority: u8,
}

impl KMutex {
    pub const fn new() -> Self {
        Self {
            owner_tid: 0,
            recursion: 0,
            waiters: WaitQueue::new(),
            saved_owner_priority: 31,
        }
    }

    /// Acquire the mutex. Blocks if owned by another thread.
    pub fn acquire(&mut self, tid: u32, deadline: WaitDeadline) -> u32 {
        if self.owner_tid == 0 {
            self.owner_tid = tid;
            self.recursion = 1;
            self.saved_owner_priority = with_thread(tid, |t| t.priority).unwrap_or(8);
            return STATUS_SUCCESS;
        }
        if self.owner_tid == tid {
            self.recursion += 1;
            return STATUS_SUCCESS;
        }
        // Priority inheritance: boost owner to max(owner_prio, waiter_prio).
        let waiter_prio = with_thread(tid, |t| t.priority).unwrap_or(8);
        let owner_prio = with_thread(self.owner_tid, |t| t.priority).unwrap_or(8);
        if waiter_prio < owner_prio {
            boost_thread_priority_locked(self.owner_tid, owner_prio - waiter_prio);
        }
        if deadline == WaitDeadline::Immediate {
            return STATUS_TIMEOUT;
        }
        self.waiters.enqueue(tid);
        block_thread_locked(tid, deadline);
        STATUS_PENDING
    }

    /// Release the mutex. Transfers ownership to the highest-priority waiter.
    pub fn release(&mut self, tid: u32) -> u32 {
        if self.owner_tid != tid {
            return STATUS_MUTANT_NOT_OWNED;
        }
        self.recursion -= 1;
        if self.recursion > 0 {
            return STATUS_SUCCESS;
        }
        // Restore owner's original priority.
        set_thread_priority_locked(tid, self.saved_owner_priority);
        self.owner_tid = 0;

        if let Some(next) = self.waiters.dequeue_highest() {
            self.owner_tid = next;
            self.recursion = 1;
            self.saved_owner_priority = with_thread(next, |t| t.priority).unwrap_or(8);
            unblock_thread_locked(next, STATUS_SUCCESS);
        }
        STATUS_SUCCESS
    }

    pub fn is_owned_by(&self, tid: u32) -> bool {
        self.owner_tid == tid
    }

    /// Called when the owning thread terminates without releasing.
    pub fn abandon(&mut self) {
        self.owner_tid = 0;
        self.recursion = 0;
        if let Some(next) = self.waiters.dequeue_highest() {
            self.owner_tid = next;
            self.recursion = 1;
            unblock_thread_locked(next, STATUS_ABANDONED_WAIT_0);
        }
    }
}

// ── KSemaphore ────────────────────────────────────────────────────────────────

pub struct KSemaphore {
    pub count: i32,
    pub max_count: i32,
    pub waiters: WaitQueue,
}

impl KSemaphore {
    pub const fn new(initial: i32, maximum: i32) -> Self {
        Self {
            count: initial,
            max_count: maximum,
            waiters: WaitQueue::new(),
        }
    }

    /// Release `count` units. Wakes waiting threads.
    pub fn release(&mut self, count: i32) -> u32 {
        if self.count + count > self.max_count {
            return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
        }
        self.count += count;
        while self.count > 0 {
            let Some(tid) = self.waiters.dequeue_highest() else {
                break;
            };
            self.count -= 1;
            unblock_thread_locked(tid, STATUS_SUCCESS);
        }
        STATUS_SUCCESS
    }

    /// Wait for a unit. Blocks if count == 0.
    /// Returns STATUS_SUCCESS if immediately available, STATUS_TIMEOUT if
    /// deadline==Immediate, or STATUS_PENDING — caller reads wait.result after wakeup.
    pub fn wait(&mut self, tid: u32, deadline: WaitDeadline) -> u32 {
        if self.count > 0 {
            self.count -= 1;
            return STATUS_SUCCESS;
        }
        if deadline == WaitDeadline::Immediate {
            return STATUS_TIMEOUT;
        }
        self.waiters.enqueue(tid);
        block_thread_locked(tid, deadline);
        STATUS_PENDING
    }

    pub fn current_count(&self) -> i32 {
        self.count
    }
}
