// sched/sync/wait_queue.rs — Priority-sorted intrusive wait queue
//
// Uses KThread::wait.wait_next as the intrusive link (TID-based, no raw ptrs).
// Sorted by priority (ascending = highest priority first).

use crate::sched::global::{with_thread, with_thread_mut};
use crate::sched::wait::unblock_thread_locked;
use crate::sched::wait::STATUS_SUCCESS;

pub struct WaitQueue {
    /// Head TID of the priority-sorted list (0 = empty).
    head: u32,
    len:  usize,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self { head: 0, len: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.head == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Insert `tid` in priority order (highest priority = lowest number = front).
    pub fn enqueue(&mut self, tid: u32) {
        let prio = with_thread(tid, |t| t.priority).unwrap_or(31);

        // Find insertion point.
        let mut prev = 0u32;
        let mut cur  = self.head;
        while cur != 0 {
            let cur_prio = with_thread(cur, |t| t.priority).unwrap_or(31);
            if prio < cur_prio {
                break; // insert before cur
            }
            prev = cur;
            cur  = with_thread(cur, |t| t.wait.wait_next).unwrap_or(0);
        }

        // Link tid → cur.
        with_thread_mut(tid, |t| t.wait.wait_next = cur);

        if prev == 0 {
            self.head = tid;
        } else {
            with_thread_mut(prev, |t| t.wait.wait_next = tid);
        }
        self.len += 1;
    }

    /// Remove and return the highest-priority (front) TID.
    pub fn dequeue_highest(&mut self) -> Option<u32> {
        if self.head == 0 {
            return None;
        }
        let tid  = self.head;
        let next = with_thread(tid, |t| t.wait.wait_next).unwrap_or(0);
        with_thread_mut(tid, |t| t.wait.wait_next = 0);
        self.head = next;
        self.len  = self.len.saturating_sub(1);
        Some(tid)
    }

    /// Remove a specific TID from the queue. Returns true if found.
    pub fn remove(&mut self, tid: u32) -> bool {
        let mut prev = 0u32;
        let mut cur  = self.head;
        while cur != 0 {
            let next = with_thread(cur, |t| t.wait.wait_next).unwrap_or(0);
            if cur == tid {
                if prev == 0 {
                    self.head = next;
                } else {
                    with_thread_mut(prev, |t| t.wait.wait_next = next);
                }
                with_thread_mut(tid, |t| t.wait.wait_next = 0);
                self.len = self.len.saturating_sub(1);
                return true;
            }
            prev = cur;
            cur  = next;
        }
        false
    }

    /// Wake all waiters with STATUS_SUCCESS.
    pub fn wake_all(&mut self) {
        while let Some(tid) = self.dequeue_highest() {
            unblock_thread_locked(tid, STATUS_SUCCESS);
        }
    }

    /// Wake all waiters with the provided wait result.
    pub fn wake_all_with_status(&mut self, status: u32) {
        while let Some(tid) = self.dequeue_highest() {
            unblock_thread_locked(tid, status);
        }
    }

    /// Peek at the highest-priority waiter's priority, if any.
    pub fn highest_priority(&self) -> Option<u8> {
        with_thread(self.head, |t| t.priority)
    }
}
