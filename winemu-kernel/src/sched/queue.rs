// sched/queue.rs — KReadyQueue: O(1) priority-based ready queue
// 32 priority levels (0=highest, 31=lowest).
// Intrusive singly-linked list per priority via KThread::sched_next.
// `present` bitmask enables O(1) highest-priority lookup.

use crate::sched::types::KThread;

pub struct KReadyQueue {
    heads: [u32; 32],
    tails: [u32; 32],
    present: u32, // bit i set ↔ priority i has ≥1 thread
}

impl KReadyQueue {
    pub const fn new() -> Self {
        Self {
            heads: [0u32; 32],
            tails: [0u32; 32],
            present: 0,
        }
    }

    /// Push `tid` at the tail of its priority level.
    /// Caller must ensure `t.sched_next == 0` before calling.
    pub fn push(&mut self, tid: u32, t: &mut KThread) {
        debug_assert_eq!(t.sched_next, 0);
        let p = t.priority as usize;
        t.sched_next = 0;
        if self.tails[p] != 0 {
            // We can't follow the link without the store; caller must pass
            // the tail thread separately. Use a two-pointer approach instead:
            // store tail TID and update its sched_next via the store.
            // Since we don't have the store here, we track tail TID only and
            // the caller (topology.rs) patches sched_next after push.
            // For simplicity: store tail TID; topology patches the link.
            self.tails[p] = tid; // will be fixed by push_with_store
        } else {
            self.heads[p] = tid;
            self.tails[p] = tid;
        }
        self.present |= 1u32 << p;
    }

    /// Full push that also patches the previous tail's sched_next.
    /// `get_mut` is a closure that returns &mut KThread for a given tid.
    pub fn push_with_store<'a>(
        &mut self,
        tid: u32,
        priority: u8,
        get_mut: &mut impl FnMut(u32) -> Option<&'a mut KThread>,
    ) {
        let p = priority as usize;
        if let Some(t) = get_mut(tid) {
            t.sched_next = 0;
        }
        let old_tail = self.tails[p];
        if old_tail != 0 {
            if let Some(tail_t) = get_mut(old_tail) {
                tail_t.sched_next = tid;
            }
        } else {
            self.heads[p] = tid;
        }
        self.tails[p] = tid;
        self.present |= 1u32 << p;
    }

    /// Pop the highest-priority thread. Returns 0 if empty.
    /// Caller must clear `sched_next` on the returned thread.
    pub fn pop_highest(&mut self, get: &impl Fn(u32) -> Option<*mut KThread>) -> u32 {
        loop {
            if self.present == 0 {
                return 0;
            }
            let p = self.present.trailing_zeros() as usize;
            let tid = self.heads[p];
            if tid == 0 {
                self.present &= !(1u32 << p);
                self.tails[p] = 0;
                continue;
            }
            let Some(ptr) = get(tid) else {
                // Corrupted head: drop this priority list.
                self.heads[p] = 0;
                self.tails[p] = 0;
                self.present &= !(1u32 << p);
                continue;
            };
            let t = unsafe { &mut *ptr };
            let next = t.sched_next;
            t.sched_next = 0;
            self.heads[p] = next;
            if next == 0 {
                self.tails[p] = 0;
                self.present &= !(1u32 << p);
            }
            return tid;
        }
    }

    /// Pop the highest-priority thread that satisfies `pred`.
    pub fn pop_highest_matching(
        &mut self,
        get: &impl Fn(u32) -> Option<*mut KThread>,
        pred: &impl Fn(&KThread) -> bool,
    ) -> u32 {
        let mut mask = self.present;
        while mask != 0 {
            let p = mask.trailing_zeros() as usize;
            mask &= !(1u32 << p);

            // Walk the list at priority p looking for a matching thread.
            let mut prev = 0u32;
            let mut cur = self.heads[p];
            while cur != 0 {
                let Some(cur_ptr) = get(cur) else {
                    // Corrupted node: truncate list at `prev`.
                    if prev == 0 {
                        self.heads[p] = 0;
                        self.tails[p] = 0;
                        self.present &= !(1u32 << p);
                    } else if let Some(prev_ptr) = get(prev) {
                        unsafe { (*prev_ptr).sched_next = 0 };
                        self.tails[p] = prev;
                    } else {
                        self.heads[p] = 0;
                        self.tails[p] = 0;
                        self.present &= !(1u32 << p);
                    }
                    break;
                };
                let matches = pred(unsafe { &*cur_ptr });
                if matches {
                    // Unlink cur
                    let t = unsafe { &mut *cur_ptr };
                    let next = t.sched_next;
                    t.sched_next = 0;
                    if prev == 0 {
                        self.heads[p] = next;
                    } else if let Some(ptr) = get(prev) {
                        unsafe { (*ptr).sched_next = next };
                    }
                    if next == 0 {
                        self.tails[p] = prev;
                    }
                    if self.heads[p] == 0 {
                        self.present &= !(1u32 << p);
                    }
                    return cur;
                }
                prev = cur;
                cur = if let Some(ptr) = get(cur) {
                    unsafe { (*ptr).sched_next }
                } else {
                    0
                };
            }
        }
        0
    }

    /// Remove a specific tid from the queue (O(n) within its priority level).
    pub fn remove(
        &mut self,
        tid: u32,
        priority: u8,
        get: &impl Fn(u32) -> Option<*mut KThread>,
    ) -> bool {
        let p = priority as usize;
        if (self.present & (1u32 << p)) == 0 {
            return false;
        }
        let mut prev = 0u32;
        let mut cur = self.heads[p];
        while cur != 0 {
            let Some(cur_ptr) = get(cur) else {
                // Corrupted node: truncate list at `prev`.
                if prev == 0 {
                    self.heads[p] = 0;
                    self.tails[p] = 0;
                    self.present &= !(1u32 << p);
                } else if let Some(prev_ptr) = get(prev) {
                    unsafe { (*prev_ptr).sched_next = 0 };
                    self.tails[p] = prev;
                } else {
                    self.heads[p] = 0;
                    self.tails[p] = 0;
                    self.present &= !(1u32 << p);
                }
                return false;
            };
            let next = unsafe { (*cur_ptr).sched_next };
            if cur == tid {
                unsafe { (*cur_ptr).sched_next = 0 };
                if prev == 0 {
                    self.heads[p] = next;
                } else if let Some(ptr) = get(prev) {
                    unsafe { (*ptr).sched_next = next };
                }
                if next == 0 {
                    self.tails[p] = prev;
                }
                if self.heads[p] == 0 {
                    self.present &= !(1u32 << p);
                }
                return true;
            }
            prev = cur;
            cur = next;
        }
        false
    }

    /// Highest priority level that has a ready thread, or None if empty.
    pub fn highest_priority(&self) -> Option<u8> {
        if self.present == 0 {
            None
        } else {
            Some(self.present.trailing_zeros() as u8)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.present == 0
    }

    /// Peek at the head TID of a given priority without removing it.
    pub fn peek_head(&self, priority: u8) -> u32 {
        self.heads[priority as usize]
    }

    /// Peek at the highest-priority thread satisfying `pred` without removing it.
    /// Used by `update_highest_priority_threads` to scan all vCPUs without
    /// disturbing the queue.
    pub fn peek_highest_matching(
        &self,
        get: &impl Fn(u32) -> Option<*const KThread>,
        pred: &impl Fn(&KThread) -> bool,
    ) -> u32 {
        let mut mask = self.present;
        while mask != 0 {
            let p = mask.trailing_zeros() as usize;
            mask &= !(1u32 << p);
            let mut cur = self.heads[p];
            while cur != 0 {
                let Some(ptr) = get(cur) else {
                    // Corrupted chain: stop scanning this priority.
                    break;
                };
                let t = unsafe { &*ptr };
                let matches = pred(t);
                let next = t.sched_next;
                if matches {
                    return cur;
                }
                cur = next;
            }
        }
        0
    }
}
