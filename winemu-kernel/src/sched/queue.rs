// sched/queue.rs — KReadyQueue: 单一优先级队列（32级 bitset O(1)）
// 当前实现：单队列 + last_vcpu_hint 区分 scheduled/suggested
// 与旧 ReadyQueue 接口兼容，供 topology 逻辑调用

use super::thread_store::{thread_exists, with_thread, with_thread_mut};

pub struct KReadyQueue {
    heads: [u32; 32],
    tails: [u32; 32],
    /// bit i = 1 表示优先级 i 有就绪线程（NT 优先级 31 最高）
    present: u32,
}

impl KReadyQueue {
    pub const fn new() -> Self {
        Self {
            heads: [0u32; 32],
            tails: [0u32; 32],
            present: 0,
        }
    }

    pub fn push(&mut self, tid: u32, priority: u8, sched_next_setter: impl FnOnce()) {
        let p = priority as usize;
        sched_next_setter();
        if self.tails[p] != 0 {
            let tail_tid = self.tails[p];
            if thread_exists(tail_tid) {
                with_thread_mut(tail_tid, |tail| tail.sched_next = tid);
            } else {
                self.heads[p] = tid;
            }
        } else {
            self.heads[p] = tid;
        }
        self.tails[p] = tid;
        self.present |= 1 << p;
    }

    pub fn push_thread(&mut self, tid: u32, priority: u8) {
        let p = priority as usize;
        with_thread_mut(tid, |t| t.sched_next = 0);
        if self.tails[p] != 0 {
            let tail_tid = self.tails[p];
            if thread_exists(tail_tid) {
                with_thread_mut(tail_tid, |tail| tail.sched_next = tid);
            } else {
                self.heads[p] = tid;
            }
        } else {
            self.heads[p] = tid;
        }
        self.tails[p] = tid;
        self.present |= 1 << p;
    }

    pub fn pop_highest(&mut self) -> u32 {
        while self.present != 0 {
            let p = 31 - self.present.leading_zeros() as usize;
            let tid = self.heads[p];
            if tid == 0 || !thread_exists(tid) {
                self.heads[p] = 0;
                self.tails[p] = 0;
                self.present &= !(1u32 << p);
                continue;
            }
            let mut next = with_thread(tid, |t| t.sched_next);
            if next != 0 && !thread_exists(next) {
                next = 0;
                with_thread_mut(tid, |t| t.sched_next = 0);
            }
            self.heads[p] = next;
            if next == 0 {
                self.tails[p] = 0;
                self.present &= !(1u32 << p);
            }
            with_thread_mut(tid, |t| t.sched_next = 0);
            return tid;
        }
        0
    }

    pub fn pop_highest_matching<F>(&mut self, mut matcher: F) -> u32
    where
        F: FnMut(u32) -> bool,
    {
        let mut present = self.present;
        while present != 0 {
            let p = 31 - present.leading_zeros() as usize;
            let mut prev = 0u32;
            let mut cur = self.heads[p];
            while cur != 0 {
                let mut next = if thread_exists(cur) {
                    with_thread(cur, |t| t.sched_next)
                } else {
                    0
                };
                if next != 0 && !thread_exists(next) {
                    next = 0;
                }
                if !thread_exists(cur) {
                    if prev == 0 {
                        self.heads[p] = next;
                    } else {
                        with_thread_mut(prev, |t| t.sched_next = next);
                    }
                    if next == 0 {
                        self.tails[p] = prev;
                    }
                    cur = next;
                    continue;
                }
                if matcher(cur) {
                    if prev == 0 {
                        self.heads[p] = next;
                    } else {
                        with_thread_mut(prev, |t| t.sched_next = next);
                    }
                    if next == 0 {
                        self.tails[p] = prev;
                    }
                    if self.heads[p] == 0 {
                        self.present &= !(1u32 << p);
                    }
                    with_thread_mut(cur, |t| t.sched_next = 0);
                    return cur;
                }
                prev = cur;
                cur = next;
            }
            if self.heads[p] == 0 {
                self.present &= !(1u32 << p);
            }
            present &= !(1u32 << p);
        }
        0
    }

    pub fn highest_priority_matching<F>(&self, mut matcher: F) -> Option<u8>
    where
        F: FnMut(u32) -> bool,
    {
        let mut present = self.present;
        while present != 0 {
            let p = 31 - present.leading_zeros() as usize;
            let mut cur = self.heads[p];
            while cur != 0 {
                if !thread_exists(cur) {
                    break;
                }
                if matcher(cur) {
                    return Some(p as u8);
                }
                let mut next = with_thread(cur, |t| t.sched_next);
                if next != 0 && !thread_exists(next) {
                    next = 0;
                }
                cur = next;
            }
            present &= !(1u32 << p);
        }
        None
    }

    pub fn highest_priority(&self) -> Option<u8> {
        if self.present == 0 {
            None
        } else {
            Some((31 - self.present.leading_zeros() as usize) as u8)
        }
    }

    pub fn remove(&mut self, tid: u32) {
        for p in 0..32usize {
            let mut prev = 0u32;
            let mut cur = self.heads[p];
            while cur != 0 {
                if !thread_exists(cur) {
                    if prev == 0 {
                        self.heads[p] = 0;
                        self.tails[p] = 0;
                    } else {
                        with_thread_mut(prev, |t| t.sched_next = 0);
                        self.tails[p] = prev;
                    }
                    self.present &= !(1u32 << p);
                    break;
                }
                let mut next = with_thread(cur, |t| t.sched_next);
                if next != 0 && !thread_exists(next) {
                    next = 0;
                    with_thread_mut(cur, |t| t.sched_next = 0);
                }
                if cur == tid {
                    if prev == 0 {
                        self.heads[p] = next;
                    } else {
                        with_thread_mut(prev, |t| t.sched_next = next);
                    }
                    if next == 0 {
                        self.tails[p] = prev;
                    }
                    if self.heads[p] == 0 {
                        self.present &= !(1u32 << p);
                    }
                    with_thread_mut(cur, |t| t.sched_next = 0);
                    return;
                }
                prev = cur;
                cur = next;
            }
        }
    }
}
