// sched/queue.rs — KReadyQueue with scheduled + suggested per-vCPU queues
//
// `scheduled[core]` contains threads whose current home core is `core`.
// `suggested[core]` contains migratable threads that are currently homed on a
// different core but may be stolen by `core`.

use crate::sched::types::{CpuMask, KThread, MAX_VCPUS};

#[derive(Clone, Copy)]
pub struct ReadyQueueShape {
    pub home_core: usize,
    pub affinity_mask: CpuMask,
    pub priority: u8,
    pub allow_migration: bool,
}

#[derive(Clone, Copy)]
pub struct ReadyQueueCandidate {
    pub tid: u32,
    pub source_core: usize,
    pub requires_migration: bool,
}

#[derive(Clone, Copy)]
enum QueueLane {
    Scheduled,
    Suggested(usize),
}

#[inline]
fn link_ref(thread: &KThread, lane: QueueLane) -> u32 {
    match lane {
        QueueLane::Scheduled => thread.scheduled_next,
        QueueLane::Suggested(core) => thread.suggested_next[core],
    }
}

#[inline]
fn set_link(thread: &mut KThread, lane: QueueLane, next: u32) {
    match lane {
        QueueLane::Scheduled => thread.scheduled_next = next,
        QueueLane::Suggested(core) => thread.suggested_next[core] = next,
    }
}

pub struct PerVcpuPriorityQueue {
    heads: [[u32; 32]; MAX_VCPUS],
    tails: [[u32; 32]; MAX_VCPUS],
    present: [u32; MAX_VCPUS],
}

impl PerVcpuPriorityQueue {
    pub const fn new() -> Self {
        Self {
            heads: [[0u32; 32]; MAX_VCPUS],
            tails: [[0u32; 32]; MAX_VCPUS],
            present: [0u32; MAX_VCPUS],
        }
    }

    #[inline]
    pub fn highest_priority(&self, core: usize) -> Option<u8> {
        let present = self.present[core];
        if present == 0 {
            None
        } else {
            Some(present.trailing_zeros() as u8)
        }
    }

    #[inline]
    pub fn peek_front(&self, core: usize) -> u32 {
        self.highest_priority(core)
            .map(|priority| self.heads[core][priority as usize])
            .unwrap_or(0)
    }

    fn next_after(
        &self,
        core: usize,
        priority: u8,
        tid: u32,
        lane: QueueLane,
        get: &impl Fn(u32) -> Option<*const KThread>,
    ) -> u32 {
        let Some(ptr) = get(tid) else {
            return 0;
        };
        // SAFETY: `get` returns pointers into the scheduler-owned thread store.
        // Callers hold the scheduler lock while traversing queue links, so this
        // immutable read sees a stable queue node.
        let thread = unsafe { &*ptr };
        let next = link_ref(thread, lane);
        if next != 0 {
            return next;
        }

        for next_priority in (priority as usize + 1)..32 {
            let head = self.heads[core][next_priority];
            if head != 0 {
                return head;
            }
        }

        0
    }

    fn push_back<'a>(
        &mut self,
        core: usize,
        priority: u8,
        tid: u32,
        lane: QueueLane,
        get_mut: &mut impl FnMut(u32) -> Option<&'a mut KThread>,
    ) {
        let p = priority as usize;
        if let Some(thread) = get_mut(tid) {
            set_link(thread, lane, 0);
        }

        let old_tail = self.tails[core][p];
        if old_tail != 0 {
            if let Some(tail_thread) = get_mut(old_tail) {
                set_link(tail_thread, lane, tid);
            }
        } else {
            self.heads[core][p] = tid;
        }

        self.tails[core][p] = tid;
        self.present[core] |= 1u32 << p;
    }

    fn remove(
        &mut self,
        core: usize,
        priority: u8,
        tid: u32,
        lane: QueueLane,
        get: &impl Fn(u32) -> Option<*mut KThread>,
    ) -> bool {
        let p = priority as usize;
        if (self.present[core] & (1u32 << p)) == 0 {
            return false;
        }

        let mut prev = 0u32;
        let mut cur = self.heads[core][p];
        while cur != 0 {
            let Some(cur_ptr) = get(cur) else {
                self.truncate_from_corruption(core, p, prev, lane, get);
                return false;
            };

            // SAFETY: `get` returns pointers into the scheduler-owned thread
            // store while the scheduler lock is held, so this mutable access is
            // exclusive for queue-link maintenance.
            let cur_thread = unsafe { &mut *cur_ptr };
            let next = link_ref(cur_thread, lane);
            if cur == tid {
                set_link(cur_thread, lane, 0);
                if prev == 0 {
                    self.heads[core][p] = next;
                } else if let Some(prev_ptr) = get(prev) {
                    // SAFETY: same scheduler-lock guarantee as above.
                    let prev_thread = unsafe { &mut *prev_ptr };
                    set_link(prev_thread, lane, next);
                }
                if next == 0 {
                    self.tails[core][p] = prev;
                }
                if self.heads[core][p] == 0 {
                    self.present[core] &= !(1u32 << p);
                }
                return true;
            }
            prev = cur;
            cur = next;
        }

        false
    }

    fn truncate_from_corruption(
        &mut self,
        core: usize,
        priority: usize,
        prev: u32,
        lane: QueueLane,
        get: &impl Fn(u32) -> Option<*mut KThread>,
    ) {
        if prev == 0 {
            self.heads[core][priority] = 0;
            self.tails[core][priority] = 0;
            self.present[core] &= !(1u32 << priority);
        } else if let Some(prev_ptr) = get(prev) {
            // SAFETY: `get` returns pointers into the scheduler-owned thread
            // store while the scheduler lock is held, so truncating the link is
            // exclusive and valid here.
            let prev_thread = unsafe { &mut *prev_ptr };
            set_link(prev_thread, lane, 0);
            self.tails[core][priority] = prev;
        } else {
            self.heads[core][priority] = 0;
            self.tails[core][priority] = 0;
            self.present[core] &= !(1u32 << priority);
        }
    }
}

pub struct KReadyQueue {
    scheduled: PerVcpuPriorityQueue,
    suggested: PerVcpuPriorityQueue,
}

impl KReadyQueue {
    pub const fn new() -> Self {
        Self {
            scheduled: PerVcpuPriorityQueue::new(),
            suggested: PerVcpuPriorityQueue::new(),
        }
    }

    fn enqueue_shape<'a>(
        &mut self,
        tid: u32,
        shape: ReadyQueueShape,
        get_mut: &mut impl FnMut(u32) -> Option<&'a mut KThread>,
    ) {
        self.scheduled.push_back(
            shape.home_core,
            shape.priority,
            tid,
            QueueLane::Scheduled,
            get_mut,
        );

        if !shape.allow_migration {
            return;
        }

        for core in shape
            .affinity_mask
            .difference(CpuMask::from_cpu(shape.home_core))
            .iter_set()
        {
            self.suggested.push_back(
                core,
                shape.priority,
                tid,
                QueueLane::Suggested(core),
                get_mut,
            );
        }
    }

    fn remove_shape(
        &mut self,
        tid: u32,
        shape: ReadyQueueShape,
        get: &impl Fn(u32) -> Option<*mut KThread>,
    ) -> bool {
        let mut removed = self.scheduled.remove(
            shape.home_core,
            shape.priority,
            tid,
            QueueLane::Scheduled,
            get,
        );

        if shape.allow_migration {
            for core in shape
                .affinity_mask
                .difference(CpuMask::from_cpu(shape.home_core))
                .iter_set()
            {
                removed |= self.suggested.remove(
                    core,
                    shape.priority,
                    tid,
                    QueueLane::Suggested(core),
                    get,
                );
            }
        }

        removed
    }

    fn change_shape<'a>(
        &mut self,
        tid: u32,
        old_shape: ReadyQueueShape,
        new_shape: ReadyQueueShape,
        get: &impl Fn(u32) -> Option<*mut KThread>,
        get_mut: &mut impl FnMut(u32) -> Option<&'a mut KThread>,
    ) -> bool {
        if !self.remove_shape(tid, old_shape, get) {
            return false;
        }
        self.enqueue_shape(tid, new_shape, get_mut);
        true
    }

    pub fn enqueue<'a>(
        &mut self,
        tid: u32,
        shape: ReadyQueueShape,
        get_mut: &mut impl FnMut(u32) -> Option<&'a mut KThread>,
    ) {
        self.enqueue_shape(tid, shape, get_mut);
    }

    pub fn remove(
        &mut self,
        tid: u32,
        shape: ReadyQueueShape,
        get: &impl Fn(u32) -> Option<*mut KThread>,
    ) -> bool {
        self.remove_shape(tid, shape, get)
    }

    pub fn change_priority<'a>(
        &mut self,
        tid: u32,
        old_priority: u8,
        new_shape: ReadyQueueShape,
        get: &impl Fn(u32) -> Option<*mut KThread>,
        get_mut: &mut impl FnMut(u32) -> Option<&'a mut KThread>,
    ) -> bool {
        let old_shape = ReadyQueueShape {
            priority: old_priority,
            ..new_shape
        };
        self.change_shape(tid, old_shape, new_shape, get, get_mut)
    }

    pub fn change_affinity<'a>(
        &mut self,
        tid: u32,
        old_shape: ReadyQueueShape,
        new_shape: ReadyQueueShape,
        get: &impl Fn(u32) -> Option<*mut KThread>,
        get_mut: &mut impl FnMut(u32) -> Option<&'a mut KThread>,
    ) -> bool {
        self.change_shape(tid, old_shape, new_shape, get, get_mut)
    }

    pub fn peek_candidate_for_core(
        &self,
        core: usize,
        get: &impl Fn(u32) -> Option<*const KThread>,
    ) -> Option<ReadyQueueCandidate> {
        let scheduled = self.scheduled.peek_front(core);
        if scheduled != 0 {
            return Some(ReadyQueueCandidate {
                tid: scheduled,
                source_core: core,
                requires_migration: false,
            });
        }

        let mut suggested = self.suggested.peek_front(core);
        while suggested != 0 {
            let Some(ptr) = get(suggested) else {
                return None;
            };
            // SAFETY: callers hold the scheduler lock while inspecting ready
            // queue candidates, so the thread store pointer is stable here.
            let thread = unsafe { &*ptr };
            let source_core = thread.ready_home_vcpu();
            let source_front = self.scheduled.peek_front(source_core);
            if source_front != suggested {
                return Some(ReadyQueueCandidate {
                    tid: suggested,
                    source_core,
                    requires_migration: true,
                });
            }

            let next_on_source = self.scheduled.next_after(
                source_core,
                thread.priority,
                suggested,
                QueueLane::Scheduled,
                get,
            );
            if next_on_source != 0 {
                return Some(ReadyQueueCandidate {
                    tid: suggested,
                    source_core,
                    requires_migration: true,
                });
            }

            suggested = self.suggested.next_after(
                core,
                thread.priority,
                suggested,
                QueueLane::Suggested(core),
                get,
            );
        }

        None
    }
}
