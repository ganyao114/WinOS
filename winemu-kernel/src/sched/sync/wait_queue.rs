// ── 等待队列（slab 节点池，按优先级排序）───────────────────────

struct WaitQueueNode {
    tid: u32,
    next: *mut WaitQueueNode,
}

fn wait_queue_alloc_node(tid: u32, next: *mut WaitQueueNode) -> *mut WaitQueueNode {
    if tid == 0 {
        return null_mut();
    }
    let pool_slot = wait_queue_pool_mut();
    if pool_slot.is_none() {
        *pool_slot = Some(SlabPool::new());
    }
    let Some(ptr) = pool_slot.as_mut().unwrap().alloc_slot() else {
        return null_mut();
    };
    unsafe {
        ptr.write(WaitQueueNode { tid, next });
    }
    ptr
}

fn wait_queue_free_node(node: *mut WaitQueueNode) {
    if node.is_null() {
        return;
    }
    let Some(pool) = wait_queue_pool_mut().as_mut() else {
        return;
    };
    unsafe {
        core::ptr::drop_in_place(node);
        pool.free_slot(node);
    }
}

#[inline]
fn waiter_priority(tid: u32) -> u8 {
    if tid == 0 || !thread_exists(tid) {
        0
    } else {
        with_thread(tid, |t| t.priority)
    }
}

pub struct WaitQueue {
    head: *mut WaitQueueNode,
    len: usize,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            head: null_mut(),
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn enqueue(&mut self, tid: u32) -> bool {
        if tid == 0 {
            return false;
        }
        let prio = waiter_priority(tid);
        let mut prev: *mut WaitQueueNode = null_mut();
        let mut cur = self.head;
        while !cur.is_null() {
            let cur_tid = unsafe { (*cur).tid };
            if cur_tid == tid {
                return true;
            }
            let cur_prio = waiter_priority(cur_tid);
            if prio > cur_prio {
                break;
            }
            prev = cur;
            cur = unsafe { (*cur).next };
        }

        let node = wait_queue_alloc_node(tid, cur);
        if node.is_null() {
            return false;
        }
        if prev.is_null() {
            self.head = node;
        } else {
            unsafe {
                (*prev).next = node;
            }
        }
        self.len = self.len.saturating_add(1);
        true
    }

    pub fn dequeue_waiting(&mut self) -> u32 {
        while !self.head.is_null() {
            let node = self.head;
            let tid = unsafe { (*node).tid };
            self.head = unsafe { (*node).next };
            wait_queue_free_node(node);
            if self.len != 0 {
                self.len -= 1;
            }
            if tid != 0
                && thread_exists(tid)
                && with_thread(tid, |t| t.state == ThreadState::Waiting)
            {
                return tid;
            }
        }
        0
    }

    pub fn remove(&mut self, tid: u32) {
        if tid == 0 || self.head.is_null() {
            return;
        }
        let mut prev: *mut WaitQueueNode = null_mut();
        let mut cur = self.head;
        while !cur.is_null() {
            let cur_tid = unsafe { (*cur).tid };
            let next = unsafe { (*cur).next };
            if cur_tid == tid {
                if prev.is_null() {
                    self.head = next;
                } else {
                    unsafe {
                        (*prev).next = next;
                    }
                }
                wait_queue_free_node(cur);
                if self.len != 0 {
                    self.len -= 1;
                }
                return;
            }
            prev = cur;
            cur = next;
        }
    }

    pub fn highest_waiting_priority(&self) -> Option<u8> {
        let mut best: Option<u8> = None;
        let mut cur = self.head;
        while !cur.is_null() {
            let tid = unsafe { (*cur).tid };
            if tid != 0 && thread_exists(tid) {
                let prio = with_thread(tid, |t| {
                    if t.state == ThreadState::Waiting {
                        Some(t.priority)
                    } else {
                        None
                    }
                });
                if let Some(p) = prio {
                    best = match best {
                        Some(cur_best) if cur_best >= p => Some(cur_best),
                        _ => Some(p),
                    };
                }
            }
            cur = unsafe { (*cur).next };
        }
        best
    }
}
