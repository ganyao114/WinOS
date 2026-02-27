// Guest kernel 同步原语 — EL1
// KEvent, KMutex, KSemaphore, HandleTable
// 所有状态机在 guest 内完成，不走 HVC。

use super::{current_tid, sched_lock_acquire, sched_lock_release, wake, with_thread, with_thread_mut, ThreadState};

// ── NTSTATUS 常量 ─────────────────────────────────────────────
pub const STATUS_SUCCESS:           u32 = 0x0000_0000;
pub const STATUS_PENDING:           u32 = 0x0000_0103;
pub const STATUS_TIMEOUT:           u32 = 0x0000_0102;
pub const STATUS_ABANDONED:         u32 = 0x0000_0080;
pub const STATUS_INVALID_HANDLE:    u32 = 0xC000_0008;
pub const STATUS_MUTANT_NOT_OWNED:  u32 = 0xC000_0046;

// ── 等待队列（侵入式，按优先级排序）─────────────────────────

pub struct WaitQueue {
    head: u32,  // TID of first waiter (0 = empty)
}

impl WaitQueue {
    pub const fn new() -> Self { Self { head: 0 } }

    /// 按优先级插入（高优先级在前）
    pub fn enqueue(&mut self, tid: u32) {
        use super::with_thread;
        let prio = with_thread(tid, |t| t.priority);
        with_thread_mut(tid, |t| t.wait_next = 0);

        if self.head == 0 {
            self.head = tid;
            return;
        }
        let head_prio = with_thread(self.head, |t| t.priority);
        if prio > head_prio {
            with_thread_mut(tid, |t| t.wait_next = self.head);
            self.head = tid;
            return;
        }
        let mut prev = self.head;
        loop {
            let next = with_thread(prev, |t| t.wait_next);
            if next == 0 {
                with_thread_mut(prev, |t| t.wait_next = tid);
                break;
            }
            let next_prio = with_thread(next, |t| t.priority);
            if prio > next_prio {
                with_thread_mut(tid,  |t| t.wait_next = next);
                with_thread_mut(prev, |t| t.wait_next = tid);
                break;
            }
            prev = next;
        }
    }

    /// 移除队首，返回 TID（0 = empty）
    pub fn dequeue(&mut self) -> u32 {
        let tid = self.head;
        if tid != 0 {
            self.head = with_thread(tid, |t| t.wait_next);
            with_thread_mut(tid, |t| t.wait_next = 0);
        }
        tid
    }

    /// 移除指定 TID（用于超时取消）
    pub fn remove(&mut self, tid: u32) {
        if self.head == 0 { return; }
        if self.head == tid {
            self.head = with_thread(tid, |t| t.wait_next);
            with_thread_mut(tid, |t| t.wait_next = 0);
            return;
        }
        let mut prev = self.head;
        loop {
            let next = with_thread(prev, |t| t.wait_next);
            if next == 0 { break; }
            if next == tid {
                let after = with_thread(tid, |t| t.wait_next);
                with_thread_mut(prev, |t| t.wait_next = after);
                with_thread_mut(tid,  |t| t.wait_next = 0);
                break;
            }
            prev = next;
        }
    }

    pub fn is_empty(&self) -> bool { self.head == 0 }
}

// ── KEvent ────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    NotificationEvent = 0,  // manual-reset
    SynchronizationEvent = 1, // auto-reset
}

pub struct KEvent {
    pub in_use:    bool,
    pub signaled:  bool,
    pub ev_type:   EventType,
    pub waiters:   WaitQueue,
}

impl KEvent {
    const fn new() -> Self {
        Self {
            in_use:   false,
            signaled: false,
            ev_type:  EventType::NotificationEvent,
            waiters:  WaitQueue::new(),
        }
    }
}

pub const MAX_EVENTS: usize = 256;
static mut EVENTS: [KEvent; MAX_EVENTS] = [const { KEvent::new() }; MAX_EVENTS];

pub fn event_alloc(ev_type: EventType, initial_state: bool) -> Option<u16> {
    unsafe {
        for i in 1..MAX_EVENTS {
            if !EVENTS[i].in_use {
                EVENTS[i].in_use   = true;
                EVENTS[i].signaled = initial_state;
                EVENTS[i].ev_type  = ev_type;
                EVENTS[i].waiters  = WaitQueue::new();
                return Some(i as u16);
            }
        }
        None
    }
}

pub fn event_set(idx: u16) -> u32 {
    unsafe {
        let ev = &mut EVENTS[idx as usize];
        if !ev.in_use { return STATUS_INVALID_HANDLE; }
        sched_lock_acquire();
        let waiter = ev.waiters.dequeue();
        if waiter != 0 {
            wake(waiter, STATUS_SUCCESS);
            if ev.ev_type == EventType::NotificationEvent {
                ev.signaled = true;
            }
            // auto-reset: stays unsignaled, one waiter woken
        } else {
            ev.signaled = true;
        }
        sched_lock_release();
        STATUS_SUCCESS
    }
}

pub fn event_reset(idx: u16) -> u32 {
    unsafe {
        let ev = &mut EVENTS[idx as usize];
        if !ev.in_use { return STATUS_INVALID_HANDLE; }
        ev.signaled = false;
        STATUS_SUCCESS
    }
}

/// Returns STATUS_SUCCESS or STATUS_TIMEOUT.
/// deadline = 0 means wait forever.
pub fn event_wait(idx: u16, deadline: u64) -> u32 {
    unsafe {
        let ev = &mut EVENTS[idx as usize];
        if !ev.in_use { return STATUS_INVALID_HANDLE; }
        sched_lock_acquire();
        if ev.signaled {
            if ev.ev_type == EventType::SynchronizationEvent {
                ev.signaled = false;
            }
            sched_lock_release();
            return STATUS_SUCCESS;
        }
        // slow path: enqueue and mark current thread waiting.
        let cur = current_tid();
        ev.waiters.enqueue(cur);
        with_thread_mut(cur, |t| {
            t.state = ThreadState::Waiting;
            t.wait_deadline = deadline;
            t.wait_result = STATUS_PENDING;
        });
        sched_lock_release();
        STATUS_PENDING
    }
}

pub fn event_free(idx: u16) {
    unsafe { EVENTS[idx as usize].in_use = false; }
}

// ── KMutex ────────────────────────────────────────────────────

pub struct KMutex {
    pub in_use:       bool,
    pub owner_tid:    u32,   // 0 = unowned
    pub recursion:    u32,
    pub waiters:      WaitQueue,
}

impl KMutex {
    const fn new() -> Self {
        Self { in_use: false, owner_tid: 0, recursion: 0, waiters: WaitQueue::new() }
    }
}

pub const MAX_MUTEXES: usize = 256;
static mut MUTEXES: [KMutex; MAX_MUTEXES] = [const { KMutex::new() }; MAX_MUTEXES];

pub fn mutex_alloc(initial_owner: bool) -> Option<u16> {
    unsafe {
        for i in 1..MAX_MUTEXES {
            if !MUTEXES[i].in_use {
                MUTEXES[i].in_use    = true;
                MUTEXES[i].recursion = 0;
                MUTEXES[i].waiters   = WaitQueue::new();
                MUTEXES[i].owner_tid = if initial_owner { current_tid() } else { 0 };
                if initial_owner { MUTEXES[i].recursion = 1; }
                return Some(i as u16);
            }
        }
        None
    }
}

pub fn mutex_acquire(idx: u16, deadline: u64) -> u32 {
    unsafe {
        let m = &mut MUTEXES[idx as usize];
        if !m.in_use { return STATUS_INVALID_HANDLE; }
        sched_lock_acquire();
        let cur = current_tid();
        if m.owner_tid == 0 {
            m.owner_tid  = cur;
            m.recursion  = 1;
            sched_lock_release();
            return STATUS_SUCCESS;
        }
        if m.owner_tid == cur {
            m.recursion += 1;
            sched_lock_release();
            return STATUS_SUCCESS;
        }
        // priority inheritance
        let cur_prio = with_thread_mut(cur, |t| t.priority);
        with_thread_mut(m.owner_tid, |t| {
            if cur_prio > t.priority { t.priority = cur_prio; }
        });
        m.waiters.enqueue(cur);
        with_thread_mut(cur, |t| {
            t.state = ThreadState::Waiting;
            t.wait_deadline = deadline;
            t.wait_result = STATUS_PENDING;
        });
        sched_lock_release();
        STATUS_PENDING
    }
}

pub fn mutex_release(idx: u16) -> u32 {
    unsafe {
        let m = &mut MUTEXES[idx as usize];
        if !m.in_use { return STATUS_INVALID_HANDLE; }
        sched_lock_acquire();
        let cur = current_tid();
        if m.owner_tid != cur {
            sched_lock_release();
            return STATUS_MUTANT_NOT_OWNED;
        }
        m.recursion -= 1;
        if m.recursion > 0 {
            sched_lock_release();
            return STATUS_SUCCESS;
        }
        // restore base priority
        with_thread_mut(cur, |t| t.priority = t.base_priority);
        let next_waiter = m.waiters.dequeue();
        if next_waiter != 0 {
            m.owner_tid  = next_waiter;
            m.recursion  = 1;
            wake(next_waiter, STATUS_SUCCESS);
        } else {
            m.owner_tid = 0;
        }
        sched_lock_release();
        STATUS_SUCCESS
    }
}

pub fn mutex_free(idx: u16) {
    unsafe { MUTEXES[idx as usize].in_use = false; }
}

// ── KSemaphore ────────────────────────────────────────────────

pub struct KSemaphore {
    pub in_use:   bool,
    pub count:    i32,
    pub maximum:  i32,
    pub waiters:  WaitQueue,
}

impl KSemaphore {
    const fn new() -> Self {
        Self { in_use: false, count: 0, maximum: 0, waiters: WaitQueue::new() }
    }
}

pub const MAX_SEMAPHORES: usize = 128;
static mut SEMAPHORES: [KSemaphore; MAX_SEMAPHORES] = [const { KSemaphore::new() }; MAX_SEMAPHORES];

pub fn semaphore_alloc(initial: i32, maximum: i32) -> Option<u16> {
    unsafe {
        for i in 1..MAX_SEMAPHORES {
            if !SEMAPHORES[i].in_use {
                SEMAPHORES[i].in_use  = true;
                SEMAPHORES[i].count   = initial;
                SEMAPHORES[i].maximum = maximum;
                SEMAPHORES[i].waiters = WaitQueue::new();
                return Some(i as u16);
            }
        }
        None
    }
}

pub fn semaphore_wait(idx: u16, deadline: u64) -> u32 {
    unsafe {
        let s = &mut SEMAPHORES[idx as usize];
        if !s.in_use { return STATUS_INVALID_HANDLE; }
        sched_lock_acquire();
        if s.count > 0 {
            s.count -= 1;
            sched_lock_release();
            return STATUS_SUCCESS;
        }
        let cur = current_tid();
        s.waiters.enqueue(cur);
        with_thread_mut(cur, |t| {
            t.state = ThreadState::Waiting;
            t.wait_deadline = deadline;
            t.wait_result = STATUS_PENDING;
        });
        sched_lock_release();
        STATUS_PENDING
    }
}

/// Returns previous count (or STATUS_SEMAPHORE_LIMIT_EXCEEDED packed in high bits)
pub fn semaphore_release(idx: u16, count: i32) -> u32 {
    unsafe {
        let s = &mut SEMAPHORES[idx as usize];
        if !s.in_use { return STATUS_INVALID_HANDLE; }
        sched_lock_acquire();
        let prev = s.count;
        let new_count = s.count + count;
        if new_count > s.maximum {
            sched_lock_release();
            return 0xC000_0047; // STATUS_SEMAPHORE_LIMIT_EXCEEDED
        }
        s.count = new_count;
        let mut to_wake = count;
        while to_wake > 0 {
            let w = s.waiters.dequeue();
            if w == 0 { break; }
            s.count -= 1;
            wake(w, STATUS_SUCCESS);
            to_wake -= 1;
        }
        sched_lock_release();
        prev as u32
    }
}

pub fn semaphore_free(idx: u16) {
    unsafe { SEMAPHORES[idx as usize].in_use = false; }
}

// ── HandleTable ───────────────────────────────────────────────
// Handle encoding: bits[15:12] = type, bits[11:0] = index
// Type 0 = invalid, 1 = event, 2 = mutex, 3 = semaphore
// Handles are u64 (Windows HANDLE), we use low 16 bits.

pub const HANDLE_TYPE_EVENT:     u64 = 1;
pub const HANDLE_TYPE_MUTEX:     u64 = 2;
pub const HANDLE_TYPE_SEMAPHORE: u64 = 3;
pub const HANDLE_TYPE_THREAD:    u64 = 4;
pub const HANDLE_TYPE_FILE:      u64 = 5;
pub const HANDLE_TYPE_SECTION:   u64 = 6;
pub const HANDLE_TYPE_KEY:       u64 = 7;

pub fn make_handle(htype: u64, idx: u16) -> u64 {
    ((htype & 0xF) << 12) | (idx as u64 & 0xFFF)
}

pub fn handle_type(h: u64) -> u64 { (h >> 12) & 0xF }
pub fn handle_idx(h: u64)  -> u16 { (h & 0xFFF) as u16 }

/// Wait on a single handle. Returns NTSTATUS.
pub fn wait_handle(h: u64, deadline: u64) -> u32 {
    match handle_type(h) {
        HANDLE_TYPE_EVENT     => event_wait(handle_idx(h), deadline),
        HANDLE_TYPE_MUTEX     => mutex_acquire(handle_idx(h), deadline),
        HANDLE_TYPE_SEMAPHORE => semaphore_wait(handle_idx(h), deadline),
        _                     => STATUS_INVALID_HANDLE,
    }
}

pub fn close_handle(h: u64) -> u32 {
    match handle_type(h) {
        HANDLE_TYPE_EVENT     => { event_free(handle_idx(h));     STATUS_SUCCESS }
        HANDLE_TYPE_MUTEX     => { mutex_free(handle_idx(h));     STATUS_SUCCESS }
        HANDLE_TYPE_SEMAPHORE => { semaphore_free(handle_idx(h)); STATUS_SUCCESS }
        HANDLE_TYPE_THREAD    => STATUS_SUCCESS,
        _                     => STATUS_INVALID_HANDLE,
    }
}
