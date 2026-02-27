// Guest kernel 同步原语 — EL1
// KEvent, KMutex, KSemaphore, Thread waiters, HandleTable
// 所有状态机在 guest 内完成，不走 HVC。

use super::{
    current_tid, sched_lock_acquire, sched_lock_release, wake, with_thread, with_thread_mut,
    ThreadState, MAX_THREADS, MAX_WAIT_HANDLES, WAIT_KIND_MULTI_ALL, WAIT_KIND_MULTI_ANY,
    WAIT_KIND_NONE, WAIT_KIND_SINGLE,
};

// ── NTSTATUS 常量 ─────────────────────────────────────────────

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_TIMEOUT: u32 = 0x0000_0102;
pub const STATUS_ABANDONED: u32 = 0x0000_0080;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_MUTANT_NOT_OWNED: u32 = 0xC000_0046;
pub const STATUS_SEMAPHORE_LIMIT_EXCEEDED: u32 = 0xC000_0047;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WaitDeadline {
    Infinite,
    Immediate,
    DeadlineTicks(u64),
}

// ── 等待队列（零分配，按优先级排序）──────────────────────────
//
// 说明：
// - 不能使用 KThread.wait_next 侵入式链表，因为 WaitMultiple 需要把同一线程注册到多个队列。
// - 这里用定长数组保存 TID，支持同一线程出现在不同对象队列里。

pub struct WaitQueue {
    tids: [u32; MAX_THREADS],
    len: usize,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            tids: [0; MAX_THREADS],
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn enqueue(&mut self, tid: u32) {
        if tid == 0 || self.len >= MAX_THREADS {
            return;
        }
        for i in 0..self.len {
            if self.tids[i] == tid {
                return;
            }
        }

        let prio = with_thread(tid, |t| t.priority);
        let mut pos = self.len;
        for i in 0..self.len {
            let cur_tid = self.tids[i];
            let cur_prio = with_thread(cur_tid, |t| t.priority);
            if prio > cur_prio {
                pos = i;
                break;
            }
        }

        let mut j = self.len;
        while j > pos {
            self.tids[j] = self.tids[j - 1];
            j -= 1;
        }
        self.tids[pos] = tid;
        self.len += 1;
    }

    pub fn dequeue_waiting(&mut self) -> u32 {
        while self.len > 0 {
            let tid = self.tids[0];
            let mut i = 1usize;
            while i < self.len {
                self.tids[i - 1] = self.tids[i];
                i += 1;
            }
            self.len -= 1;
            self.tids[self.len] = 0;

            if tid != 0 && with_thread(tid, |t| t.state == ThreadState::Waiting) {
                return tid;
            }
        }
        0
    }

    pub fn remove(&mut self, tid: u32) {
        if tid == 0 || self.len == 0 {
            return;
        }
        let mut i = 0usize;
        while i < self.len {
            if self.tids[i] == tid {
                let mut j = i + 1;
                while j < self.len {
                    self.tids[j - 1] = self.tids[j];
                    j += 1;
                }
                self.len -= 1;
                self.tids[self.len] = 0;
                return;
            }
            i += 1;
        }
    }
}

// ── KEvent ────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    NotificationEvent = 0,    // manual-reset
    SynchronizationEvent = 1, // auto-reset
}

pub struct KEvent {
    pub in_use: bool,
    pub signaled: bool,
    pub ev_type: EventType,
    pub waiters: WaitQueue,
}

impl KEvent {
    const fn new() -> Self {
        Self {
            in_use: false,
            signaled: false,
            ev_type: EventType::NotificationEvent,
            waiters: WaitQueue::new(),
        }
    }
}

pub const MAX_EVENTS: usize = 256;
static mut EVENTS: [KEvent; MAX_EVENTS] = [const { KEvent::new() }; MAX_EVENTS];

// ── KMutex ────────────────────────────────────────────────────

pub struct KMutex {
    pub in_use: bool,
    pub owner_tid: u32, // 0 = unowned
    pub recursion: u32,
    pub waiters: WaitQueue,
}

impl KMutex {
    const fn new() -> Self {
        Self {
            in_use: false,
            owner_tid: 0,
            recursion: 0,
            waiters: WaitQueue::new(),
        }
    }
}

pub const MAX_MUTEXES: usize = 256;
static mut MUTEXES: [KMutex; MAX_MUTEXES] = [const { KMutex::new() }; MAX_MUTEXES];

// ── KSemaphore ────────────────────────────────────────────────

pub struct KSemaphore {
    pub in_use: bool,
    pub count: i32,
    pub maximum: i32,
    pub waiters: WaitQueue,
}

impl KSemaphore {
    const fn new() -> Self {
        Self {
            in_use: false,
            count: 0,
            maximum: 0,
            waiters: WaitQueue::new(),
        }
    }
}

pub const MAX_SEMAPHORES: usize = 128;
static mut SEMAPHORES: [KSemaphore; MAX_SEMAPHORES] = [const { KSemaphore::new() }; MAX_SEMAPHORES];

// 每个目标线程一个等待队列，用于 Wait(ThreadHandle)
static mut THREAD_WAITERS: [WaitQueue; MAX_THREADS] = [const { WaitQueue::new() }; MAX_THREADS];

// ── HandleTable ───────────────────────────────────────────────
// Handle encoding: bits[15:12] = type, bits[11:0] = index
// Type 0 = invalid, 1 = event, 2 = mutex, 3 = semaphore, 4 = thread
// Handles are u64 (Windows HANDLE), we use low 16 bits.

pub const HANDLE_TYPE_EVENT: u64 = 1;
pub const HANDLE_TYPE_MUTEX: u64 = 2;
pub const HANDLE_TYPE_SEMAPHORE: u64 = 3;
pub const HANDLE_TYPE_THREAD: u64 = 4;
pub const HANDLE_TYPE_FILE: u64 = 5;
pub const HANDLE_TYPE_SECTION: u64 = 6;
pub const HANDLE_TYPE_KEY: u64 = 7;

pub fn make_handle(htype: u64, idx: u16) -> u64 {
    ((htype & 0xF) << 12) | (idx as u64 & 0xFFF)
}

pub fn handle_type(h: u64) -> u64 {
    (h >> 12) & 0xF
}
pub fn handle_idx(h: u64) -> u16 {
    (h & 0xFFF) as u16
}

// ── 内部辅助 ──────────────────────────────────────────────────

fn deadline_ticks(timeout: WaitDeadline) -> u64 {
    match timeout {
        WaitDeadline::Infinite | WaitDeadline::Immediate => 0,
        WaitDeadline::DeadlineTicks(t) => t,
    }
}

fn set_wait_metadata(tid: u32, kind: u8, handles: &[u64], timeout: WaitDeadline) {
    let count = if handles.len() > MAX_WAIT_HANDLES {
        MAX_WAIT_HANDLES
    } else {
        handles.len()
    };
    let deadline = deadline_ticks(timeout);
    with_thread_mut(tid, |t| {
        t.state = ThreadState::Waiting;
        t.wait_result = STATUS_PENDING;
        t.wait_deadline = deadline;
        t.wait_kind = kind;
        t.wait_count = count as u8;
        t.wait_signaled = 0;
        t.wait_handles.fill(0);
        let mut i = 0usize;
        while i < count {
            t.wait_handles[i] = handles[i];
            i += 1;
        }
    });
}

fn clear_wait_metadata(tid: u32) {
    with_thread_mut(tid, |t| {
        t.wait_kind = WAIT_KIND_NONE;
        t.wait_count = 0;
        t.wait_signaled = 0;
        t.wait_deadline = 0;
        t.wait_handles.fill(0);
    });
}

fn validate_thread_target_tid(target_tid: u32) -> bool {
    if target_tid == 0 || target_tid as usize >= MAX_THREADS {
        return false;
    }
    let state = with_thread(target_tid, |t| t.state);
    state != ThreadState::Free
}

fn validate_waitable_handle_locked(h: u64) -> u32 {
    let idx = handle_idx(h) as usize;
    match handle_type(h) {
        HANDLE_TYPE_EVENT => unsafe {
            if idx == 0 || idx >= MAX_EVENTS || !EVENTS[idx].in_use {
                STATUS_INVALID_HANDLE
            } else {
                STATUS_SUCCESS
            }
        },
        HANDLE_TYPE_MUTEX => unsafe {
            if idx == 0 || idx >= MAX_MUTEXES || !MUTEXES[idx].in_use {
                STATUS_INVALID_HANDLE
            } else {
                STATUS_SUCCESS
            }
        },
        HANDLE_TYPE_SEMAPHORE => unsafe {
            if idx == 0 || idx >= MAX_SEMAPHORES || !SEMAPHORES[idx].in_use {
                STATUS_INVALID_HANDLE
            } else {
                STATUS_SUCCESS
            }
        },
        HANDLE_TYPE_THREAD => {
            if validate_thread_target_tid(idx as u32) {
                STATUS_SUCCESS
            } else {
                STATUS_INVALID_HANDLE
            }
        }
        _ => STATUS_INVALID_HANDLE,
    }
}

fn is_handle_signaled_locked(waiter_tid: u32, h: u64) -> bool {
    let idx = handle_idx(h) as usize;
    match handle_type(h) {
        HANDLE_TYPE_EVENT => unsafe {
            idx != 0 && idx < MAX_EVENTS && EVENTS[idx].in_use && EVENTS[idx].signaled
        },
        HANDLE_TYPE_MUTEX => unsafe {
            idx != 0
                && idx < MAX_MUTEXES
                && MUTEXES[idx].in_use
                && (MUTEXES[idx].owner_tid == 0 || MUTEXES[idx].owner_tid == waiter_tid)
        },
        HANDLE_TYPE_SEMAPHORE => unsafe {
            idx != 0 && idx < MAX_SEMAPHORES && SEMAPHORES[idx].in_use && SEMAPHORES[idx].count > 0
        },
        HANDLE_TYPE_THREAD => {
            let tid = idx as u32;
            if tid == 0 || idx >= MAX_THREADS {
                false
            } else {
                let state = with_thread(tid, |t| t.state);
                state == ThreadState::Terminated || state == ThreadState::Free
            }
        }
        _ => false,
    }
}

fn consume_handle_signal_locked(waiter_tid: u32, h: u64) -> bool {
    let idx = handle_idx(h) as usize;
    match handle_type(h) {
        HANDLE_TYPE_EVENT => unsafe {
            if idx == 0 || idx >= MAX_EVENTS {
                return false;
            }
            let ev = &mut EVENTS[idx];
            if !ev.in_use || !ev.signaled {
                return false;
            }
            if ev.ev_type == EventType::SynchronizationEvent {
                ev.signaled = false;
            }
            true
        },
        HANDLE_TYPE_MUTEX => unsafe {
            if idx == 0 || idx >= MAX_MUTEXES {
                return false;
            }
            let m = &mut MUTEXES[idx];
            if !m.in_use {
                return false;
            }
            if m.owner_tid == 0 {
                m.owner_tid = waiter_tid;
                m.recursion = 1;
                return true;
            }
            if m.owner_tid == waiter_tid {
                m.recursion = m.recursion.saturating_add(1);
                return true;
            }
            false
        },
        HANDLE_TYPE_SEMAPHORE => unsafe {
            if idx == 0 || idx >= MAX_SEMAPHORES {
                return false;
            }
            let s = &mut SEMAPHORES[idx];
            if !s.in_use || s.count <= 0 {
                return false;
            }
            s.count -= 1;
            true
        },
        HANDLE_TYPE_THREAD => is_handle_signaled_locked(waiter_tid, h),
        _ => false,
    }
}

fn copy_wait_handles_for_thread(tid: u32) -> ([u64; MAX_WAIT_HANDLES], usize) {
    let mut local = [0u64; MAX_WAIT_HANDLES];
    let mut count = 0usize;
    with_thread(tid, |t| {
        count = t.wait_count as usize;
        let mut i = 0usize;
        while i < count && i < MAX_WAIT_HANDLES {
            local[i] = t.wait_handles[i];
            i += 1;
        }
    });
    (local, count)
}

fn wait_all_handles_signaled_locked(tid: u32, handles: &[u64]) -> bool {
    let mut i = 0usize;
    while i < handles.len() {
        if !is_handle_signaled_locked(tid, handles[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn consume_wait_all_locked(tid: u32, handles: &[u64]) -> bool {
    if !wait_all_handles_signaled_locked(tid, handles) {
        return false;
    }
    let mut i = 0usize;
    while i < handles.len() {
        if !consume_handle_signal_locked(tid, handles[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn register_waiter_on_handle_locked(h: u64, tid: u32) {
    let idx = handle_idx(h) as usize;
    match handle_type(h) {
        HANDLE_TYPE_EVENT => unsafe {
            if idx > 0 && idx < MAX_EVENTS && EVENTS[idx].in_use {
                EVENTS[idx].waiters.enqueue(tid);
            }
        },
        HANDLE_TYPE_MUTEX => unsafe {
            if idx > 0 && idx < MAX_MUTEXES && MUTEXES[idx].in_use {
                MUTEXES[idx].waiters.enqueue(tid);
            }
        },
        HANDLE_TYPE_SEMAPHORE => unsafe {
            if idx > 0 && idx < MAX_SEMAPHORES && SEMAPHORES[idx].in_use {
                SEMAPHORES[idx].waiters.enqueue(tid);
            }
        },
        HANDLE_TYPE_THREAD => unsafe {
            if idx > 0 && idx < MAX_THREADS && validate_thread_target_tid(idx as u32) {
                THREAD_WAITERS[idx].enqueue(tid);
            }
        },
        _ => {}
    }
}

fn remove_waiter_from_handle_locked(h: u64, tid: u32) {
    let idx = handle_idx(h) as usize;
    match handle_type(h) {
        HANDLE_TYPE_EVENT => unsafe {
            if idx > 0 && idx < MAX_EVENTS && EVENTS[idx].in_use {
                EVENTS[idx].waiters.remove(tid);
            }
        },
        HANDLE_TYPE_MUTEX => unsafe {
            if idx > 0 && idx < MAX_MUTEXES && MUTEXES[idx].in_use {
                MUTEXES[idx].waiters.remove(tid);
            }
        },
        HANDLE_TYPE_SEMAPHORE => unsafe {
            if idx > 0 && idx < MAX_SEMAPHORES && SEMAPHORES[idx].in_use {
                SEMAPHORES[idx].waiters.remove(tid);
            }
        },
        HANDLE_TYPE_THREAD => unsafe {
            if idx > 0 && idx < MAX_THREADS {
                THREAD_WAITERS[idx].remove(tid);
            }
        },
        _ => {}
    }
}

fn cleanup_wait_registration_locked(tid: u32) {
    let (handles, count) = copy_wait_handles_for_thread(tid);
    let mut i = 0usize;
    while i < count {
        remove_waiter_from_handle_locked(handles[i], tid);
        i += 1;
    }
}

fn wait_index_for_handle_locked(tid: u32, h: u64) -> Option<usize> {
    with_thread(tid, |t| {
        let count = t.wait_count as usize;
        let mut i = 0usize;
        while i < count && i < MAX_WAIT_HANDLES {
            if t.wait_handles[i] == h {
                return Some(i);
            }
            i += 1;
        }
        None
    })
}

fn complete_wait_locked(tid: u32, result: u32) {
    cleanup_wait_registration_locked(tid);
    clear_wait_metadata(tid);
    wake(tid, result);
}

fn try_complete_waiter_for_handle_locked(tid: u32, signaled_handle: u64) -> bool {
    let (state, kind) = with_thread(tid, |t| (t.state, t.wait_kind));
    if state != ThreadState::Waiting {
        return false;
    }

    match kind {
        WAIT_KIND_SINGLE => {
            let expected = with_thread(tid, |t| t.wait_handles[0]);
            if expected != signaled_handle {
                return false;
            }
            if !consume_handle_signal_locked(tid, expected) {
                return false;
            }
            complete_wait_locked(tid, STATUS_SUCCESS);
            true
        }
        WAIT_KIND_MULTI_ANY => {
            let Some(index) = wait_index_for_handle_locked(tid, signaled_handle) else {
                return false;
            };
            if !consume_handle_signal_locked(tid, signaled_handle) {
                return false;
            }
            complete_wait_locked(tid, STATUS_SUCCESS + index as u32);
            true
        }
        WAIT_KIND_MULTI_ALL => {
            if let Some(index) = wait_index_for_handle_locked(tid, signaled_handle) {
                with_thread_mut(tid, |t| t.wait_signaled |= 1u64 << (index as u64));
            }
            let (handles, count) = copy_wait_handles_for_thread(tid);
            let handles = &handles[..count];
            if !wait_all_handles_signaled_locked(tid, handles) {
                return false;
            }
            if !consume_wait_all_locked(tid, handles) {
                return false;
            }
            complete_wait_locked(tid, STATUS_SUCCESS);
            true
        }
        _ => false,
    }
}

fn wake_queue_one_for_handle_locked(queue: &mut WaitQueue, signaled_handle: u64) -> bool {
    let attempts = queue.len();
    let mut i = 0usize;
    while i < attempts {
        let tid = queue.dequeue_waiting();
        if tid == 0 {
            return false;
        }
        if try_complete_waiter_for_handle_locked(tid, signaled_handle) {
            return true;
        }
        // 条件尚未满足（常见于 WaitAll），保留在队列中等待其它对象信号。
        if with_thread(tid, |t| t.state == ThreadState::Waiting) {
            queue.enqueue(tid);
        }
        i += 1;
    }
    false
}

fn wake_queue_all_for_handle_locked(queue: &mut WaitQueue, signaled_handle: u64) -> usize {
    let attempts = queue.len();
    let mut i = 0usize;
    let mut woke = 0usize;
    while i < attempts {
        let tid = queue.dequeue_waiting();
        if tid == 0 {
            break;
        }
        if try_complete_waiter_for_handle_locked(tid, signaled_handle) {
            woke += 1;
        } else if with_thread(tid, |t| t.state == ThreadState::Waiting) {
            queue.enqueue(tid);
        }
        i += 1;
    }
    woke
}

fn wait_common_locked(handles: &[u64], wait_all: bool, timeout: WaitDeadline) -> u32 {
    if handles.is_empty() || handles.len() > MAX_WAIT_HANDLES {
        return STATUS_INVALID_PARAMETER;
    }

    let mut i = 0usize;
    while i < handles.len() {
        let st = validate_waitable_handle_locked(handles[i]);
        if st != STATUS_SUCCESS {
            return st;
        }
        i += 1;
    }

    if wait_all {
        let mut i = 0usize;
        while i < handles.len() {
            let mut j = i + 1;
            while j < handles.len() {
                if handles[i] == handles[j] {
                    return STATUS_INVALID_PARAMETER;
                }
                j += 1;
            }
            i += 1;
        }
    }

    let cur = current_tid();

    if wait_all {
        if consume_wait_all_locked(cur, handles) {
            return STATUS_SUCCESS;
        }
    } else {
        let mut idx = 0usize;
        while idx < handles.len() {
            let h = handles[idx];
            if is_handle_signaled_locked(cur, h) && consume_handle_signal_locked(cur, h) {
                return STATUS_SUCCESS + idx as u32;
            }
            idx += 1;
        }
    }

    if timeout == WaitDeadline::Immediate {
        return STATUS_TIMEOUT;
    }

    let kind = if handles.len() == 1 {
        WAIT_KIND_SINGLE
    } else if wait_all {
        WAIT_KIND_MULTI_ALL
    } else {
        WAIT_KIND_MULTI_ANY
    };
    set_wait_metadata(cur, kind, handles, timeout);

    let mut i = 0usize;
    while i < handles.len() {
        register_waiter_on_handle_locked(handles[i], cur);
        i += 1;
    }

    STATUS_PENDING
}

// ── 对外接口：等待/清理/线程终止通知 ─────────────────────────

/// Wait on a single handle. Returns NTSTATUS.
pub fn wait_handle(h: u64, timeout: WaitDeadline) -> u32 {
    sched_lock_acquire();
    let st = wait_common_locked(core::slice::from_ref(&h), false, timeout);
    sched_lock_release();
    st
}

/// Wait on multiple handles. wait_all=false => WaitAny, true => WaitAll.
pub fn wait_multiple(handles: &[u64], wait_all: bool, timeout: WaitDeadline) -> u32 {
    sched_lock_acquire();
    let st = wait_common_locked(handles, wait_all, timeout);
    sched_lock_release();
    st
}

/// Remove a waiting thread from all object wait queues.
/// Called on timeout/cancel/wake cleanup paths.
pub fn cleanup_wait_registration(tid: u32) {
    if tid == 0 {
        return;
    }
    sched_lock_acquire();
    cleanup_wait_registration_locked(tid);
    sched_lock_release();
}

/// Notify synchronization subsystem that a thread became terminated.
/// Wakes waiters blocked on this thread handle.
pub fn thread_notify_terminated(target_tid: u32) {
    if target_tid == 0 || target_tid as usize >= MAX_THREADS {
        return;
    }
    sched_lock_acquire();
    let h = make_handle(HANDLE_TYPE_THREAD, target_tid as u16);
    unsafe {
        wake_queue_all_for_handle_locked(&mut THREAD_WAITERS[target_tid as usize], h);
    }
    sched_lock_release();
}

// ── Event API ────────────────────────────────────────────────

pub fn event_alloc(ev_type: EventType, initial_state: bool) -> Option<u16> {
    unsafe {
        for i in 1..MAX_EVENTS {
            if !EVENTS[i].in_use {
                EVENTS[i].in_use = true;
                EVENTS[i].signaled = initial_state;
                EVENTS[i].ev_type = ev_type;
                EVENTS[i].waiters = WaitQueue::new();
                return Some(i as u16);
            }
        }
        None
    }
}

pub fn event_set(idx: u16) -> u32 {
    let i = idx as usize;
    if i == 0 || i >= MAX_EVENTS {
        return STATUS_INVALID_HANDLE;
    }
    unsafe {
        if !EVENTS[i].in_use {
            return STATUS_INVALID_HANDLE;
        }

        sched_lock_acquire();
        let ev_ptr = &mut EVENTS[i] as *mut KEvent;
        let h = make_handle(HANDLE_TYPE_EVENT, idx);

        if (*ev_ptr).ev_type == EventType::SynchronizationEvent {
            // SyncEvent: expose signaled state before probing waiters so
            // WAIT_KIND_SINGLE/MULTI_ANY can consume it in common path.
            (*ev_ptr).signaled = true;
            if wake_queue_one_for_handle_locked(&mut (*ev_ptr).waiters, h) {
                (*ev_ptr).signaled = false;
            }
        } else {
            (*ev_ptr).signaled = true;
            let _ = wake_queue_all_for_handle_locked(&mut (*ev_ptr).waiters, h);
        }

        sched_lock_release();
    }
    STATUS_SUCCESS
}

pub fn event_reset(idx: u16) -> u32 {
    let i = idx as usize;
    if i == 0 || i >= MAX_EVENTS {
        return STATUS_INVALID_HANDLE;
    }
    unsafe {
        if !EVENTS[i].in_use {
            return STATUS_INVALID_HANDLE;
        }
        EVENTS[i].signaled = false;
    }
    STATUS_SUCCESS
}

pub fn event_free(idx: u16) {
    let i = idx as usize;
    if i == 0 || i >= MAX_EVENTS {
        return;
    }
    unsafe {
        if EVENTS[i].in_use {
            EVENTS[i].in_use = false;
            EVENTS[i].signaled = false;
            EVENTS[i].waiters = WaitQueue::new();
        }
    }
}

// ── Mutex API ────────────────────────────────────────────────

pub fn mutex_alloc(initial_owner: bool) -> Option<u16> {
    unsafe {
        for i in 1..MAX_MUTEXES {
            if !MUTEXES[i].in_use {
                MUTEXES[i].in_use = true;
                MUTEXES[i].waiters = WaitQueue::new();
                MUTEXES[i].recursion = 0;
                MUTEXES[i].owner_tid = if initial_owner { current_tid() } else { 0 };
                if initial_owner {
                    MUTEXES[i].recursion = 1;
                }
                return Some(i as u16);
            }
        }
    }
    None
}

pub fn mutex_release(idx: u16) -> u32 {
    let i = idx as usize;
    if i == 0 || i >= MAX_MUTEXES {
        return STATUS_INVALID_HANDLE;
    }
    unsafe {
        if !MUTEXES[i].in_use {
            return STATUS_INVALID_HANDLE;
        }

        sched_lock_acquire();

        let m_ptr = &mut MUTEXES[i] as *mut KMutex;
        let cur = current_tid();
        if (*m_ptr).owner_tid != cur {
            sched_lock_release();
            return STATUS_MUTANT_NOT_OWNED;
        }

        if (*m_ptr).recursion > 0 {
            (*m_ptr).recursion -= 1;
        }
        if (*m_ptr).recursion > 0 {
            sched_lock_release();
            return STATUS_SUCCESS;
        }

        with_thread_mut(cur, |t| t.priority = t.base_priority);
        (*m_ptr).owner_tid = 0;

        let h = make_handle(HANDLE_TYPE_MUTEX, idx);
        let _ = wake_queue_one_for_handle_locked(&mut (*m_ptr).waiters, h);

        sched_lock_release();
    }
    STATUS_SUCCESS
}

pub fn mutex_free(idx: u16) {
    let i = idx as usize;
    if i == 0 || i >= MAX_MUTEXES {
        return;
    }
    unsafe {
        if MUTEXES[i].in_use {
            MUTEXES[i].in_use = false;
            MUTEXES[i].owner_tid = 0;
            MUTEXES[i].recursion = 0;
            MUTEXES[i].waiters = WaitQueue::new();
        }
    }
}

// ── Semaphore API ────────────────────────────────────────────

pub fn semaphore_alloc(initial: i32, maximum: i32) -> Option<u16> {
    if maximum <= 0 || initial < 0 || initial > maximum {
        return None;
    }
    unsafe {
        for i in 1..MAX_SEMAPHORES {
            if !SEMAPHORES[i].in_use {
                SEMAPHORES[i].in_use = true;
                SEMAPHORES[i].count = initial;
                SEMAPHORES[i].maximum = maximum;
                SEMAPHORES[i].waiters = WaitQueue::new();
                return Some(i as u16);
            }
        }
    }
    None
}

/// Returns previous count, or STATUS_SEMAPHORE_LIMIT_EXCEEDED.
pub fn semaphore_release(idx: u16, count: i32) -> u32 {
    let i = idx as usize;
    if i == 0 || i >= MAX_SEMAPHORES {
        return STATUS_INVALID_HANDLE;
    }
    if count <= 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        if !SEMAPHORES[i].in_use {
            return STATUS_INVALID_HANDLE;
        }

        sched_lock_acquire();
        let s_ptr = &mut SEMAPHORES[i] as *mut KSemaphore;
        let prev = (*s_ptr).count;
        let new_count = (*s_ptr).count.saturating_add(count);
        if new_count > (*s_ptr).maximum {
            sched_lock_release();
            return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
        }
        (*s_ptr).count = new_count;

        let h = make_handle(HANDLE_TYPE_SEMAPHORE, idx);
        let mut rounds = (*s_ptr).waiters.len();
        while rounds > 0 && (*s_ptr).count > 0 {
            if !wake_queue_one_for_handle_locked(&mut (*s_ptr).waiters, h) {
                break;
            }
            rounds -= 1;
        }

        sched_lock_release();
        prev as u32
    }
}

pub fn semaphore_free(idx: u16) {
    let i = idx as usize;
    if i == 0 || i >= MAX_SEMAPHORES {
        return;
    }
    unsafe {
        if SEMAPHORES[i].in_use {
            SEMAPHORES[i].in_use = false;
            SEMAPHORES[i].count = 0;
            SEMAPHORES[i].maximum = 0;
            SEMAPHORES[i].waiters = WaitQueue::new();
        }
    }
}

// ── Handle wait / close ─────────────────────────────────────

pub fn close_handle(h: u64) -> u32 {
    match handle_type(h) {
        HANDLE_TYPE_EVENT => {
            event_free(handle_idx(h));
            STATUS_SUCCESS
        }
        HANDLE_TYPE_MUTEX => {
            mutex_free(handle_idx(h));
            STATUS_SUCCESS
        }
        HANDLE_TYPE_SEMAPHORE => {
            semaphore_free(handle_idx(h));
            STATUS_SUCCESS
        }
        HANDLE_TYPE_THREAD => STATUS_SUCCESS,
        _ => STATUS_INVALID_HANDLE,
    }
}
