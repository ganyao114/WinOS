use super::ThreadId;
use std::collections::VecDeque;

// ── SyncHandle ───────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyncHandle(pub u32);

// ── NT 状态码 ────────────────────────────────────────────────
pub const STATUS_SUCCESS: u64 = 0x0000_0000;
pub const STATUS_TIMEOUT: u64 = 0x0000_0102;
pub const STATUS_WAIT_0: u64 = 0x0000_0000;
pub const STATUS_ABANDONED_WAIT_0: u64 = 0x0000_0080;
pub const STATUS_MUTANT_NOT_OWNED: u64 = 0xC000_0046;

// ── Event ────────────────────────────────────────────────────
pub struct EventObj {
    pub manual_reset: bool,
    pub signaled: bool,
    pub waiters: VecDeque<ThreadId>,
}

impl EventObj {
    pub fn new(manual_reset: bool, initial: bool) -> Self {
        Self {
            manual_reset,
            signaled: initial,
            waiters: VecDeque::new(),
        }
    }

    /// 尝试立即获取信号。返回 true 表示成功消费。
    pub fn try_acquire(&mut self) -> bool {
        if self.signaled {
            if !self.manual_reset {
                self.signaled = false; // auto-reset: 消费信号
            }
            true
        } else {
            false
        }
    }

    /// SetEvent — 返回需要唤醒的线程列表
    pub fn set(&mut self) -> Vec<ThreadId> {
        self.signaled = true;
        if self.manual_reset {
            // 唤醒所有 waiter，信号保持
            self.waiters.drain(..).collect()
        } else {
            // 唤醒一个 waiter，消费信号
            if let Some(tid) = self.waiters.pop_front() {
                self.signaled = false;
                vec![tid]
            } else {
                vec![] // 无 waiter，信号留着
            }
        }
    }

    /// ResetEvent
    pub fn reset(&mut self) {
        self.signaled = false;
    }

    pub fn add_waiter(&mut self, tid: ThreadId) {
        self.waiters.push_back(tid);
    }

    pub fn remove_waiter(&mut self, tid: ThreadId) {
        self.waiters.retain(|&t| t != tid);
    }
}

// ── Mutex ────────────────────────────────────────────────────
pub struct MutexObj {
    pub owner: Option<ThreadId>,
    pub rec_count: u32,
    pub waiters: VecDeque<ThreadId>,
    pub abandoned: bool,
}

impl MutexObj {
    pub fn new(initial_owner: Option<ThreadId>) -> Self {
        let (owner, rec_count) = match initial_owner {
            Some(tid) => (Some(tid), 1),
            None => (None, 0),
        };
        Self {
            owner,
            rec_count,
            waiters: VecDeque::new(),
            abandoned: false,
        }
    }

    /// 尝试获取。返回 (acquired, abandoned)
    pub fn try_acquire(&mut self, tid: ThreadId) -> (bool, bool) {
        if self.owner.is_none() {
            let was_abandoned = self.abandoned;
            self.abandoned = false;
            self.owner = Some(tid);
            self.rec_count = 1;
            (true, was_abandoned)
        } else if self.owner == Some(tid) {
            // 递归获取
            self.rec_count += 1;
            (true, false)
        } else {
            (false, false)
        }
    }

    /// ReleaseMutex — 返回下一个要唤醒的线程
    pub fn release(&mut self, tid: ThreadId) -> Result<Option<ThreadId>, u64> {
        if self.owner != Some(tid) {
            return Err(STATUS_MUTANT_NOT_OWNED);
        }
        self.rec_count -= 1;
        if self.rec_count == 0 {
            self.owner = None;
            Ok(self.waiters.pop_front())
        } else {
            Ok(None)
        }
    }

    pub fn add_waiter(&mut self, tid: ThreadId) {
        self.waiters.push_back(tid);
    }

    pub fn remove_waiter(&mut self, tid: ThreadId) {
        self.waiters.retain(|&t| t != tid);
    }
}

// ── Semaphore ────────────────────────────────────────────────
pub struct SemaphoreObj {
    pub count: i64,
    pub maximum: i64,
    pub waiters: VecDeque<ThreadId>,
}

impl SemaphoreObj {
    pub fn new(initial: i64, maximum: i64) -> Self {
        Self {
            count: initial,
            maximum,
            waiters: VecDeque::new(),
        }
    }

    pub fn try_acquire(&mut self) -> bool {
        if self.count > 0 {
            self.count -= 1;
            true
        } else {
            false
        }
    }

    /// ReleaseSemaphore(n) — 返回要唤醒的线程列表
    pub fn release(&mut self, n: i64) -> Result<Vec<ThreadId>, u64> {
        if self.count + n > self.maximum {
            // STATUS_SEMAPHORE_LIMIT_EXCEEDED
            return Err(0xC000_0047);
        }
        self.count += n;
        let wake_count = (n as usize).min(self.waiters.len());
        let woken: Vec<ThreadId> = self.waiters.drain(..wake_count).collect();
        self.count -= woken.len() as i64;
        Ok(woken)
    }

    pub fn add_waiter(&mut self, tid: ThreadId) {
        self.waiters.push_back(tid);
    }

    pub fn remove_waiter(&mut self, tid: ThreadId) {
        self.waiters.retain(|&t| t != tid);
    }
}

// ── SyncObject ───────────────────────────────────────────────
pub enum SyncObject {
    Event(EventObj),
    Mutex(MutexObj),
    Semaphore(SemaphoreObj),
    /// 等待线程退出
    Thread(ThreadId),
}
