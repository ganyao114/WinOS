use super::sync::{SyncHandle, SyncObject, STATUS_ABANDONED_WAIT_0, STATUS_SUCCESS, STATUS_WAIT_0};
use super::{SchedResult, Scheduler, ThreadId, WaitKind, WaitRequest};
use std::time::{Duration, Instant};

/// NT 超时单位：100ns，负值=相对，正值=绝对，0=立即
fn deadline_from_nt(timeout_100ns: i64) -> Option<Instant> {
    if timeout_100ns == i64::MIN {
        // INFINITE
        return None;
    }
    if timeout_100ns == 0 {
        return Some(Instant::now()); // 立即超时
    }
    let nanos = if timeout_100ns < 0 {
        (-timeout_100ns) as u64 * 100
    } else {
        // 绝对时间：简化处理为相对时间（Phase 3 改用系统时钟）
        timeout_100ns as u64 * 100
    };
    Some(Instant::now() + Duration::from_nanos(nanos))
}

impl Scheduler {
    /// NT_WAIT_SINGLE hypercall 处理
    /// timeout_100ns: i64::MIN = INFINITE
    pub fn wait_single(
        &self,
        tid: ThreadId,
        handle: SyncHandle,
        timeout_100ns: i64,
    ) -> SchedResult {
        let shard = Self::object_shard(handle);
        let mut objects = self.objects[shard].lock().unwrap();

        match objects.get_mut(&handle) {
            None => SchedResult::Sync(0xC000_0008), // STATUS_INVALID_HANDLE

            Some(obj) => {
                // 快路径：尝试立即获取
                let (acquired, ret) = try_acquire_obj(obj, tid);
                if acquired {
                    return SchedResult::Sync(ret);
                }

                // 超时为 0：不等待，直接返回 STATUS_TIMEOUT
                if timeout_100ns == 0 {
                    return SchedResult::Sync(0x0000_0102);
                }

                // 慢路径：注册 waiter
                add_waiter_obj(obj, tid);
                drop(objects);

                let req = WaitRequest {
                    kind: WaitKind::Single(handle),
                    deadline: deadline_from_nt(timeout_100ns),
                    wake_index: None,
                };
                SchedResult::Block(req)
            }
        }
    }

    /// NT_WAIT_MULTIPLE hypercall 处理
    pub fn wait_multiple(
        &self,
        tid: ThreadId,
        handles: Vec<SyncHandle>,
        wait_all: bool,
        timeout_100ns: i64,
    ) -> SchedResult {
        if wait_all {
            // 检查所有对象是否全部可获取
            let all_ready = handles.iter().all(|&h| {
                let shard = Self::object_shard(h);
                let objects = self.objects[shard].lock().unwrap();
                match objects.get(&h) {
                    Some(obj) => obj_is_signaled(obj, tid),
                    None => false,
                }
            });

            if all_ready {
                // 全部获取
                for &h in &handles {
                    let shard = Self::object_shard(h);
                    let mut objects = self.objects[shard].lock().unwrap();
                    if let Some(obj) = objects.get_mut(&h) {
                        try_acquire_obj(obj, tid);
                    }
                }
                return SchedResult::Sync(STATUS_WAIT_0);
            }
        } else {
            // 任意一个 signaled 即可
            for (i, &h) in handles.iter().enumerate() {
                let shard = Self::object_shard(h);
                let mut objects = self.objects[shard].lock().unwrap();
                if let Some(obj) = objects.get_mut(&h) {
                    let (acquired, ret) = try_acquire_obj(obj, tid);
                    if acquired {
                        let base = if ret == STATUS_ABANDONED_WAIT_0 {
                            STATUS_ABANDONED_WAIT_0
                        } else {
                            STATUS_WAIT_0
                        };
                        return SchedResult::Sync(base + i as u64);
                    }
                }
            }
        }

        if timeout_100ns == 0 {
            return SchedResult::Sync(0x0000_0102); // STATUS_TIMEOUT
        }

        // 注册到所有对象的 waiter 列表
        for &h in &handles {
            let shard = Self::object_shard(h);
            let mut objects = self.objects[shard].lock().unwrap();
            if let Some(obj) = objects.get_mut(&h) {
                add_waiter_obj(obj, tid);
            }
        }

        let req = WaitRequest {
            kind: WaitKind::Multiple { handles, wait_all },
            deadline: deadline_from_nt(timeout_100ns),
            wake_index: None,
        };
        SchedResult::Block(req)
    }

    /// 唤醒等待某个 handle 的线程（由 SetEvent/ReleaseMutex 等调用）
    pub fn wake_waiters(&self, woken: Vec<ThreadId>) {
        for tid in woken {
            let shard = Self::thread_shard(tid);
            let mut map = self.threads[shard].lock().unwrap();
            if let Some(t) = map.get_mut(&tid) {
                // 从 Waiting 中取出 wait_req，清理其他对象的 waiter 列表
                if let super::ThreadState::Waiting(ref req) = t.state {
                    let req = req.clone();
                    drop(map);
                    self.remove_from_waiters(tid, &req);
                    // 重新获取并设置 Ready
                    let mut map = self.threads[shard].lock().unwrap();
                    if let Some(t) = map.get_mut(&tid) {
                        t.state = super::ThreadState::Ready;
                    }
                }
                self.ready.lock().unwrap().push_back(tid);
                self.unpark_one_vcpu();
            }
        }
    }

    /// 从等待对象的 waiter 列表中移除 tid（超时或唤醒后清理）
    fn remove_from_waiters(&self, tid: ThreadId, req: &WaitRequest) {
        let handles: Vec<SyncHandle> = match &req.kind {
            WaitKind::Single(h) => vec![*h],
            WaitKind::Multiple { handles, .. } => handles.clone(),
        };
        for h in handles {
            let shard = Self::object_shard(h);
            let mut objects = self.objects[shard].lock().unwrap();
            if let Some(obj) = objects.get_mut(&h) {
                remove_waiter_obj(obj, tid);
            }
        }
    }
}

// ── 辅助函数 ─────────────────────────────────────────────────

fn obj_is_signaled(obj: &SyncObject, tid: ThreadId) -> bool {
    match obj {
        SyncObject::Event(e) => e.signaled,
        SyncObject::Mutex(m) => m.owner.is_none() || m.owner == Some(tid),
        SyncObject::Semaphore(s) => s.count > 0,
        SyncObject::Thread(_) => false, // Phase 3
    }
}

/// 尝试获取对象，返回 (acquired, return_value)
fn try_acquire_obj(obj: &mut SyncObject, tid: ThreadId) -> (bool, u64) {
    match obj {
        SyncObject::Event(e) => {
            if e.try_acquire() {
                (true, STATUS_SUCCESS)
            } else {
                (false, 0)
            }
        }
        SyncObject::Mutex(m) => {
            let (ok, abandoned) = m.try_acquire(tid);
            if ok {
                let ret = if abandoned {
                    STATUS_ABANDONED_WAIT_0
                } else {
                    STATUS_SUCCESS
                };
                (true, ret)
            } else {
                (false, 0)
            }
        }
        SyncObject::Semaphore(s) => {
            if s.try_acquire() {
                (true, STATUS_SUCCESS)
            } else {
                (false, 0)
            }
        }
        SyncObject::Thread(_) => (false, 0),
    }
}

fn add_waiter_obj(obj: &mut SyncObject, tid: ThreadId) {
    match obj {
        SyncObject::Event(e) => e.add_waiter(tid),
        SyncObject::Mutex(m) => m.add_waiter(tid),
        SyncObject::Semaphore(s) => s.add_waiter(tid),
        SyncObject::Thread(_) => {}
    }
}

fn remove_waiter_obj(obj: &mut SyncObject, tid: ThreadId) {
    match obj {
        SyncObject::Event(e) => e.remove_waiter(tid),
        SyncObject::Mutex(m) => m.remove_waiter(tid),
        SyncObject::Semaphore(s) => s.remove_waiter(tid),
        SyncObject::Thread(_) => {}
    }
}
