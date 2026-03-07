# Unlock-Edge 调度路径对齐设计

## 一、问题陈述

当前 `sched/sync/primitives_api.rs` 中的 `KEvent::wait` / `KMutex::acquire` / `KSemaphore::wait`
在调用 `block_thread_locked(tid, deadline)` 后**立即读取** `t.wait.result` 并返回。
这在语义上是错误的：`block_thread_locked` 只是把线程状态改为 `Waiting` 并加入就绪队列之外，
**并不挂起当前执行流**。真正的挂起必须由调度器在 unlock-edge 触发。

Atmosphere 的正确流程（`KSynchronizationObject::Wait`）是：

```
KScopedSchedulerLockAndSleep slp(timer, thread, timeout);
  // 构造时: KScheduler::s_scheduler_lock.Lock()
  //         RegisterAbsoluteTask 推迟到析构

  [检查 IsSignaled → 直接返回]
  [检查 timeout==0 → 返回 TIMEOUT]
  objects[i]->LinkNode(node)          // 加入对象等待链
  thread->BeginWait(&wait_queue)      // 设置线程状态 = Waiting

// slp 析构时:
//   1. timer->RegisterAbsoluteTask(thread, timeout_tick)  ← 注册定时器
//   2. KScheduler::s_scheduler_lock.Unlock()
//        └─ KAbstractSchedulerLock::Unlock()
//              └─ UpdateHighestPriorityThreads()   ← 选出各核最高优先级线程
//              └─ EnableScheduling(cores_mask)
//                    └─ RescheduleOtherCores(IPI)
//                    └─ RescheduleCurrentCore()    ← 触发本核切换
```

关键点：**定时器注册 + 调度器解锁 是原子地在同一个析构里完成的**，
解锁时立即触发 `UpdateHighestPriorityThreads` + `EnableScheduling`，
后者调用 `RescheduleCurrentCore` 完成实际的上下文切换。

---

## 二、我们当前代码的状态

| 组件 | 现状 | 问题 |
|------|------|------|
| `KSchedulerLock` (lock.rs) | RAII Drop 只释放 spinlock | Drop 时没有调用 `UpdateHighestPriorityThreads` + `EnableScheduling` |
| `block_thread_locked` (wait.rs) | 设置 deadline + 状态→Waiting | 正确，但调用方紧接着读 wait.result（错误） |
| `KEvent::wait` 等 (primitives_api.rs) | `block_thread_locked` 后立即读 result | 错误：此时线程还没真正挂起，result 未被写入 |
| `check_wait_timeouts_locked` (wait.rs) | 扫描所有线程，到期则 unblock | 正确，但只在 `scheduler_round_locked` 开头调用 |
| `scheduler_round_locked` (schedule.rs) | 选出下一个线程 | 正确，但没有被 unlock-edge 自动触发 |
| `KSchedulerLock::Drop` (lock.rs) | 只 release spinlock | **缺少**：flush deferred updates + 触发重调度 |

---

## 三、对齐目标

复现 Atmosphere 的 unlock-edge 语义，分三步：

### Step 1 — `KSchedulerLock::Drop` 触发 flush + reschedule

```
Drop:
  depth -= 1
  if depth == 0:
    flush_deferred_updates()   ← 新增：运行 scheduler_round_locked
    SCHED_LOCK.release()
    trigger_reschedule_self()  ← 新增：如果本核需要切换，立即切换
```

具体实现：在 `lock.rs` 的 `Drop` 里，depth 降到 0 时：
1. 调用 `schedule::flush_unlock_edge(vid)` — 在 spinlock 仍持有时运行一次
   `scheduler_round_locked`，把结果写入 `vcpu[vid].needs_scheduling` 和
   `vcpu[vid].highest_priority_thread`（新增字段）。
2. 释放 spinlock。
3. 如果 `needs_scheduling`，调用 `schedule::reschedule_current_core()` 触发切换。

### Step 2 — `KScopedSchedulerLockAndSleep` 等价物

新增 `SchedLockAndSleep` RAII 类型（在 `lock.rs` 或新文件 `sched/sleep.rs`）：

```rust
pub struct SchedLockAndSleep {
    tid:          u32,
    deadline:     WaitDeadline,
    cancelled:    bool,
    _guard:       KSchedulerLock,
}

impl SchedLockAndSleep {
    pub fn new(tid: u32, deadline: WaitDeadline) -> Self { ... }
    pub fn cancel(&mut self) { self.cancelled = true; }
}

impl Drop for SchedLockAndSleep {
    fn drop(&mut self) {
        if !self.cancelled && self.deadline != WaitDeadline::Infinite {
            // 定时器已在 block_thread_locked 里通过 wait.deadline 字段注册，
            // check_wait_timeouts_locked 会在下一轮 scheduler_round 里处理。
            // 此处只需确保 KSchedulerLock 的 Drop 触发 unlock-edge。
        }
        // _guard 的 Drop 自动触发 flush + reschedule
    }
}
```

### Step 3 — `KEvent::wait` 等改写为 lock-and-sleep 模式

```rust
pub fn wait(&mut self, tid: u32, deadline: WaitDeadline) -> u32 {
    // 调用方已持有 sched lock（或由此处获取）
    if self.signaled {
        if self.auto_reset { self.signaled = false; }
        return STATUS_SUCCESS;
    }
    if deadline == WaitDeadline::Immediate {
        return STATUS_TIMEOUT;
    }
    self.waiters.enqueue(tid);
    block_thread_locked(tid, deadline);
    // 返回 STATUS_PENDING — 真正的结果在线程被唤醒后由调用方读取
    STATUS_PENDING  // 新增常量 0x0000_0103
}
```

调用方（syscall handler）模式：

```rust
// nt/sync.rs — NtWaitForSingleObject
{
    let _slp = SchedLockAndSleep::new(tid, deadline);
    // 检查已信号
    if event.is_signaled() { _slp.cancel(); return STATUS_SUCCESS; }
    // 检查 timeout==0
    if deadline == Immediate { _slp.cancel(); return STATUS_TIMEOUT; }
    // 加入等待队列 + 设置 Waiting
    event.enqueue_waiter(tid);
    block_thread_locked(tid, deadline);
    // _slp 析构 → unlock-edge → 调度器切走本线程
}
// 线程被唤醒后在此处继续执行
with_thread(tid, |t| t.wait.result).unwrap_or(STATUS_TIMEOUT)
```

---

## 四、`UpdateHighestPriorityThreads` 对应实现

Atmosphere 在 unlock-edge 调用 `UpdateHighestPriorityThreadsImpl()`，
遍历所有核，为每核选出最高优先级线程，并处理跨核迁移。

我们的对应实现是 `scheduler_round_locked(vid, from_tid, quantum)`，
但它只处理单核。需要在 `flush_unlock_edge` 里：

1. 对**本核**运行 `scheduler_round_locked`，得到 `SchedulerRoundAction`。
2. 如果结果是 `RunThread { to_tid, .. }`，设置 `vcpu[vid].needs_scheduling = true`
   并记录 `to_tid`。
3. 对**其他核**，如果它们的 `needs_reschedule` 被设置，发送 IPI（通过
   `hypercall::send_ipi(target_vid)`）。

---

## 五、具体修改清单

### 5.1 `sched/types.rs`
- 无需修改。

### 5.2 `sched/global.rs`
- `KVcpuState` 新增字段：
  ```rust
  pub highest_priority_tid: u32,   // 本核下一个要运行的线程
  ```

### 5.3 `sched/lock.rs`
- `KSchedulerLock::Drop` 在 depth==0 时调用
  `schedule::flush_unlock_edge(self.vid)`（在 spinlock 释放前）。
- 新增 `pub struct SchedLockAndSleep` 及其 `cancel()` 方法。

### 5.4 `sched/schedule.rs`
- 新增 `pub fn flush_unlock_edge(vid: usize)`：
  - 在 spinlock 持有期间运行 `scheduler_round_locked`。
  - 把结果写入 `vcpu[vid].highest_priority_tid` 和 `needs_scheduling`。
  - 对需要 IPI 的其他核调用 `hypercall::send_ipi`。
- 新增 `pub fn reschedule_current_core(vid: usize)`：
  - 读取 `vcpu[vid].highest_priority_tid`。
  - 调用 `execute_kernel_continuation_switch` 或
    `enter_kernel_continuation_noreturn` 完成切换。

### 5.5 `sched/sync/primitives_api.rs`
- `KEvent::wait` / `KMutex::acquire` / `KSemaphore::wait`：
  - 移除 `block_thread_locked` 后的 `with_thread(tid, |t| t.wait.result)` 读取。
  - 改为返回 `STATUS_PENDING`（新常量）。
- 新增 `KEvent::enqueue_waiter(tid)` 等拆分方法，供 syscall handler 使用。

### 5.6 `sched/sync/handles.rs` / `nt/sync.rs`
- `wait_for_single_object` / `wait_for_multiple_objects`：
  - 改用 `SchedLockAndSleep` 模式。
  - 在 `_slp` 析构后读取 `wait.result`。

### 5.7 `sched/wait.rs`
- 新增常量 `pub const STATUS_PENDING: u32 = 0x0000_0103;`。
- `block_thread_locked` 保持不变。

---

## 六、执行顺序（unlock-edge 完整路径）

```
NtWaitForSingleObject(handle, timeout)
  │
  ├─ SchedLockAndSleep::new(tid, deadline)
  │     └─ KSchedulerLock::lock()  ← 获取 sched spinlock
  │
  ├─ [检查 IsSignaled → cancel + return SUCCESS]
  ├─ [检查 timeout==0 → cancel + return TIMEOUT]
  │
  ├─ event.enqueue_waiter(tid)     ← 加入 WaitQueue
  ├─ block_thread_locked(tid, dl)  ← state = Waiting, deadline 写入
  │
  └─ SchedLockAndSleep::drop()
        └─ KSchedulerLock::drop()
              ├─ flush_unlock_edge(vid)
              │     ├─ scheduler_round_locked(vid, from, 0)
              │     │     ├─ check_wait_timeouts_locked()
              │     │     ├─ pick_next_thread_locked(vid) → to_tid
              │     │     └─ → SchedulerRoundAction::RunThread { to_tid }
              │     ├─ vcpu[vid].highest_priority_tid = to_tid
              │     └─ vcpu[vid].needs_scheduling = true
              ├─ SCHED_LOCK.release()
              └─ reschedule_current_core(vid)
                    └─ execute_kernel_continuation_switch(from_tid, to_tid, ...)
                          └─ __sched_switch_kernel_context(from_kctx, to_kctx)
                                ← 本线程挂起，to_tid 开始运行

[to_tid 运行一段时间后，某处 set_event / release_mutex / release_semaphore]
  └─ KScopedSchedulerLock sl
        ├─ unblock_thread_locked(tid, STATUS_SUCCESS)
        │     ├─ t.wait.result = STATUS_SUCCESS
        │     └─ set_thread_state_locked(tid, Ready) → 加入就绪队列
        └─ sl.drop() → flush_unlock_edge → 下一轮调度
              └─ 可能切回 tid

[tid 被调度回来，从 SchedLockAndSleep::drop() 之后继续]
  └─ with_thread(tid, |t| t.wait.result)  → STATUS_SUCCESS
```

---

## 七、不需要改动的部分

- `topology.rs` — `set_thread_state_locked` 已正确处理就绪队列 push/pop。
- `queue.rs` — `KReadyQueue` 已实现 scheduled/suggested 双队列。
- `context.rs` — `ensure_user_entry_continuation_locked` 已正确。
- `threads.rs` — `spawn_locked` 已调用 `ensure_user_entry_continuation_locked`。
- `thread_control.rs` — 优先级、suspend/resume 逻辑正确。

---

## 八、实现优先级

| 优先级 | 任务 |
|--------|------|
| P0 | `lock.rs`: Drop 调用 `flush_unlock_edge` |
| P0 | `schedule.rs`: 实现 `flush_unlock_edge` + `reschedule_current_core` |
| P1 | `lock.rs`: 新增 `SchedLockAndSleep` |
| P1 | `primitives_api.rs`: wait 方法返回 STATUS_PENDING，移除错误的 result 读取 |
| P2 | `handles.rs` / `nt/sync.rs`: 改用 lock-and-sleep 模式 |
| P3 | `global.rs`: KVcpuState 新增 `highest_priority_tid` |
