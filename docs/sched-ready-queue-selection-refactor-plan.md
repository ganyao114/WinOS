# 调度器 Ready-Queue 选择重构方案（对齐 Mesosphere）

## 一、问题定义

当前 `thread_test` 仅剩 `Wait/Wake Burst` 失败，表现是批量唤醒后只有部分 waiter 在线程窗口内完成，说明调度选择与状态迁移之间仍有不一致。

结合现状代码（`winemu-kernel/src/sched/schedule.rs`）主要风险点：

1. `pick_next_thread_locked()` 是“先 pop 再判断是否继续当前线程”，会引入额外 requeue 和顺序扰动。
2. `ContinueCurrent` 条件过宽，`unlock-edge / wake / yield / timer-preempt` 共用一套策略，缺少“调度原因”语义。
3. 存在强修复路径（`rebuild_ready_queue_locked()` / `sanitize_invalid_thread_states_locked()`），掩盖根因并放大复杂度。
4. `ReadyQueue` 去重与 purge 分散在多个调用点，状态机不够单向。

## 二、目标（与 Mesosphere 一致的方向）

1. 保留全局优先队列 + 多核协作，不回退到每核就绪队列。
2. 调度决策必须“按原因区分”（yield、唤醒、抢占、unlock-edge）。
3. `yield` 语义严格化：存在其它可运行线程时，不能继续选中当前线程。
4. 缩小 `ContinueCurrent` 适用面，避免 burst 场景下同优先级线程被长期推迟。
5. 去掉临时“重建队列”类逻辑，恢复可证明的队列不变式。

## 三、分阶段改造

### 阶段 A：引入调度原因并收敛选择入口

新增 `ScheduleReason`（建议位置：`winemu-kernel/src/sched/schedule.rs`）：

- `UnlockEdge`
- `Yield`
- `TimerPreempt`
- `Wakeup`
- `Ipi`
- `Timeout`

改造点：

1. `scheduler_round_locked(...)` 增加 `reason: ScheduleReason` 参数。
2. `flush_unlock_edge()` 传 `UnlockEdge`。
3. `NtYieldExecution` 路径传 `Yield`。
4. IRQ 抢占路径传 `TimerPreempt` / `Ipi`。
5. 纯超时唤醒路径传 `Timeout`，同步对象唤醒传 `Wakeup`。

收益：

1. 策略可按原因收敛，不再靠 `pending_resched` 和多个布尔组合推导语义。
2. 为后续对齐 Mesosphere 的 `Yield*` 行为提供稳定入口。

### 阶段 B：改造 pick/continue 判定，去除 destructive pop

核心原则：先“看候选”，再“做状态迁移”，最后“必要时出队”。

改造点：

1. 新增 `peek_next_thread_locked(vid)`，默认只读查看候选。
2. `Yield` 分支：
   - 若存在 `to_tid != from_tid`，必须切走；
   - 若无其它候选，继续当前线程。
3. `Wakeup/Timeout` 分支：
   - 只要候选不劣于当前（优先级更高或同优先级且当前并非唯一候选），触发切换；
   - 避免 burst 唤醒后长期继续当前线程。
4. 仅在决定 `RunThread` 后才执行真实 `pop/remove`。

收益：

1. 队列顺序不被“试探式 pop/requeue”污染。
2. `Wait/Wake Burst` 下新 readied 线程更快获得 CPU。

### 阶段 C：清理临时修复路径并固化不变式

移除或降级为 debug-only：

1. `rebuild_ready_queue_locked()`
2. 全局扫描式 `sanitize_invalid_thread_states_locked()`
3. 多处重复 purge 的兜底环

固化不变式：

1. `set_thread_state_locked()` 是 ReadyQueue 入队/出队唯一入口。
2. `Running` 线程不在 ready queue（现有模型）或在后续阶段切到“Mesosphere 风格 Runnable 在队列中”，二选一并全局一致。
3. 任一 `tid` 在任一时刻最多存在一个 ready-queue 链接。

## 四、代码落点（首批）

1. `winemu-kernel/src/sched/schedule.rs`
2. `winemu-kernel/src/sched/topology.rs`
3. `winemu-kernel/src/sched/lock.rs`
4. `winemu-kernel/src/sched/mod.rs`
5. `winemu-kernel/src/arch/aarch64/timer.rs`
6. `winemu-kernel/src/arch/aarch64/vectors.rs`
7. `winemu-kernel/src/nt/thread.rs`（`NtYieldExecution` 路径）

## 五、验收标准

1. `thread_test` 全量通过，特别是：
   - `Wait/Wake Burst`
   - `Timer Preemption (No Yield)`
2. 单核和多核模式均通过：
   - `WINEMU_VCPU_COUNT=1`
   - `WINEMU_VCPU_COUNT=2`
3. 日志中不再出现 ready-queue rebuild/self-heal 才能维持正确性的迹象。

## 六、Mesosphere 会不会有同样问题？

结论：按当前代码实现，Mesosphere 不会以“同样机制”触发该问题，风险显著更低。

依据：

1. 状态迁移统一入口：
   - `KThread::SetState(...)` -> `KScheduler::OnThreadStateChanged(...)`
   - Runnable 入队/出队是单入口更新（`source/kern_k_thread.cpp`, `source/kern_k_scheduler.cpp`）。
2. Yield 语义明确：
   - `YieldWithoutCoreMigration/WithCoreMigration/ToAnyThread` 明确执行 `MoveToScheduledBack(...)`，不是“先 pop 再条件 requeue”（`source/kern_k_scheduler.cpp`）。
3. 全局调度更新模型稳定：
   - `KAbstractSchedulerLock::Unlock()` 只在最终解锁点调用 `UpdateHighestPriorityThreads()` 和 `EnableScheduling(...)`（`include/mesosphere/kern_k_scheduler_lock.hpp`）。
4. 批量唤醒路径在同一调度锁下完成：
   - `KReadableEvent::Signal()` -> `NotifyAvailable()` -> waiter `EndWait/SetState(Runnable)`（`source/kern_k_readable_event.cpp`, `source/kern_k_synchronization_object.cpp`, `source/kern_k_thread_queue.cpp`）。

补充说明：

Mesosphere 也会面临公平性策略权衡（例如同优先级轮转频率），但其不会依赖“重建 ready queue”这类补丁来维持正确性，因此不属于当前 WinEmu 的同类问题。

## 七、执行顺序建议

1. 先落地阶段 A（只引入 `ScheduleReason` 与入口路由，不改队列结构）。
2. 再落地阶段 B（替换 destructive pop，严格化 yield）。
3. 最后阶段 C（删除临时修复逻辑，保留最小 debug 断言）。
