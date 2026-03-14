# 调度器剩余重构清单

## 一、结论

当前调度器已经满足“主流程可运行、关键回归可通过”的要求，但还没有达到“结构彻底收口、后续继续扩 syscall / wait / 多核协作时不会继续积累复杂度”的状态。

结论分两层：

1. 如果目标只是“当前测试稳定”，可以先停。
2. 如果目标是“继续向 Mesosphere 对齐，并把后续演进成本压低”，还应该继续做 4 组重构。

本文件只定义“剩余值得继续做的重构”，不重复已经完成的部分。

---

## 二、当前已完成的部分

以下方向已经基本到位：

1. 调度决策核心已经收敛到 `schedule_core_locked(...)`
   - `winemu-kernel/src/sched/schedule.rs`
2. unlock-edge 调度提交点已经收敛到 `KSchedulerLock::Drop`
   - `winemu-kernel/src/sched/lock.rs`
   - `winemu-kernel/src/sched/schedule.rs`
3. trap 路径已经基本转为 adapter，而不是单独维护一套调度器
   - `winemu-kernel/src/nt/trap_schedule.rs`
4. 主核和次核已经共享统一的 scheduler entry
   - `winemu-kernel/src/sched/schedule.rs`
5. destructive pop + requeue 的主要问题已经修掉，`thread_test` 双核稳定性已经明显提升

这意味着下一阶段不应该再“整体推倒重来”，而应该继续收不变式和边界。

---

## 三、剩余问题总览

还值得继续重构的点一共有 4 组，按优先级排序如下：

1. ReadyQueue 修改入口没有真正单点化
2. `needs_reschedule / needs_scheduling / pending_local_schedule_reason` 三套调度意图仍然混杂
3. trap adapter 仍然承担偏多 carrier 修补逻辑
4. ready-queue 结构尚未对齐 Mesosphere 的 `scheduled + suggested` 模型

此外还有一些低优先级清理项，但不应抢在上述 4 组之前做。

---

## 四、P0：ReadyQueue 修改入口单点化

### 4.1 问题

当前 ready-queue 的 push / purge / remove / dequeue 仍然分散在多个位置：

1. `winemu-kernel/src/sched/topology.rs`
2. `winemu-kernel/src/sched/thread_control.rs`
3. `winemu-kernel/src/sched/schedule.rs`

这和我们想要的不变式不一致：

1. 一个 `tid` 在任意时刻最多存在一个 ready link
2. ReadyQueue 的进出必须由单入口维护
3. 线程状态变迁和队列变迁要么一起成功，要么一起不发生

当前虽然功能上能跑，但“同类逻辑散落在多个模块里”会导致：

1. 优先级变更、affinity 变更、wait 唤醒、抢占回队列时再次复制逻辑
2. 后续很容易出现某一路径漏清 `in_ready_queue` 或 `sched_next`
3. 代码阅读成本高，不容易证明状态机正确

### 4.2 目标

把 ready-queue 修改收敛为单一模块，例如：

1. `sched/ready_queue_ops.rs`
2. 或者直接收进 `sched/topology.rs`，但只保留公开 API，不允许其他文件复制实现

最终只保留以下几类原语：

1. `enqueue_ready_locked(tid)`
2. `dequeue_ready_locked(tid)`
3. `take_next_ready_locked(vid)`
4. `peek_next_ready_locked(vid)`
5. `on_thread_state_change_locked(tid, old, new)`
6. `on_thread_priority_change_locked(tid, old, new)`
7. `on_thread_affinity_change_locked(tid, old_mask, new_mask)`

### 4.3 实施要求

1. 删除 `thread_control.rs` 中重复的 `push_tid_to_ready_queue_locked` / `purge_tid_from_ready_queue_locked`
2. 删除 `schedule.rs` 中直接操作 `in_ready_queue` 的散点逻辑，改为调用统一 helper
3. 明确 `set_thread_state_locked()` 是否仍作为唯一状态迁移入口
4. 对 `priority change`、`affinity change`、`wake`、`preempt requeue` 逐条改成统一接口

### 4.4 完成标准

1. ReadyQueue 的增删改只剩一处实现
2. `in_ready_queue` / `sched_next` 不再被多个模块独立维护
3. `thread_test`、`full_test` 回归无退化

---

## 五、P1：调度意图语义拆清

### 5.1 问题

当前至少存在三套“需要调度”的语义：

1. 本地 trap/当前核重入调度
   - `cpu_local().needs_reschedule`
   - `winemu-kernel/src/sched/cpu.rs`
2. 远端 vCPU 需要重新调度
   - `KVcpuState.needs_scheduling`
   - `winemu-kernel/src/sched/global.rs`
3. 本地 unlock-edge 希望用什么 reason 重新评估
   - `KVcpuState.pending_local_schedule_reason`
   - `winemu-kernel/src/sched/global.rs`
   - `winemu-kernel/src/sched/schedule.rs`

现在这些语义在多个路径里交叉设置：

1. `wait.rs`
2. `topology.rs`
3. `sync/primitives_api.rs`
4. `sync/state.rs`
5. `thread_control.rs`
6. `nt/trap_schedule.rs`

这会导致一个核心问题：代码能跑，但很难直接判断“这次调度意图是本地 unlock-edge、还是本地 trap、还是远端 reschedule”。

### 5.2 目标

把调度意图明确拆成 3 类：

1. `LocalTrapResched`
   - 含义：当前 vCPU 在 trap 返回边界需要再次进入 `schedule_from_trap`
2. `LocalUnlockEdgeReason`
   - 含义：当前 vCPU 在最终 unlock 时需要以什么 `ScheduleReason` 重新评估
3. `RemoteReschedMask`
   - 含义：哪些 vCPU 需要被 kick / IPI 叫醒重新评估

### 5.3 方向

建议做法：

1. 保留 `pending_local_schedule_reason`
   - 它本身已经比较接近 unlock-edge 语义
2. 重新命名 `needs_reschedule`
   - 强调它只代表 trap-safe-point 的本地重入请求
3. 重新命名 `needs_scheduling`
   - 强调它只代表远端核需要重新跑一次 scheduler round
4. 为各类 setter 增加明确 helper
   - `request_local_trap_reschedule()`
   - `request_local_unlock_edge_schedule(reason)`
   - `request_remote_vcpu_reschedule(vid)`

### 5.4 实施要求

1. 不再在业务路径里直接写布尔字段
2. 所有设置点改为调用明确 helper
3. 所有 helper 的注释必须说明“调度在哪里真正发生”

### 5.5 完成标准

1. 搜索代码时，不再看到各模块散点直接写 `needs_reschedule` / `needs_scheduling`
2. 阅读任何一个 wait/wake 路径时，能明确知道它触发的是哪一类调度请求

---

## 六、P2：trap adapter 继续瘦身

### 6.1 问题

当前 `winemu-kernel/src/nt/trap_schedule.rs` 已经比之前干净很多，但仍然承担了较多“当前 carrier 是 user-frame 还是 kctx”的修补逻辑，例如：

1. `current_not_running`
2. `pending_resched`
3. `timeout_woke`
4. `should_resume_user_frame(...)`
5. `classify_trap_switch_target(...)`
6. syscall 前后手动切 `in_kernel`

这说明 trap 路径虽然不再自己选线程，但仍然知道太多线程执行载体内部细节。

### 6.2 目标

继续收敛到以下模型：

1. trap adapter 只负责：
   - 保存当前 `SvcFrame`
   - 让 scheduler core 给出决策
   - 把目标线程恢复到 `SvcFrame` 或切入 continuation
2. carrier 状态机的规则尽量收进更小、更明确的 helper
   - 例如 `context` / `carrier` / `resume` 子模块

### 6.3 非目标

这一步不追求“彻底消灭 trap 调度路径”。

原因很简单：

1. EL0 timer IRQ / syscall return 本身就需要 trap adapter
2. trap 路径存在是合理的，问题是不要让它变成第二套 scheduler

### 6.4 实施要求

1. 把 `in_kernel` 的切换规则收成更少的 helper
2. 把 “恢复 user frame” 与 “切 continuation” 的分支判定压缩成更可读的接口
3. 避免 `trap_schedule.rs` 继续堆 carrier 修补分支

### 6.5 完成标准

1. `trap_schedule.rs` 主要只剩 adapter 逻辑
2. `in_kernel` / continuation / frame restore 规则能在独立 helper 中单独阅读

---

## 七、P3：向 Mesosphere 的 `scheduled + suggested` 双队列继续靠拢

### 7.1 问题

当前 ready-queue 仍然是单个全局优先级队列，再通过 `peek_highest_matching(...)` / `pop_highest_matching(...)` 按 `affinity` 和 `in_kernel` 做过滤。

对应文件：

1. `winemu-kernel/src/sched/queue.rs`
2. `winemu-kernel/src/sched/schedule.rs`

这种模型的优点是：

1. 简单
2. 当前已经能通过主要回归

但它和 Mesosphere 的模型并不一致：

1. Mesosphere 更强调“已分配到某核的 scheduled work”
2. 和“可迁移的 suggested work”分开
3. 多核协作时不依赖在热路径里反复扫全局队列 + 过滤

### 7.2 何时值得做

满足下面任一条件时就值得做：

1. 线程数继续增多
2. affinity 场景继续增多
3. 更多跨核唤醒 / IPI / stealing 场景出现
4. 需要更贴近 Mesosphere 的调度拓扑

### 7.3 目标

将单全局 `KReadyQueue` 演进到：

1. `scheduled[vcpu][prio]`
2. `suggested[vcpu][prio]` 或等价结构

并明确：

1. 哪些线程已经被分配到指定 vCPU
2. 哪些线程只是“建议由某 vCPU 消费”
3. 哪些线程允许迁移
4. 固定 affinity 的线程绝不进入错误核的偷取路径

### 7.4 实施要求

1. 在完成 P0 和 P1 之前，不做这一步
2. 先收不变式，再升级队列结构
3. 升级时必须同步调整跨核 reschedule 计算逻辑

### 7.5 完成标准

1. 调度拓扑模型和文档一致
2. `pick_next` 不再主要依赖“全局队列 + predicate 过滤”
3. 多核唤醒、affinity、迁移语义更直接

---

## 八、低优先级清理项

这些项可以做，但不应该抢在前面 4 组之前：

1. `sched/sync/legacy_handles.rs` 的归属继续清理
2. wait absolute timeout 的完善
   - `winemu-kernel/src/sched/wait.rs`
3. 统计/调试字段继续归位
4. 冗余 panic 文案与注释整理

这些工作会改善整洁度，但不改变调度器的核心结构风险。

---

## 九、建议执行顺序

建议严格按顺序推进：

1. P0：ReadyQueue 单入口
2. P1：调度意图语义拆清
3. P2：trap adapter 继续瘦身
4. P3：双队列 / scheduled + suggested 对齐

原因：

1. P0/P1 是不变式与语义问题
2. P2 是适配层复杂度问题
3. P3 才是结构升级问题

如果跳过前两步直接做 P3，很容易把复杂度带进新队列结构里。

---

## 十、每阶段验收标准

每完成一个阶段，至少回归：

1. `thread_test`
2. `full_test`
3. `window_test`

建议重点关注：

1. `Timer Preemption (No Yield)`
2. `Wait/Wake Burst`
3. `ReleaseMutant Wake Preemption`
4. `ReleaseSemaphore Wake Preemption`
5. 窗口消息循环是否仍然正常退出

额外要求：

1. 不允许为了“修测试”重新引入散点状态修补
2. 不允许恢复“全局重建 ready queue”类补丁逻辑
3. 每次改造后必须能解释新的不变式比之前更简单，而不是更隐蔽

---

## 十一、最终完成定义

调度器可以认为“基本收工”的标准是：

1. ReadyQueue 修改入口单点化
2. 三类调度意图边界明确
3. trap adapter 只保留 adapter 责任
4. 若继续向 Mesosphere 靠拢，则双队列结构落地

在这之前，调度器可以说“能用”，但还不适合说“已经完全收口”。
