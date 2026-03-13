# 调度路径统一方案

## 一、目标

本方案只解决一个问题：把当前调度器里混在一起的 trap 调度、unlock-edge 调度、idle 调度彻底收口成一套清晰模型。

目标不是“所有入口都调用同一个切换函数”，而是：

1. 所有入口共享同一个调度决策核心。
2. `kctx` 线程的让出核心发生在 unlock-edge。
3. trap 路径只负责 `SvcFrame` 的保存/恢复与返回适配。
4. 主核与次核进入 idle 后走同一套调度语义。

这与 Mesosphere 的对齐点是：

1. 调度决策在 scheduler lock 保护下统一产生。
2. 最终 unlock 触发 scheduling enable。
3. 真正的上下文提交点依赖当前执行载体，而不是让各入口各写一套选线程逻辑。

---

## 二、先澄清一个关键概念：当前线程的执行载体

当前线程在 CPU 上运行时，只可能落在两种载体之一：

### 2.1 `SvcFrame` 载体

表示线程当前是“从 EL0 trap 进来，最终需要 `eret` 返回”的状态。

特点：

1. 用户态寄存器活在 `SvcFrame` 里。
2. 当前调用链还没有完全转化为一个可恢复的 kernel continuation。
3. 若要切换，必须先把 `SvcFrame` 保存到 `KThread.ctx`。

对应当前代码：

- [winemu-kernel/src/nt/dispatch.rs](/Users/swift/WinEmu/winemu-kernel/src/nt/dispatch.rs)
  - `save_ctx_for`
  - `restore_ctx_to_frame`
  - `schedule_from_trap`

### 2.2 `KernelContext(kctx)` 载体

表示线程当前已经是一个真正可恢复的内核 continuation。

特点：

1. CPU 上下文切换通过 `switch_kernel_context(from, to)` 完成。
2. 当前线程若阻塞、yield、被更高优先级线程抢占，让出核心应该发生在 unlock-edge。
3. 这条路径不应该依赖 `schedule_from_trap`。

对应当前代码：

- [winemu-kernel/src/sched/schedule.rs](/Users/swift/WinEmu/winemu-kernel/src/sched/schedule.rs)
  - `execute_kernel_continuation_switch`
  - `enter_kernel_continuation_noreturn`

这个区分非常重要。后续所有统一设计都建立在它上面。

---

## 三、现状问题

当前实现的问题不是“有两个入口”，而是“两边都在做一半调度器”：

1. trap 路径自己调用 `scheduler_round_locked()`，自己决定继续/切换/idle。
2. unlock-edge 路径也调用 `scheduler_round_locked()`，但又把结果搬运到 `highest_priority_tid` / `needs_scheduling`，再由 `reschedule_current_core()` 二次执行。
3. `needs_scheduling` 同时承担“远端核提醒”和“本核切换 carrier”两种职责，语义混乱。
4. `highest_priority_tid` 本质上是本核 staged decision，属于重复状态。
5. `yield_current_thread()` 名字像“立即让出 CPU”，但当前更多是在设置调度意图。

结果是：

1. 调度决策并没有真正单点收敛。
2. trap/unlock-edge/idle 三条路径的职责边界不清楚。
3. 主核和次核虽然行为逐步接近，但仍没有完全共享同一调度流程。

---

## 四、目标架构：一个调度核心，两个适配层

统一后的结构如下：

```text
调度入口
  -> schedule_core_locked(...)
  -> ScheduleDecision
  -> adapter.apply(...)
```

具体是：

1. 一个调度决策核心：`schedule_core_locked`
2. 一个 trap 适配层：`trap adapter`
3. 一个 unlock-edge 适配层：`unlock-edge adapter`
4. 一个共享的本地调度迭代 helper：供 idle thread / core scheduler entry 复用

### 4.1 调度决策核心

建议从现有 `scheduler_round_locked()` 演进为：

```rust
pub fn schedule_core_locked(
    vid: u32,
    from_tid: u32,
    quantum_100ns: u64,
    reason: ScheduleReason,
) -> ScheduleDecision
```

它只做这些事：

1. drain deferred kstack
2. timeout 到期处理
3. free terminated threads
4. 观察 ready queue
5. 根据 `ScheduleReason` 计算当前线程与候选线程的关系
6. 输出统一决策

它不做这些事：

1. 不保存/恢复 `SvcFrame`
2. 不直接切 `KernelContext`
3. 不写 `highest_priority_tid`
4. 不调用 `eret`
5. 不负责 IPI 发送

### 4.2 决策对象

建议统一成：

```rust
pub enum ScheduleDecision {
    ContinueCurrent {
        now_100ns: u64,
        next_deadline_100ns: u64,
        slice_remaining_100ns: u64,
    },
    SwitchToThread {
        from_tid: u32,
        to_tid: u32,
        now_100ns: u64,
        next_deadline_100ns: u64,
        slice_remaining_100ns: u64,
        current_not_running: bool,
    },
    EnterIdle {
        from_tid: u32,
        now_100ns: u64,
        next_deadline_100ns: u64,
    },
}
```

这份决策只描述“要做什么”，不描述“如何在某个上下文载体里做”。

---

## 五、统一后的三条执行路径

## 5.1 trap 路径

trap 路径只负责 `SvcFrame` 适配。

### 入口

1. syscall 返回边界
2. timer IRQ 抢占
3. host 唤醒/other core 唤醒导致的 trap 边界调度

### 统一流程

```text
trap 进入
  -> 保存当前 SvcFrame 到 current_thread.ctx
  -> acquire scheduler lock
  -> schedule_core_locked(...)
  -> release scheduler lock
  -> 按决策落地
```

### 落地规则

#### A. `ContinueCurrent`

1. 恢复当前线程的 running 状态
2. 设置 timer slice
3. 直接返回 trap

#### B. `SwitchToThread`

分两种情况：

1. 目标线程是 `kctx` continuation
   - 当前 trap 线程的 `SvcFrame` 已保存
   - 直接切到 `to.kctx`
   - 将来切回来时，再把当前线程 `ctx` 恢复回 `SvcFrame`

2. 目标线程没有 `kctx`，而是普通用户态可返回线程
   - 直接把 `to.ctx` 恢复进当前 `SvcFrame`
   - `eret`

#### C. `EnterIdle`

1. 释放锁
2. 进入 idle wait / shutdown exit

### trap 路径的边界

trap 路径不是“完整调度器”，它只是：

1. 持有 `SvcFrame`
2. 能保存/恢复用户寄存器
3. 能决定是继续 `eret` 当前线程、切去别的用户线程，还是切入某个 `kctx`

---

## 5.2 unlock-edge 路径

这条路径是 `kctx` 线程让出核心的提交点。

### 入口

1. 内核线程/continuation 在 syscall 深处阻塞
2. 内核线程执行 `yield`
3. 同步对象唤醒后导致本核需要切到别的就绪线程
4. 任何 “当前线程已经是 kctx 载体” 的让出场景

### 统一流程

```text
持有 KSchedulerLock 的内核路径
  -> 修改线程状态 / ready queue / wait state
  -> KSchedulerLock 最终 Drop
  -> schedule_core_locked(..., ScheduleReason::UnlockEdge / Yield / Wakeup ...)
  -> 生成 unlock-edge plan
  -> release scheduler lock
  -> plan.apply()
```

### 落地规则

#### A. `ContinueCurrent`

1. 不做切换
2. 恢复当前线程运行态
3. 返回原内核控制流

#### B. `SwitchToThread`

1. 若 `from_tid == to_tid`，不切
2. 若 `from_tid != to_tid`，执行 `switch_kernel_context(from.kctx, to.kctx)`
3. 若当前没有 `from_tid`，则 `enter_kernel_continuation_noreturn(to_tid)`

#### C. `EnterIdle`

1. 切入本核 idle continuation
2. 后续 idle loop 再经同一调度核心挑选线程

### unlock-edge 路径的核心约束

1. 已经运行在 `kctx` 上的线程，让出 CPU 必须发生在 unlock-edge。
2. unlock-edge 不应该再依赖 `schedule_from_trap()` 代为完成本核切换。
3. unlock-edge 不应该再借 `highest_priority_tid` 做 staged commit。

---

## 5.3 idle 路径

idle 线程不应是另一套“特判调度器”，它只是一个普通的 `kctx` 载体。

### 统一流程

```text
idle continuation loop
  -> acquire scheduler lock
  -> schedule_core_locked(..., reason = Ipi/TimerPreempt/UnlockEdge)
  -> release scheduler lock
  -> apply decision
```

### 主核与次核的统一原则

主核和次核在“进入 idle 之后”应该完全一致：

1. 都拥有 idle thread continuation
2. 都通过同一个 `schedule_core_locked()` 取下一线程
3. 都通过同一个 kernel adapter 提交切换

主核和次核只允许在“启动前职责”上不同，例如：

1. 主核负责全局 init
2. 次核负责 secondary bringup

进入 scheduler 之后，不应再保留“主核 idle loop”和“次核 idle loop”两套语义。

---

## 六、需要删掉或降级职责的现有机制

## 6.1 `highest_priority_tid`

这个字段本质是在本核缓存一份已经算出来的切换目标。

问题：

1. 它不是稳定状态，只是一次 unlock-edge 的临时决策。
2. 它让调度决策和调度执行分裂成两步。
3. 它导致 `flush_unlock_edge()` 和 `reschedule_current_core()` 形成重复流水线。

目标：

1. 删除 `highest_priority_tid`
2. 由 `build_unlock_edge_dispatch_locked()` 直接返回本次解锁要做的事

## 6.2 `reschedule_current_core()`

这个函数当前是“读取 staged decision，然后再做真正切换”。

问题：

1. 它使 unlock-edge 不再是原子决策-提交链路
2. 它必须重新理解 `needs_scheduling/highest_priority_tid`
3. 它会让本核路径继续依赖额外的 carrier 状态

目标：

1. 删除 `reschedule_current_core()`
2. 本核切换改成“drop 前构造 plan，drop 后直接 apply”

## 6.3 `needs_scheduling`

这个字段应保留，但必须降级职责。

保留后的语义：

1. 远端核 reschedule 提示
2. idle 核唤醒提示
3. 拓扑更新需要对某核重新进入调度核心的提示

不再承担：

1. 本核目标线程 carrier
2. 本核 staged switch decision

---

## 七、模块职责重划分

建议职责如下。

## 7.1 `sched/core.rs` 或 `sched/schedule_core.rs`

职责：

1. `ScheduleReason`
2. `ScheduleDecision`
3. `schedule_core_locked`
4. ready queue 选择与公平性策略
5. timeout/free terminated 等调度前维护

## 7.2 `nt/trap_schedule.rs`

职责：

1. `save_ctx_for`
2. `restore_ctx_to_frame`
3. `schedule_from_trap`
4. trap 场景下 `ScheduleDecision` 的 apply

当前 [winemu-kernel/src/nt/dispatch.rs](/Users/swift/WinEmu/winemu-kernel/src/nt/dispatch.rs) 里的 trap 调度逻辑应逐步搬到这里，减少 `dispatch.rs` 同时承担 syscall 分发和调度适配两种职责。

## 7.3 `sched/unlock_edge.rs` 或 `sched/lock.rs`

职责：

1. `build_unlock_edge_dispatch_locked`
2. `LocalSchedulePlan::apply`
3. `KSchedulerLock::Drop` 最终 unlock 的统一提交逻辑

建议新增：

```rust
pub enum LocalSchedulePlan {
    None,
    ContinueCurrent {
        now_100ns: u64,
        next_deadline_100ns: u64,
        slice_remaining_100ns: u64,
    },
    SwitchKernelContext {
        from_tid: u32,
        to_tid: u32,
        now_100ns: u64,
        next_deadline_100ns: u64,
        slice_remaining_100ns: u64,
    },
    EnterIdle {
        now_100ns: u64,
        next_deadline_100ns: u64,
    },
}
```

这样本地切换结果不再借全局字段中转，也不再局限于 unlock-edge 路径。

---

## 八、统一后的入口清单

所有入口都必须先映射成 `ScheduleReason`，再进入统一决策核心。

### 8.1 syscall unlock

1. 普通 syscall 结束
2. 当前线程未离开 `Running`
3. reason = `UnlockEdge`

### 8.2 显式 yield

1. `NtYieldExecution`
2. 当前线程声明愿意让出 CPU
3. reason = `Yield`

注意：`yield_current_thread()` 这个 helper 的最终语义应变成“请求一次带 `Yield` 原因的调度”，而不是“立即完成切换”。

### 8.3 timer 抢占

1. timer IRQ 到期
2. 当前 timeslice 用完
3. reason = `TimerPreempt`

### 8.4 IPI / host 唤醒 / other core wake

1. 远端核或 host 事件要求本核重进调度
2. reason = `Ipi` 或 `Wakeup`

### 8.5 timeout 到期

1. wait timeout 触发就绪
2. reason = `Timeout`

---

## 九、统一后的关键不变式

## 9.1 ReadyQueue 不变式

1. `Running` 线程不在 ready queue
2. `Ready` 线程最多出现一次
3. 状态迁移与 ready queue 入队/出队有单入口

## 9.2 `kctx` 不变式

1. `in_kernel == true` 表示线程当前拥有有效内核 continuation
2. `kctx.has_continuation()` 与 `in_kernel` 语义保持一致
3. idle thread 始终视作 `in_kernel == true`

## 9.3 切换提交点不变式

1. `kctx -> kctx` 切换提交点在 unlock-edge
2. `SvcFrame` 相关保存/恢复只在 trap adapter
3. trap adapter 不应再维护另一套 ready queue 选择规则

---

## 十、分阶段实施计划

## Phase 0：补回归用例，冻结行为

目标：

1. 为 `yield`、unlock-edge wait/wake、timer preempt、idle re-entry 增加最小回归覆盖
2. 在开始重构前固定外部行为

建议覆盖：

1. 单核 `yield` 必须切到同优先级其他线程
2. 多核 wait/wake 后被唤醒线程能重新获得 CPU
3. idle 核在 wakeup 后能重新进入调度

## Phase 1：抽统一 `ScheduleDecision`

目标：

1. 从 `SchedulerRoundAction` 演进到 `ScheduleDecision`
2. 保持现有行为基本不变

动作：

1. 在 `sched/schedule.rs` 先引入 `ScheduleDecision`
2. 让 `scheduler_round_locked()` 只承担“算决策”
3. 暂时保留现有 trap/unlock-edge 调用点

完成标准：

1. 本核和 trap 两边都消费同一种决策对象

## Phase 2：抽 trap adapter

目标：

1. 把 `dispatch.rs` 里的 trap 调度落地逻辑收成单独模块

动作：

1. 提取 `save_ctx_for`
2. 提取 `restore_ctx_to_frame`
3. 提取 `schedule_from_trap`
4. 把“按决策 apply”逻辑和 syscall 分发表解耦

完成标准：

1. `dispatch.rs` 不再同时承担 syscall 分发和调度适配

## Phase 3：抽 unlock-edge plan

目标：

1. 让 unlock-edge 直接消费 `ScheduleDecision`
2. 去掉 staged local decision 字段依赖

动作：

1. 新增 `UnlockEdgePlan`
2. 在最终 unlock 前构造 plan
3. 解锁后直接 apply plan

完成标准：

1. 本核路径不再需要 `highest_priority_tid`

## Phase 4：删掉 `highest_priority_tid` / `reschedule_current_core`

目标：

1. 删除重复的本核 decision carrier

动作：

1. 从 `KVcpuState` 移除 `highest_priority_tid`
2. 删除 `reschedule_current_core()`
3. `enable_scheduling()` 只保留“kick other cores”职责

完成标准：

1. 本核切换提交点只剩 unlock-edge plan apply

## Phase 5：统一 idle 路径

目标：

1. 主核和次核进入 idle 后走同一条逻辑

动作：

1. 让 idle loop 直接消费 `ScheduleDecision`
2. 消除主次核不同的调度分叉

完成标准：

1. 调度语义上不再区分 boot core / secondary core

## Phase 6：清理命名和语义残留

目标：

1. 避免 helper 名称继续误导

动作：

1. 审核 `yield_current_thread()` 的命名
2. 审核 `needs_scheduling` 注释与调用点
3. 审核 `in_kernel` 与 `kctx.has_continuation()` 的断言

完成标准：

1. 代码名词与真实行为一致

---

## 十一、验收标准

## 11.1 结构验收

1. 调度决策核心只有一份
2. trap/unlock-edge/idle 只保留适配职责
3. `highest_priority_tid` 被删除
4. `reschedule_current_core()` 被删除

## 11.2 行为验收

1. `kctx` 线程的让出核心发生在 unlock-edge
2. trap 路径只处理 `SvcFrame` 保存/恢复与返回
3. 主核和次核 idle 之后的调度流程一致

## 11.3 回归验收

至少验证：

1. `thread_test`
2. `full_test`
3. `process_test`
4. 2 vCPU 下的 wait/wake、yield、timer-preempt 场景

---

## 十二、当前进展

截至 2026-03-13，已落地：

1. Phase 1：`scheduler_round_locked` 已收口为 `schedule_core_locked`，统一返回 `ScheduleDecision`。
2. Phase 2：trap 适配层已从 `nt/dispatch.rs` 拆出到 [winemu-kernel/src/nt/trap_schedule.rs](/Users/swift/WinEmu/winemu-kernel/src/nt/trap_schedule.rs)。
3. Phase 3：unlock-edge 已改为 `build_unlock_edge_dispatch_locked(...) -> dispatch.apply_after_unlock(...)`。
4. Phase 4：`highest_priority_tid` 与 `reschedule_current_core()` 已删除；`needs_scheduling` 只保留跨核/idle 唤醒提示语义。
5. Phase 5（部分）：[winemu-kernel/src/sched/schedule.rs](/Users/swift/WinEmu/winemu-kernel/src/sched/schedule.rs) 中的 `enter_core_scheduler_entry()` 已切到 `schedule_core_locked()`，主核/次核进入 scheduler 的选线程逻辑不再单独维护一套。
6. `schedule_noreturn_locked()` 已改为复用 `schedule_core_locked() -> local plan -> apply`，不再手写一套 `pick_next_thread_locked()` + switch 流程。
7. Phase 6（部分）：已删除未使用且语义误导的 `yield_current_thread_locked()`，`NtYieldExecution` 的 helper 已更名为更准确的请求式命名。
8. `idle_thread_fn()` 已改为消费同一套 local plan，不再保留单独的本地切换写法。
9. `enter_core_scheduler_entry()` 与 `idle_thread_fn()` 已进一步共享 `run_local_scheduler_iteration(...)`。
10. `KVcpuState.is_idle` 已删除；idle vCPU 判定改为从 `current_tid/idle_tid` 与真实线程状态实时推导，避免依赖失效的镜像状态。
11. `KThread` 已新增 `has_kernel_continuation()` / `can_run_on_vcpu()` 语义 helper，ready-queue 选择与回收判断不再散落重复条件。
12. `SchedLockAndSleep::cancelled` 这类不参与实际调度决策的伪状态已删除，`cancel()` 只保留兼容调用点的空操作语义。
13. 主核与次核最终进入 scheduler 的入口已统一为 `enter_current_core_scheduler()`；idle thread 注册被收成统一预备动作，不再由 `main.rs` 分别拼装。
14. thread0 bootstrap 绑定与首个 user entry 回填已收成调度器 helper，`main.rs` 不再直接手写 `set_current_tid/set_vcpu_current_thread/set_thread_state_locked` 这类调度状态变更。
15. `enter_current_core_scheduler()` 明确不走 `KSchedulerLock` 的 unlock-edge 路径，而是只做 raw pre-entry 初始化，避免 bootstrap 期间把账面 `current_tid` 误当成 live continuation。
16. `trap_schedule.rs` 已按 `ContinueCurrent / SwitchToThread / EnterIdle` 拆成更明确的 apply helper，trap adapter 不再把所有分支细节堆在一个大 `match` 里。
17. `with_sched_raw_lock(...)` 已显式引入，用来标记“只持有原始调度自旋锁、不触发 unlock-edge”的 bootstrap / pre-entry 路径。
18. `dispatch.rs` 的 syscall 入口前置准备已进一步收成 `begin_syscall_trap()`；`dispatch.rs` 现在只负责 syscall 解码、handler 分发与 trap-finish 调用。
19. `TrapScheduleRequest` 已落地，syscall 与 user IRQ 两条 trap 路径不再用布尔参数组合描述调度请求。
20. `user_irq_dispatch()` 已拆出“是否延期调度 / 补短重试 slice / 选择 IRQ 调度原因”三个 helper，IRQ trap 入口不再内联一段状态分支。
21. trap adapter 已显式跟踪当前 `SvcFrame` 已保存到哪个 `tid`，避免在同一次 trap 调度里重复执行 `save_ctx_for(...)`。
22. `TRAP_SCHED_ACTIVE` 与 `LOCK_DEPTH` 这类按核静态状态已改为跟随 `MAX_VCPUS`，不再散落硬编码 `8`。
23. `trap_schedule.rs` 里的 syscall 调度原因选择已拆成更明确的 wait/wakeup helper；目标线程 carrier 判断也不再靠 `(bool, bool)` 组合返回，而是显式分类为 `KernelContinuation / UserFrame`。
24. [winemu-kernel/src/sched/schedule.rs](/Users/swift/WinEmu/winemu-kernel/src/sched/schedule.rs) 中 `schedule_core_locked()` 的“无 ready 候选时继续当前线程”和“候选线程是否允许抢占当前线程”逻辑已收成 helper，调度核心不再把主要策略全部堆在一个大函数里。
25. unlock-edge 最终提交已从 `(mask, plan)` tuple 收成 `UnlockEdgeDispatch`；`LocalSchedulePlan` 也已改为 `from_decision / apply / apply_noreturn` 这一组明确接口。
26. `compute_remote_reschedule_mask_locked()` 已进一步拆成“收集显式 reschedule mask”和“刷新远端核重调度 mask”两个 helper，unlock-edge 的远端协作路径不再挤在单个函数里。
27. “把线程绑定为某个 vCPU 上的 Running 线程” 这一组状态提交已抽成共享 helper `bind_running_thread_to_vcpu(...)`，`schedule.rs / trap_schedule.rs / threads.rs` 不再各自维护一份 `set_vcpu_current_thread + current_tid + state + hint` 组合。
28. 回归矩阵已从 `thread_test` 扩到 `full_test` 与 `process_test`，当前统一调度路径在这三类测试上均保持通过。

仍待完成：

1. 继续清理 trap/irq 侧的历史注释和兼容分支，确认 `schedule_from_trap()` 只保留 frame/save-restore 与 trap-return 适配职责。
2. 继续把 `schedule.rs` 里 local-plan / unlock-edge 相关的旧注释、helper 边界再理顺，减少“核心决策”和“本地提交”文件内交错。
3. 后续可以再补更多双核场景回归（例如 `full_test` 的多 vCPU 运行），当前已稳定覆盖 `thread_test` 单核/双核，以及 `full_test / process_test` 单核基线。

---

## 十三、当前代码与目标的对应关系

### 已具备的基础

1. 已有 `ScheduleReason`
2. 已有 `schedule_core_locked()` 作为统一调度核心
3. 已有 `execute_kernel_continuation_switch()` 与 `enter_kernel_continuation_noreturn()`
4. idle thread 已具备 continuation 基础

### 仍需收口的地方

1. [winemu-kernel/src/nt/dispatch.rs](/Users/swift/WinEmu/winemu-kernel/src/nt/dispatch.rs)
   - trap 调度逻辑过重
2. [winemu-kernel/src/sched/lock.rs](/Users/swift/WinEmu/winemu-kernel/src/sched/lock.rs)
   - final unlock 虽已收成 `UnlockEdgeDispatch::apply_after_unlock()`，但注释与命名还可以继续向“unlock-edge adapter”语义靠拢
3. [winemu-kernel/src/sched/schedule.rs](/Users/swift/WinEmu/winemu-kernel/src/sched/schedule.rs)
   - 仍有部分 helper 注释残留旧术语

---

## 十四、最终结论

统一后的调度路径不是把所有场景硬塞进一个切换函数，而是：

```text
所有入口
  -> 同一个 schedule_core_locked()
  -> 同一种 ScheduleDecision
  -> trap adapter / unlock-edge adapter 各自落地
```

其中必须严格满足：

1. `kctx` 线程让出核心在 unlock-edge
2. trap 路径只处理 `SvcFrame`
3. idle 线程也是同一个调度模型中的普通 `kctx` 载体

后续代码改造以本文件的 Phase 0 - Phase 6 顺序推进。
