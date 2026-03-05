# WinEmu 调度器改进方案（对齐 Mesosphere）

## 1. 范围与目标

本文仅聚焦两部分：

1. `winemu-kernel` 调度与等待路径（`src/sched`、`src/nt/dispatch.rs`、`src/hostcall.rs`）。
2. `winemu-vmm` vCPU 唤醒/空闲调度协作（`crates/winemu-vmm/src/sched`、`src/vcpu.rs`、`src/hostcall/broker.rs`）。

目标是把当前“多入口、混职责”的调度逻辑收敛到 Mesosphere 风格：

1. 线程状态迁移单入口。
2. 解锁边界统一提交调度决定。
3. trap 路径只做 trap 相关工作，不夹带独立调度策略。
4. kernel 与 vmm 的唤醒语义一致、可验证。

### 1.1 本次补充的调度强约束

1. 调度入口只允许两类：
   1. syscall 路径触发的 `Lock -> Unlock Edge`。
   2. IRQ 触发的抢占路径（TimerTask 到期 / host 发送 / 其他核心唤醒）进入 `Preempt -> Lock -> Unlock Edge`。
2. 调度流程固定三步：
   1. 先从全局优先队列中获取当前核心 `scheduled front` 的下一个线程。
   2. 若当前核心无可运行线程，再通过 `suggested queue` 进行跨核心迁移；不满足核心亲和的线程禁止迁移。
   3. 最终统一执行 `switch kctx`。
3. 队列策略采用 Mesosphere 风格“全局优先队列 + suggested queue”：
   1. 线程状态/优先级/亲和性变化统一驱动队列更新。
   2. 高阶策略（负载均衡、NUMA/缓存亲和等）后续在该框架上迭代。

## 2. Mesosphere 关键参考点

以下为本次对齐的核心参考实现（本地路径）：/Users/swift/Downloads/Atmosphere-master

1. `libraries/libmesosphere/include/mesosphere/kern_k_scheduler_lock.hpp:48-91`
   1. `Lock/Unlock` 中通过 `DisableScheduling/EnableScheduling` 把“解锁后调度”固化为统一语义。
2. `libraries/libmesosphere/include/mesosphere/kern_k_scheduler.hpp:135-205`
   1. `EnableScheduling -> RescheduleOtherCores + RescheduleCurrentCore`，本核/他核重调度路径一致。
3. `libraries/libmesosphere/source/kern_k_scheduler.cpp:110-207`
   1. `UpdateHighestPriorityThreadsImpl` 在统一入口计算多核最高优先级线程与迁移。
4. `libraries/libmesosphere/source/kern_k_scheduler.cpp:294-336`
   1. `OnThreadStateChanged/OnThreadPriorityChanged/OnThreadAffinityMaskChanged` 统一触发 runqueue 更新。
5. `libraries/libmesosphere/source/kern_k_thread.cpp:1430-1486`
   1. `BeginWait/EndWait/CancelWait/SetState` 以线程状态 API 为核心，不散落状态写入点。
6. `libraries/libmesosphere/source/kern_k_thread_queue.cpp:25-49`
   1. `EndWait/CancelWait` 最终只负责“写结果 + 设 Runnable + 清 wait queue + cancel timer”。

## 3. 当前实现差异（问题清单）

### 3.1 P0：调度执行入口分叉，导致策略重复且不一致

1. 锁释放路径执行解锁边界切换：`winemu-kernel/src/sched/lock.rs:93-117`。
2. trap 退出路径也做独立调度决策/切换：`winemu-kernel/src/nt/dispatch.rs:194-330`。
3. 启动路径还有独立分发循环：`winemu-kernel/src/sched/schedule.rs:205-254`。

影响：同一轮状态变化可能走三种不同调度执行器，行为和故障模型不统一。

### 3.2 P0：状态机存在旁路写入，破坏“单入口状态迁移”

1. `set_thread_state_locked` 是名义单入口：`winemu-kernel/src/sched/topology.rs:399-434`。
2. 但仍有直接写状态：
   1. `winemu-kernel/src/sched/schedule.rs:55`（stale ready 节点分支直接写 `Running`）。
   2. `winemu-kernel/src/main.rs:343`（thread0 初始化直接写 `Running`）。

影响：runqueue 与线程状态的一致性不能完全由一个函数保证。

### 3.3 P0：等待路径语义混杂（内核阻塞 vs 轮询等待）

1. 阻塞入口：`block_current_and_resched` 只设置等待状态：`winemu-kernel/src/sched/wait.rs:254-270`。
2. hostcall 又通过 `current_wait_result` 做循环轮询+状态回写：`winemu-kernel/src/sched/wait.rs:271-315`、`winemu-kernel/src/hostcall.rs:323-337`。
3. 同时 `NtWait*` 走 `wait_common_locked` 返回 `STATUS_PENDING` 再依赖 trap 路径推进：`winemu-kernel/src/sched/sync/wait_path.rs:592-633`。

影响：同样“线程等待”在不同调用点使用两套恢复模型，推理复杂、易出现状态交错。

### 3.4 P1：调度拓扑与 runqueue 逻辑耦合度过高

1. `topology.rs` 同时承担 ready queue、mask 管理、unlock-edge 选线程、状态机：`winemu-kernel/src/sched/topology.rs`。
2. `prepare_unlock_edge_kernel_switch_locked` 额外维护“只选有 continuation 的 ready 子路径”：`winemu-kernel/src/sched/topology.rs:329-379`。
3. `schedule()` 与该路径又并行存在独立选线程策略：`winemu-kernel/src/sched/schedule.rs:17-108`。

影响：策略拆散在多个函数，修改一处很容易漏另一处。

### 3.5 P1：VMM 唤醒机制可用但过粗

1. completion 到达后通过 `request_external_irq()`（bool）触发：`crates/winemu-vmm/src/hostcall/broker.rs:505-522`、`crates/winemu-vmm/src/sched/mod.rs:107-114`。
2. `unpark_one_vcpu()` 在有 idle mask 时实际唤醒全部 idle vCPU：`crates/winemu-vmm/src/sched/mod.rs:98-105`。

影响：可运行，但高并发 completion 时更容易出现“惊群式唤醒”与不必要的上下文抖动。

### 3.6 P0：当前 `ready_global + ready_local` 结构与 Mesosphere `scheduled + suggested` 模型不一致

1. 现有选线程路径是 `local -> global -> donor`：`winemu-kernel/src/sched/mod.rs:449`、`winemu-kernel/src/sched/topology.rs:106-143`。
2. 缺少类似 Mesosphere `UpdateHighestPriorityThreadsImpl` 的统一更新过程，迁移决策分散在 `schedule` 与 `topology`。

影响：多核迁移与亲和性约束难以在一个决策点内保证，策略一致性不足。

## 4. 目标调度架构（对齐 Mesosphere）

### 4.1 六条硬约束（收敛后必须满足）

1. 调度入口固定为两类：
   1. syscall 触发 `Lock -> Unlock Edge`。
   2. IRQ 抢占触发 `Preempt -> Lock -> Unlock Edge`。
2. 线程状态迁移只允许一个入口 API（含 runqueue 回调）。
3. 队列模型固定为“全局优先队列 + scheduled/suggested 双视图”。
4. 选线程顺序固定：
   1. 先取当前核心 `scheduled front`。
   2. 当前核心无可运行线程时，才从 `suggested queue` 触发迁移。
   3. 迁移必须满足线程 affinity 与迁移约束。
5. 切换执行统一为 `switch kctx`（上下文切换执行器唯一）。
6. 队列更新与迁移决策都在调度锁保护下完成，并在 unlock edge 提交。

### 4.2 全局优先队列 + suggested queue 的目标结构

1. `KPriorityQueue`（全局）
   1. `scheduled queue`：按核心维度查看当前可调度 front。
   2. `suggested queue`：用于空闲核心迁移候选。
2. `Thread` 调度关键字段
   1. `priority`、`active_core`、`affinity_mask`。
3. `UpdateHighestPriorityThreads` 统一更新
   1. 计算每核心 `highest thread` 与 `needs_scheduling`。
   2. 对 idle core 执行 suggested 迁移并校验 affinity/迁移限制。
4. `ReschedDecision`
   1. 输出本核切换动作与跨核唤醒 mask。

### 4.3 与 Mesosphere 的对齐与差异

对齐点：

1. Mesosphere `KThread::SetState` -> WinEmu 单状态入口 `thread_set_state_locked()`。
2. Mesosphere `OnThreadStateChanged` -> WinEmu `runqueue_on_state_changed_locked()`。
3. Mesosphere `Unlock -> EnableScheduling` -> WinEmu `sched_lock_release -> commit_and_reschedule()`。

差异点（本项目阶段性选择）：

1. `UpdateHighestPriorityThreads` 语义已落在 `topology.rs + schedule.rs` 组合实现，尚未完全抽成独立更新模块。
2. `hostcall::call_sync` 已切换为 `wait_current_for_request_pending + completion 收敛循环`，不再依赖 `current_wait_result_blocking`；syscall 侧 hostcall 等待也已切到挂起返回模型。

## 5. 分阶段改造计划与当前状态（2026-03-05）

### Phase 0：建立“可改造”基线（1-2 天）

目标：先把不变量钉牢，避免边改边漂移。
状态：`已完成`。

改动：

1. 在 `set_thread_state_locked` 增加持锁断言（与 `_locked` 命名一致）。
2. 禁止旁路状态写入：
   1. 替换 `main.rs:343` 直接写状态。
   2. 替换 `schedule.rs:55` 直接写状态。
3. 增加调度来源计数器（unlock-edge/trap/idle wake）用于回归对比。

验收：

1. 全代码不再有 `t.state = ThreadState::...` 的旁路赋值（初始化构造除外）。
2. 单核/双核 `thread_test` 行为不回退。

### Phase 1：统一调度入口与提交点（2-4 天）

目标：把调度触发源收敛到你定义的两类入口，并在 unlock edge 统一提交决策。
状态：`已完成`。

改动：

1. 固化两类入口：
   1. syscall `Lock -> Unlock Edge`。
   2. IRQ `Preempt -> Lock -> Unlock Edge`。
2. 新增 `ReschedDecision`（本核动作 + 远端唤醒 mask），由 unlock 边界统一生成。
3. `sched_lock_release` 与 `schedule_from_trap` 仅消费同一种决策对象，不再各自实现独立选线程策略。

验收：

1. 调度执行路径收敛为单函数。
2. `lock.rs` 与 `dispatch.rs` 不再分别维护不同调度策略。

### Phase 2：全局优先队列 + suggested queue 收敛（3-5 天）

目标：把 `ready_global + ready_local` 收敛到 Mesosphere 风格的统一优先队列模型。
状态：`已完成`（当前调度主路径为 `scheduled front -> suggested migration -> switch_kctx`）。

改动：

1. 引入全局 `priority_queue`（含 `scheduled/suggested` 两类视图）。
2. 线程状态/优先级/affinity 变化统一走队列更新回调（对齐 `OnThreadStateChanged` 语义）。
3. 仅在核心无可运行线程时走 suggested 迁移，并严格校验 affinity 与迁移限制。
4. 下线 `local -> global -> donor` 多路径选择逻辑，收敛为统一决策流程。

验收：

1. 调度主路径满足 `scheduled front -> suggested migration -> switch_kctx`。
2. 绑定核心亲和线程在压力测试中不会被错误迁移。
3. 代码层不再保留 `ready_local + ready_global` 双路径选择。

### Phase 3：等待路径单模型化（2-3 天）

目标：统一 `NtWait*`、`Delay`、`hostcall` 的等待恢复语义。
状态：`已完成`（目标范围内）。

改动：

1. 明确内部态与用户可见态：
   1. 内部可出现 pending。
   2. 用户态返回只允许最终结果。
2. 收敛 `block_current_and_resched + current_wait_result` 双段模型。
3. 把 hostcall 等待并入与 `wait_common_locked` 一致的收敛流程。
4. `schedule_from_trap` 在“同线程继续执行但发生等待结果更新”的场景下，回填线程上下文到 SVC frame，避免 `x0=STATUS_PENDING` 残留。
5. `block_current_and_resched` 成为统一“进入等待态”原语；hostcall 等待恢复统一由 completion 驱动。
6. `call_sync` 改为 `wait_current_for_request_pending + wait_for_sync_completion`，将同步 hostcall 收敛到 completion 语义，不再走通用 `current_wait_result` 轮询接口。
7. 下线旧接口：移除 `wait_current_for_request`、`block_current_and_wait` 及 `current_wait_result_*` 轮询辅助链路。

验收：

1. `winemu-kernel/src/hostcall.rs` 不再依赖 `current_wait_result` 轮询循环。
2. `NtWait*` 与 hostcall 阻塞都通过同一恢复链路写最终状态码。

### Phase 4：VMM 唤醒协作优化（1-2 天）

目标：让 vCPU 唤醒更可控，减少惊群。
状态：`已完成并持续观测`（已实现位图去重、目标化唤醒、统计观测与查询接口）。

改动：

1. `external_irq_pending` 从 bool 升级为位图/原因集合（可去重、可观测）。
2. `unpark_one_vcpu` 改为优先目标化唤醒，不默认唤醒全部 idle vCPU。
3. `KICK_VCPU_MASK` 与 hostcall completion 唤醒统一到一个调度接口层。

验收：

1. completion 风暴场景下 vCPU 唤醒次数下降，吞吐不降。
2. 2 vCPU 下不存在长时间 idle 核不被唤醒的饥饿。

### Phase 5：清理与固化（1-2 天）

目标：把新模型沉淀成可维护结构。
状态：`未开始`。

改动：

1. 更新 `docs/threading-scheduler-design.md` 与本文件保持一致。
2. 补齐调试开关和故障签名（切换失败、非法状态迁移、锁顺序错误）。

验收：

1. 文档与代码路径一一对应。
2. 关键断言在 debug 构建可稳定复现错误。

### 5.1 最近验证结果（2026-03-05）

1. `bash scripts/build-kernel-bin.sh` 通过。
2. `cargo build -p winemu-vmm` 通过。
3. `thread_test` 单核通过（`EXIT:0`）。
4. `thread_test` 双核通过（`EXIT:0`）。
5. `full_test` 单核通过（`EXIT:0`）。
6. `full_test` 双核通过（`EXIT:0`）。
7. 双核日志仍可观察到 `kick_req == kick_coalesced` 且 `unpark_mask=0`，当前判定为“无 idle 目标时的去重命中”，后续继续做压力场景验证。

## 6. 代码落点建议（按模块）

### 6.1 winemu-kernel

1. `winemu-kernel/src/sched/mod.rs`
   1. 去 `include!` 聚合式组织，改显式子模块导出。
2. `winemu-kernel/src/sched/topology.rs`
   1. 仅保留 topology 与跨核唤醒。
3. `winemu-kernel/src/sched/priority_queue.rs`（新增）
   1. 承载全局 `scheduled/suggested` 优先队列结构。
4. `winemu-kernel/src/sched/scheduler_update.rs`（新增）
   1. 承载 `UpdateHighestPriorityThreads` 风格统一更新与迁移决策。
5. `winemu-kernel/src/sched/schedule.rs`
   1. 收敛为 `scheduled front -> suggested migration -> switch_kctx` 调度管线。
6. `winemu-kernel/src/sched/lock.rs`
   1. 解锁只做提交与执行调度决定。
7. `winemu-kernel/src/sched/wait.rs`
   1. 下线 `current_wait_result` 轮询模型。
8. `winemu-kernel/src/nt/dispatch.rs`
   1. 压缩为 trap 保存/恢复 + 调度器调用。
9. `winemu-kernel/src/hostcall.rs`
   1. 对齐统一等待恢复语义，不再自建“第二套等待结果循环”。

### 6.2 winemu-vmm

1. `crates/winemu-vmm/src/sched/mod.rs`
   1. 重构 idle 唤醒策略与 pending IRQ 数据结构。
2. `crates/winemu-vmm/src/vcpu.rs`
   1. 统一外部 IRQ 置位/清除策略，减少无效中断窗口。
3. `crates/winemu-vmm/src/hostcall/broker.rs`
   1. completion 唤醒调用改为目标化接口（而非泛化广播）。

## 7. 验证矩阵

每个 phase 至少执行：

1. `bash scripts/build-kernel-bin.sh`
2. `cargo build`
3. `RUST_LOG=info target/debug/winemu run tests/thread_test/target/aarch64-pc-windows-msvc/release/thread_test.exe`
4. `WINEMU_VCPU_COUNT=2 RUST_LOG=info target/debug/winemu run tests/thread_test/target/aarch64-pc-windows-msvc/release/thread_test.exe`
5. `RUST_LOG=info target/debug/winemu run tests/full_test/target/aarch64-pc-windows-msvc/release/full_test.exe`

关键指标：

1. 线程状态非法迁移断言次数 = 0。
2. `switch_kernel_continuation` 失败次数 = 0。
3. 多核场景无 `PROCESS_EXIT: code=225` 回归。
4. 2 vCPU 场景下 completion 到调度生效延迟稳定（日志可观测）。

## 8. 风险与回滚

1. 风险：Phase 1/2 改动会改变 trap 与等待恢复时序，短期可能暴露隐藏竞态。
2. 缓解：
   1. 每 phase 保留特性开关（新旧调度执行器切换）。
   2. 新路径先在 `NtWait*` + hostcall 两条路径灰度。
3. 回滚：
   1. 回滚到上一 phase 的调度提交逻辑。
   2. 不回滚到旁路状态写入模型。

## 9. 本次建议结论

1. 当前主要问题不是“功能缺失”，而是“调度执行入口分叉 + 等待恢复模型双轨”。
2. 参考 Mesosphere，优先级最高的是收敛“单状态入口 + 单调度提交点 + 单切换执行器”。
3. 建议先做 Phase 0/1/2，再推进等待与 VMM 侧优化；否则后续策略增强会持续被入口分叉与队列语义冲突拖累。
