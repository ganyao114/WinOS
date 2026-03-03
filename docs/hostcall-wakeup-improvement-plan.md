# HostCall `WAIT_KIND_HOSTCALL` 唤醒链路改进计划

## 1. 背景

当前 `WAIT_KIND_HOSTCALL` 的唤醒主路径可工作，但存在两个核心问题：

1. completion 拉取触发点分散（SVC/timer IRQ 入口都主动 `pump`），语义不够“纯 IRQ 驱动”。
2. `request_id -> waiter` 路由存在线性扫描，复杂度和并发风险都偏高。

现状主链路：

1. host 完成请求并入队 completion。
2. VMM 注入 external IRQ。
3. guest 在 `svc_dispatch/timer_irq_dispatch` 入口 `pump_completions()`。
4. 根据 `request_id` 找 waiter，`sched::wake` 唤醒等待线程。
5. unlock-edge 触发调度，线程恢复执行。

## 2. 目标（强约束）

1. `call_sync` 在 host 返回 `PENDING` 时必须进入内核等待态，不允许直接失败返回。
2. `WAIT_KIND_HOSTCALL` 唤醒由 IRQ 边界驱动，不依赖 syscall 频繁进入作为“轮询器”。
3. completion 路由收敛为 `O(1)`，避免全表扫描。
4. 唤醒后仍严格走调度器状态机：`Waiting -> Ready -> unlock-edge reschedule`。

## 3. 目标架构

### 3.1 IRQ 驱动 completion 处理

1. host completion 到达后只通过 external IRQ 唤醒 guest。
2. guest 在 IRQ 调度边界集中 drain completion 队列。
3. 移除常规 SVC/timer 入口上的无条件 `pump_completions()`。

### 3.2 O(1) 请求路由

1. 引入 `request_id -> PendingWaiter` 的直接索引结构（哈希桶或定长表+冲突链）。
2. `register/unregister/take` 全部改成 O(1) 平均复杂度。
3. 删除 `reap_stale_waiters` 的全量扫描路径。

### 3.3 同步/异步统一 completion 协议

1. `call_sync` 与异步等待共用同一 completion 分发路径。
2. `call_sync` 仅额外保存 `SubmitDone`（`host_result/value0`）并在唤醒后取回。
3. host 错误码映射统一，避免不同路径语义漂移。

## 4. 分阶段实施

### Phase A：数据结构收敛

1. 引入请求索引表（`request_id` key）。
2. 将 `register_request/take_waiter_by_request/unregister_pending_request` 切到新索引。
3. 删除线性扫描辅助函数。

完成标准：

1. `hostcall.rs` 不再出现按 `request_id` 的全表遍历。
2. `submit_tracked/call_sync/wait_current_for_request` 行为保持一致。

### Phase B：IRQ 边界收敛

1. 把 completion drain 固定在 IRQ 唤醒路径。
2. 移除 `svc_dispatch/timer_irq_dispatch` 的无条件 `pump_completions()`。
3. 保证空 completion IRQ 不影响线程状态机。

完成标准：

1. 唤醒完全由 IRQ 驱动，不依赖 syscall 流量。
2. `thread_test/process_test/full_test` 全通过。

### Phase C：同步等待语义固化

1. `call_sync(PENDING)` 只允许“注册 -> 等待 -> completion -> 返回”。
2. completion 缺失/取消/超时路径全部显式清理请求状态。
3. 明确 `HC_* -> NTSTATUS` 映射表，补齐 `HC_IO_ERROR` 等分支。

完成标准：

1. 不出现 `STATUS_PENDING` 泄露到用户态。
2. 同步 hostcall 与异步 hostcall 的 completion 分发代码不分叉。

### Phase D：回归与压测

1. 新增 hostcall 等待专项测试：
   - `call_sync` 返回 `PENDING` 后成功唤醒并拿到 `value0`。
   - 取消/超时/进程终止时请求可回收、线程可退出。
2. 保留 VMM broker 单测并扩展 kernel 侧集成用例。

完成标准：

1. 无活锁、无悬挂 waiter、无 completion 泄漏。
2. 长时间压测下 completion 队列稳定。

## 5. 验证矩阵

每阶段至少执行：

1. `cargo build -q`
2. `cargo test -q`
3. `cargo test -q -p winemu-vmm hostcall::broker -- --nocapture`
4. `codesign --force --entitlements entitlements.plist -s - target/debug/winemu`
5. `target/debug/winemu run tests/thread_test/target/aarch64-pc-windows-msvc/release/thread_test.exe`
6. `target/debug/winemu run guest/sysroot/process_test.exe`
7. `target/debug/winemu run tests/full_test/target/aarch64-pc-windows-msvc/release/full_test.exe`

重点观察项：

1. `WAIT_KIND_HOSTCALL` 线程可稳定被 host completion 唤醒。
2. `call_sync` 在 `PENDING` 场景不再错误失败。
3. 无 `KERNEL_FAULT`、无异常 panic、无请求泄漏。

## 6. 风险与回滚

1. 风险：IRQ 边界收敛后，若外部 IRQ 触发链有缺口，completion 可能堆积。
2. 缓解：Phase B 引入阶段性统计（completion backlog、高水位、唤醒延迟）。
3. 回滚：保留单开关恢复“入口补偿 pump”模式，但不回退同步等待语义。

## 7. 当前状态（2026-03-03）

1. `call_sync(PENDING)` 已收敛为“注册请求 -> 进入等待 -> completion 唤醒 -> 取回 SubmitDone”语义。
2. `request_id` 路由已切到哈希桶索引，`register/unregister/take` 为 O(1) 平均复杂度。
3. 已删除 `reap_stale_waiters` 的 IRQ 热路径全表扫描；改为线程/进程终止时的显式 hostcall 清理钩子。
4. completion drain 已收敛到 IRQ 调度边界（`schedule_from_trap(..., drain_hostcall=true)`），不再在 SVC 入口补偿 pump。
5. `HC_IO_ERROR -> STATUS_OBJECT_NAME_NOT_FOUND` 映射已补齐。
6. 验证矩阵已通过：`cargo build/test`、broker 单测、`thread_test/process_test/full_test` 运行回归。

剩余工作（若继续 Phase D）：

1. 增加专门覆盖 `call_sync(PENDING)` 与取消/超时竞争态的内核集成测试用例（目前主要依赖现有端到端回归）。
