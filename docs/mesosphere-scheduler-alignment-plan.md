# Mesosphere 调度对齐设计（重构版）

## 1. 背景与问题定义

当前 WinEmu 调度器在“等待后立即进入调度”这条链路上，存在一个 Mesosphere 不具备的中间机制：`dispatch_kctx`。

该机制把“当前线程在 syscall 深栈中的执行点”先跳回一个 dispatch continuation，再进入调度。它能工作，但有三个问题：

1. 语义偏离 Mesosphere：不是 `Unlock -> RescheduleCurrentCoreImpl` 直达调度。
2. 状态复杂度高：每线程双内核上下文（`kctx` + `dispatch_kctx`）增加一致性成本。
3. 故障面增大：和 unlock-edge 触发、等待唤醒、抢占时序叠加时，容易出现重入/坏续点问题。

本次文档重构目标是：以你确认的生命周期为准，收敛到“单 `KThread.kctx` 模型”。

## 2. 目标行为（强约束）

以 `SetEvent/NtWait*` 为代表，统一采用如下内核线程生命周期：

1. 用户态进入 syscall。
2. 当前 `KThread` 在内核态执行 syscall 逻辑。
3. 若进入等待：
   1. 持调度锁设置 `Waiting`。
   2. 注册 timeout `TimerTask`。
   3. 解锁并触发调度。
4. 调度器选择下一个 `Ready` 线程。
5. 在同一 vCPU 上执行 `switch_kernel_context(cur.kctx, next.kctx)`。
6. 当前线程被唤醒后恢复 `cur.kctx`，继续从原 syscall 位置执行并返回结果。

关键点：不允许引入“跳到 dispatch continuation 再调度”的中间层。

## 3. 与 Mesosphere 对齐原则

1. 调度决策边界在 unlock 之后，行为等价于 `EnableScheduling`。
2. 等待顺序固定为：`BeginWait -> RegisterTimerTask -> Unlock -> Reschedule`。
3. 调度状态变迁单入口（`set_thread_state_locked`）。
4. 锁顺序固定：`sched lock -> timer lock`。
5. waiter 注册和撤销必须事务化，失败必须回滚。

## 4. 架构收敛方案

### 4.1 内核上下文模型

1. 保留：`KThread.kctx`（唯一内核上下文）。
2. 删除：`dispatch_kctx` / `dispatch_valid` / `dispatch_save_gen`。
3. 删除：`save_current_dispatch_continuation` / `reschedule_current_via_dispatch_continuation` 及其调用链。

### 4.2 unlock-edge 调度模型

1. `sched_lock_release()` 只负责：
   1. 提交 deferred scheduling。
   2. 唤醒 idle vCPU（`KICK_VCPU_MASK`）。
   3. 标记“当前核需要立即重调度”。
2. 立即重调度动作直接进入 `RescheduleCurrentCore` 语义，不经过 dispatch trampoline。
3. 若发生线程切换，直接 `switch_kernel_context(cur.kctx, next.kctx)`。

### 4.3 等待/唤醒模型

1. `NtWait*`/`Delay`/同步 hostcall 的阻塞全部走同一 `BeginWait` 主路径。
2. 唤醒路径统一走 `EndWait`，写入 `wait_result` 并转 `Ready`。
3. timer 到期、对象销毁、线程终止、对象 signal 都走同一 cancel/wake 收敛点。

### 4.4 SetEvent 语义

1. `SetEvent` 仅做：设置对象信号态 + 唤醒 waiter 到 `Ready`。
2. 抢占由调度器决定，触发点在 unlock/schedule 边界。
3. 不允许 `SetEvent` 路径依赖 dispatch continuation 才能让出 CPU。

## 5. 分阶段实施计划

### Phase A：删除 dispatch continuation 基础设施

1. 从 `KThread` 移除 `dispatch_*` 字段。
2. 从 `sched/continuation.rs` 移除 dispatch 保存/恢复 API。
3. 清理 `sched/mod.rs`、`nt/dispatch.rs`、`sched/lock.rs` 中相关调用。
4. 编译通过 + 基础回归通过。

完成标准：

1. 代码中不再出现 `dispatch_kctx`、`dispatch_valid`、`dispatch_save_gen`。
2. 代码中不再出现 `reschedule_current_via_dispatch_continuation`。

### Phase B：建立 direct kctx 切换路径

1. 在调度入口实现“当前线程在内核阻塞后直接切 next.kctx”。
2. 确认等待线程被唤醒后能从原 syscall 点继续执行。
3. 收敛 `wait_result` 读取点，避免 `STATUS_PENDING` 泄露到用户态。

完成标准：

1. `NtWait*` 在用户态只看到最终结果（`SUCCESS/TIMEOUT/...`）。
2. `SetEvent` 后可稳定触发 caller 让出 CPU（单 vCPU 场景）。

### Phase C：模块职责拆分（对应 `sched/mod.rs` 臃肿问题）

1. `sched/core.rs`：runqueue、pick-next、timeslice。
2. `sched/context_switch.rs`：`kctx` 保存/恢复和切换。
3. `sched/wait_path.rs`：`BeginWait/EndWait/CancelWait`。
4. `sched/lock.rs`：锁、deferred commit、unlock-edge 触发。
5. `sched/topology.rs`：vCPU mask、idle 唤醒。

完成标准：

1. `sched/mod.rs` 只保留 re-export 和初始化入口。
2. 每个子文件职责单一，禁止交叉复制状态机逻辑。

## 6. 验证矩阵

每阶段至少执行：

1. `bash scripts/build-kernel-bin.sh`
2. `cargo build`
3. `target/debug/winemu run tests/thread_test/target/aarch64-pc-windows-msvc/release/thread_test.exe`
4. `target/debug/winemu run guest/sysroot/process_test.exe`
5. `target/debug/winemu run tests/full_test/target/aarch64-pc-windows-msvc/release/full_test.exe`

强制观察项：

1. 不出现 `KERNEL_FAULT`。
2. `thread_test` 完整输出并 `PROCESS_EXIT: code=0`。
3. `NtClose INVALID_HANDLE` 仅在预期测试路径出现，不可导致活锁或错误退出。

## 7. 风险与回滚策略

1. 风险：去掉 dispatch trampoline 后，部分 syscall 深栈阻塞路径可能暴露新的切换点缺陷。
2. 缓解：先在 `NtWait*`、`SetEvent`、`Delay`、sync hostcall 四条关键路径灰度启用 direct kctx 切换。
3. 回滚：保留单开关回退到“仅 trap-exit 调度”，但不回退到 `dispatch_kctx` 设计。

## 8. 当前结论

1. `dispatch_kctx` 不是目标架构，不符合 Mesosphere 对齐方向。
2. 目标是“单 `kctx` + unlock 后直接调度 + 线程间 direct kctx 切换”。
3. 后续代码改造以本文件 Phase A/B/C 顺序执行，不再引入新的 continuation 中间层。

## 9. 落地状态（2026-03-03）

已完成：

1. Phase A 基础设施收敛：`dispatch_*` 相关字段与调度入口依赖已移除。
2. 等待门禁命名收敛：`ensure_current_wait_continuation_locked` 更名为 `ensure_current_wait_preconditions_locked`，去除 continuation 语义残留。
3. `wait_current_for_request` 收敛到统一等待结果接口：通过 `current_wait_result_or_pending` 读取解锁后状态，不在结果读取接口里做调度/切换。
4. `call_sync` 收敛为“仅同步 hostcall”：遇到 host 侧 `PENDING` 立即 cancel + unregister 并返回错误，避免错误进入内核等待态。
   - 接口层同时移除 `call_sync` 的 `timeout` 形参，避免语义漂移。
5. idle 路径移除 1ms fallback 轮询：无 deadline 时不再周期性定时唤醒，仅依赖 IRQ/SEV 唤醒。
6. hostcall completion 收敛为单路径：移除 completion 存储中间层，改为“到达即分发或按 host result 唤醒 waiter”。
7. direct `kctx` 主路径已接通：
   - `sched_lock_release` 外层解锁时，若当前线程已离开 `Running` 且本核存在 reschedule 请求，会优先尝试切换到就绪内核 continuation 线程。
   - `schedule_from_trap` 在 pick 到具备 continuation 的目标线程时，优先走 `switch_kernel_continuation(from, to)`。
   - 无可切 continuation 目标时回落到现有 trap-exit 调度路径（不使用轮询+WFI 回退，也不在 wait-result 读取接口里做补偿切换）。

待完成：

1. 仍待收敛为“纯 direct-kctx 主路径”：当前实现是“direct-kctx 优先 + trap-exit 回落”，尚未完全移除回落分支。
