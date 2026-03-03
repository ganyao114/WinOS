# Mesosphere 调度对齐改造方案

## 1. 目标

严格对齐 Mesosphere 的内核线程等待/调度时序（以 `KSynchronizationObject::Wait` 为基准）：

1. 进入调度锁。
2. 将当前内核线程切到 `Waiting`（`BeginWait` 语义）。
3. 在解锁前注册绝对超时任务（`RegisterAbsoluteTask`）。
4. 解锁后进入调度（`EnableScheduling` 语义）。

重点是 **内核线程阻塞与切换**，不是用户线程轮询或返回 `STATUS_PENDING` 后用户态自旋。

## 2. 现状差异（WinEmu）

1. `sched_lock_release()` 目前只做 deferred commit，不直接触发当前核调度。
2. `prepare_wait_locked()` 中等待时序是“先注册 timer，再设 `Waiting`”，与 Mesosphere 顺序相反。
3. 同步对象 waiter 注册存在“静默失败”路径（内存不足时直接 return），会导致等待状态与对象队列不一致。
4. `NtWait*`/`Delay` 慢路径虽然可阻塞，但关键路径缺少“解锁即进入调度”的收敛点。

## 3. 改造原则

1. 保持状态变迁单入口（`set_thread_state_locked`）不变。
2. 锁顺序继续保持 `sched lock -> timer lock`。
3. 等待注册必须事务化：任一步失败都完整回滚。
4. 先做 P0 级时序一致性，再做 P1/P2 扩展收敛。

## 4. 分阶段计划

### Phase A（本次落地）

1. 调整等待准备顺序：
   - 在调度锁内先写等待元数据；
   - `BeginWait`（切 `Waiting`）；
   - 注册超时 `TimerTask`；
   - 失败回滚到原状态。

2. waiter 注册事务化：
   - `WaitQueue::enqueue` 返回 `bool`；
   - 各对象 `register_waiter` 返回 `bool`；
   - 任一 handle 注册失败时，撤销已注册项并清理等待元数据。

3. 解锁触发调度（局部 EnableScheduling 语义）：
   - 在 `sched_lock_release()` 外层解锁时，若当前核存在 pending reschedule 且当前线程处于 `Waiting` 且有 dispatch continuation，立即尝试切回 dispatch continuation，触发调度决策。

### Phase B（后续）

1. [x] 将 `NtWait*` 慢路径统一为“内核线程阻塞恢复”主路径，减少 `STATUS_PENDING` 兼容分支。
2. [x] 统一 `BeginWait/EndWait/CancelWait` 风格 API，减少 `sync.rs` 分散状态拼装。
3. [x] 增加 wait-cancel/termination 与 timer-cancel 的一致性断言。

## 5. 代码落点

1. `winemu-kernel/src/sched/mod.rs`
   - 拆分/重构等待准备 API：
     - `prepare_wait_tracking_locked`
     - `begin_wait_locked`
     - `prepare_wait_locked`（组合）

2. `winemu-kernel/src/sched/sync.rs`
   - waiter 注册改为可失败并事务回滚。
   - `wait_common_locked` 改为“注册 waiters -> BeginWait -> 注册 timer”时序。

3. `winemu-kernel/src/sched/lock.rs`
   - 外层 unlock 后补本核立即调度触发点（受条件保护）。

## 6. 验收标准

1. `cargo test -q` 通过。
2. `scripts/stress-regression.sh 10 core` 通过。
3. `thread_test`/`process_test` 无新增 hang。
4. 关键不变量满足：
   - `Waiting` 线程不会出现“无对象 waiter 且无 timer 且无唤醒来源”的悬空状态；
   - waiter 注册失败可完全回滚。

## 7. Phase B 执行记录（2026-03-03）

1. [x] `NtWait*` 慢路径已统一走 `wait_*_sync`，由内核线程阻塞恢复返回结果，不再依赖用户态轮询 `STATUS_PENDING`。
2. [x] 已落地 `begin_wait_locked` / `end_wait_locked` / `cancel_wait_locked`，并在 timeout/terminate/wake 路径收敛到统一状态迁移。
3. [x] 已补充等待元数据一致性断言，覆盖 wait/timer 清理与 timeout 取消路径。

已执行回归：

1. `cargo test -q`
2. `target/debug/winemu run guest/sysroot/process_test.exe`
3. `target/debug/winemu run tests/thread_test/target/aarch64-pc-windows-msvc/release/thread_test.exe`
4. `bash scripts/stress-regression.sh 3 core`

## 8. Hostcall 收敛（2026-03-03）

1. [x] 线程上下文下的 hostcall 等待改为调度器主路径：
   - `block_current_and_resched(WAIT_KIND_HOSTCALL, ...)`
   - `wait_current_pending_result()`
2. [x] 移除轮询+WFI 回退；`call_sync` 严格要求当前内核线程上下文，确保 hostcall 只走 IRQ/调度阻塞链路。
3. [x] completion 发布与 waiter 唤醒顺序调整为“先存 completion，再唤醒 waiter”，避免唤醒后取不到 completion 的竞态。
4. [x] `wait_current_for_request` 语义收敛为“同步阻塞直到 resolved status”，不再返回 `STATUS_PENDING`。

本轮附加回归：

1. `cargo test -q`
2. `target/debug/winemu run guest/sysroot/process_test.exe`
3. `target/debug/winemu run tests/thread_test/target/aarch64-pc-windows-msvc/release/thread_test.exe`
4. `bash scripts/stress-regression.sh 2 core`
5. `target/debug/winemu run tests/full_test/target/aarch64-pc-windows-msvc/release/full_test.exe`
