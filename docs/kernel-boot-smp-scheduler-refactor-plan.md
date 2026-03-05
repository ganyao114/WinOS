# Kernel Boot/SMP 调度收敛改造方案

## 1. 目标

将当前内核启动路径收敛为标准 SMP 启动模型：

1. Bootstrap CPU(BSP) 先启动并完成全局内核初始化。
2. BSP 初始化内存管理/调度器全局状态并建立主进程主线程上下文。
3. BSP 发布 `boot_ready`，通知 Secondary CPU(AP) 可以继续。
4. AP 在等待 `boot_ready` 后执行每核初始化。
5. BSP/AP 最终进入同一条 per-core 调度循环。

约束：

1. 不保留 BSP 直跳用户态的特殊路径。
2. 不保留 AP 专用且与 trap 调度割裂的调度路径。
3. 启动同步使用 release/acquire 语义，避免仅靠 volatile+SEV。
4. per-core 调度循环只调度内核线程并切换 `kctx`，不能在循环内直接进入用户态。

## 2. 当前问题

1. BSP 路径在 `kernel_main` 末尾直接 `enter_initial_user_thread(...)`，未进入统一调度循环。
2. AP 路径 `kernel_secondary_main` 有独立调度实现，与 trap-return 调度逻辑分裂。
3. `__boot_primary_ready` 为 `u32` + volatile，缺少明确的内存序语义。
4. `mm::init()` 混合了全局页表构建和每核 MMU 使能，职责不清晰。
5. 当前过渡实现把 `enter_user_thread_noreturn` 放入调度循环，违背“调度器只负责内核线程”的职责边界。

## 3. 目标架构

### 3.1 启动状态机

1. `BootState::Early`：BSP 尚未完成全局初始化。
2. `BootState::Ready`：BSP 已完成全局初始化并可放行 AP。

行为：

1. AP 在 `Early` 阶段仅等待 `BootState::Ready`（WFE）。
2. BSP 完成 thread0 启动上下文提交后，以 release 语义写入 `Ready`，并 `SEV`。
3. AP 以 acquire 语义观测到 `Ready` 后，执行 per-core 初始化进入调度循环。

### 3.2 初始化职责拆分

`mm` 拆分为两段：

1. `mm::init_global_bootstrap()`：仅 BSP 执行。负责一次性的全局页表构建等。
2. `mm::init_per_cpu()`：每核执行。负责本核 MMU/TLB/系统寄存器配置。

### 3.3 统一 per-core 内核调度入口

引入统一入口（名称可调整）：

1. `kernel_cpu_scheduler_loop(vcpu_id: usize) -> !`

要求：

1. BSP 完成 global init 后进入该循环。
2. AP 完成 per-core init 后进入同一循环。
3. 该循环只处理：
   1. 调度锁、超时检查、`ThreadState` 变迁。
   2. `kctx` 级别线程切换（`switch_kernel_context`）。
4. 不允许在该循环里显式 `enter_user_thread_noreturn`。

### 3.4 用户态进入职责

用户态入口必须归属“被调度执行的内核线程”，而不是调度器本身：

1. 线程被调度后，内核线程从其 `kctx` 续点继续执行。
2. 内核线程在其自身执行流中，通过 trap-return/线程启动 trampoline 进入 EL0。
3. 调度器不直接拼装用户寄存器并 `eret` 到用户入口。

## 4. 分阶段执行

## Phase 1：Boot 同步语义收敛

改动：

1. 将 `__boot_primary_ready` 收敛为原子 boot state（release/acquire）。
2. AP 等待路径改为原子读取 + WFE 循环。
3. BSP 放行 AP 改为 release-store + SEV。

验收：

1. AP 仅在 `Ready` 后继续执行。
2. 无早期并发访问未初始化全局状态的问题。

## Phase 2：MM 初始化职责拆分 + 调用点改造

改动：

1. `mm::init()` 拆为 `init_global_bootstrap` + `init_per_cpu`。
2. BSP 启动路径调用顺序：
   1. `vectors::install()`
   2. `mm::init_global_bootstrap()`
   3. `mm::init_per_cpu()`
3. AP 启动路径调用顺序：
   1. `vectors::install()`
   2. `mm::init_per_cpu()`
4. 不引入额外 VMM 启动阶段耦合。

验收：

1. 单核路径行为不回退。
2. 双核下 AP 可正常完成 per-core 初始化。

## Phase 3：调度职责去用户态化（新增）

改动：

1. 从 per-core 调度循环移除 `enter_user_thread_noreturn`。
2. 调度循环仅保留内核线程调度动作：`schedule` + `switch_kernel_context` 或 idle。
3. 首次运行线程与普通恢复线程统一为“线程内路径进入 EL0”：
   1. 新建线程由内核线程启动 trampoline 首次返回用户态。
   2. 被抢占/阻塞线程由既有 trap-return 路径恢复用户态。
4. 对“无可用内核 continuation 却要求内核态切换”的路径直接 panic，禁止静默回落到调度器直入用户态。

验收：

1. 调度循环代码中不再出现 `enter_user_thread_noreturn`。
2. `thread_test` 在 1 vCPU/2 vCPU 下都不出现 `PROCESS_EXIT: code=225`。
3. `SetEvent` 唤醒抢占与 `NtWait*` timeout 行为不回退。

## 5. 验证清单

每次改动后执行：

1. `bash scripts/build-kernel-bin.sh`
2. `cargo build`
3. `codesign --force --sign - --entitlements entitlements.plist --options runtime target/debug/winemu`
4. `WINEMU_VCPU_COUNT=2 RUST_LOG=info target/debug/winemu run tests/thread_test/target/aarch64-pc-windows-msvc/release/thread_test.exe`

通过标准：

1. 不出现 `PROCESS_EXIT: code=225`。
2. 不出现 secondary 进入用户态后的异常 MMIO fault 链路。
3. 能观察到 AP 参与调度（后续可补强日志/计数器断言）。

## 6. 后续（本次不含）

1. 收敛为单一调度循环实现（删除 duplicated secondary loop 实现差异）。
2. 去除 BSP 首线程特判，改为 thread0 也通过统一调度入口首选执行。
3. 增加多核调度一致性测试（唤醒抢占、超时、多线程迁移）。

## 7. 本次执行记录（2026-03-04）

已完成：

1. Phase 1：`boot_ready` 同步语义收敛为 release/acquire。
2. Phase 2：`mm` 初始化拆分为 global/per-cpu 并改造 BSP/AP 调用点。
3. 额外防护：调度器过滤 stale ready 节点，避免同一线程被多个 vCPU 同时绑定。
4. BSP 启动路径不再直跳 `enter_initial_user_thread`，改为进入统一 per-core 调度循环（过渡实现）。
5. 已确认过渡实现存在职责越界：调度循环内仍直接 `enter_user_thread_noreturn`，需要按 Phase 3 收敛。

验证结果：

1. `WINEMU_VCPU_COUNT=1`：`thread_test` 全量通过，`PROCESS_EXIT: code=0`。
2. `WINEMU_VCPU_COUNT=2`：仍失败，`PROCESS_EXIT: code=225`。

关键现象（2 vCPU）：

1. AP 已被正确放行并进入调度（可见 `secondary: mpidr... vid=1` 日志）。
2. 早期“双核并发调度同一线程”已被识别并加防护。
3. 当前剩余故障为多核并发阶段的后续内核 fault（创建更多线程场景）。

调试日志：

1. `/tmp/thread_test_boot_refactor_dbg4.log`
2. `/tmp/thread_test_boot_refactor_v1.log`
