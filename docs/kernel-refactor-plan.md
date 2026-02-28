# WinEmu Kernel 代码结构重构计划

## 背景

当前 `winemu-kernel` 存在三个结构性问题：

1. 架构相关实现（ARM64 汇编、系统寄存器访问、HVC/WFI 等）散落在业务模块中，平台耦合较重。
2. 存在较多 hard code（状态码、页大小、栈大小、frame 偏移、syscall number 等）。
3. NT syscall 处理偏 C 风格，`handle_xxx` 中承载大量业务逻辑，职责边界不清晰。

本计划目标是在不破坏现有行为的前提下，逐步重构为“平台抽象 + 常量集中 + 面向对象业务实现”。

## 目标

1. 建立 `arch` 目录，统一封装平台相关能力，业务代码仅调用通用接口。
2. 收敛硬编码到统一常量模块，减少魔法值散落。
3. 将 syscall 处理改为“dispatch + service/object impl”，`handle_xxx` 仅做 ABI 解析与分发。

## 实施进度（2026-02-28）

- Phase A：已完成
  - 已建立 `arch/` 抽象层并迁移 ARM64 启动、向量、中断计时器、系统寄存器、HVC/WFI、自旋锁和 MMU 寄存器访问。
  - 业务模块已改为通过 `arch::*` 调用平台能力。
  - 已将后端绑定点统一为 `arch::backend`，并建立多架构能力契约文档：`docs/arch-backend-contract.md`。
- Phase B：进行中（高优先级项已落地）
  - 已新增并接入 `nt/sysno.rs`、`nt/constants.rs`、`nt/status.rs`。
  - 已将 SVC tag 解析位段、关键结构尺寸、线程信息类、故障调试 tag、handle 编码位段等魔法值收敛为常量。
- Phase C：进行中（线程主路径已下沉）
  - 线程创建/终止/查询/优先级设置主逻辑已下沉到 `sched` 服务与 `KThread` 相关实现，`nt/thread.rs` 进一步变薄。
  - 修正 `NtCreateThreadEx` 栈参数读取，`MaxStackSize` 读取对齐到正确槽位。
- Phase D：进行中（同步子系统样板已推进）
  - `nt/sync.rs` 已改为薄分发，主要逻辑下沉到 `sched/sync.rs`。
  - `KEvent/KMutex/KSemaphore` 已增加对象化核心方法（set/reset/release）。
  - 新增按句柄 service API（create/set/reset/release）并统一错误返回语义。
- 回归状态：通过
  - `./scripts/build-kernel-bin.sh`
  - `cargo build`
  - `codesign --entitlements entitlements.plist -s - target/debug/winemu`
  - `thread_test` / `full_test` / `registry_test` / `hello_win`

## 分阶段实施

### Phase A：平台抽象落地（行为不变）

- 新增 `winemu-kernel/src/arch/`。
- 将下列平台细节迁移到 `arch/aarch64/*`：
  - 启动入口汇编（`_start`）
  - 异常向量与 SVC/Abort 路径汇编
  - 定时器 IRQ 汇编与 CNTV 访问
  - `TPIDR_EL1/EL0`、`ESR_EL1/FAR_EL1` 等系统寄存器访问
  - 自旋锁 LDXR/STXR
  - HVC 调用与 WFI
- 业务模块仅保留调用 `arch::*` 的逻辑。

### Phase B：hard code 收敛

- 新增常量模块：
  - `nt/sysno.rs`：系统调用号
  - `nt/constants.rs`：页大小、栈大小、句柄特殊值等
  - `nt/status.rs`：统一 NTSTATUS 常量入口
- 替换裸十六进制状态码与关键尺寸常量。
- 为 `SvcFrame` 布局添加静态尺寸校验，避免汇编偏移漂移。

### Phase C：线程路径面向对象化

- 以线程子系统为首个样板：
  - `nt/thread.rs` 仅做参数解析/返回写回。
  - 主要逻辑下沉到 `impl KThread` 与 `sched` 服务函数。
- 包含：创建线程、查询线程信息、设置线程信息、终止线程、yield。

### Phase D：推广到其它 NT 子系统

- 按领域逐步推进：`sync / file / section / registry / object`。
- `handle_xxx` 统一降级为 thin dispatcher。
- 逐步拆分超大文件（如 `sched/sync.rs`）为职责子模块。

### Phase E：收尾与文档同步

- 清理冗余代码与旧入口。
- 更新架构文档，固化目录与编码规范。

## 回归策略

每个 Phase 完成后执行：

1. `./scripts/build-kernel-bin.sh`
2. `cargo build`
3. `codesign --entitlements entitlements.plist -s - target/debug/winemu`
4. 回归运行：
   - `tests/thread_test`
   - `tests/full_test`
   - `tests/registry_test`
   - `tests/hello_win`

原则：先通过回归再进入下一阶段。
