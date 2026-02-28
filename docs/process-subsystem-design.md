# WinEmu Guest Kernel 进程子系统设计

## 1. 目标与边界

### 1.1 目标

在现有 `thread/sync/memory/section/registry` 已迁移到 guest 的基础上，补齐进程子系统，使以下 NT 语义在 **guest kernel** 实现：

- `NtCreateProcessEx`
- `NtTerminateProcess`
- `NtQueryInformationProcess`（逐步补全常见信息类）
- 进程对象句柄、引用计数、生命周期清理
- 线程归属进程、进程级资源回收

### 1.2 边界（保持架构原则）

遵循 `docs/architecture.md` 与 `docs/architecture-split.md`：

- NT 语义在 guest kernel 内实现
- 只有需要 host 资源时才走 hypercall：
  - 原始文件访问（镜像文件、注册表文件）
  - 物理页申请/释放
  - 最终进程退出（当前仍通过 `PROCESS_EXIT`）

VMM 不承载进程语义状态机。

## 2. 当前现状与差距

### 2.1 现状

- `winemu-kernel/src/nt/process.rs`
  - `NtCreateProcessEx` 返回 `STATUS_NOT_IMPLEMENTED`
  - `NtQueryInformationProcess` 仅硬编码最小返回
  - `NtTerminateProcess` 直接 `hypercall::process_exit`
- 调度器线程模型仅有 `tid`，无 `pid`
- `nt/state.rs` 的虚拟内存区域、section/view/file 为全局单实例，不区分进程
- 句柄管理在 `sched/sync.rs` 全局表，尚无“每进程句柄表”

### 2.2 差距

- 缺少 `KProcess` 内核对象
- 缺少 PID 分配和进程状态机
- 缺少进程对象句柄语义
- 缺少进程级资源归集与销毁流程
- `CreateThreadEx` 的目标进程句柄语义未落地（当前基本等价“当前进程”）

## 3. 设计原则

1. **先语义后隔离**：先做完整进程对象语义与生命周期，再推进更强地址空间隔离能力。
2. **dispatcher 只分发**：`nt/process.rs` 仅做 ABI 解析与参数写回，核心逻辑下沉到进程服务模块。
3. **对象统一管理**：沿用现有 `ObjectStore` + 句柄引用计数模型，扩展到 `Process` 类型。
4. **与现有代码兼容迭代**：不一次性重写 `sync` 句柄系统，分阶段演进到 per-process handle table。

## 4. 目标架构

### 4.1 模块划分

新增 `winemu-kernel/src/process/`（进程服务层）：

- `process/mod.rs`
  - `KProcess` 定义
  - PID 分配、进程存储、基础查询
- `process/lifecycle.rs`
  - create/terminate/exit 清理路径
- `process/query.rs`
  - `PROCESSINFOCLASS` 打包与返回构造
- `process/handle.rs`
  - 进程句柄解析辅助（先适配现有全局 handle，后续平滑迁移 per-process）
- `process/address_space.rs`（Phase 2/3）
  - 进程地址空间上下文（先逻辑层，后接 TTBR0）

现有 `nt/process.rs` 改为 thin dispatcher，调用 `process::*` 服务。

### 4.2 核心对象

`KProcess`（建议）

- `pid: u32`
- `parent_pid: u32`
- `state: ProcessState`（Creating/Running/Terminating/Terminated）
- `exit_status: u32`
- `image_base: u64`
- `peb_va: u64`
- `main_thread_tid: u32`
- `thread_count: u32`
- `create_time_100ns: u64`
- `vm_regions_root`（Phase 2：进程级虚拟内存视图）
- `handles_root`（Phase 2：进程级句柄表入口）

`KThread` 扩展：

- 新增 `pid: u32`

### 4.3 句柄模型（分阶段）

### Phase 1（兼容模式）

- 复用 `sched/sync.rs` 的全局句柄系统
- 新增 `HANDLE_TYPE_PROCESS`
- 通过 `make_new_handle(HANDLE_TYPE_PROCESS, pid)` 暴露进程句柄
- 先满足语义正确性

### Phase 2（目标模式）

- 引入每进程句柄表：
  - 句柄值仅在所属进程上下文解析
  - `DuplicateObject` 支持跨进程复制（先限制同进程，再放开）
- 对象引用计数独立于句柄槽，支持多表引用

## 5. Syscall 语义设计

### 5.1 NtCreateProcessEx

MVP（Phase 1）语义：

- 支持 `ParentProcess=-1`（当前进程）与 `SectionHandle` 创建
- 创建 `KProcess` 并返回进程句柄
- 不立即创建主线程（保持与 NT 接口分离；由 `NtCreateThreadEx` 创建首线程）
- 初始 `ProcessState=Running`

失败回滚：

- 任一步骤失败都必须回收已分配对象/句柄，返回对应 NTSTATUS

### 5.2 NtTerminateProcess

- `ProcessHandle=-1`：终止当前进程
- 其他句柄：解析目标进程并执行终止
- 终止流程：
  1. 标记 `Terminating`
  2. 批量终止该进程下所有线程（含等待队列清理）
  3. 关闭/释放进程拥有资源（句柄、VM 区域、section view 等）
  4. 写入 `exit_status`，置 `Terminated`
  5. 若为最后可运行进程，触发 `PROCESS_EXIT`

### 5.3 NtQueryInformationProcess

优先实现信息类：

- `ProcessBasicInformation (0)`
- `ProcessImageFileName (27)`（至少返回结构合法与长度正确）

后续扩展：

- `ProcessWow64Information`
- `ProcessTimes`
- `ProcessVmCounters`

要求：

- 严格校验 buffer/return length
- 返回值与长度行为对齐 NT 语义

## 6. 内存与地址空间策略

### 6.1 Phase 1（逻辑分离）

- 在现有单地址空间基础上，给 `VmRegion/SectionView` 增加 `owner_pid`
- `NtAllocateVirtualMemory/NtMapViewOfSection` 按当前进程归属记账
- 终止进程时按 `owner_pid` 回收全部区域

优势：

- 改动小，可快速建立正确的进程生命周期

限制：

- 尚不提供硬隔离（同地址空间）

### 6.2 Phase 2（地址空间上下文）

- 每进程维护独立 `VaSpace` 实例
- 线程切换时若 `pid` 变化，切换进程地址空间上下文
- 暂可先“软切换映射视图”，后续演进为 TTBR0 真切换

### 6.3 Phase 3（硬隔离）

- 每进程独立用户页表根（TTBR0）
- 内核共享 TTBR1
- 完整实现跨进程地址空间隔离

## 7. 与线程/调度器集成

需要新增的调度服务能力：

- `thread_pid(tid) -> Option<u32>`
- `terminate_threads_by_pid(pid, exit_status)`
- `for_each_thread_in_pid(pid, f)`

调度语义：

- 线程可调度前必须检查所属进程状态为 `Running`
- 进程进入 `Terminating` 后，不再接受新线程

## 8. 目录与职责调整建议

为保持“按职责拆分”风格，建议：

- `nt/process.rs`：仅 syscall 参数解析 + 调用 service + 写回
- `process/*`：进程业务逻辑
- `sched/mod.rs`：只保留调度相关，不承载进程生命周期主逻辑
- `nt/state.rs`：逐步拆成进程归属明确的状态模块（memory/file/section 分离）

## 9. 分阶段实施计划

### Phase A（MVP，可快速落地）

目标：进程对象语义可用

- 新增 `process/mod.rs` + `KProcess` + PID 分配
- `KThread` 增加 `pid`
- `NtCreateProcessEx` 返回真实进程句柄
- `NtTerminateProcess` 支持按进程终止
- `NtQueryInformationProcess` 改为读 `KProcess` 实际数据

验收：

- 新增 process 基础测试：
  - create -> query -> terminate -> query terminated

### Phase B（资源归属与清理）

目标：进程级资源回收完整

- `VmRegion/SectionView/File` 增加 `owner_pid`
- 进程终止时按 PID 回收资源
- `CreateThreadEx` 支持目标进程句柄（至少 same-process + 当前进程）

验收：

- 压测创建/销毁进程后无对象泄漏（ObjectStore live count 回到基线）

### Phase C（句柄体系升级）

目标：句柄语义接近 NT

- 引入 per-process handle table（可先与全局系统并存）
- `DuplicateObject` 支持源/目标进程句柄路径
- `Close` 在进程上下文解析句柄

验收：

- 句柄跨进程复制、关闭、引用计数行为正确

### Phase D（地址空间强化）

目标：多进程隔离能力

- 每进程独立 `VaSpace`
- 线程切换联动进程地址空间上下文
- 最终支持 TTBR0 真切换（如当前 MMU 结构允许）

验收：

- 多进程同虚拟地址映射不同内容互不干扰

## 10. 回归与测试计划

每阶段执行：

1. `./scripts/build-kernel-bin.sh`
2. `cargo build`
3. `codesign --entitlements entitlements.plist -s - target/debug/winemu`
4. 回归：
   - `tests/thread_test`
   - `tests/full_test`
   - `tests/registry_test`
   - `tests/hello_win`
5. 新增：
   - `tests/process_test`（按阶段扩展用例）

## 11. 风险与缓解

- 风险：一次性重构句柄系统影响面过大  
  缓解：先兼容全局句柄，再迁移 per-process

- 风险：地址空间隔离改动触发大量 MMU 回归  
  缓解：先做 `owner_pid` 逻辑归属，最后再切 TTBR0

- 风险：线程终止与进程终止竞态  
  缓解：统一在调度锁保护下执行状态迁移，固定销毁顺序

## 12. 待你确认的决策点

1. `NtCreateProcessEx` 的 Phase A 是否只支持 `Parent=-1` 与当前镜像 section 路径（先不做完整 fork/clone）？
2. 句柄体系是否同意“先兼容全局句柄，后迁移 per-process”？
3. 地址空间隔离是否按四阶段推进（先语义，后 TTBR0）？
