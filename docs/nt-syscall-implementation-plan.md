# WinEmu NT Syscall 实施计划（ARM64，先不考虑 x86）

## 1. 目标

- 基于真实程序使用频次，优先补齐高价值 NT syscall。
- 每实现一个 syscall，必须有对应测试，且单项可独立验证。
- 保持架构原则：**NT 语义在 guest kernel**，仅 host 资源访问走 hypercall。

## 2. 数据来源与方法

- 使用频次来源（Wine 代码库）  
  `rg -o --no-filename -g '*.[ch]' -g '*.inl' --glob '!**/tests/**' '\bNt[A-Z][A-Za-z0-9_]*\s*\(' dlls programs server`
- syscall number 参考  
  `/Users/swift/Downloads/SyscallTables-master/data/Composition/ARM64/ntos/{22631,26100}.txt`
- 语义行为参考  
  `/Users/swift/wine-proton-macos`
- 当前实现基线  
  `winemu-kernel/src/nt/dispatch.rs` + 各 `winemu-kernel/src/nt/*.rs`

## 3. 当前 guest 已实现覆盖

- 文件：`NtCreateFile/NtOpenFile/NtReadFile/NtWriteFile/NtQueryInformationFile/NtSetInformationFile/NtQueryDirectoryFile`
- 同步：`NtCreateEvent/NtSetEvent/NtResetEvent/NtWaitForSingleObject/NtWaitForMultipleObjects/NtCreateMutant/NtReleaseMutant/NtCreateSemaphore/NtReleaseSemaphore`
- 注册表：`NtOpenKey/NtCreateKey/NtDeleteKey/NtSetValueKey/NtQueryValueKey/NtEnumerateKey/NtEnumerateValueKey/NtDeleteValueKey`
- 内存/Section：`NtAllocateVirtualMemory/NtFreeVirtualMemory/NtProtectVirtualMemory/NtQueryVirtualMemory/NtCreateSection/NtMapViewOfSection/NtUnmapViewOfSection`
- 进程/线程：`NtCreateProcessEx/NtOpenProcess/NtTerminateProcess/NtQueryInformationProcess/NtCreateThreadEx/NtTerminateThread/NtQueryInformationThread/NtSetInformationThread/NtYieldExecution`
- 对象：`NtDuplicateObject/NtClose/NtQueryObject(ObjectBasicInformation)`

## 4. 程序常用但尚未在 guest 落地（按 Wine 频次）

高优先级（P0）：
- `NtQuerySystemInformation`（80）
- `NtDeviceIoControlFile`（59）
- `NtQuerySystemTime`（31）
- `NtQueryPerformanceCounter`（31）
- `NtSetInformationProcess`（24）
- `NtQueryInformationToken`（22）
- `NtQueryObject`（18）
- `NtDelayExecution`（18）
- `NtFsControlFile`（17）
- `NtContinue`（16）

中优先级（P1）：
- `NtQueryKey`（12）
- `NtQueryVolumeInformationFile`（12）
- `NtQueueApcThread`（11）
- `NtQueryAttributesFile`（11）
- `NtOpenSection`（11）
- `NtOpenProcess`（10）
- `NtRaiseException`（10）
- `NtResumeThread`（10）

后续（P2）：
- `NtReadVirtualMemory`（8）
- `NtWriteVirtualMemory`（6）
- `NtAllocateVirtualMemoryEx`（7）
- `NtMapViewOfSectionEx`（6）
- `NtUnmapViewOfSectionEx`（7）
- `NtCreateIoCompletion/NtRemoveIoCompletion/NtSetIoCompletion`（6/6/5）

## 5. syscall number 策略（关键）

当前项目 `winemu-kernel/src/nt/sysno.rs` 与 `config/syscall-tables/win11-arm64.toml` 使用的是**现有项目 ABI profile**，并不完整等同 SyscallTables 原始 ARM64 编号。  
因此采用策略：

1. **项目 ABI 兼容优先**：新增 syscall 先与现有 profile 对齐，避免破坏已有程序。
2. **SyscallTables 作为参考基线**：用于核对名称、趋势和潜在冲突，不直接全量覆盖现有编号。
3. 对存在编号冲突的 syscall，优先采用：
   - 与现有编号可兼容的分发策略（例如同号语义分流）；或
   - 延后到“编号统一迁移阶段”再处理。

## 6. 分阶段实施

### Phase 1（立即执行）

目标：先补齐“系统时间/计数器/系统信息/延时”最常见基础能力。

- `NtQuerySystemInformation`
- `NtQuerySystemTime`
- `NtQueryPerformanceCounter`
- `NtDelayExecution`

验收标准：
- 每个 syscall 有独立测试用例（C + mingw）。
- 通过新用例 + 现有回归用例。

### Phase 2（对象与进程信息补全）

- `NtQueryObject`（补齐 ObjectTypeInformation 等类）
- `NtSetInformationProcess`
- `NtQueryInformationToken`
- `NtOpenProcess`

### Phase 3（I/O 控制与异常/APC）

- `NtDeviceIoControlFile`
- `NtFsControlFile`
- `NtContinue`
- `NtRaiseException`
- `NtQueueApcThread`

### Phase 4（内存与完成端口）

- `NtReadVirtualMemory/NtWriteVirtualMemory`
- `NtAllocateVirtualMemoryEx/NtMapViewOfSectionEx/NtUnmapViewOfSectionEx`
- `NtCreateIoCompletion/NtRemoveIoCompletion/NtSetIoCompletion`

## 7. 单 syscall 测试模板（统一）

每个 syscall 至少覆盖：

1. **Happy path**
2. **参数错误路径**
3. **边界长度/空指针/对齐**
4. **返回码与返回长度**
5. **行为语义**（例如延时精度、时间单调性、对象可见性）

执行方式：

1. `make -C guest`
2. `./scripts/build-kernel-bin.sh`
3. `cargo build`
4. `codesign --entitlements entitlements.plist -s - target/debug/winemu`
5. `target/debug/winemu run guest/sysroot/<test>.exe`

回归集合：
- `tests/full_test`
- `tests/thread_test`
- `tests/registry_test`
- `tests/hello_win`
- `guest/process_test`

## 8. 最近进展

1. 已完成 Phase 1：  
   `NtQuerySystemInformation/NtQuerySystemTime/NtQueryPerformanceCounter/NtDelayExecution`
2. 已新增并通过：`guest/syscall_sysinfo_test`
3. 已开始 Phase 2：实现 `NtOpenProcess` 与 `NtQueryObject(ObjectBasicInformation)`，并新增/扩展 `guest/open_process_test`
4. 回归通过：`tests/full_test`、`tests/thread_test`、`tests/registry_test`、`tests/hello_win`
