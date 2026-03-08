# CPU-Z ARM64 静态 Syscall 缺口分析（基于导入符号 + Wine 映射）

## 1. 分析范围与方法

- 目标二进制：`/Users/swift/Downloads/cpuz-arm64_1/cpuz_arm64.exe`
- 静态分析步骤（不依赖 runtime fail 点）：
  1. 解析 PE import table，提取 DLL + 导入符号（含序号导入）。
  2. 用 Wine 源码做 `DLL API -> Nt* / NtUser* / NtGdi*` 映射：
     - 先看 `.spec`（导出/转发关系）
     - 再看 `kernelbase/*.c`、`ntdll/*.c`（实际 Nt 调用）
  3. 对照 WinEmu 当前 syscall 分发与 fallback 行为，识别缺口并按优先级排序。

## 2. 导入符号概览（CPU-Z）

- DLL 数：17
- 导入符号总量：630
- 主要集中在 GUI 和基础运行时：
  - `USER32.dll`: 223
  - `KERNEL32.dll`: 181
  - `GDI32.dll`: 98
  - `ole32.dll`: 23
  - `gdiplus.dll`: 22
  - `ADVAPI32.dll`: 13

备注：
- `OLEAUT32.dll` 为 ordinal 导入（如 `#10/#114/...`），可解码出 `VariantCopy / VarBstrFromDate / LoadTypeLib` 等。

## 3. 当前 WinEmu 能力基线（关键结论）

### 3.1 Table 0（Nt）是 guest kernel 主处理路径

`svc_dispatch` 里 Table 0 的已处理集合见：
- [winemu-kernel/src/nt/dispatch.rs](/Users/swift/WinEmu/winemu-kernel/src/nt/dispatch.rs#L115)
- [winemu-kernel/src/nt/sysno.rs](/Users/swift/WinEmu/winemu-kernel/src/nt/sysno.rs#L1)

### 3.2 Table 1（win32k）当前会走 `NOT_IMPLEMENTED`

- `table != 0` 且非 `0x127` 时，当前直接 `forward_to_vmm`：
  - [winemu-kernel/src/nt/dispatch.rs](/Users/swift/WinEmu/winemu-kernel/src/nt/dispatch.rs#L95)
- VMM 的 legacy `NT_SYSCALL` 已移除，固定返回 `NOT_IMPLEMENTED`：
  - [crates/winemu-vmm/src/hypercall/mod.rs](/Users/swift/WinEmu/crates/winemu-vmm/src/hypercall/mod.rs#L297)
- 即使走 hostcall win32k bridge，目前也是 `NOT_IMPLEMENTED`：
  - [crates/winemu-vmm/src/hostcall/broker.rs](/Users/swift/WinEmu/crates/winemu-vmm/src/hostcall/broker.rs#L685)

这意味着：CPU-Z 的大量 `USER32/GDI32` 路径在当前版本必然卡死/失败。

## 4. 静态映射结果（关键链路）

### 4.1 KERNEL32 -> kernelbase -> Nt*

关键证据（Wine）：
- `CreateFileW -> NtCreateFile`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/file.c:778`
- `ReadFile -> NtReadFile`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/file.c:3496`
- `WriteFile -> NtWriteFile`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/file.c:3896`
- `DeviceIoControl -> NtDeviceIoControlFile / NtFsControlFile`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/file.c:4246`
- `FindFirstFileExW -> NtOpenFile / NtQueryDirectoryFile`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/file.c:1180`
- `GetFileAttributesExW -> NtQueryFullAttributesFile`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/file.c:1721`
- `LockFile / UnlockFile / FlushFileBuffers -> NtLockFile / NtUnlockFile / NtFlushBuffersFile`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/file.c:3306`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/file.c:3863`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/file.c:3027`
- `VirtualAlloc/Protect/Query -> NtAllocateVirtualMemory / NtProtectVirtualMemory / NtQueryVirtualMemory`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/memory.c:443`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/memory.c:576`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/memory.c:599`
- `CreateThread -> RtlCreateUserThread -> NtCreateThreadEx`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/thread.c:110`  
  `/Users/swift/wine-proton-macos/dlls/ntdll/thread.c:266`
- `QueueUserAPC -> NtQueueApcThread`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/thread.c:372`

### 4.2 ADVAPI32 注册表 API -> kernelbase/registry -> Nt*

关键证据（Wine）：
- `RegOpenKeyExW -> NtOpenKeyEx`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/registry.c:710`  
  `open_key()` 内 `NtOpenKeyEx`: `/Users/swift/wine-proton-macos/dlls/kernelbase/registry.c:377`
- `RegCreateKeyExW -> NtCreateKey`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/registry.c:632`  
  `create_key()` 内 `NtCreateKey`: `/Users/swift/wine-proton-macos/dlls/kernelbase/registry.c:475`
- `RegQueryValueExW -> NtQueryValueKey`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/registry.c:1702`
- `RegQueryInfoKeyW -> NtQueryKey`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/registry.c:1023`
- `RegEnumKeyExW / RegEnumValueW -> NtEnumerateKey / NtEnumerateValueKey`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/registry.c:867`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/registry.c:2210`
- `RegSetValueExW -> NtSetValueKey`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/registry.c:1275`
- `RegDeleteKeyW -> RegDeleteKeyExW -> NtDeleteKey`  
  `/Users/swift/wine-proton-macos/dlls/advapi32/registry.c:321`  
  `/Users/swift/wine-proton-macos/dlls/kernelbase/registry.c:1206`

### 4.3 USER32 / GDI32 -> NtUser* / NtGdi*（win32k）

CPU-Z 导入集中在 USER/GDI，Wine `.spec` 映射显示大量直接 win32k 调用，例如：
- `EnumDisplayMonitors -> NtUserEnumDisplayMonitors`  
  `/Users/swift/wine-proton-macos/dlls/user32/user32.spec:477`
- `SetWindowPos -> NtUserSetWindowPos`  
  `/Users/swift/wine-proton-macos/dlls/user32/user32.spec:1117`
- `CreatePopupMenu -> NtUserCreatePopupMenu`  
  `/Users/swift/wine-proton-macos/dlls/user32/user32.spec:337`
- `GetDC -> NtUserGetDC`  
  `/Users/swift/wine-proton-macos/dlls/user32/user32.spec:545`
- `CreateCompatibleDC -> NtGdiCreateCompatibleDC`  
  `/Users/swift/wine-proton-macos/dlls/gdi32/gdi32.spec:61`
- `CreateRectRgn -> NtGdiCreateRectRgn`  
  `/Users/swift/wine-proton-macos/dlls/gdi32/gdi32.spec:94`

结论：CPU-Z GUI 路径对 win32k 依赖是“硬依赖”，不是可选优化项。

## 5. 缺口清单（按重要性）

## P0（先做，不做就起不来）

1. `win32k table(1)` 端到端可用（NtUser/NtGdi）
- 现状：guest dispatch 未走完整 win32k handler，VMM bridge 也固定 `NOT_IMPLEMENTED`。
- 影响：`USER32/GDI32` 核心路径不可用，CPU-Z GUI 初始化会早期失败。

2. `NtOpenKeyEx`
- 来源：`RegOpenKeyExW`（CPU-Z 显式导入）。
- 现状：guest 仅有 `NtOpenKey` 语义入口，缺 `OpenKeyEx` 对应路径。

3. `NtQueryFullAttributesFile`
- 来源：`GetFileAttributesExW`（CPU-Z 显式导入）。
- 现状：已有 `NtQueryAttributesFile`，但 `FullAttributes` 是另一条系统调用路径。

4. `NtLockFile` / `NtUnlockFile` / `NtFlushBuffersFile`
- 来源：`LockFile/UnlockFile/FlushFileBuffers`（CPU-Z 显式导入）。
- 现状：当前分发表未覆盖这些 syscall。

## P1（高概率在继续初始化时命中）

1. `NtWaitForAlertByThreadId` / `NtAlertThreadByThreadId`
- 来源：`SleepConditionVariableSRW -> RtlSleepConditionVariableSRW -> RtlWaitOnAddress/WakeAddress*`
- Wine 证据：`ntdll/sync.c:910/957/964`
- 影响：线程同步和 runtime 并发路径可能卡住或异常。

2. `NtOpenEvent` / `NtOpenMutant` / `NtOpenSemaphore`（按实际命中补齐）
- 来源：Win32 同步对象 open 路径常见分支。
- 现状：当前已实现 create/release 为主，open 家族不足。

## P2（功能完备性）

1. `NtAllocateVirtualMemoryEx` / `NtUnmapViewOfSectionEx` 等扩展内存接口
- 来源：现代运行库与新 API 可能触发。
- 现状：基础内存接口已可用，扩展接口不齐全。

2. OLE/TypeLib 相关附加路径
- `OLEAUT32 #161 = LoadTypeLib`，后续可能引出更多 COM/注册表/文件细节。

## 6. 建议改造计划（实施顺序）

1. **先打通 win32k 最小闭环（P0-1）**
- guest：`table=1` 统一走 `win32k::handle_win32k_syscall`（不再直接 `forward_to_vmm`）。
- host：`OP_WIN32K_CALL` 至少先支持 CPU-Z 启动所需的最小 `NtUser/NtGdi` 子集。
- 先覆盖：
  - `NtUserGetMessage/PeekMessage/DispatchMessage/TranslateMessage`
  - `NtUserCreateWindowEx/ShowWindow/SetWindowPos/DestroyWindow`
  - `NtUserGetDC/ReleaseDC/BeginPaint/EndPaint`
  - `NtGdiCreateCompatibleDC/BitBlt/CreateRectRgn/DeleteObject`（按调用继续扩）

2. **补齐 Table 0 的硬缺口（P0-2~4）**
- 增加并接入：
  - `NtOpenKeyEx`（可先复用 `NtOpenKey` 逻辑，补 `options` 语义）
  - `NtQueryFullAttributesFile`
  - `NtLockFile` / `NtUnlockFile` / `NtFlushBuffersFile`

3. **补同步 futex 系统调用（P1）**
- 增加：
  - `NtWaitForAlertByThreadId`
  - `NtAlertThreadByThreadId`
- 目标：让 `SleepConditionVariableSRW` 和 runtime 并发路径稳定。

4. **最后再做扩展接口（P2）**
- 内存扩展接口、TypeLib/COM 边角路径。

## 7. 结论

按静态证据看，CPU-Z 当前最大阻塞并不是“某一个零散 Nt syscall”，而是：
- **win32k（Table=1）整体不可用** + **少量关键 Table=0 缺口（OpenKeyEx/QueryFullAttributesFile/Lock&Flush）**。

优先级上应先解决 win32k 最小闭环，再补 Table 0 缺口；否则会一直在 GUI 初始化阶段反复撞 `NOT_IMPLEMENTED`。

