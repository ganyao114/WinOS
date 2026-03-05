# Win32u + Msvcrt 源码复用实现方案（不使用 Wine 预编译 DLL）

## 1. 目标与约束

### 1.1 目标

1. 让 CPU-Z 在 WinEmu 中走通窗口与控件绘制主路径。
2. `win32u` 与 `msvcrt` 均采用“源码复用 + 本地构建”方式落地。
3. syscall 入口仍然是 Guest Kernel（`SVC #0`），Host 仅承担窗口/GDI 执行。

### 1.2 硬约束

1. 不直接使用 Wine 现成 `win32u.dll` / `msvcrt.dll` 二进制产物。
2. 必须复用 Wine 绝大多数源码与 spec，避免手写维护大规模导出表。
3. 保持当前调度原则：等待/唤醒仍由内核线程调度主路径负责，不新增轮询回退。

## 2. 当前差距（与目标相比）

1. `guest/win32u/win32u.c` 仅少量导出，无法满足 `user32/gdi32` 的导入需求。
2. `winemu-kernel/src/nt/win32k.rs` 目前只处理 `NtUserInitializeClientPfnArrays`。
3. HostCall broker 仅覆盖文件类 opcode，缺少 win32k/窗口/GDI opcode。
4. `guest/sysroot/msvcrt.dll` 当前来自外部 Wine 产物（符号链路可用，但不满足“源码复用本地构建”约束）。

## 3. 总体架构

```
Guest App
  -> user32/gdi32 (Wine 源码构建)
  -> win32u (Wine 源码复用构建)
  -> SVC #0 (table=1, win32k syscall)
  -> Guest Kernel win32k dispatch
  -> hypercall HOSTCALL_SUBMIT(OP_WIN32K_*)
  -> Host Window/GDI Runtime (主线程执行)
```

关键点：

1. DLL 层复用 Wine 源码。
2. 内核负责 syscall 号解析、参数封送、线程等待与唤醒。
3. Host 负责窗口系统对接和绘制执行。

## 4. 代码组织方案

1. 新增源码镜像目录（仅源码，不含产物，直接放在 `guest` 下）：
   - `guest/win32u/*`
   - `guest/msvcrt/*`
2. 新增 WinEmu 适配层：
   - `guest/win32u/*`
   - `guest/msvcrt/*`
3. 新增生成脚本：
   - `scripts/gen_win32u_exports.py`（从 `win32u.spec` 生成导出/桩）
   - `scripts/gen_msvcrt_exports.py`（从 `msvcrt.spec` 生成导出/桩）
4. 新增源码同步脚本：
   - `scripts/sync_wine_sources.sh`（从指定 Wine 源目录同步并记录 commit）

## 5. win32u 实施计划

## W0. 基线切换

1. `guest/Makefile` 移除现有极简 `win32u` 构建路径。
2. 新增 `win32u` 构建目标，产物输出 `guest/sysroot/win32u.dll`（本地编译）。
3. 导出完整性校验：`objdump -p win32u.dll` 对比 `win32u.spec` 必需导出。

## W1. 导出与 syscall 封装自动生成

1. 以 `win32u.spec` 为唯一源：
   - `-syscall` 条目：生成 ARM64 syscall trampoline（`x8=0x1000+id`, `svc #0`）。
   - `stub` 条目：生成 `STATUS_NOT_IMPLEMENTED` 占位导出（先保证加载）。
2. 自动生成 `win32k_sysno_generated.h` 与导出源文件，避免手写号漂移。

## W2. Guest Kernel win32k 分发扩展

1. `table==1` 改为统一入口：
   - 本地内核处理：`NtUserInitializeClientPfnArrays` 等必须本地项。
   - 其余进入 `win32k bridge`，封送参数到 HostCall。
2. 支持参数个数驱动（来自 spec 生成信息）：
   - `x0..x7` 直接取寄存器。
   - 超过 8 参数从用户栈按只读校验复制。

## W3. HostCall 扩展（win32k 域）

1. 在 `winemu-shared::hostcall` 新增 opcode：
   - `OP_WIN32K_CALL`
   - 后续可按热点拆分 `OP_WIN32K_USER`, `OP_WIN32K_GDI`。
2. 默认 GUI 相关请求走 `FLAG_MAIN_THREAD` 执行通道。
3. completion 仍走现有 IRQ 唤醒链路，不添加轮询兜底。

## W4. Host 窗口/GDI 运行时

1. 新增 `crates/winemu-vmm/src/win32k/`：
   - `dispatcher.rs`：按 syscall id 分派
   - `window.rs`：HWND 与原生窗口管理
   - `gdi.rs`：HDC/bitmap/surface 与 BitBlt 最小实现
2. 先实现 CPU-Z 路径所需最小集（trace 驱动增量实现）。
3. 未实现接口返回明确 NTSTATUS，并保留限流日志。

## W5. 兼容收敛

1. 清理内核中针对旧极简 `win32u` 的补丁式兼容路径。
2. 保留统一 bridge + Host runtime 单一路径，避免双实现分叉。

## 6. msvcrt 实施计划

## C0. 源码复用落地

1. 同步 Wine `dlls/msvcrt` 源码到 `guest/msvcrt/`。
2. 新增 `guest/msvcrt/Makefile`，由本地工具链编译 `guest/sysroot/msvcrt.dll`。

## C1. 导出层自动化

1. 以 `msvcrt.spec` 自动生成导出定义与入口桩。
2. 第一阶段确保 CPU-Z 依赖链涉及符号全部存在（真实实现或可接受占位）。

## C2. 核心模块优先级

按 CPU-Z 实际调用优先：

1. `heap/file/string/time/locale/errno/environ`
2. `math/printf/scanf` 最小可运行集合
3. C++ EH/RTTI 仅按依赖增量引入

## C3. 与 WinEmu 运行时对接

1. 统一调用已有 `ntdll/kernelbase` 路径，不引入额外私有 ABI。
2. 对宿主差异的适配仅放在 `guest/msvcrt` 本地适配层，不修改 Wine 大块源码语义。

## 7. 构建与生成流程

1. `scripts/sync_wine_sources.sh` 同步源码并记录来源 commit。
2. `scripts/gen_win32u_exports.py` / `scripts/gen_msvcrt_exports.py` 生成代码。
3. `make -C guest` 产出本地构建的 `win32u.dll` 与 `msvcrt.dll`。
4. 校验：
   - 导出覆盖率
   - PE load 无 unresolved import

## 8. 测试与验收

## T0. 静态校验

1. `objdump -p` 检查导出与导入完整性。
2. 校验 `gdi32/user32 -> win32u` forwarder 是否可解析。

## T1. 回归

1. `tests/thread_test`
2. `tests/full_test`
3. `tests/registry_test`
4. `tests/hello_win`

## T2. 目标场景

1. CPU-Z 不再出现 `PE load failed`。
2. CPU-Z 能创建窗口并进入消息循环。
3. 关键 UI 操作不中断（显示、基本控件绘制、关闭窗口退出）。

## 9. 里程碑顺序

1. 里程碑 A：W0 + W1 + C0 + C1（先解决导出与加载）
2. 里程碑 B：W2 + W3（打通内核到 Host 的 win32k 主链路）
3. 里程碑 C：W4 + T2（CPU-Z 最小可视化运行）
4. 里程碑 D：W5 + C2 + C3（收敛与可维护性提升）

## 10. 明确不采用的方案

1. 不直接复用外部 Wine 预编译 `win32u.dll/msvcrt.dll`。
2. 不保留旧极简 `win32u` 与新方案并行长期共存。
3. 不在等待链路加入“轮询 + WFI 回退”作为常规路径。

## 11. 当前进度（2026-03-04）

### 已完成

1. `win32u` / `msvcrt` 导出生成链路支持 `passthrough_exports.txt`：
   - 可按符号粒度把导出从 `winemu_stub_export` 切到真实对象符号。
2. 两个 DLL 的 Makefile 已接入 passthrough 输入，并修复并行构建下重复生成问题（改为 stamp 驱动）。
3. `msvcrt` 已接入第一批真实导出（来自 Wine `string.c` / `math.c` 的最小实现裁剪）：
   - `_abs64, abs, labs`
   - `_memccpy, memchr, memcmp, memcpy, memmove, memset`
   - `strcat, strchr, strcmp, strcpy, strlen, strncmp, strncpy, strnlen, strrchr`

### 已验证

1. `make -C guest/msvcrt` 通过，导出表中上述符号已切为直接导出。
2. `make -C guest/win32u` 通过。
3. `make -C guest` 全量构建通过。
4. `thread_test` 运行通过（无调度回归）。

### 下一步

1. 将 `msvcrt` 真实实现从“最小裁剪文件”扩展为“直接编译 Wine 源文件对象”为主。
2. 建立 `win32u` 第一批真实对象导出（先选低依赖 syscall 封装与基础用户态入口）。
3. 结合 CPU-Z 实际调用链，按缺失导出与 `STATUS_NOT_IMPLEMENTED` 热点增量推进。
