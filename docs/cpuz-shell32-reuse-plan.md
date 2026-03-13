# CPU-Z Shell32 复用接入方案

## 0. 进度更新（2026-03-13）

这份文档的主体仍保留了最初制定方案时的分析，但当前实际进度已经明显前移，先给出最新状态，避免把后文的“首个阻塞点”当成当前事实。

### 0.1 当前状态

`cpuz_arm64.exe` 当前已经不再停在 `SHELL32.dll!SHGetMalloc` unresolved import。

当前链路状态：

1. `shell32` 已经纳入 `guest/` 内源码管理和构建链，`guest/sysroot/shell32.dll` 不再依赖外部黑箱二进制。
2. `SHGetMalloc` 及其所需的最小 shell/COM 路径已经可解析、可执行。
3. `cpuz` 已经能从最初的加载期 unresolved import，推进到运行期真实逻辑。
4. 结合最近一轮 `cpuz` 调试，`wininet/urlcache` 使用的 `INetCookies/index.dat` file-backed section 已支持 page-out/writeback，能够把 URL cache header 真正落盘。
5. 在清理旧坏缓存目录后，`cpuz` 当前可以跑到 `PROCESS_EXIT: code=0`。

关键运行结果：

- 命令：
  `RUST_LOG=debug WINEMU_VCPU_COUNT=1 target/debug/winemu run /Users/swift/Downloads/cpuz-arm64_1/cpuz_arm64.exe`
- 最近验证结果：
  `PROCESS_EXIT: code=0`
- `users/Default/AppData/Local/Microsoft/Windows/INetCookies/index.dat` 已能正确写出：
  文件头为 `WINE URLCache Ver 0.2012001`

### 0.2 当前已经打通的关键阻塞

相较于本文最初写下时，以下阻塞已经不再是当前主问题：

1. `SHELL32.dll!SHGetMalloc` unresolved import
2. `shell32` 不在仓库内、不可调试不可维护
3. `wininet/urlcache` 的 `index.dat` 初始化内容无法持久化
4. 因坏的 `index.dat` 导致的 `cache_container_open_index -> FreeUrlCacheSpaceW -> cache_container_open_index` 递归压栈

### 0.3 当前剩余问题

`cpuz` 虽然已经可以完整跑通到退出，但这不代表功能已经完整：

1. 仍存在大量能力空洞和 stub 路径，特别是更深的 shell/COM/WMI/设备探测能力。
2. `PhysicalDriveN` 的探测当前仍会大量返回 `STATUS_OBJECT_NAME_NOT_FOUND`，只是程序已能容忍。
3. GUI/数据正确性还需要继续以真实运行期行为为准做验证，而不是只看“能启动/能退出”。
4. 旧的坏 `INetCookies/index.dat` 如果已存在于工作目录，仍建议清理后再验证；当前修复保证的是“新建/重建路径正确落盘”。

### 0.4 接下来最合理的推进方向

1. 继续沿真实 runtime fail 点推进，而不是回到“静态只补一个 shell32 导出”的阶段。
2. 优先补齐 `cpuz` 继续运行时实际命中的 shell/COM/WMI/设备相关缺口。
3. 将本文后续的 `Phase B/C/D` 视为“仍然有效的分层推进策略”，而不是当前阻塞点描述。

## 1. 背景与目标

当前 `cpuz` 的首个加载期阻塞点已经明确：

- 运行 `target/debug/winemu run /Users/swift/Downloads/cpuz-arm64_1/cpuz_arm64.exe`
- 当前首个失败点为：`ldr: unresolved import SHELL32.dll!SHGetMalloc`

这说明：

1. 继续只补 syscall 已经不够。
2. `shell32.dll` 必须进入 WinEmu 自己可控的源码/构建链。
3. 但不应该手写一个新的 `shell32`，而应尽量复用 Wine 实现。

本方案的目标是：

1. 先把 `shell32` 纳入 `guest/` 内部源码管理和构建。
2. 优先复用 Wine `shell32` 源码，不自己重新实现 Shell 语义。
3. 采用“模块整体纳管、功能按对象切片逐步启用”的方式，先解决 `cpuz` 当前阻塞，再逐步扩展。

## 2. CPU-Z 的 DLL 依赖闭包

## 2.1 直接依赖（Level 1）

`cpuz_arm64.exe` 直接导入 17 个 DLL：

- `VERSION.dll`
- `KERNEL32.dll`
- `USER32.dll`
- `GDI32.dll`
- `MSIMG32.dll`
- `WINSPOOL.DRV`
- `ADVAPI32.dll`
- `SHELL32.dll`
- `SHLWAPI.dll`
- `UxTheme.dll`
- `ole32.dll`
- `OLEAUT32.dll`
- `gdiplus.dll`
- `OLEACC.dll`
- `dwmapi.dll`
- `IMM32.dll`
- `WINMM.dll`

## 2.2 递归常规依赖闭包（当前 sysroot 静态分析）

按当前 `guest/sysroot` 中这些 DLL 的 import table 递归展开，常规依赖闭包共 31 个 DLL：

- Level 1:
  `ADVAPI32.dll`, `dwmapi.dll`, `GDI32.dll`, `gdiplus.dll`, `IMM32.dll`,
  `KERNEL32.dll`, `MSIMG32.dll`, `ole32.dll`, `OLEACC.dll`, `OLEAUT32.dll`,
  `SHELL32.dll`, `SHLWAPI.dll`, `USER32.dll`, `UxTheme.dll`, `VERSION.dll`,
  `WINMM.dll`, `WINSPOOL.DRV`
- Level 2:
  `combase.dll`, `coml2.dll`, `compstui.dll`, `kernelbase.dll`, `mlang.dll`,
  `msacm32.dll`, `msvcrt.dll`, `ntdll.dll`, `rpcrt4.dll`, `sechost.dll`,
  `shcore.dll`, `ucrtbase.dll`, `win32u.dll`
- Level 3:
  `comctl32.dll`

结论：

1. `cpuz` 的主依赖面已经明显偏向 GUI/COM/Shell 路径，而不是纯 Nt syscall。
2. `shell32` 本身不是孤立模块，它位于 `shlwapi/user32/gdi32/advapi32/ole32` 这条现有依赖网中。
3. 从文件存在性看，当前 `guest/sysroot` 中闭包内 DLL 都存在，没有“找不到 DLL 文件”的问题，问题在于模块实现和可解析性。

## 2.3 CPU-Z 对 shell32 的直接需求

从 `cpuz_arm64.exe` 的 import table 看，当前对 `shell32.dll` 的直接导入只有 1 个：

- `SHGetMalloc`

这很关键，意味着首阶段不需要把整个 Shell 命名空间、Explorer 视图、回收站、控制面板等全部做完，先让 `SHGetMalloc` 可工作即可把加载流程继续向前推进。

## 3. Shell32 在 Wine 中的实现边界

## 3.1 主要入口

Wine `shell32` 的核心入口和构建边界：

- 构建清单：
  [Makefile.in](/Users/swift/wine-proton-macos/dlls/shell32/Makefile.in)
- 导出 ABI：
  [shell32.spec](/Users/swift/wine-proton-macos/dlls/shell32/shell32.spec)
- 进程级入口：
  [shell32_main.c](/Users/swift/wine-proton-macos/dlls/shell32/shell32_main.c)
- COM / allocator / class factory 相关入口：
  [shellole.c](/Users/swift/wine-proton-macos/dlls/shell32/shellole.c)
- 内部公共头：
  [shell32_main.h](/Users/swift/wine-proton-macos/dlls/shell32/shell32_main.h)

## 3.2 Wine shell32 的直接依赖

Wine `dlls/shell32/Makefile.in` 定义的依赖如下：

- `IMPORTS`:
  `uuid`, `shlwapi`, `user32`, `gdi32`, `advapi32`
- `DELAYIMPORTS`:
  `ole32`, `oleaut32`, `shdocvw`, `version`, `comctl32`, `comdlg32`, `gdiplus`

与 `cpuz` 当前闭包对照：

1. 常规 import 依赖基本都已经在当前闭包内。
2. delay-import 会额外把 `comdlg32.dll`、`shdocvw.dll` 这类模块带进来。
3. 这也是为什么 `shell32` 不能简单当成“只补一个导出”的孤立 DLL 看待。

## 3.3 可以直接复用的部分

可以直接作为 Wine 对象切片复用的部分：

- `shellole.c`
- `shellstring.c`
- `pidl.c`
- `enumidlist.c`
- `shellord.c`
- `shellpath.c` 的非 Unix/known-folder 路径

尤其是当前 `cpuz` 卡住的 `SHGetMalloc`，Wine 实现非常直接：

- [shellole.c](/Users/swift/wine-proton-macos/dlls/shell32/shellole.c#L287)
- 语义就是：`CoGetMalloc(MEMCTX_TASK, lpmal)`

这类实现非常适合首阶段直接复用。

## 3.4 不能整体平移的部分

Wine `shell32` 虽然没有 `unix call` 主路径，但它并不是“零改动可直接搬运”的模块。主要阻塞点有：

1. Wine 私有基础设施依赖：
   - `wine/debug.h`
   - `wine/list.h`
   - `wine/heap.h`
2. 资源注册依赖：
   - `__wine_register_resources()`
   - `__wine_unregister_resources()`
3. Unix 路径 / Wine 环境桥接：
   - `wine_get_unix_file_name`
   - `wine_get_dos_file_name`
   - `\\??\\unix`
   - `UnixFolder`
   - `WINEHOMEDIR`
4. 外部工具调用：
   - `winemenubuilder.exe`
5. 重型 Shell 功能面：
   - 文件系统 Shell folder
   - desktop / recycle bin
   - shell view / browser / dispatch
   - change notification / control panel

结论：

- `shell32` 可“切片复用”，不可“整目录原样平移立即启用”。

## 4. 为什么要把 shell32 纳入 WinEmu 源码，而不是继续依赖现成 sysroot 二进制

当前 `guest/sysroot` 已经存在一个 `shell32.dll` 二进制，但它对 WinEmu 来说是不可维护的黑箱：

1. 遇到 `SHGetMalloc` 这样的加载失败时，我们无法在仓库内直接修它。
2. 无法对照当前 WinEmu 的 DLL/内核/hostcall 环境做最小裁剪。
3. 无法像 `win32u/msvcrt` 一样通过 `spec + passthrough + real object slice` 渐进推进。

因此更合理的路线是：

- 把 Wine `shell32` 源码同步进 `guest/shell32`
- 由 WinEmu 自己构建 `guest/sysroot/shell32.dll`
- 后续所有兼容修复都落在仓库内，可持续调试和演进

## 5. 推荐接入策略

## 5.1 总体原则

1. 不手写新的 `shell32` 语义实现。
2. 不尝试第一步就完整移植 Explorer / shell namespace。
3. 先沿用 `win32u/msvcrt` 已经验证过的模式：
   - `spec_codegen` 生成导出
   - `passthrough_exports.txt` 标记真实对象导出
   - `objcopy` 按符号/section 切真实 Wine 对象
4. 先解决 `cpuz` 当前命中的最小需求，再根据下一跳失败点扩展对象切片。

## 5.2 Phase A: 源码纳管与构建基线

目标：让 `shell32` 进入 WinEmu 自己的构建链，但先不追求完整功能。

建议改造：

1. 扩展 `scripts/sync_wine_sources.sh`
   - 新增同步 `dlls/shell32 -> guest/shell32`
2. 新增 `guest/shell32/Makefile`
   - 复用 `guest/common.mk`
   - 复用 `scripts/spec_codegen.py`
3. 新增 `guest/shell32/passthrough_exports.txt`
4. 使用 `shell32.spec` 生成：
   - `shell32_exports.generated.c`
   - `shell32_exports.generated.def`
5. 将 `guest/Makefile` 接入 `shell32.dll` 产物构建

说明：

- 这一阶段允许大部分导出先走 generated stub。
- 关键在于建立“WinEmu 自己可构建的 shell32.dll”。

## 5.3 Phase B: 最小可用切片，先打通 cpuz 当前阻塞

目标：先让 `SHELL32.dll!SHGetMalloc` 真正可解析、可执行。

首批建议接入的真实对象：

1. `shellole.c`
   - `SHGetMalloc`
   - `SHAlloc`
   - `SHFree`
   - 必要时连带 `ILFree` / `SHCoCreateInstance` 相关极小集合
2. 视构建情况决定是否接入 `shell32_main.c`
   - 如果 generated `DllMainCRTStartup -> DllMain` 足够，就先不引入真实 `DllMain`
   - 如果某些初始化必须存在，再切 `shell32_main.c` 的最小入口 section

原因：

1. `SHGetMalloc` 本质只依赖 `ole32!CoGetMalloc`
2. 风险低
3. 能最快把 `cpuz` 从当前加载阻塞点推到下一跳

这一阶段不建议接入：

- `shlview.c`
- `ebrowser.c`
- `shelldispatch.c`
- `shfldr_fs.c`
- `shfldr_desktop.c`
- `recyclebin.c`
- `changenotify.c`
- `control.c`
- `shelllink.c` 中 `winemenubuilder` 路径

## 5.4 Phase C: 扩展低风险 Shell helper 切片

当 `cpuz` 继续前进并命中更多 `shell32` 导出时，再按需要扩展：

建议优先级：

1. `shellstring.c`
2. `pidl.c`
3. `enumidlist.c`
4. `shellord.c`
5. `shellpath.c` 的非 Unix / 非 known-folder 路径

这一阶段的目标不是“完整 shell32”，而是补齐低风险、可独立工作的 helper / path / pidl 能力。

## 5.5 Phase D: WinEmu shim 收口 Wine 特有基础设施

当必须进入更深的 Shell 功能面时，再为 Wine 私有基础设施建立 shim：

1. `wine/debug.h` / `wine/list.h` / `wine/heap.h`
   - 继续复用现有 `guest/wine/include` / `guest/wine/compat`
2. 资源注册 shim
   - 提供 `__wine_register_resources()` / `__wine_unregister_resources()` 的 WinEmu 版本
3. Unix 路径桥接 shim
   - 不复用 Wine 的 UnixFolder 语义
   - 改为走 WinEmu 的 VFS/NT path 语义
4. `winemenubuilder` 路径
   - 首期直接 no-op
5. 少量 `ntdll` helper 缺口
   - 按实际编译/运行需要补

## 6. 设计判断

## 6.1 不推荐的方案

### 方案 A: 手写一个最小 shell32.dll

不推荐，原因：

1. 会把 `shell32` 再做成一个长期不可维护的兼容层。
2. 后续每命中一个导出都要重新手补。
3. 与“尽量复用 Wine，不自己实现”的原则相违背。

### 方案 B: 直接整目录照搬 Wine shell32 并全量编译

也不推荐，原因：

1. 依赖面太大。
2. Wine 特有基础设施和 WinEmu 当前 guest 环境还没对齐。
3. 容易一次性把 `shdocvw/comdlg32/gdiplus/Explorer folder` 复杂度全部拉进来。

## 6.2 推荐方案

推荐：

- `shell32` 整体模块纳管
- 导出层用 `spec_codegen`
- 功能层按 Wine 真实对象切片逐步启用

这和当前 `win32u/msvcrt` 路线一致，也最适合持续推进 `cpuz`。

## 7. 建议实施顺序

1. 建立 `guest/shell32` 目录与同步脚本支持
2. 建立 `guest/shell32/Makefile`
3. 用 `shell32.spec` 生成导出壳
4. 首批接入 `shellole.c`，让 `SHGetMalloc`、`SHAlloc`、`SHFree` 可用
5. 构建新的 `guest/sysroot/shell32.dll`
6. 回归运行 `cpuz`
7. 根据新的运行期失败点继续扩展 `shell32` 切片，或回到 syscall / win32k 缺口

## 8. 验收标准

Phase A:

1. `guest/shell32` 能被同步和构建
2. `guest/sysroot/shell32.dll` 由仓库内源码产出，而非外部黑箱

Phase B:

1. `objdump -p guest/sysroot/shell32.dll` 能看到 `SHGetMalloc`
2. `cpuz` 不再因 `SHELL32.dll!SHGetMalloc` unresolved import 失败

Phase C:

1. `cpuz` 能继续推进到下一个真实运行期缺口
2. 新缺口优先继续通过 Wine 对象切片解决，而不是手写 shell32 逻辑

## 9. 结论

`cpuz` 当前虽然表面上只缺 `SHELL32.dll!SHGetMalloc`，但从工程角度看，真正需要的是：

- 把 `shell32` 纳入 WinEmu 自己的 Wine 源码复用体系

最合理的路线不是“补一个导出就算完”，也不是“整包硬搬 shell32”，而是：

- 先整体纳管 `shell32`
- 再从 `shellole.c` 这类低风险对象开始，按 `cpuz` 的真实命中路径逐步启用

这条路线最符合当前仓库已经形成的 `win32u/msvcrt` 复用方式，也最符合“能复用 Wine 实现就不自己实现”的原则。
