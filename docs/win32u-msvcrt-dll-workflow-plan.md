# Win32u / Msvcrt DLL 落地工作流（Wine 源码复用）

## 1. 目标

1. `win32u`、`msvcrt` 不使用 Wine 预编译 DLL，改为复用 Wine 源码本地构建。
2. 建立可复用的 Wine 共享头与兼容层，供所有 guest DLL 共用。
3. 将 Wine `unix call` 收敛到 `guest user dll -> kernel -> hostcall -> vmm` 主路径。
4. 将 Wine 私有 syscall 替换为 WinEmu guest kernel 的真实 syscall 入口，号表由参考表驱动。

## 2. 统一工作流（按你提出的 4 步）

1. 拷贝 DLL 代码：
   - 同步 `dlls/win32u`、`dlls/msvcrt` 到 `guest/win32u`、`guest/msvcrt`。
2. 实现 Wine 共有头：
   - 同步 `Wine/include` 到 `guest/wine/include`（共享给所有 DLL）。
   - 仅在必要时通过 `guest/wine/compat` 做最小兼容，不在单个 DLL 私有目录重复造头。
3. 替换 unix call：
   - 用户态 DLL 通过 `NtDeviceIoControlFile` 与 `\Device\WinEmuHost` 通信。
   - kernel `NtDeviceIoControlFile` 处理 IOCTL 并转 `hostcall` 到 VMM。
   - 异步结果统一复用现有 pending + IRQ completion 唤醒链路。
4. 替换 Wine 私有 syscall：
   - `win32u.spec` 中 syscall 项映射到 guest kernel 真实 syscall 入口。
   - syscall 号以参考表为准（`/Users/swift/Downloads/SyscallTables-master`，按固定目标 build）。

## 3. 分阶段落地

## Phase A: 共享头与构建基线

1. `scripts/sync_wine_sources.sh` 扩展为同步 `Wine/include` 到 `guest/wine/include`。
2. `guest/common.mk` 暴露共享 include 路径变量（`WINE_CFLAGS`）。
3. `guest/win32u/Makefile`、`guest/msvcrt/Makefile` 统一使用共享头路径。
4. 移除临时重复实现文件（例如手写复制自 `string.c` 的中间文件），避免双份源码。

验收：
1. `make -C guest/win32u`、`make -C guest/msvcrt` 可通过当前基线构建。
2. 构建链路不再依赖 DLL 私有伪造头文件。

## Phase B: unix call -> IOCTL -> hostcall 主路径

1. 新增 `\Device\WinEmuHost` 设备语义（最小可用集合）。
2. `NtDeviceIoControlFile` 支持 WinEmuHost IOCTL 分发。
3. kernel IOCTL handler 封送参数，调用 `hostcall::submit_tracked/call_sync`。
4. pending IOCTL 使用现有等待/唤醒主链路，不引入轮询兜底。

验收：
1. 至少一条 IOCTL（例如 ping/echo 或 win32k-bridge probe）同步成功。
2. 至少一条异步 IOCTL（host 返回 pending）成功唤醒并完成。

## Phase C: 私有 syscall 号表与替换

1. 引入“号表输入 -> 生成头文件”的脚本化流程（固定目标 Windows build）。
2. `win32u` syscall stub 与 kernel 分发表统一使用同一生成产物。
3. 清理手写/硬编码号值，避免漂移。

验收：
1. 号值来源可追溯到参考表版本。
2. `win32u` 与 kernel 对同名 syscall 的号值一致。

## Phase D: 真实源码编译切片

1. `msvcrt`：先接低依赖模块，逐步从 generated stub 导出切换到真实对象导出。
2. `win32u`：先接 syscall 封装与初始化路径，再扩 UI/GDI 热点。
3. 保留 `passthrough_exports` 仅作为过渡机制，最终以真实源码符号为主。

验收：
1. CPU-Z 路径缺失符号显著下降。
2. `PE load failed` 相关加载问题收敛。

## 4. 当前执行顺序（本轮）

1. 先完成 Phase A（共享头、构建基线、删除重复实现）。
2. 开始 Phase B 的框架接入（先实现最小 WinEmuHost IOCTL 骨架，不破坏现有路径）。
3. 每一阶段都做构建与回归验证。

## 5. 最新进度（2026-03-04）

1. Phase A：已完成（源码同步 + 共享头 + win32u/msvcrt 构建基线）。
2. Phase B：已完成最小主路径（`\\Device\\WinEmuHost` + `NtDeviceIoControlFile` + hostcall sync/async + IRQ 唤醒）。
3. Phase C（进行中）：
   - `scripts/gen_win32u_exports.py` 已支持同时生成 Rust syscall 常量文件。
   - `scripts/spec_codegen.py` 已支持 `extern` 数据导出的 passthrough 重定向（`export=impl @ordinal DATA`）。
   - 新增共享常量产物：`crates/winemu-shared/src/win32k_sysno_generated.rs`。
   - kernel/vmm 已改为使用共享常量，移除 `NtUserInitializeClientPfnArrays` 的硬编码号分叉。
   - `msvcrt` 的 `_sys_errlist/_sys_nerr` 已通过 `errno.c` 真实数据符号导出（`MSVCRT__sys_errlist/MSVCRT__sys_nerr`），不再依赖 generated stub data 占位。
   - 已接入 `SyscallTables-master`（ARM64/26100）参考号输入并生成映射：
     `guest/win32u/generated/win32k_sysno_map.csv`。
     当前结果：`442` 个 syscall 中 `429` 个使用参考号（低 12 位编码），`13` 个因冲突/缺失回落顺序号。
4. Phase D（已开始）：
   - `msvcrt` 已接入首批真实 Wine 源对象：`string.c`。
   - `msvcrt` 已新增第二批真实 Wine 源对象切片：`wcs.c`（当前已覆盖基础宽字符 API + 安全版本 + 转换/大小写与集合操作）。
   - `wcs.c` 在 guest 构建下通过 `WINEMU_MSVCRT_NO_WTYPES` 做最小头隔离，避免 `wtypes.h`
     与 mingw 头冲突；仅在 `wcs.full.o` 目标生效，不影响其他对象。
   - 为避免整文件依赖被拉入，构建链路采用：
     “完整编译 `string.full.o` -> `objcopy` 保留目标 `.text$*` section -> `strip-unneeded`”。
   - 已切换为真实导出的符号（`string.c`）：
     `_memccpy, memchr, memcmp, memcpy, memmove, memset, strcat, strchr, strcmp, strcpy, strlen, strncmp, strncpy, strnlen, strrchr, strcspn, strncat, strpbrk, strspn, strstr, strcpy_s, strcat_s, strncpy_s, strncat_s`。
   - 已切换为真实导出的符号（`errno.c`）：
     `__doserrno, _errno, _get_doserrno, _get_errno, _set_doserrno, _set_errno, _sys_errlist, _sys_nerr`。
   - 已切换为真实导出的新增符号（`wcs.c` 增量）：
     `wcscat_s, wcscpy_s, wcsncat_s, wcsncpy_s, wcsrtombs, wcsrtombs_s, wcstod, wcstol, wcstombs, wcstombs_s, wcstoul, wctob, wctomb, wctomb_s, _wtoi, _wtoi64, _wtoi_l, _wtoi64_l, _wtol, _wtol_l, _wcslwr*, _wcsupr*, _wcsnset*, _wcsset*, _wcsrev, _wcsto*_l`。
   - 验证（本轮）：
     `make -C guest/msvcrt clean && make -C guest/msvcrt -j4`、
     `make -C guest/win32u clean && make -C guest/win32u -j4`、
     `make -C guest -j4`、
     `RUST_LOG=info target/debug/winemu run guest/sysroot/hello_win.exe`、
     `RUST_LOG=info target/debug/winemu run guest/sysroot/syscall_file_control_test.exe` 均已通过。
   - CPU-Z 探测（`RUST_LOG=debug target/debug/winemu run /Users/swift/Downloads/cpuz-arm64_1/cpuz_arm64.exe`）：
     未再出现 `PE load failed`，当前失败点为运行期 `PAGE_FAULT_UNRESOLVED`（`PROCESS_EXIT: code=255`），说明当前主要阻塞已从加载期转移到运行期执行路径。
5. win32u 真实对象切换前置（新增）：
   - 已新增脚本化生成产物 `guest/win32u/generated/win32syscalls.h`（来源 `win32u.spec` + 参考号映射），为复用 Wine `main.c/syscall.c` 做准备。
   - `main.c` 路径已打通：通过 `-D__WINE_PE_BUILD` 兼容 PE/COFF 汇编宏，并以对象切片方式仅保留
     `DllMain`、`__wine_spec_unimplemented_stub`、`__wine_syscall_dispatcher` 等初始化相关符号接入 `win32u.dll`。
   - `gen_win32u_exports.py` 新增 `--no-dllmain`，generated C 改为仅生成 `DllMainCRTStartup -> DllMain` 跳转，避免与真实 `main.c` 的 `DllMain` 冲突。
   - 验证：`make -C guest/win32u`、`make -C guest`、`target/debug/winemu run guest/sysroot/syscall_file_control_test.exe` 均已通过。
   - 已将最小 guest shim 合并回 `guest/win32u/syscall.c`（`WINEMU_PE_GUEST` 条件分支）并接入构建：
     当前 guest 分支提供 `__wine_unix_call_funcs`/`zero_bits` 的 PE 侧符号落点，避免直接走 Wine
     Unix-only 私有头路径导致编译冲突。
     当前实现仍为 no-op init，后续在头冲突收敛后再替换为真实 `syscall.c` 行为。
   - 仍未打通：`win32u/syscall.c` 直接编译存在 Unix 侧头依赖与 mingw 头冲突（例如 `wine/gdi_driver.h` 的 Unix-only 限制、`winbase.h`/`wtypesbase.h` 类型重定义），需补 guest 侧最小兼容头隔离。

下一步：
1. 继续扩展 `msvcrt` 真实导出集合（优先 `string.c` 之外的低依赖模块，例如 `wcs.c`/`errno.c` 可切片函数）。
2. 继续推进 `win32u`：先做 `syscall.c` 所需的 Unix-only 头隔离和 mingw 头冲突收敛，再尝试接入第一批真实对象导出。
3. 对 `win32k_sysno_map.csv` 中 `13` 个 `seq` 项逐项收敛，减少参考号偏差。

## 6. 边界约束

1. 不回退到“轮询 + WFI”路径。
2. 不保留重复实现的临时文件长期共存。
3. 不在每个 DLL 目录重复维护一套 Wine 公共头。
