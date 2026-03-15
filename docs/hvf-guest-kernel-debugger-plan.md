# HVF Guest Kernel 动态调试器方案

## 1. 结论

可以调试，但不能指望宿主侧的 LLDB/GDB 直接像调普通 macOS 进程那样穿透到跑在 HVF 里的 guest kernel。

正确路线是：

1. 在 VMM 内实现一个 guest-aware 的调试核心。
2. 由这个调试核心接管 vCPU 停机、寄存器快照、guest 内存读写、符号化。
3. 在此之上再接一个前端：
   - 第一阶段可以是简单命令 socket / REPL。
   - 第二阶段接 gdb-remote stub，让 LLDB 作为前端使用。

这条路线和当前 WinEmu 的结构是兼容的，而且不会把关键能力押在 HVF 是否完整暴露硬件单步 / 硬件断点寄存器上。

## 2. 当前代码现状与约束

### 2.1 vCPU 句柄被 vCPU 线程独占

当前 `Box<dyn Vcpu>` 只在各自的 vCPU 线程里持有并运行：

- `crates/winemu-vmm/src/lib.rs`
- `crates/winemu-vmm/src/vcpu.rs`

这意味着：

1. 外部线程不能直接抓某个 vCPU 的寄存器。
2. 调试控制面必须进入 `vcpu_thread()` 所在的执行路径。
3. “另起一个宿主线程直接调 HVF 拿 guest 寄存器” 不是当前结构下的正确做法。

### 2.2 当前 HVF backend 还没有调试型 exit 语义

当前 `VmExit` 只有：

- `Hypercall`
- `Timer`
- `Wfi`
- `MmioRead / MmioWrite`
- `IoRead / IoWrite`
- `Halt / Shutdown`
- `Unknown`

相关文件：

- `crates/winemu-hypervisor/src/types.rs`
- `crates/winemu-hypervisor/src/hvf/vcpu.rs`

也就是说，当前没有把“断点命中 / 单步 / 调试异常 / 显式调试中断”上抛成一等事件。

### 2.3 Host 端已经能直接读写 guest 物理内存

`GuestMemory` 本质上是一段 host `mmap`，而且整段 guest physical memory 已被 VMM 管理：

- `crates/winemu-vmm/src/memory.rs`

这意味着 host 端调试器天然就能：

1. 直接按 GPA 读写 guest 内存。
2. 基于 TTBR + page table walk 实现 guest VA 读写。
3. 做软件断点时直接 patch guest 指令字节。

### 2.4 Kernel 符号文件是现成的

当前加载进虚机的是 `winemu-kernel.bin`，但未剥离的 ELF 仍然存在：

- 加载地址：`0x4000_0000`
- 链接脚本：`winemu-kernel/link.ld`
- ELF：`winemu-kernel/target/aarch64-unknown-none/release/winemu-kernel`
- 运行镜像：`winemu-kernel.bin`

这意味着第一阶段就可以做函数级符号化，后续只要补足 `debuginfo` 就能继续提升到源码行号。

### 2.5 多 vCPU 下必须是 all-stop，而不是 non-stop

当前调度器和 VMM 都已经支持多 vCPU，调试如果允许“一个 vCPU 停住，其他 vCPU 继续跑”，会立刻引入：

1. 共享内存继续变化。
2. 断点页被其他核踩过去。
3. 当前现场不再可重复。

所以第一版必须做 all-stop。

## 3. 设计目标

第一阶段的目标不追求“功能看起来很多”，而是追求“基础面是对的”。

必须具备：

1. 手动中断正在运行的 guest，并稳定停住全部 vCPU。
2. 读取全部 vCPU 的寄存器和关键系统寄存器。
3. 读取 / 写入 guest 内存。
4. 基于符号文件做 PC 符号化。
5. 在 guest kernel panic / fatal trap / 显式 debug trap 时自动停机。
6. 支持双核及以上的稳定 all-stop / continue。

第二阶段再补：

1. LLDB / GDB 前端接入。
2. 最小 gdb-remote stub。
3. 更完整的 thread / register / memory 协议映射。

第三阶段才考虑：

1. 真正的动态断点。
2. 单步。
3. watchpoint。

## 4. 明确不作为第一阶段目标的事情

以下能力不要在 MVP 阶段当成硬依赖：

1. 任意地址软件断点一定可用。
2. 真正的硬件单步一定可用。
3. 直接让宿主 LLDB “attach winemu 进程”后就能看到 guest kernel 栈。
4. non-stop 多核调试。

原因很简单：

1. 这几件事都依赖 HVF 对 debug exception / debug register 的真实支持程度。
2. 当前代码结构尚未建立统一的“暂停点”和“调试态”。
3. 如果一开始就把方案押在单步/断点能力上，失败风险很高。

## 5. 推荐架构

推荐分三层：

### 5.1 调试核心层

放在 `crates/winemu-vmm/src/debugger/`，负责：

1. all-stop 状态机
2. vCPU 快照
3. guest 内存读写
4. guest VA 翻译
5. breakpoint 元数据
6. stop reason 管理

建议结构：

```text
crates/winemu-vmm/src/debugger/
  mod.rs
  controller.rs
  types.rs
  memory.rs
  translate.rs
  symbol.rs
  server.rs
  gdb_remote.rs
```

### 5.2 backend 适配层

职责：

1. 把 HVF 的 “run canceled / exception / system register” 语义整理成统一调试事件。
2. 暴露调试能力位，而不是在上层假定所有 backend 都支持单步和断点。

建议新增 capability：

```rust
pub struct DebugCaps {
    pub async_interrupt: bool,
    pub cooperative_break: bool,
    pub sw_breakpoint_candidate: bool,
    pub hw_single_step_candidate: bool,
}
```

注意这里故意用 `candidate`，因为真正可用性还要经过实测。

### 5.3 前端协议层

第一阶段：

1. Unix socket / TCP socket
2. 命令式接口，例如 `pause`, `regs`, `x`, `set-reg`, `continue`

第二阶段：

1. gdb-remote stub
2. 让 LLDB 接上来做 UI / symbol / memory 命令前端

## 6. 停机模型

### 6.1 只做 all-stop

状态机建议：

```text
Running
  -> PauseRequested
  -> Paused
  -> Running
```

### 6.2 停机入口

第一阶段只做三类停机入口：

1. 手动中断
2. guest cooperative debug trap
3. guest kernel panic / fatal trap

### 6.3 手动中断实现

macOS/HVF 下，当前已经有现成经验可用：

- `hv_vcpus_exit(...)`

而且项目里已经在 `PROCESS_EXIT` 路径用过类似逻辑：

- `crates/winemu-vmm/src/hypercall/mod.rs`

推荐做法：

1. `DebugController::request_pause_all(reason)` 置位全局 pause epoch。
2. 调用 `hv_vcpus_exit(all_vcpus)` 强制所有正在 `run()` 的 vCPU 退回宿主。
3. vCPU 线程在 `run()` 返回后识别“这是调试暂停，不是错误”。
4. 各 vCPU 把寄存器快照写入 controller 后进入 barrier。
5. 全部 vCPU 就位后，state 进入 `Paused`。

### 6.4 continue 实现

1. 前端发 `continue`。
2. controller 清理本轮 pause epoch。
3. 如有待写回的寄存器 / 内存 / 断点恢复，先统一提交。
4. 释放 barrier，让所有 vCPU 回到 `run()` 主循环。

## 7. vCPU 调试控制面如何接入

当前关键点在 `crates/winemu-vmm/src/vcpu.rs`。

建议改造点：

1. `vcpu_thread()` 循环开头检查 `DebugController` 是否存在待处理命令。
2. `run_vcpu_once()` 返回 `Err(canceled)` 时，不直接按普通错误处理。
3. 先问 `DebugController`：这是 shutdown、debug pause，还是异常错误。
4. 在 `handle_vmexit()` 前后都允许进入调试态。

建议新增逻辑：

```text
loop {
  debugger.poll_pre_run(vcpu_id, &mut vcpu);
  let exit = vcpu.run();
  match debugger.intercept_run_result(vcpu_id, &mut vcpu, exit) {
    EnteredPaused => continue,
    ResumeWithExit(exit) => handle_vmexit(...),
    Shutdown => break,
    Fatal(err) => ...
  }
}
```

这样调试器不会和现有 scheduler / hypercall 主流程缠死。

## 8. guest memory 与 guest VA 访问

### 8.1 GPA 访问是现成能力

`GuestMemory` 已经支持按 GPA 直接读写，所以：

1. `x /p <gpa>`
2. `write /p <gpa>`

这类能力几乎不需要额外设计。

### 8.2 VA 访问需要 page table walker

为了让调试器真正可用，必须支持 guest VA。

建议在 VMM 侧实现独立 walker：

1. 输入：`TTBR0_EL1` / `TTBR1_EL1` / `TCR_EL1` / 目标 VA
2. 输出：GPA
3. 再通过 `GuestMemory` 完成读写

数据来源：

1. `Vcpu::special_regs()`
2. 必要时补充 `get_sys_reg()` 风格的 backend 能力

注意：

1. 当前 kernel 还未完全走真实 TTBR1 高半区内核布局时，也不要把 walker 写死成“只认 TTBR0”。
2. 调试器应该按寄存器快照工作，而不是按当前实现细节硬编码。

### 8.3 断点 patch 后需要指令 cache 处理

如果后续实现软件断点，host 直接修改 guest RAM 后，需要考虑 icache 同步。

否则风险是：

1. host 已经把指令改成 `BRK`
2. guest 侧仍然执行旧 icache 内容

因此软件断点方案必须带上：

1. host 写内存
2. 对对应 HVA 范围做 icache invalidate
3. 再恢复 vCPU 运行

这一点不能省。

## 9. 断点策略

### 9.1 第一阶段只做两类可靠断点

第一类：手动暂停

1. 外部命令触发 `pause`
2. 强制全部 vCPU 退出到宿主
3. 检查当前现场

第二类：cooperative debug trap

通过 guest kernel 显式发出调试陷入，例如：

1. `panic`
2. fatal exception
3. `kbreak!()`
4. 特定断言失败

这类能力不依赖 HVF 的 debug exception 是否上抛给宿主，工程风险最低。

### 9.2 cooperative debug trap 的建议做法

新增一条专用 hypercall，例如：

```text
nr::DEBUG_TRAP
```

语义：

1. guest 传入 reason code
2. 可选传入 message pointer / pc / sp
3. host 收到后进入 `PauseRequested`
4. 直接把当前 vCPU 作为 stop leader

适合挂接的位置：

- `winemu-kernel/src/hypercall/mod.rs`
- `winemu-kernel/src/log.rs`
- `winemu-kernel/src/arch/*/vectors.rs`

### 9.3 动态软件断点不要作为第一阶段关键路径

软件断点的真正难点不是“把指令改成 BRK”，而是：

1. BRK 是否会可靠退出到宿主，而不是只在 guest EL1 内部消费。
2. 命中后如何 step-over 并恢复原指令。
3. HVF 是否提供可控的单步 / debug exception 机制。

所以推荐顺序是：

1. 先把调试 core 做对。
2. 再单独做一个 HVF spike，验证 BRK / MDSCR / debug register 可行性。
3. 证明可行后再引入真正的动态断点。

### 9.4 若 HVF debug trap 能力不足的备选方案

如果实测发现 HVF 不适合承载通用 BRK / single-step：

1. 保留手动暂停。
2. 保留 cooperative debug trap。
3. 对关键内核位置采用 `kbreak!()` / `debug_assert_break!()` 形式的显式断点。

这不够通用，但足够先把 kernel bring-up / scheduler / MMU / trap 问题调起来。

## 10. 符号化与回溯

### 10.1 符号化

符号化直接使用：

- `winemu-kernel/target/aarch64-unknown-none/release/winemu-kernel`

因为链接地址已经固定在 `0x4000_0000`，所以不需要复杂重定位适配。

第一阶段先做到：

1. `pc -> 函数名`
2. `lr -> 函数名`
3. `地址区间 -> 符号`

### 10.2 回溯

建议把回溯拆成两个层次：

第一层：

1. 打印 `pc/sp/lr/fp`
2. 对这些地址做符号化

第二层：

1. 如果内核构建打开 frame pointer，则按 `x29` 链回溯
2. 后续再考虑 DWARF unwind

为了让回溯可用，建议单独准备一个 debug-friendly kernel build 选项：

1. `debuginfo=2`
2. `force-frame-pointers=yes`

这比一开始就硬啃 unwind 更现实。

## 11. 前端方案

### 11.1 第一阶段：命令 socket

建议增加环境变量：

```text
WINEMU_GUEST_DEBUG=1
WINEMU_GUEST_DEBUG_ADDR=127.0.0.1:9001
```

支持命令例如：

```text
pause
continue
regs [vcpu]
sregs [vcpu]
x <va> <len>
xp <gpa> <len>
set-reg <vcpu> <name> <value>
sym <addr>
bt [vcpu]
```

优点：

1. bring-up 快
2. 易于观察 all-stop 状态机是否正确
3. 不会一开始就被 gdb-remote 细节拖住

### 11.2 第二阶段：gdb-remote

当 core 稳定后，再实现最小 gdb-remote 子集。

建议先支持：

1. `?`
2. `g` / `p`
3. `G` / `P`
4. `m` / `M`
5. `c`
6. `H`
7. `qSupported`
8. `qAttached`
9. `qfThreadInfo` / `qsThreadInfo`

线程模型建议第一阶段按 vCPU 暴露，而不是按 guest KThread 暴露。

原因：

1. 当前直接可拿的是 vCPU 寄存器。
2. guest thread 是内核调度概念，不是 host 调试控制面的天然主键。
3. vCPU 视图足够先把 kernel bring-up 和 trap/scheduler 问题调起来。

### 11.3 LLDB 使用方式

最终目标可以是：

```text
lldb winemu-kernel/target/aarch64-unknown-none/release/winemu-kernel
(lldb) gdb-remote 127.0.0.1:9001
```

或者等价的 `process connect` 形式。

这样 LLDB 只负责前端交互，真正的 guest 语义由 WinEmu 的调试核心提供。

## 12. 代码改造建议

### 12.1 VMM 新增模块

新增：

```text
crates/winemu-vmm/src/debugger/
```

建议职责：

- `types.rs`
  - `StopReason`
  - `DebugState`
  - `VcpuSnapshot`
  - `DebugCommand`

- `controller.rs`
  - all-stop barrier
  - pause/continue
  - 当前 leader / epoch
  - snapshot 管理

- `memory.rs`
  - GPA 读写
  - 断点 patch

- `translate.rs`
  - TTBR/TCR page table walker

- `symbol.rs`
  - ELF symbol load
  - addr -> symbol

- `server.rs`
  - 命令 socket

- `gdb_remote.rs`
  - 二阶段接入

### 12.2 现有文件改造点

`crates/winemu-vmm/src/lib.rs`

1. 初始化 debugger
2. 按环境变量决定是否开启调试 server
3. 将 debugger handle 传给每个 `vcpu_thread`

`crates/winemu-vmm/src/vcpu.rs`

1. 在 `run()` 前后接入 debugger 控制点
2. 把 `hv_vcpu_run canceled` 从“错误”区分成“调试暂停”
3. 停机后抓取 `regs/special_regs`

`crates/winemu-hypervisor/src/types.rs`

二阶段建议扩展：

1. `VmExit::Debug(...)`
2. `VmExit::Exception(...)`

`crates/winemu-hypervisor/src/hvf/vcpu.rs`

二阶段建议：

1. 细化 `Unknown(ec)`，不要把潜在调试事件都压成 unknown
2. 给出更可消费的 exception 元数据

`winemu-kernel/src/hypercall/mod.rs`

建议新增：

1. `debug_trap(reason, arg0, arg1)`

`winemu-kernel/src/log.rs`

建议把 panic / fatal trap 路径接到 cooperative debug trap。

## 13. 分阶段实施计划

### Phase 0: 打底

目标：

1. 调试 controller 状态机
2. manual pause / continue
3. vCPU snapshot

交付：

1. `pause`
2. `continue`
3. `regs`
4. `sregs`

### Phase 1: 可用化

目标：

1. GPA/VA 读写
2. ELF 符号化
3. panic / fatal trap 自动停机
4. cooperative debug trap

交付：

1. `x`
2. `xp`
3. `sym`
4. `bt`
5. `kbreak!()` 或等价入口

### Phase 2: 调试器前端

目标：

1. 命令 socket 稳定
2. 最小 gdb-remote stub
3. LLDB 接入

交付：

1. `lldb` 可连接
2. 可读寄存器
3. 可读内存
4. 可 continue

### Phase 3: 高阶断点能力

前置条件：

1. 已验证 HVF 对 debug exception / debug register 的实际支持

目标：

1. 动态断点
2. 单步
3. watchpoint

如果前置条件不成立，则这一阶段降级为：

1. cooperative breakpoint 强化
2. 更好的自动停机点

### 当前落地状态（2026-03-14）

已完成：

1. Phase 0 已落地：
   - `pause`
   - `continue`
   - `status`
   - `regs`
   - `sregs`
2. Phase 1 已基本落地：
   - `xp <gpa> <len>`
   - `x <vcpu> <va> <len>`
   - `sym <addr>`
   - `bt <vcpu>`
3. Phase 2 已落一版最小 gdb-remote：
   - `WINEMU_GUEST_DEBUG_PROTOCOL=gdb`
   - `lldb ... -> gdb-remote 127.0.0.1:<port>`
   - 已支持 attach / 读寄存器 / 写寄存器 / 读内存 / 写内存（`M` / `X`）/ continue / 退出状态上报
   - 已补线程名与基础线程 JSON 信息，LLDB 的初始线程展示更稳定
4. Phase 3 已落一个最小 single-step 探针：
   - HVF debug exception 已上抬为一等 `VmExit::DebugException`
   - `gdb-remote` 已支持 `s` 与 `vCont;s`
   - 当前实现是 all-stop 下“只放行目标 vCPU 单步，其余 vCPU 保持暂停”
   - HVF 侧需要同时设置 `PSTATE.SS` 与 `MDSCR_EL1.SS|KDE|MDE`，只写 `MDSCR_EL1` 不足以让 guest 真正前进一步
5. cooperative debug trap 已接入：
   - guest `panic`
   - kernel fault
   - user fault
   - 通用 `nr::DEBUG_TRAP`
6. `WINEMU_GUEST_DEBUG_AUTO_PAUSE=kernel_ready` 已落地：
   - 在 guest 发送 `KERNEL_READY` 后自动进入 all-stop
   - 适合作为 attach / smoke / 早期 bring-up 的稳定停机点

当前验证结论：

1. 双核 `thread_test` 在 `kernel_ready` 自动暂停后可执行：
   - `status`
   - `regs 0`
   - `continue`
   - guest 正常退出，`PROCESS_EXIT: code=0`
2. `continue` 后的陈旧 `hv_vcpu_run canceled` 已通过 resume grace 机制收敛，不再被误报为真实运行错误。
3. 最小 LLDB 路径已验证：
   - `register read`
   - `register write`
   - `memory read`
   - `memory write`
   - `thread list`
   - `continue`
   - `Process exited with status = 0`
4. 当前 `memory write` 已能修改 guest RAM，但如果后续拿它做真正的软件断点或 patch 指令，仍需要补 host 侧 icache invalidate。
5. 原始 gdb-remote socket 的 `X` 二进制写包已验证，包括 `#` / `$` / `}` / `*` 这类需要转义的字节。
6. HVF single-step 已做最小实测：
   - 在 `kernel_ready` 自动暂停点，对 vcpu0 发 `s`
   - guest `PC` 从 `0x4001371c` 前进到 `0x40013720`
   - 同时 `SP` 从 `0x403b9da0` 前进到 `0x403b9db0`
   - 对应指令是 `ldp x29, x30, [sp], #0x10`，说明单步不是 fake step，而是真正执行了一条 guest 指令
   - HVF 上报的 syndrome 为 `EC=0x32`（software step from lower EL）
7. debugger 的 guest RAM 写入已补宿主侧 icache invalidate 基础设施：
   - 当前 debugger/code-patch 写路径会走显式的执行视图同步
   - 这为后续 `Z0/z0` 软件断点和指令 patch 打了基础
8. `BRK` 软件断点的最小 spike 已验证：
   - 之前 `BRK` patch 后“继续运行但宿主看不到 `EC=0x3c`”的根因，不是先前怀疑的“写错 GPA”，而是 HVF 侧没有提前打开 `trap_debug_exceptions`
   - 当前在 debugger 模式下，vCPU 启动时就会启用 `hv_vcpu_set_trap_debug_exceptions(true)`
   - 在 `kernel_ready` 自动暂停点把 `PC=0x4001371c` 的原指令 `fd7bc1a8` 改成 `brk #0` (`000020d4`) 后，宿主已稳定收到：
     - `hvf debug exit: ec=0x3c syndrome=0xf2000000 pc=0x4001371c`
     - VMM 侧对应的 `VmExit::DebugException`
   - 同时，debugger 写路径已记录：
     - `VA -> GPA` 翻译结果
     - 当前使用 `ttbr0`
     - 页表描述符
     - patch 前/后字节
   - 这说明当前 `BRK` 命中链路已经闭环
9. 断点后的最小 step-over 也已验证：
   - 在 `BRK` 命中暂停后，把原指令写回 `0x4001371c`
   - 再对同一 vCPU 执行 `s`
   - `PC` 从 `0x4001371c` 前进到 `0x40013720`
   - HVF syndrome 为 `EC=0x32`
   - 这说明“软件断点命中 -> 恢复原指令 -> 单步越过 -> 再次暂停”这条最小链路已经可行
10. 最小 `Z0/z0` 软件断点协议已落地：
   - `qSupported` 现在会声明 `swbreak+`
   - 已支持 `Z0,<addr>,4` 与 `z0,<addr>,4`
   - 当前只支持 AArch64 固定 4 字节软件断点，底层编码是 `brk #0`
   - debugger 内部已维护断点元数据：
     - 原始 4 字节指令
     - `refcount`
     - 断点 VA
11. `continue` / `step` 经过软件断点时的最小 step-over 已落地：
   - 如果当前暂停原因是 `EC=0x3c`，且 `PC` 命中了已知软件断点
   - `s` 不会原地再次命中同一个 `BRK`
   - 而是会：
     - 临时恢复原指令
     - 单步执行一条真实 guest 指令
     - 重新挂回 `BRK`
     - 再把暂停结果返回给前端
   - `c` 也会先完成同样的 step-over，再继续运行
12. 连续断点 smoke 已验证：
   - 在 `0x4001371c` 与 `0x40013720` 同时插入 `Z0`
   - 第一次 `continue` 命中 `0x4001371c`
   - 第二次 `continue` 不会在 `0x4001371c` 原地死循环
   - 而是先自动 step-over，再命中 `0x40013720`
13. raw `0x03` 异步中断已打通：
   - `gdb-remote` 的 `continue` 不再是完全阻塞式等待
   - 当前会轮询 debugger state，同时 nonblocking `peek` 连接
   - 当 client 在目标运行中发送 raw `0x03` 时，stub 会调用现有 `request_pause_all(ManualPause)`
   - 实测 `c` 后延迟发 `0x03`，能够稳定收到新的 stop reply
14. stop-reply 语义已做最小收口：
   - `kernel_ready` 这种自动暂停点不再伪装成 `swbreak`
   - 初始 attach / `?` 现在会返回普通 `T05thread:<id>;`
   - software breakpoint 停止在 client `qSupported` 声明 `swbreak+` 时会返回 `T05swbreak:;thread:<id>;`
   - 如果 client 没声明 `swbreak+`，则会降级为普通 `T05thread:<id>;`
   - raw `0x03` 手动中断会返回 `T02thread:<id>;`
   - single-step 停止当前返回 `T05thread:<id>;`
   - `jThreadExtendedInfo` / `jThreadsInfo` 中也会带上更接近真实原因的 `reason` 字段，例如 `trace` / `breakpoint` / `interrupt`
15. `jThreadExtendedInfo` / `jThreadsInfo` 的 JSON 文本包已修正：
   - 之前文本包错误复用了 binary escape 逻辑
   - JSON 里的 `}` 会被错误编码成 `}]`
   - 当前 `write_packet()` 已改成对普通文本包直接按原字节发送
   - 实测 `jThreadExtendedInfo:1` 与 `jThreadsInfo` 返回的 JSON 已恢复正常
16. 软件断点 key 已从“纯 VA”升级为“地址空间 + VA”：
   - 当前 key 由：
     - translation root（`ttbr0` / `ttbr1`）
     - root table base
     - VA
     组成
   - 断点安装、删除、临时禁用、重挂都会显式使用断点所属地址空间做页表翻译
   - 这避免了 future user-mode / multi-process 场景下，单纯按 VA 查断点导致的空间串扰
17. 按地址空间 key 的回归 smoke 已通过：
   - 两个连续 `Z0` 断点仍可正常命中
   - 第一次 `continue` 命中 `0x4001371c`
   - 第二次 `continue` 自动 step-over 后命中 `0x40013720`
   - `z0` 删除断点后返回正常
18. hypervisor/VMM 的调试能力模型已收口成 `DebugCaps`：
   - `winemu-hypervisor` 现在显式暴露：
     - `async_interrupt`
     - `debug_exception_trap`
     - `sw_breakpoint_candidate`
     - `hw_single_step_candidate`
     - `hw_breakpoint_candidate`
     - `watchpoint_candidate`
   - HVF 当前声明：
     - 支持异步打断
     - 支持 trap debug exception
     - 支持软件断点候选
     - 支持 guest single-step 候选
     - 暂不声明 hwbreak / watchpoint 候选
   - `DebugController` 会在 VMM 创建 `vcpu0` 后记录这组 backend capability，后续协议层统一从 controller 读取
19. gdb-remote 能力声明已改为 capability 驱动，而不是硬编码：
   - `qSupported` 现在会基于 `DebugCaps` 生成 `swbreak+/-`、`hwbreak+/-`
   - `vCont?` 只有在 backend 声明 `hw_single_step_candidate` 时才会暴露 `s` / `S`
   - `qHostInfo` 只有在 backend 声明 watchpoint 候选时才会上报 `watchpoint_exceptions_received:before`
   - 如果 backend 不支持软件断点，则 `Z0/z0` 会按“不支持该包”处理
   - 如果 backend 不支持 single-step，则 `s` 会返回错误而不是假装成功
20. capability 驱动 smoke 已通过：
   - `qSupported:swbreak+;hwbreak+` 返回：
     - `PacketSize=4000;QStartNoAckMode+;vContSupported+;swbreak+;hwbreak-`
   - `qHostInfo` 返回中已不再无条件宣称 watchpoint 语义
   - `vCont?` 返回：
     - `vCont;c;C;s;S`
   - 运行中发送 raw `0x03` 后仍可稳定收到：
     - `T02thread:1;`
21. `Z/z` 断点包的 unsupported 边界已显式收口：
   - 当前 stub 会先把 `Z/z` 解析成：
     - software breakpoint
     - hardware breakpoint
     - write/read/access watchpoint
   - 再根据 `DebugCaps` 明确判断是否支持，而不是靠“前面只匹配 `Z0/z0`，其余落到泛化空回复”这种隐式行为
   - HVF 当前 smoke 结果：
     - `Z0,4001371c,4` -> `OK`
     - `z0,4001371c,4` -> `OK`
     - `Z1/Z2/Z3/Z4` -> 空回复（unsupported）
   - stop-reply 里的 `hwbreak` / `watch` 字段也会再经过 backend capability gating，避免 future backend/协议声明不一致
22. stop-source 线程语义已显式建模：
   - `DebugController` 现在会记录本轮停止的来源 vCPU
   - `primary_paused_vcpu()` 会优先返回 stop-source，而不是“第一个有 snapshot 的 vCPU”
   - `gdb-remote` 的：
     - `?`
     - `qC`
     - continue 后 stop reply
     - single-step 后 stop reply
     都会先把当前线程同步到 stop-source，再生成回复
   - 这避免了“前端之前选中过别的 thread，后续 stop reply / qC 仍报旧 thread”的错误语义
23. `jThreadsInfo` / `jThreadExtendedInfo` 已开始区分触发线程与连带暂停线程：
   - stop-source 线程保留真实 reason，例如：
     - `kernel-ready`
     - `breakpoint`
     - `trace`
     - `interrupt`
   - 非 stop-source 线程会降级为通用 `stopped`
   - JSON 中新增：
     - `triggered: true/false`
24. stop-source 语义双核 smoke 已通过：
   - 在 `kernel_ready` 自动暂停点，先执行 `Hg2`
   - 即使当前 thread selection 被切到 thread 2：
     - `qC` 仍返回 `QC1`
     - `?` / stop reply 仍以 thread 1 为主
   - `jThreadsInfo` 返回中：
     - `tid=1` 为 `reason=kernel-ready, triggered=true`
     - `tid=2` 为 `reason=stopped, triggered=false`
25. legacy resume / `vCont` 恢复包兼容性已补一层：
   - 现在除了：
     - `c`
     - `s`
   - 也支持：
     - `Cxx`
     - `Sxx`
     - `vCont;Cxx`
     - `vCont;Sxx:<tid>`
   - `vCont` 在 all-stop 语义下还允许：
     - `vCont;s:<tid>;c`
     - `vCont;Sxx:<tid>;c`
     这类“单步一个线程，其余继续”请求被收敛成“单步指定线程”
   - legacy `c/s/C/S` 还支持可选 resume address，并会先把 paused snapshot 的 `PC` 改到目标地址，再执行 continue/step
26. resume 包兼容性 smoke 已通过：
   - `S05` -> 成功单步并返回 stop reply
   - `vCont;S05:1;c` -> 成功执行并返回 stop reply
   - `C05` -> 成功恢复运行；随后 raw `0x03` 仍可打断并返回 `T02thread:1;`
27. `QListThreadsInStopReply` 与 `qThreadStopInfo` 边界已补齐：
   - `QListThreadsInStopReply` 现在返回 `OK`，并会让后续 stop reply 带上：
     - `threads:<id,id,...>;`
   - 这让 all-stop 暂停时，前端可以直接从 stop reply 里看到当前已知线程集合
   - `qThreadStopInfo<tid>` 现在不会再对无效线程偷偷回退到 `current_thread`
   - 当前语义：
     - paused 且 `tid` 有效 -> 返回该线程 stop reply
     - 未 paused / `tid` 非法 / 线程不存在 -> 返回 `OK`
28. `QListThreadsInStopReply` / `qThreadStopInfo` smoke 已通过：
   - `QListThreadsInStopReply` -> `OK`
   - `?` -> `T05thread:1;threads:1,2;`
   - `qThreadStopInfo1` -> `T05thread:1;threads:1,2;`
   - `qThreadStopInfo3` -> `OK`
29. 常见探测类包已补一轮 all-stop 兼容返回：
   - `qAttached` -> `1`
   - `QNonStop:0` -> `OK`
   - `QNonStop:1` -> 空回复（明确不支持 non-stop）
   - `vMustReplyEmpty` -> 空回复
   - `qTStatus` / `qTfV` / `qTsV` -> 空回复
   - `vStopped` -> `OK`
   - 这批返回不会改变当前设计目标：stub 仍然是 all-stop，不支持 non-stop
30. 探测类包 smoke 已通过：
   - `qAttached = 1`
   - `QNonStop:0 = OK`
   - `QNonStop:1 = ""`
   - `vMustReplyEmpty = ""`
   - `qTStatus/qTfV/qTsV = ""`
   - `vStopped = OK`
31. 线程额外信息与线程配置包已补一层：
   - `qThreadExtraInfo,<tid>` 现在会返回十六进制编码后的可读字符串，例如：
     - `vcpu0 (kernel-ready, triggered)`
     - `vcpu1 (stopped)`
   - 无效线程会返回 `OK`
   - `QThreadEvents` / `QPassSignals` / `QProgramSignals` 目前按 no-op 处理并返回 `OK`
   - 这些包只补前端兼容性，不改变当前 all-stop 行为
32. `qThreadExtraInfo` / 线程配置包 smoke 已通过：
   - `qThreadExtraInfo,1` -> `vcpu0 (kernel-ready, triggered)`
   - `qThreadExtraInfo,2` -> `vcpu1 (stopped)`
   - `qThreadExtraInfo,3` -> `OK`
   - `QThreadEvents:1` -> `OK`
   - `QPassSignals:05;0b` -> `OK`
   - `QProgramSignals:05;0b` -> `OK`
33. `qXfer:features:read` 已落地：
   - `qSupported` 现在会显式声明 `qXfer:features:read+`
   - 当前支持：
     - `qXfer:features:read:target.xml:<offset>,<len>`
   - 当前不支持的 annex（例如 `aarch64-core.xml`）会返回空回复
   - `target.xml` 会按 gdb-remote 约定返回：
     - 中间分块前缀 `m`
     - 末块 / EOF 前缀 `l`
34. gdb-remote 文本回包的 wire encoding 已修正为统一 binary escape：
   - 之前把 `jThreadsInfo` / `jThreadExtendedInfo` 这类 JSON 文本当作“普通文本包”直发
   - 这会把包内原始 `}` 暴露到线上，触发 LLDB 在 `ExpandRLE`/解包路径崩溃
   - 当前 `write_packet()` 已统一走 gdb-remote binary escape，与 `write_binary_packet()` 保持一致的线协议编码
   - 现在线上 `lldb -> gdb-remote` 已可稳定完成：
     - connect
     - 初始 stop 展示
     - `thread list`
     - `register read`
     - `memory read`
35. debugger core 的 resume/restore 语义已修正为“一次性 restore”：
   - 之前 `pause_here_if_requested()` 在 `DebugState::Running` 分支会在每次进入 `run()` 前都把“上次暂停快照”重新写回 vCPU
   - 这会让 guest 在 continue 之后不断回卷到旧现场，表现为：
     - `hello_win` / `thread_test` 在 debugger 模式下长期跑不完
     - guest 在内核里出现重复 fault / 重复执行同一段路径
   - 当前已新增按 `pause_epoch` 驱动的单次 restore gate：
     - 每个 vCPU 在每次 `resume_all()` / `step_vcpu()` 后只恢复一次暂停快照
     - 后续正常 `run -> vmexit -> run` 循环不再反复重写旧寄存器现场
36. `continue -> exit` 路径已重新 smoke 通过：
   - 原始 gdb-remote socket：
     - `hello_win.exe`
     - `?` 后发送 `c`
     - 现在线上会立即收到 `W00`
   - 真实 LLDB：
     - `lldb -> gdb-remote`
     - `thread list`
     - `process continue`
     - 已验证会返回：
       - `Process 1 exited with status = 0`
37. 追查 `thread_test` 长时间不退出后，定位到的根因不在 debugger，而在 guest kernel shutdown 唤醒：
   - `thread_test` 曾出现：
     - 测试全部跑完并打印 summary
     - 但 VM 不退出
   - 根因是：
     - 最后一个线程/进程可能在次核上退出
     - `process::maybe_request_kernel_shutdown()` 只置位了 shutdown code
     - 真正消费该 code 并执行 `PROCESS_EXIT` 的是 `vCPU0` 的 `idle_wait_or_exit()`
     - 如果此时 `vCPU0` 已经 idle 睡眠且没有被 kick，就会卡住
   - 当前已修正为：
     - 首次置位 kernel shutdown code 时，若当前不是 `vCPU0`，显式 `kick_vcpu(0)`
     - 这样可以保证 `vCPU0` 从 idle 中醒来并消费 shutdown 请求
38. `thread_test` 裸跑与 debugger 路径都已重新闭环：
   - 裸跑：
     - `WINEMU_VCPU_COUNT=2`
     - `147 passed, 0 failed`
     - 进程正常退出，返回码 `0`
   - 原始 gdb-remote：
     - `thread_test.exe`
     - `?` 后发送 `c`
     - 约 `132ms` 收到 `W00`
   - 真实 LLDB：
     - `lldb -> gdb-remote`
     - `process continue`
     - 已验证 `Process 1 exited with status = 0`
39. 原始 gdb-remote socket 的关键协议路径已再扩大一轮 smoke：
   - 双核 `thread_test` 在 `kernel_ready` 自动暂停点上，已顺序验证：
     - `qXfer:features:read:target.xml:0,80`
     - `qXfer:features:read:aarch64-core.xml:0,80`
     - `QListThreadsInStopReply`
     - `qThreadStopInfo1`
     - `qThreadExtraInfo,1`
     - `jThreadsInfo`
     - `jThreadExtendedInfo:1`
     - `s`
     - `c` 后 raw `0x03`
     - 再次 `c`
   - 实际结果为：
     - `target.xml` 正常分块返回
     - 不支持的 annex 返回空包
     - `raw 0x03` 返回 `T02thread:1;threads:1,2;`
     - 最终 `c -> W00`
40. 真实 LLDB 前端也已覆盖到 single-step 路径：
   - `lldb -> gdb-remote`
   - `thread list`
   - `register read pc sp x0 x1`
   - `memory read -f x -c 4 0x4003cc24`
   - `thread step-inst`
   - 已实测：
     - 单步前 `pc = 0x4003cc24`
     - `thread step-inst` 后停在 `0x4003cc28`
     - stop reason 显示为 `instruction step into`
   - 随后重新连接并 `continue`，`thread_test` 仍正常退出，返回 `status = 0`
41. 真实 LLDB 前端的 `Z0/z0` 软件断点路径已补齐：
   - 之前 `breakpoint set --address 0x4003cc28` 会失败，表现为：
     - LLDB 在前面发了 `Hg2`
     - 随后 `Z0,4003cc28,4`
     - stub 返回 `E04`
   - 根因不是 `kind`，而是 stub 把断点地址解析错误地锚定在 `current_thread`
   - 当 `current_thread` 恰好落到一个“能给出 TTBR root、但该 VA 实际不可翻译”的 paused vCPU 上时，会误选无效 address-space anchor
   - 当前已改为：
     - 断点地址按“preferred thread -> stop source -> primary paused -> other paused vCPU”顺序解析
     - 并且候选必须真的能把目标 VA 翻译到 GPA，才会被接受
   - 实测：
     - `lldb breakpoint set --address 0x4003cc28`
     - `process continue`
     - 成功停在 `breakpoint 1.1`
     - 删除断点后继续执行，`thread_test` 仍正常退出
42. 真实 LLDB 前端的内存读写锚点也已与断点语义对齐：
   - 之前原始 `M/X` 包已可工作，但 LLDB 的：
     - `memory write -s 1 0x4003cc24 0xfd 0x7b 0xc1 0xa8`
     - 会失败
   - 抓包后确认 LLDB 走的是标准：
     - `qMemoryRegionInfo:4003cc24`
     - `M4003cc24,4:fd7bc1a8`
   - 根因同样是 `m/M/x/X` 把地址空间错误地绑定到 `current_thread`
   - 当前已修正为与断点共享同一套“可翻译候选解析”逻辑
   - 实测：
     - `memory read -f x -c 4 0x4003cc24`
     - `memory write -s 1 0x4003cc24 0xfd 0x7b 0xc1 0xa8`
     - `memory read -f x -c 4 0x4003cc24`
     - `process continue`
     - 全流程成功，最终 `Process 1 exited with status = 0`
43. 真实 LLDB 前端的寄存器写回路径已补 smoke：
   - 在 `kernel_ready` 自动暂停点上，已实测：
     - `register read x0`
     - `register write x0 0x1`
     - `register read x0`
     - `register write x0 0x0`
     - `register read x0`
   - 结果为：
     - `x0` 可从 `0x0` 写成 `0x1`
     - 也可再写回 `0x0`
   - 这说明 LLDB 前端走 `P`/寄存器写回时，当前 thread 绑定语义与 paused snapshot 更新路径是一致的
44. 真实 LLDB 前端的 `process interrupt` 已在长运行 guest 上完成多轮验证：
   - 选择 `window_test.exe` 作为长运行场景，而不是 `thread_test/full_test`
   - 原因是后两者退出太快，无法稳定覆盖前端中断窗口
   - 实测路径：
     - `gdb-remote`
     - `process continue`
     - 确认 `thread list` 报错 `Process is running`
     - `process interrupt`
     - `thread list`
     - 再次 `process continue`
     - 再确认 `thread list` 报错 `Process is running`
     - 再次 `process interrupt`
   - 抓包确认：
     - LLDB 中断时发送的是 raw `0x03`
     - stub 返回 `T02thread:<id>;threads:1,2;`
     - 随后 LLDB 会拉：
       - `qThreadStopInfo`
       - `jThreadsInfo`
       - `jThreadExtendedInfo`
     - 然后再发 `c`
   - 结果为：
     - 两个 vCPU 都能稳定以 `SIGINT` all-stop 停住
     - `continue` 后 guest 会重新进入 running，而不是被卡死在旧的 interrupt stop 上
   - 这也说明之前终端上“continue 后立刻又看到 stop 输出”的现象，主要是 LLDB 交互输出时序造成的错觉，不是 stub 重复回放旧 pause
45. manual pause 的 stop-source 记录已再收紧一层：
   - 之前 `request_pause_all(ManualPause)` 在发起时没有稳定写入 `stop_vcpu_id`
   - 这会让 `jThreadsInfo` / `jThreadExtendedInfo` 在 interrupt 之后把所有线程都标成 `triggered=true`
   - 当前已改为：
     - 在 pause capture 阶段，首个 ack 当前 `pause_epoch` 的 vCPU 会被记为 `stop_vcpu_id`
   - 原始 gdb smoke 已验证：
     - `c`
     - raw `0x03`
     - `jThreadsInfo`
   - 结果为：
     - 只有一个线程会带 `triggered=true`
     - 其余线程会退回普通 `stopped` 语义
   - 这让 stop metadata 更接近 mesosphere / 常见 debugger 的“一个 stop source + 其他线程陪停”模型
46. stop reply 已补最小但有价值的寄存器/地址字段：
   - 之前 `Txx` stop reply 只带：
     - `swbreak:;` / `hwbreak:;` / `watch:;`
     - `thread:<id>;`
     - 可选 `threads:<...>;`
   - 当前已补：
     - `pc` 寄存器字段：`20:<pc-le-hex>;`
     - watchpoint 场景在可用时会返回带地址的 `watch:<addr>;`
   - 这样前端在 stop reply 层就能直接拿到最关键的停机地址，不必总是额外发 `p20`
47. 原始 gdb-remote socket 已 smoke 新 stop reply 字段：
   - `thread_test.exe`
   - `?`
   - `c` 后 raw `0x03`
   - 实测 stop reply 示例：
     - `T0520:24cc034000000000;thread:1;`
     - `T0220:cc7a004000000000;thread:1;`
   - 说明：
     - 初始 trap stop reply 已带 `pc`
     - interrupt stop reply 也已带 `pc`
48. 真实 LLDB 前端在 stop reply 增强后未回退：
   - `lldb -> gdb-remote`
   - `thread list`
   - `register read pc`
   - `process continue`
   - 实测保持正常：
     - attach 成功
     - `thread list` 正常
     - `register read pc` 正常
     - `process continue` 后 `thread_test` 正常退出 `status = 0`
49. 这轮验证仍然没有把 `cargo test -p winemu-vmm` 作为主回归口径：
   - 原因仍是无关的 `crates/winemu-vmm/src/hostcall/tests.rs` 编译错误会先失败
   - 本轮实际使用的验证口径仍是：
     - `cargo build -p winemu-vmm -p winemu-cli`
     - 原始 gdb socket smoke
     - 真实 LLDB smoke
50. software breakpoint 的“命中后直接 continue”闭环在当前实现上仍成立：
   - 场景是：
     - 在 `0x4003cc28` 插入 `Z0`
     - 首次 `continue` 命中该断点
     - 不删除断点，直接再次 `continue`
   - 原始 gdb socket 已验证：
     - 第二次 `c` 不会在同一条 `brk` 上原地反复停住
     - 会走“临时移除 bp -> 单步 -> 重装 bp -> 继续运行”这条路径
     - 最终 `thread_test` 正常 `W00`
   - 这说明最近对 stop reply / address-space anchor / stop-source 语义的调整，没有把已有的 software-breakpoint step-over 逻辑打坏
51. stop reply 已再补一层 LLDB 扩展字段：
   - 当前在合适场景下会额外带：
     - `reason:<...>;`
     - `thread-pcs:<pc0,pc1,...>;`
   - 目前映射为：
     - manual pause -> `reason:trap;`
     - software / hardware breakpoint -> `reason:breakpoint;`
     - single-step -> `reason:trace;`
     - watchpoint -> `reason:watchpoint;`
   - `thread-pcs` 只在前端先发过 `QListThreadsInStopReply` 时才返回
52. 原始 gdb-remote socket 已 smoke 新增 `reason:` / `thread-pcs:` 字段：
   - 初始 `kernel_ready` 自动暂停点，在 `QListThreadsInStopReply` 之后返回：
     - `T0520:24cc034000000000;thread:1;threads:1,2;thread-pcs:4003cc24,40000040;`
   - 软件断点命中后返回：
     - `T05reason:breakpoint;20:28cc034000000000;thread:1;threads:1,2;thread-pcs:4003cc28,40000040;`
   - raw `0x03` interrupt 返回：
     - `T02reason:trap;20:<pc>;thread:1;threads:1,2;thread-pcs:<pc0>,<pc1>;`
   - 说明 stop reply 现在已经能在一包里提供：
     - stop signal
     - stop reason
     - current thread
     - all-stop 线程集合
     - 每线程 PC
53. 真实 LLDB 前端在 `reason:` / `thread-pcs:` 增强后保持正常：
   - `lldb -> gdb-remote`
   - `breakpoint set --address 0x4003cc28`
   - `process continue`
   - 仍可正常显示 `breakpoint 1.1`
   - 初始 attach、`thread list`、`register read pc`、`process continue` 也都未回退
54. 陪停线程的 `qThreadStopInfo` 语义已从“伪 SIGTRAP”收成 `T00`：
   - 之前非 stop-source 线程会返回：
     - `T05...` / `T02...`
   - 这会把“只是陪停”的线程也伪装成真的 trap/signal 源
   - 当前已改为：
     - 非触发线程统一返回 `T00...`
     - 仍保留：
       - `thread:<id>;`
       - `threads:<...>;`
       - `thread-pcs:<...>;`
   - 原始 gdb smoke 已验证：
     - `qThreadStopInfo2 -> T0020:4000004000000000;thread:2;threads:1,2;thread-pcs:4003cc24,40000040;`
55. 真实 LLDB 前端对 `T00` 陪停线程语义兼容正常：
   - `lldb -> gdb-remote`
   - `thread list`
   - 当前展示为：
     - 触发线程 `thread #1` 仍显示 `stop reason = signal SIGTRAP`
     - 陪停线程 `thread #2` 只显示线程与 PC，不再伪装成同样的 stop reason
   - 这比之前“双线程都像自己触发了 trap”更接近 all-stop 的真实语义
56. 真实 LLDB 前端已补 `register write sp/pc` smoke：
   - 场景：
     - 双核 `thread_test`
     - `kernel_ready` 自动暂停点
   - 已实测：
     - 初始 `pc=0x4003cc24`
     - 初始 `sp=0x403b8da0`
     - `register write sp 0x403b8db0` 后，`register read sp` 返回 `0x403b8db0`
     - `register write pc 0x4003cc28` 后，`register read pc` 返回 `0x4003cc28`
     - 恢复原值后执行 `process continue`
   - 结果：
     - `thread_test` 正常退出 `status = 0`
   - 这说明真实 LLDB 前端走 `P` 包更新 paused snapshot 的路径已经覆盖到 `sp/pc`，不是只对通用寄存器有效
57. 原始 gdb-remote socket 已补 legacy `sADDR` / `Sxx;ADDR` smoke：
   - 场景：
     - 双核 `thread_test`
     - `kernel_ready` 自动暂停点
   - 已实测：
     - 初始 `pc=0x4003cc24`
     - `s` 后停在 `0x4003cc28`
     - `s4003cc28` 后停在 `0x4003cc2c`
     - `S05;4003cc2c` 后停在 `0x4003cc30`
   - 这说明：
     - legacy single-step 包的 parser 正常
     - `set_resume_address()` 的 resume-address 在真实运行中生效
58. 原始 gdb-remote socket 已补 legacy `cADDR` / `Cxx;ADDR` smoke：
   - 验证方法：
     - 在 `pc=0x4003cc24` 与 `pc+8=0x4003cc2c` 同时安装软件断点
     - 发送 `c4003cc28` 或 `C05;4003cc28`
   - 预期：
     - 如果 resume-address 生效，应先从 `0x4003cc28` 开始跑，并命中 `0x4003cc2c`
     - 如果 resume-address 被忽略，则会先命中 `0x4003cc24`
   - 已实测：
     - `c4003cc28 -> stop pc=0x4003cc2c`
     - `C05;4003cc28 -> stop pc=0x4003cc2c`
   - 这说明 legacy continue 的带地址形式也已经真实闭环，不只是 parser 通过
59. 当前 gdb-remote 的 resume-address 覆盖面已经完整补到四类 legacy 包：
   - `sADDR`
   - `Sxx;ADDR`
   - `cADDR`
   - `Cxx;ADDR`
   - 配合前面的 `vCont` / `P` / `m/M/x/X` / `Z0/z0` smoke，当前最小 LLDB 可用面已经比较完整
60. 之前用于 `process interrupt` smoke 的 `window_test`，当前已经不再是稳定载体：
   - 现状是：
     - `continue` 后经常会在很短时间内自然退出
     - 这让 `interrupt` 回归变成偶然命中，而不是稳定覆盖
   - 结论：
     - 不再适合继续作为 debugger interrupt 的基准场景
61. 已新增专门的长运行 guest：
   - 路径：
     - `tests/debugger_interrupt_test`
   - 行为：
     - 启动后持续打印 tick
     - 大约运行 50 秒
     - 最终正常 `PROCESS_EXIT: code=0`
   - 这个 guest 只承担 debugger smoke，不承担功能正确性覆盖
62. 基于 `debugger_interrupt_test`，真实 LLDB 前端的“running -> interrupt -> continue”链路已重新稳定闭环：
   - 已实测文本命令路径：
     - `gdb-remote`
     - `process continue`
     - `thread list`
       - 返回：`Process is running. Use 'process interrupt' to pause execution.`
     - `process interrupt`
     - `thread list`
     - `process continue`
     - 最终 `Process 1 exited with status = 0`
   - 中断后 stop 现场示例：
     - `signal SIGINT`
     - 触发线程可落在：
       - `idle_thread_fn`
       - `schedule_core_locked`
       - `run_local_scheduler_iteration`
     - 这符合 all-stop + 异步中断的预期
63. 真实 LLDB 前端的终端 `Ctrl-C` 中断路径也已再次验证：
   - 在 `process continue` 的 running 状态下发送终端 `0x03`
   - 能稳定得到：
     - `Process 1 stopped`
     - `signal SIGINT`
   - 随后 `thread list` 可正常枚举 all-stop 线程
   - 再次 `process continue` 后 guest 不会卡死，最终正常退出
64. 当前对 LLDB interrupt 的结论可以明确收口为：
   - `process interrupt` 可用
   - 终端 `Ctrl-C` 可用
   - 两条路径都会落到同一套 gdb-remote async interrupt / all-stop 语义上
   - `continue` 之后不会重复回放旧 stop，也不会把 guest 卡在历史 pause 上
65. 新补了一处真实 LLDB 兼容性缺口：
   - 场景：
     - 在 `kernel_ready` 停点上，由 thread 1 安装软件断点
     - 运行后实际由 thread 2 命中该断点
     - 然后在 LLDB 中执行：
       - `breakpoint delete 1`
       - `process continue`
   - 之前的错误行为：
     - LLDB 确实会发送：
       - `z0,<addr>,4`
     - 但 stub 会返回：
       - `E04`
     - 于是目标内存中的 `brk` 无法移除，继续运行会再次在同一地址 trap
66. 这次问题的根因已经定位并修正：
   - 根因不是 LLDB 没发 `z0`
   - 根因是 WinEmu 之前把 software breakpoint key 绑定成：
     - `translation space + VA`
   - 对 kernel 这种“同一代码物理页可经不同 TTBR root 映射”的场景，这个 key 过于严格：
     - 同一 kernel 指令地址，可能先在 vcpu0 的 translation space 上安装
     - 再在 vcpu1 的 translation space 上命中/删除
     - 两边 VA 相同，但 root base 不同，导致查表删不到原 breakpoint
   - 当前已改为补一层 alias 匹配：
     - 优先精确匹配原 `BreakpointKey`
     - 若失败，则退回“同 VA 且同 GPA”的现址别名匹配
   - 这能正确覆盖：
     - kernel 全局映射
     - 以及其他共享物理页、但 translation root 不同的场景
67. 修复后已完成两层回归：
   - 原始 gdb-remote：
     - `Z0 -> c -> Hg2 -> z0 -> c`
     - 结果：
       - `z0 -> OK`
       - `m<addr>,4 -> 5f2003d5`
       - 随后的 `continue` 不再立刻 re-hit 同一 `brk`
   - 真实 LLDB：
     - `breakpoint set --address 0x40028a98`
     - `process continue`
     - 命中 `breakpoint 1.1`
     - `breakpoint delete 1`
     - `process continue`
     - `thread list` 返回 `Process is running`
     - `process interrupt`
     - `thread list`
     - `process continue`
     - 再次 `thread list` 返回 `Process is running`
     - 再次 `process interrupt`
   - 说明：
     - software breakpoint 删除路径已经和 LLDB 的真实线程切换/断点命中行为兼容
     - 删除断点后不会再卡在旧的 `brk`
68. 命中 software breakpoint 之后的 step-over 语义也已补齐：
   - 真实 LLDB：
     - `breakpoint set --address 0x40028a98`
     - `process continue`
     - 命中 `breakpoint 1.1`
     - `thread step-inst`
     - `register read pc`
   - 已实测：
     - step 后停机原因为 `SIGTRAP/trace`
     - `pc` 从 `0x40028a98` 前进到 `0x40028a9c`
   - 随后再执行：
     - `process continue`
   - 会再次命中同一断点：
     - `breakpoint 1.1`
   - 这说明当前实现已经满足：
     - 先临时去掉当前 `brk`
     - 单步执行原指令
     - 再重新装回断点
69. 相同语义已在原始 gdb-remote 两套 step 包上验证：
   - 传统单步包：
     - `Z0 -> c -> Hg2 -> s`
     - 结果：
       - `T05reason:trace;...`
       - `pc = 0x40028a9c`
       - 再 `c` 后重新命中 `0x40028a98`
   - `vCont` 单步包：
     - `Z0 -> c -> vCont;s:2`
     - 结果：
       - `T05reason:trace;...`
       - `pc = 0x40028a9c`
       - 再 `vCont;c` 后重新命中 `0x40028a98`
   - 所以现在 software breakpoint 命中点上的单步语义，已经在：
     - `s`
     - `vCont;s:<thread>`
     - `LLDB thread step-inst`
     三条路径上保持一致
70. 真实 LLDB 前端的寄存器 / 内存读写链路已补 smoke：
   - 停机点：
     - `kernel_ready`
   - 已实测命令/能力：
     - `register write x0`
     - `register read x0`
     - `memory read -f x -s 1 -c 8 <sp>`
     - `memory write -s 1 <sp> ...`
   - 校验方式：
     - 先记录原始 `x0`
     - 写入新值后再读回
     - 把 `sp` 指向的 8 字节栈内容改成固定 pattern
     - 再通过 `SBProcess.ReadMemory()` 读回验证
     - 最后恢复原始字节并再次校验
   - 当前结果：
     - `lldb-memory-register-io: OK`
   - 这说明：
     - gdb-remote 的 `P`
     - `m/M/x/X`
     - 以及 LLDB 前端对应的寄存器 / 内存命令
     已经能在真实前端路径上闭环
71. `scripts/debugger-smoke.py` 的 LLDB 驱动层这轮也补了一处实现细节：
   - LLDB 会先回显命令文本，再打印脚本输出
   - 如果按 marker 文本直接等待，容易误匹配到回显行，而不是实际执行结果
   - `process interrupt` 还带异步语义：
     - prompt 可能先出现
     - `signal SIGINT` 停机通知随后才到
   - 现在脚本已改成：
     - 按“本次命令开始到下一个 prompt”的增量输出取结果
     - 对 `process interrupt` 显式等待 `signal SIGINT`
   - 当前 `full` smoke 已再次通过：
     - `raw-breakpoint-step`
     - `raw-memory-register-io`
     - `raw-multi-breakpoint`
     - `lldb-memory-register-io`
     - `lldb-step-over`
     - `lldb-breakpoint-delete-interrupt`
72. 原始 gdb-remote socket 的寄存器 / 内存读写链路也已补 smoke：
   - 已覆盖：
     - `p0`
     - `P0=<...>`
     - `p1f`
     - `m<sp>,8`
     - `M<sp>,8:<hex>`
     - `x<sp>,8`
     - `X<sp>,8:<binary>`
   - 校验方式：
     - 读取当前线程的 `x0` 与 `sp`
     - 用 `P` 改写 `x0` 再读回
     - 用 `M` 改写 `sp` 指向的 8 字节栈内容
     - 用 `x` 读 binary reply 校验
     - 再用 `X` 写入包含 `#` / `$` / `}` / `*` 等需 escaped 的字节
     - 最后恢复原始栈字节
   - 当前结果：
     - `raw-memory-register-io: OK`
   - 这说明原始 socket 侧的：
     - `p/P`
     - `m/M`
     - `x/X`
     都已经过真实回写验证
73. software breakpoint 的“多断点并存”最小语义也已补 smoke：
   - 为了保证停机顺序可预测，这个 case 当前用单 vCPU 跑
   - 已覆盖路径：
     - 同时安装：
       - `Z0,0x40028a98,4`
       - `Z0,0x40028aa0,4`
     - `continue` 首先命中 `0x40028a98`
     - 再次 `continue` 后命中 `0x40028aa0`
     - 之后分别执行：
       - `z0,0x40028aa0,4`
       - `z0,0x40028a98,4`
     - 再用 `m` 校验两处原指令都已恢复
   - 当前结果：
     - `raw-multi-breakpoint: OK`
   - 这说明当前软件断点实现至少已经满足：
     - 同一 address space 下的多断点共存
     - 断点 1 命中后的自动 step-over，不会把断点 2 的生命周期打坏
74. 原始 gdb-remote socket 的整文件寄存器读写也已补 smoke：
   - 已覆盖：
     - `g`
     - `G<full-register-file>`
   - 校验方式：
     - 读取完整 AArch64 register file
     - 只改写其中 `x0` 对应的前 8 字节，其余寄存器位保持原样
     - 用 `G` 整体写回后，再次用 `g` 比较完整 payload
     - 最后再用原始 payload 完整恢复
   - 当前结果：
     - `raw-register-file-io: OK`
   - 这说明：
     - 当前 stub 的整文件寄存器布局
     - 以及 `G` 写回路径
     已经过真实 round-trip 校验
75. 真实 LLDB 前端的“多断点并存”也已补 smoke：
   - 当前 case 仍使用单 vCPU，确保断点命中顺序稳定
   - 已覆盖路径：
     - `breakpoint set --address 0x40028a98`
     - `breakpoint set --address 0x40028aa0`
     - `process continue` 首先命中 `breakpoint 1.1`
     - `register read pc` 校验 `pc = 0x40028a98`
     - 再次 `process continue` 命中 `breakpoint 2.1`
     - `register read pc` 校验 `pc = 0x40028aa0`
     - 最后 `breakpoint delete 1 2`
   - 当前结果：
     - `lldb-multi-breakpoint: OK`
   - 这说明：
     - LLDB 前端路径下的多断点安装/命中/删除
     - 与 software breakpoint 的自动 step-over
     当前已经能够协同工作

当前还未完成：

1. 目前只支持 AArch64 `Z0/z0`；`Z1/Z2/Z3/Z4`、硬件断点、watchpoint 仍未实现。
2. 当前断点地址空间是按 translation root + root table base 表达的；如果后续需要进程级 UI/管理语义，还需要在更高层再收成明确的 address-space identity。
3. 当前 `continue` 的异步输入只显式处理 raw `0x03`；更完整的 non-stop / async packet 语义还没做。
4. single-step 目前仍只靠 `SIGTRAP` 区分，没有进一步上报更细的 stop field。
5. `qXfer:features:read` 目前只提供内联 `target.xml`；如果后续遇到前端坚持按 annex 继续下钻，再决定是否补 `aarch64-core.xml` 等子特征文件。

建议 smoke 命令：

```text
WINEMU_DISABLE_HOST_UI=1 \
WINEMU_GUEST_DEBUG=1 \
WINEMU_GUEST_DEBUG_ADDR=127.0.0.1:9001 \
WINEMU_GUEST_DEBUG_AUTO_PAUSE=kernel_ready \
WINEMU_VCPU_COUNT=2 \
RUST_LOG=info \
target/debug/winemu run \
  tests/thread_test/target/aarch64-pc-windows-msvc/release/thread_test.exe
```

LLDB smoke 命令：

```text
WINEMU_DISABLE_HOST_UI=1 \
WINEMU_GUEST_DEBUG=1 \
WINEMU_GUEST_DEBUG_PROTOCOL=gdb \
WINEMU_GUEST_DEBUG_ADDR=127.0.0.1:9012 \
WINEMU_GUEST_DEBUG_AUTO_PAUSE=kernel_ready \
WINEMU_VCPU_COUNT=2 \
RUST_LOG=info \
target/debug/winemu run \
  tests/thread_test/target/aarch64-pc-windows-msvc/release/thread_test.exe

lldb winemu-kernel/target/aarch64-unknown-none/release/winemu-kernel
(lldb) gdb-remote 127.0.0.1:9012
(lldb) register read
(lldb) memory read 0x40000000 0x40000020
(lldb) continue
```

interrupt smoke 命令：

```text
WINEMU_DISABLE_HOST_UI=1 \
WINEMU_GUEST_DEBUG=1 \
WINEMU_GUEST_DEBUG_PROTOCOL=gdb \
WINEMU_GUEST_DEBUG_ADDR=127.0.0.1:9020 \
WINEMU_GUEST_DEBUG_AUTO_PAUSE=kernel_ready \
WINEMU_VCPU_COUNT=2 \
RUST_LOG=info \
target/debug/winemu run \
  tests/debugger_interrupt_test/target/aarch64-pc-windows-msvc/release/debugger_interrupt_test.exe

lldb winemu-kernel/target/aarch64-unknown-none/release/winemu-kernel
(lldb) gdb-remote 127.0.0.1:9020
(lldb) process continue
(lldb) thread list
(lldb) process interrupt
(lldb) thread list
(lldb) process continue
```

自动 smoke 脚本：

```text
python3 scripts/debugger-smoke.py full --port-base 9040
```

说明：

1. 这个脚本默认使用：
   - `tests/debugger_interrupt_test/target/aarch64-pc-windows-msvc/release/debugger_interrupt_test.exe`
2. 当前覆盖八条路径：
   - `raw-breakpoint-step`
   - `raw-register-file-io`
   - `raw-memory-register-io`
   - `raw-multi-breakpoint`
   - `lldb-memory-register-io`
   - `lldb-step-over`
   - `lldb-multi-breakpoint`
   - `lldb-breakpoint-delete-interrupt`
3. 脚本不负责 build / codesign：
   - 运行前仍需先完成 host build 与签名
   - 以及 guest smoke binary 的编译

## 14. 风险与关键判断

### 14.1 最大技术风险

不是“怎么写 gdb-remote”，而是：

1. HVF 是否允许稳定可控的单步 / 硬件断点。
2. `BRK` 作为 host-visible stop event 的基础能力已经验证，但要做成通用软件断点，还需要补 `Z0/z0` 与断点生命周期管理。
3. run cancel 在多 vCPU 下是否能稳定区分“调试暂停”和“真实异常”。

### 14.2 当前最值得做的事情

先做下面这条闭环：

1. 手动 pause
2. all-stop
3. 抓寄存器
4. 读 guest 内存
5. 做符号化
6. continue

只要这条链路稳定，WinEmu 就已经有真正意义上的 guest kernel 动态调试基础设施了。

### 14.3 不建议的路线

不建议一上来就：

1. 直接写完整 gdb-remote
2. 直接上软件断点
3. 直接假定 HVF 的 debug 寄存器可用

这三件事都容易把工程带偏。

## 15. 最终建议

建议采用下面的落地顺序：

1. 先做 VMM 内部的 all-stop 调试 core。
2. 接上手动 pause / continue。
3. 做寄存器快照、GPA/VA 访问、符号化。
4. 给 guest kernel 加 cooperative debug trap。
5. 等 core 稳定后，再接最小 gdb-remote。
6. 最后单独验证 HVF 断点 / 单步能力，决定是否做真正的动态断点。

这条路径最贴合当前 WinEmu 的代码现状，也最不容易浪费时间在不确定的 HVF 细节上。
