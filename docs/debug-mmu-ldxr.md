# NtCreateThreadEx 调试进展报告

## 1. 整体目标

实现并测试 `NtCreateThreadEx`，使多线程测试通过。

---

## 2. 已完成的工作

### 2.1 NtCreateThreadEx 实现（`crates/winemu-vmm/src/syscall.rs`）

- 读取 11 个参数（x0–x7 + 3 个栈参数）
- 分配用户栈（via VaSpace）
- 分配 TEB，初始化 EXCEPTION\_LIST / STACK\_BASE / STACK\_LIMIT / SELF / PEB / CLIENT\_ID
- 创建 `ThreadContext`（pc=entry, sp=stack\_top, x0=arg, x18=teb, pstate=0x0 即 EL0t）
- 注册 `SyncObject::Thread` 以支持 WaitForSingleObject
- 修复了 `NtTerminateThread`：仅终止当前线程，不退出整个进程

### 2.2 线程测试程序（`tests/thread_test/src/main.rs`）

三个测试用例：

| 测试 | 内容 | 状态 |
|------|------|------|
| `test_basic_thread_create` | 创建一个线程传递参数 0x42，主线程等待并验证 | **PASS** |
| `test_two_threads` | 创建 thread\_a / thread\_b 各自 AtomicU32::fetch\_add 10 次 | **FAIL** |
| `test_event_wake` | 创建线程等待 Event，主线程 SetEvent 唤醒 | 未到达（因上一个失败） |

### 2.3 根本原因定位

**`test_two_threads` 失败的根本原因：**

`AtomicU32::fetch_add` 在 ARM64 上编译为 `ldxr`/`stxr`（独占加载/存储）指令。
**在 Apple Silicon + HVF 环境下，MMU 未启用时，`ldxr` 会产生 Data Abort（EC=0x24）。**

这是 Apple Silicon 特有行为：MMU 关闭时，独占监控器（exclusive monitor）不可用。
（`winemu-kernel/src/alloc.rs` 中已有注释："LDXR/STXR 在 MMU 关闭时 fault"）

`test_basic_thread_create` 之所以通过，是因为 `AtomicU32::store` 编译为普通 `str`，不需要独占监控器。

---

## 3. 当前问题：MMU 初始化崩溃

### 3.1 修复方案

在 `winemu-kernel/src/mm/mod.rs` 的 `init()` 中调用 `setup_kernel_mapping()` + `enable_mmu()`，建立恒等映射并启用 MMU。

**页表设计：**
- TCR\_EL1：T0SZ=25（39-bit VA），TG0=4KB，EPD1=1
- TTBR0\_EL1 → L1\_TABLE（512个1GB条目）
- L1\_TABLE\[1\] = 块描述符，覆盖 `0x40000000–0x7FFFFFFF`（内核+用户空间）
- AP=0b01（EL0+EL1 读写），AF=1，SH=内部共享，AttrIdx=0（MAIR attr0=0xFF normal WB）

### 3.2 已知 Bug（当前阻塞点）

调试日志显示 MMU 初始化在 `msr sctlr_el1` 之后挂住：

```
[guest] mmu: isb done, enabling...
```

之后没有任何输出——说明 `msr sctlr_el1, {}` 写入后内核崩溃（翻译错误或页表走查失败）。

**已确认正常的步骤：**
- `tlbi vmalle1` ✓
- `msr mair_el1` ✓
- `msr tcr_el1` ✓
- `msr ttbr0_el1` ✓
- `isb` ✓

**崩溃点：`msr sctlr_el1` 写入 M=1（启用 MMU）后，`isb` 触发第一次页表走查，失败。**

### 3.3 可能原因分析

#### 假说 A：SCTLR 值不正确（最可能）

当前值：`0x00C50835`（在初始值 `0x00C50838` 基础上设 M=1）

原始值 `0x00C50838` 的问题位：
- bit 3 (SA1) = 1：EL1 栈指针对齐检查。若 SP 未 16 字节对齐，会立即触发 Alignment Fault。

**建议：直接从当前 SCTLR 读取后只设 M=1**，而不是用硬编码值：
```rust
let mut sctlr: u64;
asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nostack));
sctlr |= 1; // 只设 M bit
asm!("msr sctlr_el1, {}", in(reg) sctlr, options(nostack));
```

#### 假说 B：页表描述符位错误

当前描述符：`0x40000000 | (1<<10) | (0b11<<8) | (0b01<<6) | 0b01 = 0x40000741`

Level-1 块描述符验证：
- bits\[1:0\] = 0b01 ✓（块描述符）
- bits\[4:2\] = 0b000 → AttrIdx=0 → MAIR attr0=0xFF ✓
- bits\[7:6\] = 0b01 → AP=RW EL0+EL1 ✓
- bits\[9:8\] = 0b11 → SH=内部共享 ✓
- bit\[10\] = 1 → AF=1 ✓
- bits\[47:30\] = 0x40000000 >> 30 = 1 ✓

描述符本身看起来正确，但需要确认 L1\_TABLE 地址是否 4KB 对齐。

#### 假说 C：TTBR0 指向错误位置

`static mut L1_TABLE: PageTable = PageTable([0u64; 512])` — Rust 零初始化的 static 进入 BSS。
`_start` 清零 BSS 后，`setup_kernel_mapping()` 写 L1\_TABLE\[1\]。

但若 Rust 编译器将 `L1_TABLE` 放入 `.data` 而非 `.bss`（理论上不应该，但值得确认），
`_start` 的 BSS 清零可能会将它清零，然后 `setup_kernel_mapping` 再写入——顺序上是对的。

需要检查：`&L1_TABLE` 的实际值是否 >= 0x40000000（在 HVF 映射范围内）。

#### 假说 D：HVF 不支持 Guest 启用 Stage-1 MMU（不太可能）

HVF 使用 Stage-2 翻译（IPA→PA）。Guest 的 Stage-1 MMU 应该可以独立工作。
Ryujinx / Wine 等模拟器都在 HVF Guest 中成功启用了 Stage-1 MMU。

---

## 4. 下一步调试方法

### 方法 1：读取当前 SCTLR 后仅设 M=1（优先尝试）

修改 `enable_mmu()` 最后部分：

```rust
// 不用硬编码，直接读当前值然后只设 M bit
let mut sctlr: u64;
asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nostack));
sctlr |= 1;
asm!("msr sctlr_el1, {}", in(reg) sctlr, options(nostack));
asm!("isb", options(nostack));
```

### 方法 2：打印 L1\_TABLE 的物理地址

在 `setup_kernel_mapping()` 中通过 debug\_u64 打印 `&L1_TABLE` 的值，
确认它在 `0x40000000–0x7FFFFFFF` 范围内且 4KB 对齐。

```rust
let addr = core::ptr::addr_of!(L1_TABLE) as u64;
crate::hypercall::debug_u64(addr); // 应为 0x400xxxxx，低12位应为0
```

### 方法 3：禁用 D-cache，仅启用 MMU+I-cache

排除 D-cache 引起的问题：

```rust
// 不启用 C（D-cache），只启用 M（MMU）+ I（I-cache）
let sctlr: u64 = sctlr_current | 1 | (1 << 12); // M=1, I=1, C=0
```

### 方法 4：在 VMM 侧捕获 MMU 启用后的第一个 VM exit

在 `vcpu.rs` Phase 1 的 `match exit` 里，对所有 Unknown exit 类型打印 syndrome、PC、FAR，
找到 MMU 启用后第一个异常的详细信息。

### 方法 5：从 HVF 侧预设 MMU（备选方案）

如果 Guest 内部启用 MMU 过于复杂，可以改为：
在 VMM（`crates/winemu-hypervisor/src/hvf/vcpu.rs` 的 `init_el1()`）中通过
`set_sys_reg` 直接设置好 TTBR0/MAIR/TCR/SCTLR，让 Guest 一开始就运行在 MMU 开启的状态。

---

## 5. 文件清单

| 文件 | 状态 | 说明 |
|------|------|------|
| `crates/winemu-vmm/src/sched/mod.rs` | 已实现 | N:M 调度器，数据结构支持多 vCPU，当前 run() 只启动 1 个 vCPU |
| `tests/thread_test/src/main.rs` | 已修改 | 线程测试程序 |
| `winemu-kernel/src/mm/mod.rs` | 已修改，有 bug | MMU 初始化，enable_mmu() 崩溃 |
| `winemu-kernel/src/main.rs` | 已修改（临时） | 加了调试 debug_print |

---

## 6. 已排除的假说

- HVF 内存未映射：HVF 映射 `[0x40000000, 0x60000000)`，内核和用户地址都在范围内 ✓
- ADRP 计算错误：已手动解码验证 ADRP 计算结果正确（0x40020000）✓
- thread\_d 的 AtomicU32 访问失败：thread\_d 用 store，不用 ldxr，所以通过 ✓
- ldxr 地址未对齐：0x4002001c 是 4 字节对齐 ✓
