# WinEmu 技术架构文档

## 1. 项目概述

WinEmu 是一个基于 Hypervisor 技术重新实现的 Windows 兼容层，目标是在 macOS (Apple Silicon / Intel) 和 Linux (ARM64 / x86_64) 上运行 Windows PE 程序。

### 核心动机

| 问题 | 现有方案 | WinEmu 方案 |
|------|---------|------------|
| macOS 16KB 页问题 | 依赖 Rosetta 2 运行 x86_64 Wine | Guest VM 内部使用独立页表，天然支持 4KB 页 |
| 多进程架构开销 | Wine 依赖 wineserver 进程间通信 | 单进程 VMM，所有 Windows 对象在同一进程内管理 |
| inline syscall 不可拦截 | 需要 seccomp/signal 等 hack | VM 边界天然拦截所有 guest 指令 |
| iOS 不支持多进程 | 无法移植 | 单进程架构 + DBT 可移植到 iOS |
| 安全隔离 | Wine 进程与 host 共享地址空间 | Guest 用户态完全隔离在 VM 内 |

---

## 2. 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                        Guest VM                              │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Windows App │  │  Windows App │  │  Windows App ... │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         │  SVC #0          │                   │             │
│  ┌──────▼─────────────────▼───────────────────▼──────────┐  │
│  │           WinEmu Guest Kernel (EL1, Rust)              │  │
│  │                                                        │  │
│  │  ┌─────────────────┐   ┌──────────────────────────┐   │  │
│  │  │  NT Syscall 层   │   │  线程调度器 (N:M)          │   │  │
│  │  │  SVC 向量捕获    │   │  KThread / 就绪队列        │   │  │
│  │  │  syscall 分发    │   │  多 vCPU 支持              │   │  │
│  │  └────────┬────────┘   └──────────────────────────┘   │  │
│  │           │                                            │  │
│  │  ┌────────▼────────────────────────────────────────┐  │  │
│  │  │  NT 对象管理（Guest 内直接处理，无需 HVC）         │  │  │
│  │  │  Event / Mutex / Semaphore / CriticalSection     │  │  │
│  │  │  VirtualMemory / VaSpace / Section               │  │  │
│  │  │  PE 加载器（PE32+、重定位、IAT 填充）              │  │  │
│  │  │  TEB / PEB 初始化                                │  │  │
│  │  │  MMU（恒等映射，4KB 页，normal WB memory）        │  │  │
│  │  │  虚拟内存管理（VaSpace、页面映射 / 保护 / 提交）   │  │  │
│  │  │  注册表（hive 解析、键值查询，通过 HOST_READ 加载）│  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │                                                        │  │
│  │  需要 Host 资源时 → HVC #0                             │  │
│  └──────────────────────────┬─────────────────────────┘   │
│                             │ HVC #0 (Hypercall)           │
└─────────────────────────────┼──────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                    WinEmu Host VMM (Rust)                    │
│                                                              │
│  仅处理需要 Host 原生资源的操作：                              │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Hypercall 分发 (HypercallManager)                    │   │
│  │  - 物理内存分配 / 映射（GPA 管理）                     │   │
│  │  - 原始文件 I/O（HOST_OPEN/READ/WRITE/CLOSE/MMAP）    │   │
│  │  - 进程生命周期（KERNEL_READY / PROCESS_EXIT）         │   │
│  │  - 调试输出（DEBUG_PRINT）                            │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────┐  ┌─────────────────────────────┐  │
│  │  Hypervisor 抽象层    │  │  vCPU 调度循环               │  │
│  │  HvfBackend (macOS)  │  │  Phase 1: 内核启动           │  │
│  │  KvmBackend (Linux)  │  │  Phase 2: 用户线程运行        │  │
│  └──────────────────────┘  └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**设计原则**：Guest Kernel 是一个完整的操作系统内核，尽可能在 Guest 内部处理所有 NT 语义。
HVC 仅用于必须借助 Host 原生资源的操作（文件系统、物理内存、DLL 文件内容等）。
这与 Wine 的架构截然不同——Wine 的每个 syscall 都需要跨进程通信，WinEmu 的大多数 syscall 在 Guest 内直接完成。

---

## 3. 核心组件详解

### 3.1 Hypervisor 抽象层 (HAL)

统一封装 HVF 和 KVM 的差异，对上层提供一致接口：

```rust
pub trait Hypervisor: Send + Sync {
    fn create_vm(&self) -> Result<Box<dyn VirtualMachine>>;
}

pub trait VirtualMachine: Send + Sync {
    fn map_memory(&self, gpa: u64, hva: *mut u8, size: usize, prot: MemProt) -> Result<()>;
    fn unmap_memory(&self, gpa: u64, size: usize) -> Result<()>;
    fn create_vcpu(&self, id: u32) -> Result<Box<dyn VCpu>>;
}

pub trait VCpu: Send {
    fn run(&mut self) -> Result<VmExit>;
    fn get_regs(&self) -> Result<Regs>;
    fn set_regs(&mut self, regs: &Regs) -> Result<()>;
    fn get_special_regs(&self) -> Result<SpecialRegs>;
    fn set_special_regs(&mut self, sregs: &SpecialRegs) -> Result<()>;
}

pub enum VmExit {
    Hypercall { nr: u64, args: [u64; 6] },
    MmioRead  { addr: u64, size: u8 },
    MmioWrite { addr: u64, data: u64, size: u8 },
    IoRead    { port: u16, size: u8 },
    IoWrite   { port: u16, data: u32, size: u8 },
    Halt,
    Shutdown,
}
```

**平台实现：**
- `platform/hvf/` — macOS Hypervisor.framework 封装
- `platform/kvm/` — Linux KVM ioctl 封装

### 3.2 Guest Kernel (WinEmu Kernel)

运行在 VM EL1，是一个完整的操作系统内核，负责处理所有 NT 语义。**绝大多数 NT syscall 在 Guest 内部直接完成，不产生 VM exit。**

**NT Syscall 分发：**
- ARM64 SVC 向量捕获用户态 syscall
- `__winemu_syscall_dispatcher` 解析 syscall 号和表号
- 对于需要 Host 资源的操作（文件 I/O、物理内存分配等），通过 HVC 陷入 VMM
- 对于纯 Guest 内操作（同步原语、虚拟内存、线程管理等），直接在 EL1 处理

**线程调度器（N:M）：**
- `KThread` 结构体：状态机（Free/Ready/Running/Waiting/Terminated）、NT 优先级（0–31）、EL0 寄存器上下文
- 全局就绪队列（自旋锁保护），支持多 vCPU 并发调度
- 借鉴 yuzu `KAbstractSchedulerLock` 的延迟更新模式
- vCPU 空闲时执行 WFI → VM exit → VMM park 宿主线程

**NT 对象管理（Guest 内直接处理）：**
- 同步原语：Event、Mutex、Semaphore、CriticalSection — 纯 Guest 原子操作，零 HVC 开销
- 虚拟内存：`NtAllocateVirtualMemory` / `NtFreeVirtualMemory` / `NtProtectVirtualMemory` — Guest VaSpace 直接处理
- Section 对象：`NtCreateSection` / `NtMapViewOfSection`
- 文件 I/O：`NtCreateFile` / `NtReadFile` / `NtWriteFile` 等 — Guest Kernel 实现 NT 语义，底层通过 HOST_OPEN/READ/WRITE hypercall 访问宿主机文件
- 注册表：`NtOpenKey` / `NtQueryValueKey` 等 — Guest Kernel 通过文件 hypercall 加载 `.reg` 文件，在 Guest 内解析管理，写回时再通过 hypercall 持久化

**PE 加载器：**
- 解析 PE32+ 格式（`IMAGE_NT_HEADERS64`）
- 处理重定位（`.reloc` 节）、导入表（IAT 填充）
- 通过 HOST_OPEN/READ hypercall 从宿主机读取 EXE/DLL 文件内容，在 Guest 内完成映射和重定位

**内存管理：**
- Bump allocator（内核堆，`__heap_start` 之后）
- VaSpace：Guest 用户地址空间分配器
- MMU：ARM64 恒等映射（L1 块描述符，4KB 页，normal WB memory）

**TEB / PEB：**
- 初始化 `TEB`（EXCEPTION_LIST、STACK_BASE/LIMIT、SELF、PEB、CLIENT_ID）
- `x18` 寄存器始终指向当前线程 TEB（ARM64 Windows ABI）

### 3.3 NT Syscall 接口

Windows 应用通过标准 NT syscall 调用 Guest Kernel，使用**真实 Windows 系统调用号**（参考 [SyscallTables](https://github.com/hfiref0x/SyscallTables)）。

**调用约定（ARM64）：**
```
SVC #0
x8  = syscall 编号（低12位）+ 表号（位12-13）
x0-x7 = 参数
返回值: x0 = NTSTATUS
```

**分发流程：**
```
用户态 SVC #0
    │
    ▼
Guest Kernel EL1 SVC 向量
    │  __winemu_syscall_dispatcher
    ▼
┌─────────────────────────────────────────────────────┐
│  Guest 内直接处理（零 HVC 开销）                      │
│  NtWaitForSingleObject / NtSetEvent / NtResetEvent   │
│  NtAllocateVirtualMemory / NtFreeVirtualMemory       │
│  NtCreateThread / NtTerminateThread                  │
│  NtCreateMutant / NtReleaseMutant                    │
│  NtCreateSemaphore / NtReleaseSemaphore              │
│  NtCreateFile / NtReadFile / NtWriteFile             │  ← Guest 实现 NT 语义
│  NtOpenKey / NtQueryValueKey / NtSetValueKey         │  ← Guest 管理注册表
│  NtCreateSection / NtMapViewOfSection                │
│  ...（所有 NT 语义在 Guest 内实现）                   │
└──────────────────────────┬──────────────────────────┘
                           │ 需要访问宿主机资源时
                           ▼
              HVC #0 → VMM 原始资源 hypercall
┌─────────────────────────────────────────────────────┐
│  VMM 仅提供原始资源访问                               │
│  HOST_OPEN / HOST_READ / HOST_WRITE / HOST_CLOSE     │  ← 原始文件 I/O
│  HOST_MMAP / HOST_MUNMAP                             │  ← 内存映射
│  物理内存分配 / GPA 映射                              │  ← 物理内存
└─────────────────────────────────────────────────────┘
```

由于调用号随 Windows 版本变化，采用**配置文件动态加载**方案：VMM 启动时指定目标 Windows 版本的调用号表（TOML 格式），无需重新编译即可支持不同版本。

```
winemu run --syscall-table config/syscall-tables/win11-arm64.toml hello.exe
```

### 3.4 Hypercall 接口

Hypercall 仅用于 **Guest Kernel 需要 Host 原生资源**的场景。

**调用约定（ARM64）：**
```
HVC #0
x0 = hypercall 编号
x1-x6 = 参数（或指向 guest 内共享内存的指针）
返回值: x0 = 结果
```

**Hypercall 分类：**

| 类别 | 编号范围 | 说明 |
|------|---------|------|
| 系统 | 0x0000–0x000F | KERNEL_READY、DEBUG_PRINT、PROCESS_EXIT |
| 进程/线程生命周期 | 0x0010–0x001F | THREAD_CREATE（初始线程）、THREAD_EXIT |
| 宿主机文件原语 | 0x0500–0x05FF | HOST_OPEN、HOST_READ、HOST_WRITE、HOST_CLOSE、HOST_STAT |
| 内存映射原语 | 0x0800–0x08FF | HOST_MMAP、HOST_MUNMAP |
| NT Syscall 转发 | 0x0700 | NT_SYSCALL（过渡期：部分 syscall 仍由 VMM 处理） |

> **注意**：VMM 不实现任何 NT 语义。`NtCreateFile` 等 NT syscall 由 Guest Kernel 实现，
> Guest Kernel 在需要时调用 `HOST_OPEN` 等原始 hypercall 访问宿主机文件系统。
> 注册表、DLL 加载、PE 解析全部在 Guest Kernel 内完成。

### 3.4 Wine DLL 复用策略

**直接复用（无需修改）：**
纯 PE DLL，无 Unix lib，直接在 guest 内运行：
- `kernel32.dll`, `kernelbase.dll`
- `user32.dll`, `gdi32.dll` (逻辑层)
- `advapi32.dll`, `msvcrt.dll`
- `comctl32.dll`, `comdlg32.dll`, `shell32.dll`
- `ole32.dll`, `oleaut32.dll`, `rpcrt4.dll`
- `ws2_32.dll`, `winmm.dll`, `shlwapi.dll`

**改造复用（替换 Unix lib）：**
保留 PE 侧代码，将 Unix lib 替换为 hypercall shim：
- `ntdll.dll` — 最关键，Unix lib 改为 hypercall 分发
- `win32u.dll` — 图形 syscall，改为图形 hypercall
- `winevulkan.dll` — 保留 PE 层，Unix lib 替换为 Vulkan hypercall shim

**重新实现：**
- `ntdll` Unix lib → WinEmu hypercall shim (Rust)
- `win32u` Unix lib → 窗口/GDI hypercall shim
- 驱动层 (`winex11.drv`, `winemac.drv`) → 不再需要，由 win32u hypercall shim 直接对接平台窗口系统

### 3.5 图形架构

完全沿用 Wine 现有的 DLL 分层，只替换最底层的 Unix lib 为 hypercall shim，无需实现 virtio-gpu 等复杂设备模拟：

```
Guest:  D3D App
           │
       d3d11.dll / d3d9.dll (PE, DXVK 直接复用)
           │ Vulkan API
       winevulkan.dll (PE, Wine 直接复用)
           │
       unix call (hypercall shim，替换 winevulkan Unix lib)
           │ hypercall
           ▼
Host:  vulkan hypercall handler
           │
       libvulkan.so / MoltenVK
           │
       ┌───┴───┐
       │ macOS │  Metal (via MoltenVK)
       │ Linux │  Vulkan 驱动
       └───────┘
```

**关键点：**
- DXVK (D3D→Vulkan) 和 winevulkan (Vulkan PE 层) 完全不需要修改，直接在 Guest 内运行
- 只需将 `winevulkan` 的 Unix lib 替换为 hypercall shim，Host 侧调用真实 `libvulkan`
- 与 Wine 现有 unix call 机制完全一致，改造成本极低
- 延迟比 virtio-gpu 更低（无协议转换开销）

**win32u / GDI 路径（2D 图形）：**
```
Guest:  GDI App → win32u.dll (PE) → unix call (hypercall shim)
Host:   → 平台窗口系统 (macOS: CoreGraphics, Linux: Wayland/X11)
```

---

## 4. 跨架构支持 (DBT)

### 阶段一：同架构运行
- ARM64 macOS 运行 ARM64 Windows 程序
- x86_64 Linux 运行 x86_64 Windows 程序
- Guest Kernel 直接执行 native 指令，无需转译

### 阶段二：跨架构运行
在 Guest VM 内集成 FEX 或 BOX64：

```
ARM64 Host
    │
    ▼
WinEmu VMM (ARM64 native)
    │
    ▼
Guest VM (ARM64 EL0/EL1)
    │
    ├── ARM64 Windows App → 直接执行
    │
    └── x86_64 Windows App
            │
        FEX-Emu (guest 内运行)
            │ 转译为 ARM64 指令
            ▼
        ARM64 指令流 → 直接执行
```

FEX 在 guest 内作为普通 Linux 进程运行，其 syscall 被 Guest Kernel 拦截并转发。

### iOS 移植路径
- 单进程架构天然适配 iOS JIT 限制
- 将 HVF 后端替换为软件模拟 (无 hypervisor 权限时降级)
- DBT 层使用 AOT 编译绕过 iOS JIT 限制 (参考 UTM/QEMU iOS 方案)

---

## 5. 项目结构

```
WinEmu/
├── Cargo.toml                  # workspace（不含 winemu-kernel，独立编译）
├── crates/
│   ├── winemu-core/            # 核心类型、错误、公共接口（GPA/GVA、MemProt 等）
│   ├── winemu-hypervisor/      # Hypervisor 抽象层
│   │   └── src/
│   │       ├── hvf/            # macOS HVF 后端（已实现）
│   │       └── kvm/            # Linux KVM 后端（占位，未实现）
│   ├── winemu-shared/          # Guest/Host 共享常量（hypercall 编号、TEB/PEB 偏移）
│   ├── winemu-vmm/             # Host VMM 主体（已实现）
│   │   └── src/
│   │       ├── hypercall/      # Hypercall 分发（KERNEL_READY、DEBUG_PRINT、DLL 加载等）
│   │       ├── syscall.rs      # NT Syscall 分发器（50+ syscall 已实现）
│   │       ├── sched/          # VMM 侧辅助调度（vCPU 线程 park/unpark，等待超时）
│   │       ├── memory.rs       # GuestMemory（HVF 映射 [0x40000000, 0x60000000)）
│   │       ├── vaspace.rs      # VA 空间分配（用户地址）
│   │       ├── vcpu.rs         # vCPU 调度循环（Phase 1 内核启动 / Phase 2 用户线程）
│   │       ├── file_io.rs      # 虚拟文件系统
│   │       ├── section.rs      # Section 对象
│   │       ├── dll.rs          # DLL 加载器
│   │       └── host_file.rs    # 宿主机文件 I/O
│   ├── winereg/                # Windows 注册表解析器
│   └── winemu-cli/             # 命令行入口（读取 winemu-kernel.bin + syscall TOML）
├── winemu-kernel/              # Guest Kernel（aarch64-unknown-none，独立 workspace）
│   ├── src/
│   │   ├── main.rs             # _start 汇编 + kernel_main（MMU 初始化、PE 加载、KERNEL_READY）
│   │   ├── mm/mod.rs           # MMU 初始化（页表、SCTLR/TCR/MAIR/TTBR0 — 进行中）
│   │   ├── mm/vaspace.rs       # Guest 内虚拟地址分配
│   │   ├── mm/phys.rs          # 物理内存分配（hypercall）
│   │   ├── alloc.rs            # Bump allocator（内核堆）
│   │   ├── ldr.rs              # PE 加载器（PE32+、重定位、IAT 填充）
│   │   ├── teb.rs              # TEB/PEB 初始化
│   │   ├── sched/mod.rs        # Guest 内核调度器（KThread、就绪队列、多 vCPU）
│   │   ├── sched/sync.rs       # Guest 内同步原语（Event、Mutex、Semaphore）
│   │   ├── sched/dispatch.rs   # 调度分发
│   │   ├── vectors.rs          # ARM64 异常向量（SVC/Data Abort/Instruction Abort）
│   │   ├── hypercall/mod.rs    # Hypercall 客户端（hvc #0 封装）
│   │   └── syscall.rs          # SVC 分发器（__winemu_syscall_dispatcher，转发到 VMM）
│   ├── link.ld                 # 链接脚本（入口 0x40000000，栈/SVC栈/堆布局）
│   └── rust-toolchain.toml     # stable + aarch64-unknown-none
├── tests/
│   ├── full_test/              # 综合测试（24 个 syscall，全部通过）
│   └── thread_test/            # 多线程测试（NtCreateThreadEx，调试中）
├── guest/                      # (占位) Wine PE DLL
├── config/
│   └── syscall-tables/
│       └── win11-arm64.toml    # ARM64 Windows 11 syscall 编号表
├── winemu-kernel.bin           # 编译产物（rust-objcopy 生成的裸二进制）
└── docs/
    ├── architecture.md         # 本文档
    ├── architecture-split.md   # Guest/Host 职责划分设计
    ├── mmu-memory-design.md    # MMU 与内存管理技术设计
    ├── threading-scheduler-design.md  # 线程调度器设计
    └── debug-mmu-ldxr.md       # 当前调试进展（MMU 启用 + ldxr 问题）
```

---

## 6. 关键技术决策

### 6.1 为什么选 Rust

- 内存安全：VMM 是安全关键代码，Rust 消除 UAF/越界等漏洞
- 跨平台：同一套代码编译 macOS/Linux，条件编译处理平台差异
- 性能：零成本抽象，hypercall 热路径无 GC 停顿
- 生态：`kvm-ioctls`、`vmm-sys-util` 等成熟 crate 可复用

### 6.2 Guest Kernel 的形态

**方案 A：Unikernel 形态（推荐）**
- Guest Kernel 是一个 bare-metal Rust 程序，直接运行在 VM Ring 0 (x86) / EL1 (ARM64)
- 不实现 Linux ABI，只实现 Windows NT 接口
- 优点：最小化，性能最优，无 Linux 内核依赖
- 缺点：需要自己实现页表管理、中断处理、调度器

**方案 B：基于 Linux 微内核**
- Guest 运行一个最小化 Linux 内核
- 优点：复用 Linux 内存管理、调度器
- 缺点：引入 Linux 依赖，架构更复杂，16KB 页问题在 guest Linux 内仍存在

**推荐方案 A**。Quark 项目的参考价值在于其 Host VMM 侧的 Rust 实现模式（KVM/HVF 封装、hypercall 分发、共享内存通信），Guest 侧（QKernel）是 Linux 语义，与 WinEmu 无关。

### 6.3 vCPU 数量与线程模型

**vCPU 硬件上限：**

| 平台 | 上限 | 超出时错误 |
|------|------|-----------|
| HVF ARM64 (Apple Silicon) | ~16-24（经验值，与物理核拓扑绑定） | `HV_NO_RESOURCES` (0xfae94005) |
| HVF x86 (Intel Mac) | ~64（经验值） | `HV_NO_RESOURCES` |
| KVM x86_64 | 710（内核硬限，per-VM） | `EINVAL` |
| KVM ARM64 | 512（内核硬限，per-VM） | `EINVAL` |

HVF ARM64 的上限（16-24）决定了不能用 vCPU 1:1 对应 Windows 线程（Windows 程序动辄几十到几百线程）。

**线程模型：N:M（Windows 线程 : vCPU）**

vCPU 数量固定为 Host 物理核心数（可配置），Guest Kernel 内置完整调度器（`KThread`、就绪队列、多 vCPU 支持），将 N 个 Windows 线程多路复用到 M 个 vCPU。这与物理 Windows 机器的工作方式完全一致——Windows 调度器本来就是把线程调度到有限的物理核心上。

Wine 的 1:1 线程模型是因为它没有 Guest Kernel，Windows 线程直接映射为 Host 线程，由 Host OS 调度。WinEmu 有 Guest Kernel，这个问题自然消失。

**阻塞 hypercall 的处理：**

需要 Host 资源的阻塞操作（如文件 I/O）：
- Guest Kernel 将当前线程置为 `Waiting`，切换到其他就绪线程
- 通过 HVC 发起请求，Host 处理完成后返回结果
- Guest Kernel 将线程重新置为 `Ready`，重新调度上 vCPU

### 6.4 macOS 16KB 页问题的根本解决

Guest VM 有独立的页表（由 Guest Kernel 管理），Host 的 16KB 页限制只影响 GPA→HPA 映射粒度：

```
Guest VA (4KB 粒度)
    │  Guest 页表 (Guest Kernel 管理)
    ▼
Guest PA (16KB 对齐的大块)
    │  EPT/Stage-2 页表 (HVF/KVM 管理)
    ▼
Host VA (16KB 对齐)
```

Guest 内部可以自由使用 4KB 页保护，因为 Guest Kernel 控制 Guest 页表。Host 只需以 16KB 块为单位映射 guest 物理内存。

- Guest 物理内存以 16KB 对齐的大块分配
- Guest Kernel 在这些大块上建立 4KB 粒度的 Guest 页表
- `VirtualProtect` 等操作修改 Guest 页表，不涉及 Host

### 6.5 Hypercall vs MMIO

| 机制 | 延迟 | 适用场景 |
|------|------|---------|
| Hypercall (HVC/VMCALL) | ~1-5μs | 低频、需要同步返回的操作 (文件 I/O) |
| MMIO doorbell + 共享内存 | ~0.5-2μs | 中频操作 (图形命令) |
| 共享内存轮询 (无 VM exit) | ~100ns | 极高频操作 (spinlock、原子操作) |

---

## 7. 与 Wine 的关系

WinEmu 不是 Wine 的 fork，而是一个新架构，选择性复用 Wine 的成果：

```
Wine 贡献给 WinEmu:
  ✓ 纯 PE DLL 实现 (数百个 Windows API)
  ✓ Unix lib 的 API 设计参考
  ✓ PE 加载器逻辑参考
  ✓ Windows 注册表、文件系统映射逻辑
  ✓ 测试套件 (Wine Test)

WinEmu 新增:
  ✗ Guest Kernel (全新 Rust 实现)
  ✗ Hypervisor 抽象层
  ✗ Hypercall ABI
  ✗ ntdll Unix lib → hypercall shim
  ✗ 虚拟设备层
```

---

## 8. 参考项目

| 项目 | 参考点 |
|------|-------|
| [Quark](https://github.com/QuarkContainer/Quark) | Host VMM 侧：Rust KVM/HVF 封装模式、hypercall 分发、共享内存通信（Guest 侧 Linux 语义不参考） |
| [Firecracker](https://github.com/firecracker-microvm/firecracker) | Rust KVM VMM 最佳实践，async vCPU 线程模型 |
| [crosvm](https://github.com/google/crosvm) | virtio 设备实现参考（音频/输入） |
| [FEX-Emu](https://github.com/FEX-Emu/FEX) | x86→ARM64 JIT，后期跨架构 DBT 集成 |
| [Wine](https://github.com/ValveSoftware/wine) | PE DLL 复用，Unix lib / unix call 接口设计，DXVK/winevulkan |
| [QEMU](https://github.com/qemu/qemu) | HVF 后端实现参考，TCG DBT |
| [kvm-ioctls](https://github.com/rust-vmm/kvm-ioctls) | Rust KVM 绑定 |
| [Ryujinx AppleHv](https://github.com/alula/Ryujinx/tree/4930dced25c0d9ec33096b0f2601d262daa477bf/src/Ryujinx.Cpu/AppleHv) | HVF ARM64 exit 处理：exit info 指针在 `hv_vcpu_create` 时获取，ESR EC 字段解析（EC=0x15 SVC、EC=0x24/0x25 Data Abort）；MMU 寄存器初始化参考值（`TCR_EL1=0x00000011B5193519`、`SCTLR_EL1=0x0000000034D5D925`、`MAIR_EL1=0xFF`）；TTBR0/TTBR1 分割（用户/内核地址空间）；ERET-only 代码页技巧（HVC 处理完成后返回 Guest）。注：Ryujinx EL1 蹦床架构（每次 SVC 都 VM exit）与 WinEmu 真实 Guest Kernel 设计不同，不参考该模式 |
