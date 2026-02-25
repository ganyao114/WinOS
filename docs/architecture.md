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
│         │                 │                    │             │
│  ┌──────▼─────────────────▼────────────────────▼─────────┐  │
│  │              Pure PE DLL Layer (Wine DLLs)             │  │
│  │  kernel32 / kernelbase / user32 / gdi32 / ntdll(PE)   │  │
│  └──────────────────────────┬──────────────────────────┘  │
│                             │ NT Syscall                    │
│  ┌──────────────────────────▼──────────────────────────┐   │
│  │              WinEmu Guest Kernel (Rust)              │   │
│  │  - NT 对象管理 (进程/线程/句柄/同步原语)              │   │
│  │  - 虚拟内存管理 (4KB 页表)                           │   │
│  │  - PE 加载器                                         │   │
│  │  - 异常/信号分发                                     │   │
│  └──────────────────────────┬──────────────────────────┘   │
│                             │ Hypercall (HVC/VMCALL)        │
└─────────────────────────────┼───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                    WinEmu Host (Rust VMM)                    │
│                                                              │
│  ┌─────────────────┐   ┌──────────────────────────────────┐ │
│  │  Hypercall 分发  │   │     Wine Unix Lib 适配层          │ │
│  │  (HypercallMgr) │──▶│  ntdll.so / win32u.so / ...      │ │
│  └─────────────────┘   └──────────────────────────────────┘ │
│                                                              │
│  ┌─────────────────┐   ┌──────────────────────────────────┐ │
│  │  Hypervisor 抽象 │   │     设备模拟层                    │ │
│  │  HvfBackend     │   │  virtio-gpu / virtio-input /     │ │
│  │  KvmBackend     │   │  virtio-sound / virtio-fs        │ │
│  └─────────────────┘   └──────────────────────────────────┘ │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              平台 HAL (Host Abstraction Layer)        │   │
│  │   macOS: HVF + Metal/CoreAudio/CoreText              │   │
│  │   Linux: KVM + Vulkan/PipeWire/Fontconfig            │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

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

运行在 VM Ring 0（或 EL1），负责：

**NT 对象子系统：**
- 句柄表 (Handle Table)：每个进程独立，支持继承
- 对象管理器：引用计数、命名对象、目录对象
- 同步原语：Mutex、Event、Semaphore、Timer — 优先用 guest 内原子操作，无需 hypercall

**虚拟内存管理器：**
- 维护 4KB 粒度的 VAD 树 (Virtual Address Descriptor)
- `NtAllocateVirtualMemory` / `NtFreeVirtualMemory` 在 guest 内处理
- 页保护 (PAGE_GUARD, PAGE_NOACCESS 等) 通过 guest 页表实现
- 解决 macOS 16KB 页问题的关键：guest 有自己的页表，host 只需映射大块内存

**PE 加载器：**
- 解析 PE32/PE32+ 格式
- 处理重定位、导入表、延迟导入
- 支持 Side-by-Side (SxS) / manifest

**异常分发：**
- 将 guest CPU 异常转换为 Windows 结构化异常 (SEH)
- 向量化异常处理 (VEH)
- 调试事件分发

**线程调度器 (N:M)：**
- vCPU 数量固定（默认等于 Host 物理核心数），Windows 线程 N:M 复用到 vCPU 上
- 这与物理 Windows 机器的工作方式完全一致，Windows 本身就是 N 线程调度到 M 核心
- 就绪队列 + 32 级优先级（简化实现）
- 阻塞型 hypercall（I/O 等）不阻塞 vCPU：Guest Kernel 将线程置为 Waiting 后切换到其他就绪线程，Host 异步完成后通过虚拟中断唤醒

```
Guest 线程调用 NtReadFile
    │
    ▼
Guest Kernel: 线程 → Waiting，切换到其他就绪线程
    │ hypercall (异步，立即返回)
    ▼
Host: I/O 请求投入 async runtime (tokio)
    │ I/O 完成
    ▼
Host: 注入虚拟中断 → Guest Kernel 中断处理
    │
    ▼
Guest Kernel: 线程 → Ready，重新调度上 vCPU
```

### 3.3 NT Syscall 接口

Windows 应用通过标准 NT syscall 调用 Guest Kernel，使用**真实 Windows 系统调用号**（参考 [SyscallTables](https://github.com/hfiref0x/SyscallTables)）。

由于调用号随 Windows 版本变化，采用**配置文件动态加载**方案：VMM 启动时指定目标 Windows 版本的调用号表（TOML 格式），Guest Kernel 通过 hypercall 读取后构建运行时分发表，无需重新编译即可支持不同版本。

```
winemu run --syscall-table config/syscall-tables/win11-arm64.toml hello.exe
```

**调用约定（ARM64）：**
```
SVC #0
x8  = syscall 编号 (真实 Windows NT syscall number，运行时从配置加载)
x0-x7 = 参数
返回值: x0 = NTSTATUS
```

**调用约定（x86_64）：**
```
SYSCALL
rax = syscall 编号 (真实 Windows NT syscall number，运行时从配置加载)
rcx, rdx, r8, r9, [rsp+...] = 参数
返回值: rax = NTSTATUS
```

Guest Kernel 在 EL1（ARM64）或 Ring 0（x86）拦截 `SVC`/`SYSCALL` 指令，通过运行时分发表映射到对应的 NT 实现。调用号与真实 Windows 保持一致，未修改的 ntdll.dll PE 层可直接运行。

**NT Syscall 分类（编号来自真实 Windows，以 ARM64 Win11 为例）：**

| 类别 | 编号范围（参考值） | 示例 |
|------|-----------------|------|
| 核心 NT | 0x0000 - 0x01FF | NtCreateFile(0x55), NtReadFile(0x06) |
| 进程/线程 | 0x004B, 0x00C1... | NtCreateProcessEx, NtCreateThreadEx |
| 同步 | 0x0004, 0x0040... | NtWaitForSingleObject, NtSetEvent |
| 注册表 | 0x0012, 0x0016... | NtOpenKey, NtQueryValueKey |
| 内存 | 0x0015, 0x001E... | NtAllocateVirtualMemory, NtFreeVirtualMemory |
| win32k (图形) | 0x1000+ | NtGdiCreateCompatibleDC, NtUserCreateWindowEx |

**动态加载流程：**
```
VMM 启动
  │ 读取 win11-arm64.toml
  ▼
hypercall: LOAD_SYSCALL_TABLE (传入 TOML 内容)
  ▼
Guest Kernel: 解析 TOML，构建 nr → SyscallId 哈希表
  ▼
SVC 向量安装完成，开始接受 syscall
```

### 3.4 Hypercall 接口

Hypercall 仅用于 **Guest Kernel 需要调用 Host 原生库**的场景，即 Wine unix call 的替代路径。NT syscall 本身在 Guest Kernel 内处理，不走 hypercall。

**使用 hypercall 的场景：**
- `winevulkan` unix call → Host `libvulkan` / MoltenVK
- `win32u` unix call → Host 原生窗口系统（NSWindow / Wayland）
- `winmm`/`mmdevapi` unix call → Host CoreAudio / PipeWire
- Guest Kernel 启动通知（`KERNEL_READY`）、调试输出

**调用约定（ARM64）：**
```
HVC #0
x0 = hypercall 编号
x1-x7 = 参数 (或指向 guest 内共享内存的指针)
返回值: x0 = 结果
```

**调用约定（x86_64）：**
```
VMCALL
rax = hypercall 编号
rdi, rsi, rdx, rcx, r8, r9 = 参数
返回值: rax = 结果
```

**Hypercall 编号分类（自定义，与 NT syscall 编号空间完全独立）：**

| 类别 | 编号范围 | 示例 |
|------|---------|------|
| 系统 | 0x0000 - 0x000F | KERNEL_READY, DEBUG_PRINT |
| 图形 unix call | 0x0100 - 0x01FF | win32u_create_window, vulkan_call |
| 音频 unix call | 0x0200 - 0x02FF | wave_out_open, wave_out_write |
| 文件系统辅助 | 0x0300 - 0x03FF | load_dll_image（加载 DLL 文件到 Guest 内存） |

**高频路径优化 — 共享内存 + MMIO doorbell：**

对于高频 unix call（Vulkan 命令流、音频数据），使用共享内存避免大量数据拷贝：

```
Guest                          Host
  │                              │
  │  写入共享内存 ring buffer      │
  │  MMIO write (doorbell)  ───▶ │  处理命令
  │  轮询 completion ring   ◀─── │  写入结果
```

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
├── Cargo.toml                  # workspace
├── crates/
│   ├── winemu-core/            # 核心类型、错误、公共接口
│   ├── winemu-hypervisor/      # Hypervisor 抽象层
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── hvf/            # macOS HVF 后端
│   │   │   └── kvm/            # Linux KVM 后端
│   ├── winemu-kernel/          # Guest Kernel (编译为 guest 二进制)
│   │   ├── src/
│   │   │   ├── mm/             # 内存管理
│   │   │   ├── ob/             # 对象管理器
│   │   │   ├── ps/             # 进程/线程
│   │   │   ├── io/             # I/O 管理器
│   │   │   ├── ex/             # 执行体 (同步、定时器)
│   │   │   └── ldr/            # PE 加载器
│   ├── winemu-vmm/             # Host VMM 主体
│   │   ├── src/
│   │   │   ├── hypercall/      # Hypercall 分发与实现
│   │   │   ├── devices/        # 虚拟设备 (virtio-gpu 等)
│   │   │   └── wine_bridge/    # Wine Unix lib 适配
│   ├── winemu-wine-bridge/     # Wine DLL Unix lib hypercall shim
│   └── winemu-cli/             # 命令行入口
├── guest/
│   ├── ntdll-shim/             # ntdll Unix lib hypercall 替换
│   └── wine-dlls/              # 复用的 Wine PE DLL
└── docs/
    ├── architecture.md         # 本文档
    └── hypercall-abi.md        # Hypercall ABI 规范
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

vCPU 数量固定为 Host 物理核心数（可配置），Guest Kernel 调度器负责将 N 个 Windows 线程多路复用到 M 个 vCPU。这与物理 Windows 机器的工作方式完全一致——Windows 调度器本来就是把线程调度到有限的物理核心上。

Wine 的 1:1 线程模型是因为它没有 Guest Kernel，Windows 线程直接映射为 Host 线程，由 Host OS 调度。WinEmu 有 Guest Kernel，这个问题自然消失。

**阻塞 hypercall 的处理：**

同步阻塞 hypercall 会卡住 vCPU，导致该 vCPU 上所有线程停止。解决方案：
- Guest Kernel 在发起阻塞型 hypercall 前，先将当前线程置为 `Waiting`，切换到其他就绪线程
- Host 侧用 async runtime（tokio）异步执行 I/O
- 完成后通过虚拟中断注入通知 Guest Kernel，将线程重新置为 `Ready`

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
