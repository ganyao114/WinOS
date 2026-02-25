# WinEmu 实现计划

## 阶段总览

```
Phase 0 (2周)   基础设施搭建
Phase 1 (6周)   Hypervisor 层 + 最小 Guest Kernel
Phase 2 (8周)   NT 子系统核心 + Wine DLL 集成
Phase 3 (8周)   图形/音频/输入设备虚拟化
Phase 4 (持续)  兼容性提升 + 跨架构 DBT
```

---

## Phase 0 — 基础设施 (第 1-2 周)

### 目标
建立 Rust workspace，跑通最小 VM 启动流程。

### 任务

**P0-1: Workspace 初始化**
```toml
# Cargo.toml
[workspace]
members = [
    "crates/winemu-core",
    "crates/winemu-hypervisor",
    "crates/winemu-kernel",
    "crates/winemu-vmm",
    "crates/winemu-cli",
]
```

**P0-2: CI 配置**
- GitHub Actions: macOS ARM64 + Linux x86_64 + Linux ARM64
- `cargo clippy`, `cargo test`, `cargo fmt --check`
- 平台特定 feature flags: `#[cfg(target_os = "macos")]` / `#[cfg(target_os = "linux")]`

**P0-3: 核心类型定义** (`winemu-core`)
```rust
// 错误类型
pub type Result<T> = std::result::Result<T, WinemuError>;

// NT 状态码
#[repr(u32)]
pub enum NtStatus { Success = 0, ... }

// 内存保护标志
bitflags! { pub struct MemProt: u32 { ... } }

// Guest 物理/虚拟地址类型
pub struct Gpa(pub u64);
pub struct Gva(pub u64);
```

**P0-4: 验收标准**
- `cargo build --workspace` 在 macOS ARM64 和 Linux x86_64 均通过
- 基本类型单元测试通过

---

## Phase 1 — Hypervisor 层 + 最小 Guest (第 3-8 周)

### 目标
能够启动一个最小 Guest，执行几条指令后通过 hypercall 退出，Host 正确接收。

### P1-1: Hypervisor 抽象层 (第 3-4 周)

**接口定义** (`winemu-hypervisor/src/lib.rs`):
```rust
pub trait Hypervisor: Send + Sync {
    fn create_vm(&self, config: VmConfig) -> Result<Box<dyn Vm>>;
}

pub trait Vm: Send + Sync {
    fn map_memory(&self, gpa: Gpa, hva: *mut u8,
                  size: usize, prot: MemProt) -> Result<()>;
    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>>;
}

pub trait Vcpu: Send {
    fn run(&mut self) -> Result<VmExit>;
    fn regs(&self) -> Result<Regs>;
    fn set_regs(&mut self, r: &Regs) -> Result<()>;
    fn advance_pc(&mut self, bytes: u64) -> Result<()>;
}

pub enum VmExit {
    Hypercall { nr: u64, args: [u64; 6] },
    MmioRead  { addr: u64, size: u8 },
    MmioWrite { addr: u64, data: u64, size: u8 },
    Halt,
    Shutdown,
    Unknown(u32),
}
```

**KVM 后端** (`winemu-hypervisor/src/kvm/`):
- 依赖 `kvm-ioctls = "0.16"` crate
- 实现 `Hypervisor`, `Vm`, `Vcpu` trait
- 处理 `KVM_EXIT_HYPERCALL`, `KVM_EXIT_MMIO`, `KVM_EXIT_HLT`
- ARM64: 设置 `KVM_ARM_VCPU_PSCI_0_2` feature，初始化 MPIDR

**HVF 后端** (`winemu-hypervisor/src/hvf/`):
- 通过 `extern "C"` 绑定 `Hypervisor.framework`
- `build.rs` 链接 `-framework Hypervisor`
- ARM64: 处理 `HV_EXIT_REASON_EXCEPTION`，解析 ESR syndrome
  - EC=0x16 (HVC) → `VmExit::Hypercall`
  - EC=0x24/0x25 (Data Abort) → `VmExit::MmioRead/Write`
- x86: 读取 VMCS `VMCS_RO_EXIT_REASON`

**P1-1 验收**: 单元测试：创建 VM，映射 1MB 内存，写入 `HVC #0; HLT` 指令，运行后收到 `VmExit::Hypercall { nr: 0, .. }`

### P1-2: 最小 Guest Kernel 骨架 (第 5-6 周)

Guest Kernel 编译为裸机二进制，加载到 Guest 物理地址 `0x40000000` (ARM64)。

**启动流程** (`winemu-kernel/src/start.rs`):
```rust
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. 初始化 BSS
    // 2. 设置栈
    // 3. 初始化 MMU (4KB 页表)
    // 4. 跳转到 kernel_main
    kernel_main()
}

fn kernel_main() -> ! {
    mm::init();
    ob::init();
    ps::init();
    ldr::init();
    // 通知 Host: kernel ready
    hypercall::kernel_ready();
    // 进入调度循环
    ps::scheduler_loop()
}
```

**页表初始化** (`winemu-kernel/src/mm/`):
- ARM64: 设置 TTBR0_EL1 (用户空间) + TTBR1_EL1 (内核空间)
- 4KB granule, 4-level page table
- 内核映射: GPA 0x40000000 → VA 0xFFFF000040000000
- 用户空间: 0x0000000000000000 - 0x00007FFFFFFFFFFF

**Hypercall 接口** (`winemu-kernel/src/hypercall.rs`):
```rust
#[inline(always)]
pub fn hypercall(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") nr => ret,
            in("x1") a0,
            in("x2") a1,
            in("x3") a2,
            options(nostack)
        );
    }
    ret
}

pub fn kernel_ready() {
    hypercall(HYPERCALL_KERNEL_READY, 0, 0, 0);
}
```

**P1-2 验收**: Guest Kernel 启动，MMU 开启，发送 `HYPERCALL_KERNEL_READY`，Host 收到后打印 "Guest kernel ready"

### P1-3: VMM 主循环 (第 7-8 周)

**VMM 结构** (`winemu-vmm/src/`):
```rust
pub struct Vmm {
    vm: Box<dyn Vm>,
    vcpus: Vec<VcpuThread>,
    hypercall_mgr: HypercallManager,
    memory: GuestMemory,
}

impl Vmm {
    pub fn run(&mut self) -> Result<()> {
        // 加载 Guest Kernel 镜像到 guest 内存
        self.load_kernel()?;
        // 启动 vCPU 线程
        for vcpu in &mut self.vcpus {
            vcpu.start()?;
        }
        // 等待退出
        self.wait_for_exit()
    }
}
```

**vCPU 线程循环**:

vCPU 数量固定为物理核心数，每个 vCPU 对应一个 Host 线程，Guest Kernel 调度器负责将 Windows 线程多路复用到这些 vCPU 上。

```rust
fn vcpu_thread(mut vcpu: Box<dyn Vcpu>, hc_mgr: Arc<HypercallManager>) {
    loop {
        match vcpu.run().unwrap() {
            VmExit::Hypercall { nr, args } => {
                // 异步 hypercall：立即返回，完成后通过虚拟中断通知 Guest
                // 同步 hypercall：等待结果后写回寄存器
                match hc_mgr.dispatch(nr, args) {
                    HypercallResult::Sync(ret) => {
                        vcpu.set_regs(&Regs { x0: ret, ..vcpu.regs().unwrap() }).unwrap();
                        vcpu.advance_pc(4).unwrap();
                    }
                    HypercallResult::Async => {
                        // Guest Kernel 已切换到其他线程，vCPU 继续运行
                        vcpu.advance_pc(4).unwrap();
                    }
                }
            }
            VmExit::Halt | VmExit::Shutdown => break,
            exit => log::warn!("unhandled exit: {:?}", exit),
        }
    }
}
```

**P1-3 验收**: `winemu-cli` 能启动 Guest Kernel，双向 hypercall 通信正常，`cargo test` 全绿

---

## Phase 2 — NT 子系统 + Wine DLL 集成 (第 9-16 周)

### 目标
能够在 Guest 内加载并运行一个简单的 Windows PE 控制台程序 (Hello World)。

### P2-1: PE 加载器 (第 9-10 周)

在 Guest Kernel 内实现 PE 加载器：

- 解析 PE32+ 头 (MZ → PE → Optional Header → Section Headers)
- 处理 `.reloc` 重定位表
- 解析导入表 (IAT)，递归加载依赖 DLL
- 映射各 Section 到 Guest 虚拟地址空间，设置正确页保护
- 支持 ASLR (地址随机化)

**DLL 搜索路径** (通过 hypercall 从 Host 读取文件):
```
1. 应用程序目录
2. %WINDIR%\system32  → 映射到 Host 的 Wine DLL 目录
3. %WINDIR%           → 同上
4. PATH 目录
```

### P2-2: NT 对象管理器 (第 10-11 周)

```rust
// winemu-kernel/src/ob/
pub struct ObjectManager {
    handle_tables: HashMap<ProcessId, HandleTable>,
    named_objects: BTreeMap<String, Arc<dyn KernelObject>>,
}

pub trait KernelObject: Send + Sync {
    fn object_type(&self) -> ObjectType;
    fn close(&self);
}

// 句柄表：每进程，支持继承标志
pub struct HandleTable {
    entries: Vec<Option<HandleEntry>>,
}
```

实现对象类型：
- `Process`, `Thread`
- `Event` (Auto/Manual reset)
- `Mutex`, `Semaphore`
- `Section` (内存映射文件)
- `File`, `Directory`
- `Token`

### P2-3: 进程/线程管理 (第 11-12 周)

**进程创建流程**:
1. Host 通过 hypercall 触发进程创建
2. Guest Kernel 分配进程结构，创建初始地址空间
3. PE 加载器加载 EXE 和依赖 DLL
4. 创建主线程，设置初始栈和 TEB (Thread Environment Block)
5. 将主线程加入就绪队列，调度器选择空闲 vCPU 执行

**线程调度器 (N:M)**:
- vCPU 数量 = Host 物理核心数（可通过 `--vcpus` 配置，上限受 HVF/KVM 约束）
- 就绪队列按 32 级优先级组织，每级一个 FIFO 队列
- 抢占：Host 定时器（每 15ms）向 vCPU 注入虚拟定时器中断，触发 Guest 调度
- 阻塞型 hypercall 处理：
  1. Guest Kernel 将当前线程置为 `Waiting`，保存上下文
  2. 从就绪队列取下一个线程，恢复上下文，继续执行
  3. hypercall 异步完成后，Host 注入中断，Guest Kernel 将线程重新置为 `Ready`

**TEB/PEB 结构**:
```rust
#[repr(C)]
pub struct Teb {
    pub exception_list: u64,    // SEH chain
    pub stack_base: u64,
    pub stack_limit: u64,
    pub tls_slots: [u64; 64],
    pub peb: u64,               // 指向 PEB
    // ...
}
```

### P2-4: ntdll Hypercall Shim (第 12-13 周)

这是连接 Guest 和 Host Wine 的关键桥梁。

**构建方式**:
- 编译为 PE DLL (`ntdll_unix.dll` 或直接替换 ntdll 的 Unix lib 部分)
- 每个 Wine Unix lib 函数替换为对应的 hypercall

```c
/* 原 Wine ntdll Unix lib: */
NTSTATUS unix_NtCreateFile(struct NtCreateFile_params *params) {
    return do_create_file(params->handle, params->access, ...);
}

/* WinEmu hypercall shim: */
NTSTATUS unix_NtCreateFile(struct NtCreateFile_params *params) {
    // 直接传 Guest 虚拟地址，Host 侧从 Guest 内存读取
    return (NTSTATUS)hypercall(HC_NT_CREATE_FILE, (uint64_t)params, 0, 0);
}
```

**Host 侧 hypercall handler**:
```rust
// winemu-vmm/src/hypercall/nt_file.rs
pub fn handle_nt_create_file(
    guest_mem: &GuestMemory,
    args: [u64; 6],
) -> NtStatus {
    // 直接从 Guest 内存读取参数，无需额外拷贝
    let params = guest_mem.read_struct::<NtCreateFileParams>(Gpa(args[0]));
    wine_bridge::nt_create_file(&params)
}
```

> 注：共享内存页用于高频大数据量场景（Vulkan 命令流、音频 buffer），普通 NT syscall 参数直接传 Guest 指针即可。
```

### P2-5: 同步原语 (第 13-14 周)

**Guest 内快速路径** (无 hypercall):
- 无竞争 Mutex: 用 guest 内存中的原子变量实现
- Event: guest 内 futex (通过 `WFE`/`SEV` ARM64 指令)

**跨进程/超时路径** (需要 hypercall):
- `NtWaitForSingleObject` 超时 → hypercall 到 Host，Host 用 `epoll`/`kqueue` 等待
- `NtReleaseMutex` 有等待者 → hypercall 通知 Host 唤醒

### P2-6: 基础文件 I/O (第 14-15 周)

通过 hypercall 代理到 Host：
- `NtCreateFile` / `NtOpenFile`
- `NtReadFile` / `NtWriteFile`
- `NtQueryInformationFile`
- `NtQueryDirectoryFile`

路径转换：
- `C:\Windows\System32\` → Wine 的 `$WINEPREFIX/drive_c/windows/system32/`
- `C:\Users\` → `$WINEPREFIX/drive_c/users/`

### P2-7: Hello World 验收 (第 15-16 周)

**验收程序**:
```c
// test.c (编译为 ARM64 Windows PE)
#include <windows.h>
int main() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    WriteFile(h, "Hello from WinEmu!\n", 19, &written, NULL);
    return 0;
}
```

验收标准：
- `winemu run test.exe` 输出 "Hello from WinEmu!"
- 进程正常退出，返回码正确
- Valgrind / AddressSanitizer 无内存错误

---

## Phase 3 — 图形/音频/输入 (第 17-24 周)

### P3-1: win32u hypercall shim + 窗口管理 (第 17-19 周)

将 `win32u` 的 Unix lib 替换为 hypercall shim，Host 侧创建原生窗口：

```
Guest: GDI App → win32u.dll (PE) → unix call (hypercall shim)
Host:  → macOS NSWindow/NSView 或 Linux Wayland xdg_surface
```

实现核心 Win32 窗口 hypercall：
- `NtUserCreateWindowEx`, `NtUserShowWindow`, `NtUserDestroyWindow`
- `NtUserMessageCall` (消息循环)
- `NtGdiCreateDC`, `NtGdiBitBlt`, `NtGdiStretchBlt` (基础 GDI)

Host 侧用共享内存帧缓冲承接 GDI 输出，定时 blit 到原生窗口。

### P3-2: winevulkan hypercall shim (第 19-21 周)

将 `winevulkan` 的 Unix lib 替换为 hypercall shim，DXVK 和 winevulkan PE 层完全不修改：

```
Guest:  DXVK (PE) → winevulkan.dll (PE) → unix call (hypercall shim)
                                                │ hypercall
Host:   vulkan handler → libvulkan.so / MoltenVK → Metal / Vulkan 驱动
```

实现要点：
- winevulkan unix call 参数通过共享内存传递（Vulkan 命令参数可能较大）
- Host 侧维护 VkInstance / VkDevice 等对象的映射表（Guest handle → Host handle）
- 呈现 (Present)：将 swapchain image blit 到 Host 原生窗口 surface

### P3-3: 输入事件 (第 21-22 周)

Host 捕获键盘/鼠标事件，通过共享内存 ring buffer 注入 Guest，无需 VM exit：

```rust
pub struct InputRing {
    pub head: AtomicU32,
    pub tail: AtomicU32,
    pub events: [InputEvent; 256],
}

pub enum InputEvent {
    KeyDown { vk: u16, scan: u16 },
    KeyUp   { vk: u16, scan: u16 },
    MouseMove { x: i32, y: i32 },
    MouseButton { button: u8, down: bool },
}
```

### P3-4: 音频 (第 22-23 周)

`winmm` / `mmdevapi` Unix lib 替换为 hypercall shim：
- `waveOutOpen` / `waveOutWrite` → hypercall → Host CoreAudio (macOS) / PipeWire (Linux)
- 音频数据通过共享内存传递，避免大块数据 hypercall 拷贝

### P3-5: 验收 (第 23-24 周)

验收标准：
- 能运行 Notepad.exe (ARM64 Windows 版本)，窗口正常显示，键盘输入正常
- 能运行一个使用 D3D11 的简单程序（如 d3d11 triangle demo）
- 基础 GDI 绘制正确

---

## Phase 4 — 兼容性与 DBT (持续)

### P4-1: 兼容性提升
- 运行 Wine 测试套件 (`winetest`)，追踪失败项
- 实现更多 NT API (注册表、网络、COM 等)
- 异常处理 (SEH, VEH) 完善

### P4-2: 性能优化
- Hypercall 批处理
- 共享内存 ring buffer 替换高频 hypercall
- vCPU 亲和性优化

### P4-3: FEX 集成 (跨架构)
- 在 Guest 内集成 FEX-Emu
- ARM64 Host 运行 x86_64 Windows 程序
- 测试 x86_64 Wine DLL 在 FEX 下的兼容性

### P4-4: iOS 移植
- 软件 Hypervisor 后端 (无 HVF 时降级)
- AOT 编译模式 (绕过 iOS JIT 限制)
- 单进程架构验证

---

## 依赖与工具链

### Rust 依赖
```toml
[dependencies]
# KVM
kvm-ioctls = "0.16"
vmm-sys-util = "0.12"

# 日志
log = "0.4"
env_logger = "0.11"

# 错误处理
thiserror = "1"
anyhow = "1"

# 并发
crossbeam-channel = "0.5"
parking_lot = "0.12"

# 内存映射
memmap2 = "0.9"

# 位标志
bitflags = "2"
```

### 构建工具
- `cross` — 交叉编译 (Linux ARM64 guest kernel)
- `cargo-nextest` — 更快的测试运行器
- `llvm-objcopy` — Guest kernel 二进制处理

### 测试工具
- Wine 测试套件 (`winetest.exe`)
- 自定义 PE 测试程序 (用 `mingw-w64` 或 MSVC 编译)
- `kvm-unit-tests` — KVM 层单元测试

---

## 风险与缓解

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|---------|
| HVF ARM64 vCPU 上限（~16-24）不足 | 低 | 中 | N:M 调度器天然解决；vCPU 数量等于物理核心数即可 |
| Guest Kernel 页表 bug | 高 | 高 | 充分单元测试；先用 QEMU TCG 模式辅助调试，再切 HVF/KVM |
| 异步 hypercall + 调度器死锁 | 中 | 高 | 严格区分 Guest 锁与 Host 锁；调度器路径禁止持有 Host 锁 |
| winevulkan unix call ABI 与 Wine 版本绑定 | 中 | 中 | 锁定 Wine 版本；hypercall shim 与 Wine PE DLL 同步构建 |
| Wine DLL 兼容性问题 | 高 | 中 | 逐步集成，先跑最小测试集（winetest） |
| macOS HVF API 变更 | 低 | 高 | 抽象层隔离；关注 Apple 发布说明 |
| 性能不达预期 | 中 | 中 | 早期 profiling；Vulkan 命令通过共享内存批量传递减少 VM exit |
