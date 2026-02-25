# Phase 0 — 基础设施搭建 (第 1-2 周)

## 目标

建立 Rust workspace，定义核心类型，跑通最小编译流程，配置 CI。

---

## P0-1: Cargo Workspace 初始化

### 目录结构

```
WinEmu/
├── Cargo.toml                  # workspace root
├── Cargo.lock
├── crates/
│   ├── winemu-core/            # 核心类型、错误、公共接口
│   ├── winemu-hypervisor/      # Hypervisor 抽象层 + 平台后端
│   ├── winemu-kernel/          # Guest Kernel (裸机二进制)
│   ├── winemu-vmm/             # Host VMM 主体
│   └── winemu-cli/             # 命令行入口
├── guest/
│   └── ntdll-shim/             # ntdll Unix lib hypercall 替换 (C)
└── docs/
```

### workspace Cargo.toml

```toml
[workspace]
members = [
    "crates/winemu-core",
    "crates/winemu-hypervisor",
    "crates/winemu-vmm",
    "crates/winemu-cli",
    # winemu-kernel 单独编译为裸机目标，不加入 workspace
]
resolver = "2"

[workspace.dependencies]
# 错误处理
thiserror = "1"
anyhow = "1"
# 日志
log = "0.4"
env_logger = "0.11"
# 并发
crossbeam-channel = "0.5"
parking_lot = "0.12"
# 内存映射
memmap2 = "0.9"
# 位标志
bitflags = "2"
# KVM (Linux only)
kvm-ioctls = "0.16"
vmm-sys-util = "0.12"
```

### 各 crate 的 Cargo.toml 要点

**winemu-core:**
```toml
[package]
name = "winemu-core"
version = "0.1.0"
edition = "2021"

[dependencies]
thiserror = { workspace = true }
bitflags = { workspace = true }
```

**winemu-hypervisor:**
```toml
[package]
name = "winemu-hypervisor"
version = "0.1.0"
edition = "2021"

[dependencies]
winemu-core = { path = "../winemu-core" }
thiserror = { workspace = true }
log = { workspace = true }

[target.'cfg(target_os = "linux")'.dependencies]
kvm-ioctls = { workspace = true }
vmm-sys-util = { workspace = true }

[build-dependencies]
# macOS: 链接 Hypervisor.framework
```

**winemu-kernel** (独立，不在 workspace):
```toml
[package]
name = "winemu-kernel"
version = "0.1.0"
edition = "2021"

[profile.release]
panic = "abort"
lto = true
opt-level = "s"

[dependencies]
# 无 std 依赖
```

---

## P0-2: 核心类型定义 (winemu-core)

### 错误类型

```rust
// crates/winemu-core/src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WinemuError {
    #[error("hypervisor error: {0}")]
    Hypervisor(String),
    #[error("memory error: {0}")]
    Memory(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("nt status: {0:#010x}")]
    NtStatus(u32),
}

pub type Result<T> = std::result::Result<T, WinemuError>;
```

### NT 状态码

```rust
// crates/winemu-core/src/nt_status.rs
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtStatus {
    Success              = 0x00000000,
    Pending              = 0x00000103,
    ObjectNameExists     = 0x40000000,
    BufferOverflow       = 0x80000005,
    AccessViolation      = 0xC0000005,
    InvalidHandle        = 0xC0000008,
    InvalidParameter     = 0xC000000D,
    NoSuchFile           = 0xC000000F,
    AccessDenied         = 0xC0000022,
    ObjectNameNotFound   = 0xC0000034,
    ObjectNameCollision  = 0xC0000035,
    InsufficientResources = 0xC000009A,
    NotImplemented       = 0xC0000002,
}

impl From<NtStatus> for u32 {
    fn from(s: NtStatus) -> u32 { s as u32 }
}
```

### 内存保护标志

```rust
// crates/winemu-core/src/mem.rs
use bitflags::bitflags;

bitflags! {
    #[repr(transparent)]
    pub struct MemProt: u32 {
        const NONE    = 0x00;
        const READ    = 0x01;
        const WRITE   = 0x02;
        const EXEC    = 0x04;
        const RW      = Self::READ.bits() | Self::WRITE.bits();
        const RX      = Self::READ.bits() | Self::EXEC.bits();
        const RWX     = Self::READ.bits() | Self::WRITE.bits() | Self::EXEC.bits();
    }
}

// Windows VirtualProtect 标志 → MemProt 转换
impl MemProt {
    pub fn from_win32(protect: u32) -> Self {
        match protect {
            0x01 => Self::NONE,   // PAGE_NOACCESS
            0x02 => Self::READ,   // PAGE_READONLY
            0x04 => Self::RX,     // PAGE_EXECUTE_READ
            0x40 => Self::RWX,    // PAGE_EXECUTE_READWRITE
            _ => Self::RW,        // PAGE_READWRITE (default)
        }
    }
}
```

### Guest 地址类型

```rust
// crates/winemu-core/src/addr.rs

/// Guest Physical Address
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gpa(pub u64);

/// Guest Virtual Address
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gva(pub u64);

impl Gpa {
    pub fn offset(self, n: u64) -> Self { Gpa(self.0 + n) }
    pub fn align_down(self, align: u64) -> Self { Gpa(self.0 & !(align - 1)) }
    pub fn align_up(self, align: u64) -> Self {
        Gpa((self.0 + align - 1) & !(align - 1))
    }
}
```

### NT Syscall 编号

NT syscall 编号随 Windows 版本变化，因此采用**配置文件动态加载**方案。Guest Kernel 启动时从 Host 读取调用号表，构建运行时分发表，无需重新编译即可支持不同 Windows 版本。

调用号数据来源：[SyscallTables](https://github.com/hfiref0x/SyscallTables)

### 配置文件格式

```toml
# config/syscall-tables/win11-arm64.toml
[meta]
os = "Windows 11"
arch = "ARM64"
build = 22621

[nt]
NtClose                   = 0x000F
NtCreateFile              = 0x0055
NtOpenFile                = 0x0030
NtReadFile                = 0x0006
NtWriteFile               = 0x0008
NtQueryInformationFile    = 0x0011
NtSetInformationFile      = 0x0027
NtQueryDirectoryFile      = 0x004E
NtAllocateVirtualMemory   = 0x0015
NtFreeVirtualMemory       = 0x001E
NtProtectVirtualMemory    = 0x004D
NtQueryVirtualMemory      = 0x0023
NtMapViewOfSection        = 0x0028
NtUnmapViewOfSection      = 0x002A
NtCreateProcessEx         = 0x004B
NtCreateThreadEx          = 0x00C1
NtTerminateProcess        = 0x002C
NtTerminateThread         = 0x0053
NtQueryInformationProcess = 0x0019
NtQueryInformationThread  = 0x0025
NtSetInformationThread    = 0x000D
NtWaitForSingleObject     = 0x0004
NtWaitForMultipleObjects  = 0x0040
NtCreateEvent             = 0x0048
NtSetEvent                = 0x000E
NtResetEvent              = 0x0034
NtCreateMutant            = 0x00A9
NtReleaseMutant           = 0x001C
NtCreateSemaphore         = 0x00C3
NtReleaseSemaphore        = 0x0033
NtOpenKey                 = 0x0012
NtCreateKey               = 0x001D
NtQueryValueKey           = 0x0016
NtSetValueKey             = 0x003D
NtDeleteKey               = 0x000C
NtEnumerateKey            = 0x0032
NtEnumerateValueKey       = 0x0010
NtDuplicateObject         = 0x003C

[win32k]
# win32k syscall 编号（0x1000+，由 win32u.dll 发出）
NtGdiCreateCompatibleDC   = 0x1012
NtGdiBitBlt               = 0x1001
NtUserCreateWindowEx      = 0x1056
NtUserShowWindow          = 0x10C3
NtUserMessageCall         = 0x1069
NtUserDestroyWindow       = 0x1025
```

### 运行时 Syscall 表

```rust
// crates/winemu-core/src/syscall.rs

/// 运行时 syscall 分发表，启动时从配置文件加载
pub struct SyscallTable {
    /// NT syscall: 调用号 → handler index
    nt: HashMap<u32, SyscallId>,
    /// win32k syscall: 调用号 → handler index
    win32k: HashMap<u32, SyscallId>,
}

/// 已知 syscall 的枚举，与具体编号解耦
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallId {
    NtClose,
    NtCreateFile,
    NtOpenFile,
    NtReadFile,
    NtWriteFile,
    NtQueryInformationFile,
    NtSetInformationFile,
    NtQueryDirectoryFile,
    NtAllocateVirtualMemory,
    NtFreeVirtualMemory,
    NtProtectVirtualMemory,
    NtMapViewOfSection,
    NtUnmapViewOfSection,
    NtCreateProcessEx,
    NtCreateThreadEx,
    NtTerminateProcess,
    NtTerminateThread,
    NtWaitForSingleObject,
    NtWaitForMultipleObjects,
    NtCreateEvent,
    NtSetEvent,
    NtResetEvent,
    NtCreateMutant,
    NtReleaseMutant,
    NtCreateSemaphore,
    NtReleaseSemaphore,
    NtOpenKey,
    NtCreateKey,
    NtQueryValueKey,
    NtSetValueKey,
    NtDuplicateObject,
    // win32k
    NtGdiCreateCompatibleDC,
    NtGdiBitBlt,
    NtUserCreateWindowEx,
    NtUserShowWindow,
    NtUserMessageCall,
    NtUserDestroyWindow,
    // 未知调用号
    Unknown(u32),
}

impl SyscallTable {
    pub fn lookup(&self, nr: u32) -> SyscallId {
        if nr >= 0x1000 {
            self.win32k.get(&nr).copied()
                .unwrap_or(SyscallId::Unknown(nr))
        } else {
            self.nt.get(&nr).copied()
                .unwrap_or(SyscallId::Unknown(nr))
        }
    }
}
```

### 加载流程

```rust
// crates/winemu-core/src/syscall.rs

impl SyscallTable {
    /// 从 TOML 配置文件加载，通过 hypercall 在 Guest Kernel 启动时调用
    pub fn load_from_toml(data: &str) -> Result<Self> {
        let config: SyscallConfig = toml::from_str(data)?;
        let mut nt = HashMap::new();
        let mut win32k = HashMap::new();

        for (name, nr) in &config.nt {
            if let Some(id) = SyscallId::from_name(name) {
                nt.insert(*nr, id);
            }
        }
        for (name, nr) in &config.win32k {
            if let Some(id) = SyscallId::from_name(name) {
                win32k.insert(*nr, id);
            }
        }
        Ok(Self { nt, win32k })
    }
}
```

### Guest Kernel 启动时加载

```rust
// winemu-kernel/src/syscall/mod.rs

static SYSCALL_TABLE: OnceCell<SyscallTable> = OnceCell::new();

pub fn init() {
    // 1. 通过 hypercall 从 Host 读取配置文件内容
    let toml_data = hypercall::load_syscall_table();

    // 2. 解析并存入全局表
    let table = SyscallTable::load_from_toml(&toml_data)
        .expect("failed to load syscall table");
    SYSCALL_TABLE.set(table).ok();

    // 3. 安装 SVC 向量表
    install_exception_vectors();
}

pub fn dispatch(nr: u32, args: &[u64; 8]) -> u32 {
    let id = SYSCALL_TABLE.get().unwrap().lookup(nr);
    handlers::dispatch(id, args)
}
```

### CLI 配置

```bash
# 指定目标 Windows 版本的调用号表
winemu run --syscall-table config/syscall-tables/win11-arm64.toml hello.exe

# 默认使用 win11-arm64.toml
winemu run hello.exe
```

### 内置调用号表

```
config/syscall-tables/
├── win11-arm64.toml      # Windows 11 ARM64 (默认)
├── win11-x64.toml        # Windows 11 x86_64
├── win10-arm64.toml      # Windows 10 ARM64
└── win10-x64.toml        # Windows 10 x86_64
```

> 调用号数据从 [SyscallTables](https://github.com/hfiref0x/SyscallTables) 提取，以脚本自动生成 TOML 文件。

### Hypercall 编号常量

Hypercall 仅用于跨越 VM 边界调用 Host 原生库（unix call 替代路径），与 NT syscall 编号空间完全独立。

```rust
// crates/winemu-core/src/hypercall.rs

pub mod nr {
    // 系统
    pub const KERNEL_READY:           u64 = 0x0000;
    pub const DEBUG_PRINT:            u64 = 0x0001;
    pub const LOAD_SYSCALL_TABLE:     u64 = 0x0002; // 启动时加载调用号表

    // 文件系统辅助（加载 DLL 镜像到 Guest 内存，非 NT syscall）
    pub const LOAD_DLL_IMAGE:         u64 = 0x0300;

    // 图形 unix call: 0x0100 - 0x01FF
    pub const WIN32U_CREATE_WINDOW: u64 = 0x0100;
    pub const WIN32U_SHOW_WINDOW:   u64 = 0x0101;
    pub const WIN32U_DESTROY_WINDOW: u64 = 0x0102;
    pub const WIN32U_MSG_CALL:      u64 = 0x0103;
    pub const WIN32U_GDI_BITBLT:    u64 = 0x0110;
    pub const VULKAN_CALL:          u64 = 0x0120; // winevulkan unix call

    // 音频 unix call: 0x0200 - 0x02FF
    pub const WAVE_OUT_OPEN:        u64 = 0x0200;
    pub const WAVE_OUT_WRITE:       u64 = 0x0201;
    pub const WAVE_OUT_CLOSE:       u64 = 0x0202;
}
```

---

## P0-3: CI 配置

### .github/workflows/ci.yml

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  build-macos:
    runs-on: macos-14          # Apple Silicon
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - run: cargo fmt --check
      - run: cargo clippy --workspace -- -D warnings
      - run: cargo build --workspace
      - run: cargo test --workspace

  build-linux-x64:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - run: cargo fmt --check
      - run: cargo clippy --workspace -- -D warnings
      - run: cargo build --workspace
      - run: cargo test --workspace

  build-linux-arm64:
    runs-on: ubuntu-24.04-arm  # GitHub hosted ARM64
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --workspace
      - run: cargo test --workspace
```

### 平台 feature flags 约定

```rust
// 在各 crate 中统一使用以下 cfg 条件
#[cfg(target_os = "macos")]
mod hvf;

#[cfg(target_os = "linux")]
mod kvm;

#[cfg(target_arch = "aarch64")]
mod arm64;

#[cfg(target_arch = "x86_64")]
mod x86_64;
```

---

## P0-4: 验收标准

- [ ] `cargo build --workspace` 在 macOS ARM64 通过
- [ ] `cargo build --workspace` 在 Linux x86_64 通过
- [ ] `cargo test --workspace` 全绿
- [ ] `cargo clippy --workspace -- -D warnings` 无警告
- [ ] `cargo fmt --check` 通过
- [ ] CI 三个平台 job 全绿
- [ ] 核心类型单元测试：`Gpa::align_up/down`、`MemProt::from_win32`、`NtStatus` 转换
