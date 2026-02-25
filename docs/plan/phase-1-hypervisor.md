# Phase 1 — Hypervisor 层 + 最小 Guest Kernel (第 3-8 周)

## 目标

能够启动一个最小 Guest，执行几条指令后通过 hypercall 退出，Host 正确接收。

---

## P1-1: Hypervisor 抽象层 (第 3-4 周)

### 接口定义

```rust
// crates/winemu-hypervisor/src/lib.rs

pub trait Hypervisor: Send + Sync {
    fn create_vm(&self, config: VmConfig) -> Result<Box<dyn Vm>>;
}

pub trait Vm: Send + Sync {
    fn map_memory(&self, gpa: Gpa, hva: *mut u8, size: usize, prot: MemProt) -> Result<()>;
    fn unmap_memory(&self, gpa: Gpa, size: usize) -> Result<()>;
    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>>;
}

pub trait Vcpu: Send {
    fn run(&mut self) -> Result<VmExit>;
    fn regs(&self) -> Result<Regs>;
    fn set_regs(&mut self, r: &Regs) -> Result<()>;
    fn special_regs(&self) -> Result<SpecialRegs>;
    fn set_special_regs(&mut self, sr: &SpecialRegs) -> Result<()>;
    fn advance_pc(&mut self, bytes: u64) -> Result<()>;
}

pub struct VmConfig {
    pub memory_size: usize,   // 字节，16KB 对齐
    pub vcpu_count: u32,
}

pub enum VmExit {
    Hypercall { nr: u64, args: [u64; 6] },
    MmioRead  { addr: u64, size: u8 },
    MmioWrite { addr: u64, data: u64, size: u8 },
    IoRead    { port: u16, size: u8 },          // x86 only
    IoWrite   { port: u16, data: u32, size: u8 }, // x86 only
    Halt,
    Shutdown,
    Unknown(u32),
}
```

### 寄存器结构

```rust
// ARM64
#[repr(C)]
pub struct Regs {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

// x86_64
#[repr(C)]
pub struct Regs {
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rsp: u64, pub rbp: u64,
    pub r8:  u64, pub r9:  u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64, pub rflags: u64,
}
```

---

## P1-2: HVF 后端 (macOS) (第 3-4 周)

### build.rs

```rust
// crates/winemu-hypervisor/build.rs
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "macos" {
        println!("cargo:rustc-link-lib=framework=Hypervisor");
    }
}
```

### FFI 绑定

```rust
// crates/winemu-hypervisor/src/hvf/ffi.rs
#[allow(non_camel_case_types)]
mod sys {
    pub type hv_return_t = i32;
    pub type hv_vcpuid_t = u64;
    pub type hv_memory_flags_t = u64;

    pub const HV_SUCCESS: hv_return_t = 0;
    pub const HV_MEMORY_READ:  hv_memory_flags_t = 1 << 0;
    pub const HV_MEMORY_WRITE: hv_memory_flags_t = 1 << 1;
    pub const HV_MEMORY_EXEC:  hv_memory_flags_t = 1 << 2;

    extern "C" {
        pub fn hv_vm_create(config: *mut std::ffi::c_void) -> hv_return_t;
        pub fn hv_vm_destroy() -> hv_return_t;
        pub fn hv_vm_map(uva: *mut u8, gpa: u64, size: usize,
                         flags: hv_memory_flags_t) -> hv_return_t;
        pub fn hv_vm_unmap(gpa: u64, size: usize) -> hv_return_t;
    }
}
```

### ARM64 vCPU 退出处理

```rust
// crates/winemu-hypervisor/src/hvf/vcpu_arm64.rs

fn parse_exit(vcpu: hv_vcpuid_t) -> Result<VmExit> {
    let exit_reason = read_sys_reg(vcpu, HV_SYS_REG_ESR_EL1)?;
    let ec = (exit_reason >> 26) & 0x3F;

    match ec {
        0x16 => {
            // HVC — hypercall
            let regs = get_regs(vcpu)?;
            Ok(VmExit::Hypercall {
                nr: regs.x[0],
                args: [regs.x[1], regs.x[2], regs.x[3],
                       regs.x[4], regs.x[5], regs.x[6]],
            })
        }
        0x24 | 0x25 => {
            // Data Abort — MMIO
            let far = read_sys_reg(vcpu, HV_SYS_REG_FAR_EL1)?;
            let iss = exit_reason & 0x1FFFFFF;
            let is_write = (iss >> 6) & 1 != 0;
            let sas = (iss >> 10) & 3;
            let size = 1u8 << sas;
            if is_write {
                let rt = (iss & 0x1F) as usize;
                let data = get_regs(vcpu)?.x[rt];
                Ok(VmExit::MmioWrite { addr: far, data, size })
            } else {
                Ok(VmExit::MmioRead { addr: far, size })
            }
        }
        _ => Ok(VmExit::Unknown(ec as u32)),
    }
}
```

---

## P1-3: KVM 后端 (Linux) (第 3-4 周)

```rust
// crates/winemu-hypervisor/src/kvm/mod.rs
use kvm_ioctls::{Kvm, VmFd, VcpuFd};

pub struct KvmHypervisor {
    kvm: Kvm,
}

impl Hypervisor for KvmHypervisor {
    fn create_vm(&self, config: VmConfig) -> Result<Box<dyn Vm>> {
        let vm_fd = self.kvm.create_vm()?;
        Ok(Box::new(KvmVm { vm_fd, config }))
    }
}

impl Vm for KvmVm {
    fn map_memory(&self, gpa: Gpa, hva: *mut u8,
                  size: usize, _prot: MemProt) -> Result<()> {
        use kvm_ioctls::MemoryRegion;
        let region = MemoryRegion {
            slot: self.next_slot(),
            guest_phys_addr: gpa.0,
            memory_size: size as u64,
            userspace_addr: hva as u64,
            flags: 0,
        };
        self.vm_fd.set_user_memory_region(region)?;
        Ok(())
    }
}
```

### KVM ARM64 vCPU 初始化

```rust
fn init_vcpu_arm64(vcpu_fd: &VcpuFd) -> Result<()> {
    use kvm_ioctls::VcpuInit;
    let mut init = VcpuInit::default();
    // 启用 PSCI 0.2 和 PMU
    init.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
    init.features[0] |= 1 << KVM_ARM_VCPU_PMU_V3;
    vcpu_fd.vcpu_init(&init)?;
    Ok(())
}
```

### KVM 退出处理

```rust
fn handle_exit(exit: kvm_ioctls::VcpuExit) -> VmExit {
    match exit {
        kvm_ioctls::VcpuExit::Hlt => VmExit::Halt,
        kvm_ioctls::VcpuExit::MmioRead(addr, data, len) => {
            VmExit::MmioRead { addr, size: len as u8 }
        }
        kvm_ioctls::VcpuExit::MmioWrite(addr, data, len) => {
            VmExit::MmioWrite { addr, data: u64_from_bytes(data, len), size: len as u8 }
        }
        kvm_ioctls::VcpuExit::Hypercall => {
            // ARM64: x0=nr, x1-x6=args
            // x86_64: rax=nr, rdi/rsi/rdx/rcx/r8/r9=args
            todo!("read regs and construct VmExit::Hypercall")
        }
        _ => VmExit::Unknown(0),
    }
}
```

### P1-1/P1-2/P1-3 验收

- [ ] 单元测试：创建 VM，映射 1MB 内存，写入 `HVC #0; HLT` 指令序列
- [ ] 运行后收到 `VmExit::Hypercall { nr: 0, .. }`，随后收到 `VmExit::Halt`
- [ ] macOS 和 Linux 均通过

---

## P1-4: 最小 Guest Kernel 骨架 (第 5-6 周)

Guest Kernel 编译为裸机二进制，加载到 Guest 物理地址 `0x40000000` (ARM64)。

### 编译目标

```
# ARM64 裸机
aarch64-unknown-none

# x86_64 裸机
x86_64-unknown-none
```

### 链接脚本 (ARM64)

```ld
/* winemu-kernel/link.ld */
ENTRY(_start)

SECTIONS {
    . = 0x40000000;

    .text : {
        KEEP(*(.text.start))
        *(.text .text.*)
    }

    .rodata : { *(.rodata .rodata.*) }

    .data : { *(.data .data.*) }

    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss .bss.*)
        __bss_end = .;
    }

    . = ALIGN(4096);
    __kernel_end = .;
}
```

### 启动代码

```rust
// winemu-kernel/src/start.rs
#![no_std]
#![no_main]

use core::arch::global_asm;

global_asm!(
    ".section .text.start",
    ".global _start",
    "_start:",
    // 清零 BSS
    "adr x0, __bss_start",
    "adr x1, __bss_end",
    "1: cmp x0, x1",
    "   b.ge 2f",
    "   str xzr, [x0], #8",
    "   b 1b",
    "2:",
    // 设置栈 (内核栈放在 0x40000000 下方)
    "adr x0, __kernel_stack_top",
    "mov sp, x0",
    // 跳转到 Rust 入口
    "bl kernel_main",
    // 不应返回
    "1: wfe",
    "   b 1b",
);

// 内核栈 (16KB)
#[link_section = ".bss"]
static mut KERNEL_STACK: [u8; 16 * 1024] = [0u8; 16 * 1024];

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    mm::init();
    syscall::init();   // 安装 SVC/SYSCALL 向量表
    hypercall::kernel_ready();
    loop {
        // 调度循环 (Phase 2 实现)
        core::hint::spin_loop();
    }
}
```

### MMU 初始化 (ARM64)

```rust
// winemu-kernel/src/mm/mmu.rs

// 页表基地址 (静态分配，4KB 对齐)
#[repr(align(4096))]
struct PageTable([u64; 512]);

static mut L0_TABLE: PageTable = PageTable([0u64; 512]);
static mut L1_TABLE: PageTable = PageTable([0u64; 512]);

pub fn init() {
    unsafe {
        // 内核段: GPA 0x40000000 → VA 0xFFFF000040000000
        // 用户段: 0x0 - 0x0000_7FFF_FFFF_FFFF (留空，进程创建时填充)
        setup_kernel_mapping();
        enable_mmu();
    }
}

unsafe fn enable_mmu() {
    use core::arch::asm;
    // TCR_EL1: T0SZ=16 (48-bit VA), T1SZ=16, 4KB granule
    let tcr: u64 = (16 << 0) | (16 << 16) | (0b00 << 14) | (0b10 << 30);
    asm!("msr tcr_el1, {}", in(reg) tcr);
    // MAIR_EL1: attr0=normal memory, attr1=device
    let mair: u64 = 0xFF_00;
    asm!("msr mair_el1, {}", in(reg) mair);
    // TTBR0/TTBR1
    let ttbr0 = L0_TABLE.0.as_ptr() as u64;
    asm!("msr ttbr0_el1, {}", in(reg) ttbr0);
    asm!("msr ttbr1_el1, {}", in(reg) ttbr0); // 暂用同一张表
    asm!("isb");
    // SCTLR_EL1: 开启 MMU
    let mut sctlr: u64;
    asm!("mrs , sctlr_el1", out(reg) sctlr);
    sctlr |= 1; // M bit
    asm!("msr sctlr_el1, {}", in(reg) sctlr);
    asm!("isb");
}
```

### Hypercall 接口

```rust
// winemu-kernel/src/hypercall.rs

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
    hypercall(winemu_core::hypercall::nr::KERNEL_READY, 0, 0, 0);
}

pub fn debug_print(msg: &str) {
    hypercall(
        winemu_core::hypercall::nr::PRINT_DEBUG,
        msg.as_ptr() as u64,
        msg.len() as u64,
        0,
    );
}
```

### P1-4 验收

- [ ] Guest Kernel 编译为裸机二进制，无 std 依赖
- [ ] MMU 开启，不触发 Data Abort
- [ ] 发送 `HYPERCALL_KERNEL_READY`，Host 收到后打印 "Guest kernel ready"

---

## P1-5: VMM 主循环 (第 7-8 周)

### GuestMemory

```rust
// crates/winemu-vmm/src/memory.rs
use memmap2::MmapMut;

pub struct GuestMemory {
    mmap: MmapMut,
    base_gpa: Gpa,
    size: usize,
}

impl GuestMemory {
    pub fn new(size: usize) -> Result<Self> {
        // 分配 16KB 对齐的匿名内存
        let mmap = MmapMut::map_anon(size)?;
        Ok(Self { mmap, base_gpa: Gpa(0x40000000), size })
    }

    pub fn hva(&self) -> *mut u8 {
        self.mmap.as_ptr() as *mut u8
    }

    pub fn read_struct<T: Copy>(&self, gpa: Gpa) -> T {
        let offset = (gpa.0 - self.base_gpa.0) as usize;
        unsafe {
            let ptr = self.mmap.as_ptr().add(offset) as *const T;
            ptr.read_unaligned()
        }
    }

    pub fn write_bytes(&mut self, gpa: Gpa, data: &[u8]) {
        let offset = (gpa.0 - self.base_gpa.0) as usize;
        self.mmap[offset..offset + data.len()].copy_from_slice(data);
    }
}
```

### VMM 结构

```rust
// crates/winemu-vmm/src/lib.rs
pub struct Vmm {
    vm: Box<dyn Vm>,
    memory: GuestMemory,
    hypercall_mgr: HypercallManager,
    vcpu_count: u32,
}

impl Vmm {
    pub fn new(hypervisor: Box<dyn Hypervisor>, kernel_image: &[u8]) -> Result<Self> {
        let vcpu_count = num_cpus::get() as u32;
        let config = VmConfig {
            memory_size: 512 * 1024 * 1024, // 512MB
            vcpu_count,
        };
        let vm = hypervisor.create_vm(config)?;
        let mut memory = GuestMemory::new(512 * 1024 * 1024)?;

        // 映射内存到 VM
        vm.map_memory(memory.base_gpa, memory.hva(),
                      memory.size, MemProt::RWX)?;

        // 加载 Guest Kernel 镜像
        memory.write_bytes(Gpa(0x40000000), kernel_image);

        Ok(Self {
            vm,
            memory,
            hypercall_mgr: HypercallManager::new(),
            vcpu_count,
        })
    }

    pub fn run(&mut self) -> Result<()> {
        let handles: Vec<_> = (0..self.vcpu_count)
            .map(|id| {
                let vcpu = self.vm.create_vcpu(id).unwrap();
                let hc_mgr = self.hypercall_mgr.clone_arc();
                std::thread::spawn(move || vcpu_thread(vcpu, hc_mgr))
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        Ok(())
    }
}
```

### vCPU 线程循环

```rust
// crates/winemu-vmm/src/vcpu.rs
use winemu_core::hypercall::nr;

fn vcpu_thread(mut vcpu: Box<dyn Vcpu>, hc_mgr: Arc<HypercallManager>) {
    loop {
        match vcpu.run().unwrap() {
            VmExit::Hypercall { nr: hypercall_nr, args } => {
                match hc_mgr.dispatch(hypercall_nr, args) {
                    HypercallResult::Sync(ret) => {
                        let mut regs = vcpu.regs().unwrap();
                        regs.x[0] = ret;
                        vcpu.set_regs(&regs).unwrap();
                        vcpu.advance_pc(4).unwrap();
                    }
                    HypercallResult::Async => {
                        // Guest Kernel 已切换线程，vCPU 继续运行
                        vcpu.advance_pc(4).unwrap();
                    }
                }
            }
            VmExit::Halt | VmExit::Shutdown => break,
            exit => log::warn!("unhandled vmexit: {:?}", exit),
        }
    }
}
```

### HypercallManager (Phase 1 最小实现)

```rust
// crates/winemu-vmm/src/hypercall/mod.rs
pub enum HypercallResult {
    Sync(u64),
    Async,
}

pub struct HypercallManager {
    syscall_table_toml: String, // 从 CLI --syscall-table 加载
}

impl HypercallManager {
    pub fn dispatch(&self, nr: u64, args: [u64; 6]) -> HypercallResult {
        match nr {
            winemu_core::hypercall::nr::KERNEL_READY => {
                log::info!("Guest kernel ready");
                HypercallResult::Sync(0)
            }
            winemu_core::hypercall::nr::DEBUG_PRINT => {
                log::debug!("Guest debug print (gva={:#x} len={})", args[0], args[1]);
                HypercallResult::Sync(0)
            }
            winemu_core::hypercall::nr::LOAD_SYSCALL_TABLE => {
                // args[2] == 0: 查询长度; args[2] == 1: 读取内容到 args[0](GVA), args[1]=len
                if args[2] == 0 {
                    HypercallResult::Sync(self.syscall_table_toml.len() as u64)
                } else {
                    // 将 TOML 内容写入 Guest 内存
                    // (实际实现需要 guest_mem 引用，Phase 1 占位)
                    log::debug!("LOAD_SYSCALL_TABLE: writing {} bytes to gva={:#x}",
                                args[1], args[0]);
                    HypercallResult::Sync(0)
                }
            }
            _ => {
                log::warn!("unhandled hypercall nr={:#x}", nr);
                HypercallResult::Sync(u32::MAX as u64) // STATUS_NOT_IMPLEMENTED
            }
        }
    }
}
```

### P1-5 验收

- [ ] `winemu-cli` 能加载 Guest Kernel 镜像并启动
- [ ] Host 收到 `HYPERCALL_KERNEL_READY`，打印 "Guest kernel ready"
- [ ] vCPU 线程正常退出（Guest 发送 HLT 后）
- [ ] `cargo test --workspace` 全绿
