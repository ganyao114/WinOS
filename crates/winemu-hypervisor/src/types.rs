pub struct VmConfig {
    pub memory_size: usize, // 字节，16KB 对齐
    pub vcpu_count: u32,
}

#[derive(Debug)]
pub enum VmExit {
    Hypercall { nr: u64, args: [u64; 6] },
    MmioRead { addr: u64, size: u8 },
    MmioWrite { addr: u64, data: u64, size: u8 },
    IoRead { port: u16, size: u8 },
    IoWrite { port: u16, data: u32, size: u8 },
    Timer,
    Wfi,
    Halt,
    Shutdown,
    Unknown(u32),
}

// ARM64 寄存器
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct Regs {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

// x86_64 寄存器
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct Regs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

#[derive(Debug, Default, Clone)]
pub struct SpecialRegs {
    // ARM64: system registers; x86_64: segment registers + control registers
    // 具体字段在各平台后端填充，此处作为占位
    pub data: [u64; 32],
}
