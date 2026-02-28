use crate::{
    types::{Regs, SpecialRegs, VmExit},
    Vcpu,
};
use kvm_ioctls::VcpuFd;
use winemu_core::{Result, WinemuError};

pub struct KvmVcpu {
    vcpu_fd: VcpuFd,
}

impl KvmVcpu {
    pub fn new(vcpu_fd: VcpuFd) -> Result<Self> {
        #[cfg(target_arch = "aarch64")]
        init_vcpu_arm64(&vcpu_fd)?;
        Ok(Self { vcpu_fd })
    }
}

#[cfg(target_arch = "aarch64")]
fn init_vcpu_arm64(vcpu_fd: &VcpuFd) -> Result<()> {
    use kvm_bindings::{kvm_vcpu_init, KVM_ARM_VCPU_PSCI_0_2};
    let mut init = kvm_vcpu_init::default();
    init.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
    vcpu_fd
        .vcpu_init(&init)
        .map_err(|e| WinemuError::Hypervisor(format!("kvm vcpu_init failed: {}", e)))
}

fn u64_from_bytes(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = data.len().min(8);
    buf[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(buf)
}

impl Vcpu for KvmVcpu {
    fn run(&mut self) -> Result<VmExit> {
        match self
            .vcpu_fd
            .run()
            .map_err(|e| WinemuError::Hypervisor(format!("kvm run failed: {}", e)))?
        {
            kvm_ioctls::VcpuExit::Hlt => Ok(VmExit::Halt),
            kvm_ioctls::VcpuExit::MmioRead(addr, data, len) => Ok(VmExit::MmioRead {
                addr,
                size: len as u8,
            }),
            kvm_ioctls::VcpuExit::MmioWrite(addr, data, len) => Ok(VmExit::MmioWrite {
                addr,
                data: u64_from_bytes(&data[..len]),
                size: len as u8,
            }),
            kvm_ioctls::VcpuExit::Hypercall => {
                #[cfg(target_arch = "aarch64")]
                {
                    let regs = self.regs()?;
                    Ok(VmExit::Hypercall {
                        nr: regs.x[0],
                        args: [
                            regs.x[1], regs.x[2], regs.x[3], regs.x[4], regs.x[5], regs.x[6],
                        ],
                    })
                }
                #[cfg(target_arch = "x86_64")]
                {
                    let regs = self.regs()?;
                    Ok(VmExit::Hypercall {
                        nr: regs.rax,
                        args: [regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9],
                    })
                }
            }
            kvm_ioctls::VcpuExit::Shutdown => Ok(VmExit::Shutdown),
            _ => Ok(VmExit::Unknown(0)),
        }
    }

    fn regs(&self) -> Result<Regs> {
        #[cfg(target_arch = "aarch64")]
        {
            // KVM ARM64: use ONE_REG interface
            // Stub: return default for now
            Ok(Regs::default())
        }
        #[cfg(target_arch = "x86_64")]
        {
            let r = self
                .vcpu_fd
                .get_regs()
                .map_err(|e| WinemuError::Hypervisor(format!("kvm get_regs failed: {}", e)))?;
            Ok(Regs {
                rax: r.rax,
                rbx: r.rbx,
                rcx: r.rcx,
                rdx: r.rdx,
                rsi: r.rsi,
                rdi: r.rdi,
                rsp: r.rsp,
                rbp: r.rbp,
                r8: r.r8,
                r9: r.r9,
                r10: r.r10,
                r11: r.r11,
                r12: r.r12,
                r13: r.r13,
                r14: r.r14,
                r15: r.r15,
                rip: r.rip,
                rflags: r.rflags,
            })
        }
    }

    fn set_regs(&mut self, r: &Regs) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            use kvm_bindings::kvm_regs;
            let kr = kvm_regs {
                rax: r.rax,
                rbx: r.rbx,
                rcx: r.rcx,
                rdx: r.rdx,
                rsi: r.rsi,
                rdi: r.rdi,
                rsp: r.rsp,
                rbp: r.rbp,
                r8: r.r8,
                r9: r.r9,
                r10: r.r10,
                r11: r.r11,
                r12: r.r12,
                r13: r.r13,
                r14: r.r14,
                r15: r.r15,
                rip: r.rip,
                rflags: r.rflags,
            };
            self.vcpu_fd
                .set_regs(&kr)
                .map_err(|e| WinemuError::Hypervisor(format!("kvm set_regs failed: {}", e)))?;
        }
        #[cfg(target_arch = "aarch64")]
        {
            let _ = r;
        } // stub
        Ok(())
    }

    fn special_regs(&self) -> Result<SpecialRegs> {
        Ok(SpecialRegs::default())
    }

    fn set_special_regs(&mut self, _sr: &SpecialRegs) -> Result<()> {
        Ok(())
    }

    fn advance_pc(&mut self, bytes: u64) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            let mut r = self.regs()?;
            r.rip += bytes;
            self.set_regs(&r)?;
        }
        #[cfg(target_arch = "aarch64")]
        {
            let _ = bytes;
        } // stub
        Ok(())
    }
}
