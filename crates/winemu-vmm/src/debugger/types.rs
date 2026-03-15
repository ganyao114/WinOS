use winemu_hypervisor::{Regs, SpecialRegs};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebugState {
    Running,
    PauseRequested,
    Paused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    ManualPause,
    GuestDebugTrap {
        code: u64,
        arg0: u64,
        arg1: u64,
    },
    DebugException {
        syndrome: u64,
        virtual_address: u64,
        physical_address: u64,
    },
}

#[derive(Clone, Debug)]
pub struct VcpuSnapshot {
    pub vcpu_id: u32,
    pub regs: Regs,
    pub special_regs: SpecialRegs,
    pub reason: StopReason,
}

pub struct Aarch64SystemRegs {
    pub sctlr_el1: u64,
    pub tcr_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub mair_el1: u64,
    pub vbar_el1: u64,
}

impl VcpuSnapshot {
    pub fn aarch64_system_regs(&self) -> Option<Aarch64SystemRegs> {
        #[cfg(target_arch = "aarch64")]
        {
            Some(Aarch64SystemRegs {
                sctlr_el1: self.special_regs.data[0],
                tcr_el1: self.special_regs.data[1],
                ttbr0_el1: self.special_regs.data[2],
                ttbr1_el1: self.special_regs.data[3],
                mair_el1: self.special_regs.data[4],
                vbar_el1: self.special_regs.data[5],
            })
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            None
        }
    }
}
