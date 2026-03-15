use winemu_core::{addr::Gpa, mem::MemProt, Result};

pub mod types;
pub use types::{DebugCaps, Regs, SpecialRegs, VmConfig, VmExit};

#[cfg(target_os = "macos")]
pub mod hvf;

#[cfg(target_os = "linux")]
pub mod kvm;

pub trait Hypervisor: Send + Sync {
    fn create_vm(&self, config: VmConfig) -> Result<Box<dyn Vm>>;
}

pub trait Vm: Send + Sync {
    fn map_memory(&self, gpa: Gpa, hva: *mut u8, size: usize, prot: MemProt) -> Result<()>;
    fn unmap_memory(&self, gpa: Gpa, size: usize) -> Result<()>;
    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>>;
}

pub trait Vcpu: Send {
    fn debug_caps(&self) -> DebugCaps {
        DebugCaps::default()
    }
    fn run(&mut self) -> Result<VmExit>;
    fn regs(&self) -> Result<Regs>;
    fn set_regs(&mut self, r: &Regs) -> Result<()>;
    fn special_regs(&self) -> Result<SpecialRegs>;
    fn set_special_regs(&mut self, sr: &SpecialRegs) -> Result<()>;
    fn advance_pc(&mut self, bytes: u64) -> Result<()>;
    fn set_return_value(&mut self, val: u64) -> Result<()>;
    /// ELR_EL1 — EL0 return PC saved by SVC entry
    fn elr_el1(&self) -> Result<u64>;
    /// SPSR_EL1 — EL0 pstate saved by SVC entry
    fn spsr_el1(&self) -> Result<u64>;
    /// SP_EL0 — user stack pointer
    fn sp_el0(&self) -> Result<u64>;
    /// Request virtual IRQ pending state (best-effort; backend may ignore).
    fn set_pending_irq(&mut self, _pending: bool) -> Result<()> {
        Ok(())
    }
    /// Trap guest debug exceptions to the host when the backend supports it.
    fn set_trap_debug_exceptions(&mut self, _enabled: bool) -> Result<()> {
        Err(winemu_core::WinemuError::Hypervisor(
            "guest debug exception trapping is not supported by this backend".to_string(),
        ))
    }
    /// Enable or disable guest architectural single-step state.
    fn set_guest_single_step(&mut self, _enabled: bool) -> Result<()> {
        Err(winemu_core::WinemuError::Hypervisor(
            "guest single-step is not supported by this backend".to_string(),
        ))
    }
    /// Optional host-side idle hint for trapped WFI flows.
    /// When available, VMM can park host thread roughly until this deadline.
    fn wfi_idle_hint(&self) -> Option<std::time::Duration> {
        None
    }
}

/// 根据当前平台创建默认 Hypervisor 实例
pub fn create_hypervisor() -> Result<Box<dyn Hypervisor>> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(hvf::HvfHypervisor::new()?))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(kvm::KvmHypervisor::new()?))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(winemu_core::WinemuError::Hypervisor(
            "unsupported platform".into(),
        ))
    }
}
