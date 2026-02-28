pub mod vcpu;
pub mod vm;

use crate::{Hypervisor, Vm, VmConfig};
use winemu_core::{Result, WinemuError};

pub struct KvmHypervisor {
    kvm: kvm_ioctls::Kvm,
}

impl KvmHypervisor {
    pub fn new() -> Result<Self> {
        let kvm = kvm_ioctls::Kvm::new()
            .map_err(|e| WinemuError::Hypervisor(format!("kvm open failed: {}", e)))?;
        Ok(Self { kvm })
    }
}

impl Hypervisor for KvmHypervisor {
    fn create_vm(&self, config: VmConfig) -> Result<Box<dyn Vm>> {
        let vm_fd = self
            .kvm
            .create_vm()
            .map_err(|e| WinemuError::Hypervisor(format!("kvm create_vm failed: {}", e)))?;
        Ok(Box::new(vm::KvmVm::new(vm_fd, config)))
    }
}
