use super::vcpu::KvmVcpu;
use crate::{Vcpu, Vm, VmConfig};
use kvm_ioctls::VmFd;
use std::sync::atomic::{AtomicU32, Ordering};
use winemu_core::{addr::Gpa, mem::MemProt, Result, WinemuError};

pub struct KvmVm {
    vm_fd: VmFd,
    config: VmConfig,
    next_slot: AtomicU32,
}

impl KvmVm {
    pub fn new(vm_fd: VmFd, config: VmConfig) -> Self {
        Self {
            vm_fd,
            config,
            next_slot: AtomicU32::new(0),
        }
    }
}

impl Vm for KvmVm {
    fn map_memory(&self, gpa: Gpa, hva: *mut u8, size: usize, _prot: MemProt) -> Result<()> {
        let slot = self.next_slot.fetch_add(1, Ordering::SeqCst);
        let region = kvm_ioctls::MemoryRegion {
            slot,
            guest_phys_addr: gpa.0,
            memory_size: size as u64,
            userspace_addr: hva as u64,
            flags: 0,
        };
        self.vm_fd.set_user_memory_region(region).map_err(|e| {
            WinemuError::Hypervisor(format!("kvm set_user_memory_region failed: {}", e))
        })
    }

    fn unmap_memory(&self, _gpa: Gpa, _size: usize) -> Result<()> {
        // KVM: unmap by setting memory_size=0 on the same slot
        // Requires tracking slot→gpa mapping; stub for now
        Ok(())
    }

    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>> {
        let vcpu_fd = self
            .vm_fd
            .create_vcpu(id as u64)
            .map_err(|e| WinemuError::Hypervisor(format!("kvm create_vcpu failed: {}", e)))?;
        Ok(Box::new(KvmVcpu::new(vcpu_fd)?))
    }
}
