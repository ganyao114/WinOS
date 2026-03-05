use super::ffi;
use super::vcpu::HvfVcpu;
use crate::{Vcpu, Vm, VmConfig};
use winemu_core::{addr::Gpa, mem::MemProt, Result, WinemuError};

pub struct HvfVm {
    #[allow(dead_code)]
    config: VmConfig,
}

impl HvfVm {
    pub fn new(config: VmConfig) -> Self {
        Self { config }
    }
}

impl Vm for HvfVm {
    fn map_memory(&self, gpa: Gpa, hva: *mut u8, size: usize, prot: MemProt) -> Result<()> {
        let mut flags: ffi::hv_memory_flags_t = 0;
        if prot.contains(MemProt::READ) {
            flags |= ffi::HV_MEMORY_READ;
        }
        if prot.contains(MemProt::WRITE) {
            flags |= ffi::HV_MEMORY_WRITE;
        }
        if prot.contains(MemProt::EXEC) {
            flags |= ffi::HV_MEMORY_EXEC;
        }

        let ret = unsafe { ffi::hv_vm_map(hva, gpa.0, size, flags) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!(
                "hv_vm_map failed: {:#x}",
                ret
            )));
        }
        Ok(())
    }

    fn unmap_memory(&self, gpa: Gpa, size: usize) -> Result<()> {
        let ret = unsafe { ffi::hv_vm_unmap(gpa.0, size) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!(
                "hv_vm_unmap failed: {:#x}",
                ret
            )));
        }
        Ok(())
    }

    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>> {
        Ok(Box::new(HvfVcpu::new(id)?))
    }
}
