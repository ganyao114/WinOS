pub mod ffi;
mod timer;
pub mod vcpu;
pub mod vm;

use crate::{Hypervisor, Vm, VmConfig};
use winemu_core::Result;

pub struct HvfHypervisor;

impl HvfHypervisor {
    pub fn new() -> Result<Self> {
        let mut max_vcpus = 0u32;
        let max_ret = unsafe { ffi::hv_vm_get_max_vcpu_count(&mut max_vcpus as *mut u32) };
        if max_ret == ffi::HV_SUCCESS {
            log::info!("hvf: max_vcpu_count={}", max_vcpus);
        }

        let vm_cfg = unsafe { ffi::hv_vm_config_create() };
        let ret = unsafe { ffi::hv_vm_create(vm_cfg) };
        if ret != ffi::HV_SUCCESS {
            return Err(winemu_core::WinemuError::Hypervisor(format!(
                "hv_vm_create failed: {:#x}",
                ret
            )));
        }
        Ok(Self)
    }
}

impl Drop for HvfHypervisor {
    fn drop(&mut self) {
        unsafe {
            ffi::hv_vm_destroy();
        }
    }
}

impl Hypervisor for HvfHypervisor {
    fn create_vm(&self, config: VmConfig) -> Result<Box<dyn Vm>> {
        Ok(Box::new(vm::HvfVm::new(config)))
    }
}
