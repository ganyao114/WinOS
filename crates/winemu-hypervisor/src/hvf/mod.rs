pub mod ffi;
mod timer;
pub mod vcpu;
pub mod vm;

use crate::{Hypervisor, Vm, VmConfig};
use winemu_core::Result;

pub struct HvfHypervisor;

impl HvfHypervisor {
    pub fn new() -> Result<Self> {
        let ret = unsafe { ffi::hv_vm_create(std::ptr::null_mut()) };
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
