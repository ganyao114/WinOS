use super::ffi;
use winemu_core::{Result, WinemuError};

// HVF virtual timer shim.
pub(super) struct HvfVTimer;

impl HvfVTimer {
    pub(super) const fn new() -> Self {
        Self
    }

    pub(super) fn on_vtimer_activated(&mut self, vcpu: ffi::hv_vcpuid_t) -> Result<()> {
        let _ = vcpu;
        Ok(())
    }

    pub(super) fn prepare_run(
        &mut self,
        vcpu: ffi::hv_vcpuid_t,
        use_vtimer_exit: bool,
    ) -> Result<()> {
        if !use_vtimer_exit {
            return set_vtimer_mask(vcpu, true);
        }

        // Keep vtimer exit path enabled. Guest controls next one-shot by
        // programming CNTV_* registers explicitly.
        set_vtimer_mask(vcpu, false)
    }
}

fn set_vtimer_mask(vcpu: ffi::hv_vcpuid_t, masked: bool) -> Result<()> {
    let ret = unsafe { ffi::hv_vcpu_set_vtimer_mask(vcpu, masked) };
    if ret != ffi::HV_SUCCESS {
        return Err(WinemuError::Hypervisor(format!(
            "hv_vcpu_set_vtimer_mask({}) failed: {:#x}",
            masked, ret
        )));
    }
    Ok(())
}
