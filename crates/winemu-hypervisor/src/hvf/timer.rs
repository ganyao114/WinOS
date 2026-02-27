use super::ffi;
use winemu_core::{Result, WinemuError};

// HVF virtual timer state machine.
// We keep vtimer masked after an activation exit until guest timer IRQ handler
// performs EOI by clearing CNTV_CTL_EL0.ENABLE.
pub(super) struct HvfVTimer {
    waiting_guest_eoi: bool,
}

impl HvfVTimer {
    pub(super) const fn new() -> Self {
        Self {
            waiting_guest_eoi: false,
        }
    }

    pub(super) fn on_vtimer_activated(&mut self, vcpu: ffi::hv_vcpuid_t) -> Result<()> {
        let ret =
            unsafe { ffi::hv_vcpu_set_pending_interrupt(vcpu, ffi::HV_INTERRUPT_TYPE_IRQ, true) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!(
                "hv_vcpu_set_pending_interrupt(IRQ) failed: {:#x}",
                ret
            )));
        }
        self.waiting_guest_eoi = true;
        Ok(())
    }

    pub(super) fn prepare_run(
        &mut self,
        vcpu: ffi::hv_vcpuid_t,
        use_vtimer_exit: bool,
    ) -> Result<()> {
        if !use_vtimer_exit {
            self.waiting_guest_eoi = false;
            return set_vtimer_mask(vcpu, true);
        }

        // Keep masked after activation until guest timer IRQ handler writes
        // CNTV_CTL_EL0.ENABLE=0 (our guest EOI contract).
        let mask = if self.waiting_guest_eoi {
            let cntv_ctl = get_sys_reg(vcpu, ffi::HV_SYS_REG_CNTV_CTL_EL0)?;
            if (cntv_ctl & 0x1) == 0 {
                self.waiting_guest_eoi = false;
                false
            } else {
                true
            }
        } else {
            false
        };

        set_vtimer_mask(vcpu, mask)
    }
}

fn get_sys_reg(vcpu: ffi::hv_vcpuid_t, reg: ffi::hv_sys_reg_t) -> Result<u64> {
    let mut val = 0u64;
    let ret = unsafe { ffi::hv_vcpu_get_sys_reg(vcpu, reg, &mut val) };
    if ret != ffi::HV_SUCCESS {
        return Err(WinemuError::Hypervisor(format!(
            "hv_vcpu_get_sys_reg({:#x}) failed: {:#x}",
            reg, ret
        )));
    }
    Ok(val)
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
