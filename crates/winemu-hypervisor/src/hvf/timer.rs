use super::ffi;
use winemu_core::{Result, WinemuError};

// HVF virtual timer state:
// - EL0 activation: inject virtual IRQ for guest preemption path.
// - EL1 activation (idle WFI wake): no IRQ injection; just wake guest.
// In both cases we temporarily mask vtimer exits until guest clears timer
// fired state (ISTATUS) by EOI/re-arm, preventing activation storms.
pub(super) struct HvfVTimer {
    waiting_guest_clear: bool,
    pending_irq_asserted: bool,
    guest_clear_mask_passes_remaining: u8,
}

impl HvfVTimer {
    pub(super) const fn new() -> Self {
        Self {
            waiting_guest_clear: false,
            pending_irq_asserted: false,
            guest_clear_mask_passes_remaining: 0,
        }
    }

    pub(super) fn on_vtimer_activated(
        &mut self,
        vcpu: ffi::hv_vcpuid_t,
        running_el0: bool,
    ) -> Result<()> {
        if running_el0 {
            set_pending_irq(vcpu, true)?;
            self.pending_irq_asserted = true;
        }
        self.waiting_guest_clear = true;
        // Keep the next re-entry masked so the injected IRQ can be consumed by
        // guest code before HVF reports another VTIMER_ACTIVATED exit. After
        // that single masked pass we must stop waiting, otherwise a quick
        // guest re-arm can leave us stuck in waiting_guest_clear forever.
        self.guest_clear_mask_passes_remaining = 1;
        // Avoid repeated VTIMER_ACTIVATED exits until guest handles this tick.
        set_vtimer_mask(vcpu, true)?;
        Ok(())
    }

    pub(super) fn prepare_run(
        &mut self,
        vcpu: ffi::hv_vcpuid_t,
        use_vtimer_exit: bool,
    ) -> Result<()> {
        if !use_vtimer_exit {
            self.waiting_guest_clear = false;
            if self.pending_irq_asserted {
                set_pending_irq(vcpu, false)?;
                self.pending_irq_asserted = false;
            }
            self.guest_clear_mask_passes_remaining = 0;
            return set_vtimer_mask(vcpu, true);
        }

        if self.waiting_guest_clear {
            let cntv_ctl = get_sys_reg(vcpu, ffi::HV_SYS_REG_CNTV_CTL_EL0)?;
            let enabled = (cntv_ctl & 0x1) != 0;
            let fired = (cntv_ctl & 0x4) != 0;
            // Guest EOI contract: IRQ entry writes CNTV_CTL_EL0=0.
            // Treat "disabled" as an acknowledged tick, otherwise we can keep
            // IRQ pending forever when ISTATUS stays set in HVF.
            if enabled && fired && self.guest_clear_mask_passes_remaining > 0 {
                self.guest_clear_mask_passes_remaining -= 1;
                return set_vtimer_mask(vcpu, true);
            }

            self.waiting_guest_clear = false;
            self.guest_clear_mask_passes_remaining = 0;
            if self.pending_irq_asserted {
                set_pending_irq(vcpu, false)?;
                self.pending_irq_asserted = false;
            }
        }

        // Keep vtimer exits enabled for normal one-shot preemption.
        set_vtimer_mask(vcpu, false)
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

fn set_pending_irq(vcpu: ffi::hv_vcpuid_t, pending: bool) -> Result<()> {
    let ret =
        unsafe { ffi::hv_vcpu_set_pending_interrupt(vcpu, ffi::HV_INTERRUPT_TYPE_IRQ, pending) };
    if ret != ffi::HV_SUCCESS {
        return Err(WinemuError::Hypervisor(format!(
            "hv_vcpu_set_pending_interrupt(IRQ={}) failed: {:#x}",
            pending, ret
        )));
    }
    Ok(())
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
