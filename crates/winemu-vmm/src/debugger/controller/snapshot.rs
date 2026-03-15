use crate::debugger::types::{StopReason, VcpuSnapshot};
use winemu_core::{Result, WinemuError};
use winemu_hypervisor::Vcpu;

pub(super) fn capture_snapshot(
    vcpu_id: u32,
    vcpu: &mut dyn Vcpu,
    reason: StopReason,
) -> Option<VcpuSnapshot> {
    let regs = match vcpu.regs() {
        Ok(regs) => regs,
        Err(err) => {
            log::warn!("debugger: vcpu{} regs snapshot failed: {}", vcpu_id, err);
            return None;
        }
    };
    let special_regs = match vcpu.special_regs() {
        Ok(regs) => regs,
        Err(err) => {
            log::warn!(
                "debugger: vcpu{} special regs snapshot failed: {}",
                vcpu_id,
                err
            );
            return None;
        }
    };
    Some(VcpuSnapshot {
        vcpu_id,
        regs,
        special_regs,
        reason,
    })
}

pub(super) fn apply_snapshot(vcpu_id: u32, vcpu: &mut dyn Vcpu, snapshot: &VcpuSnapshot) {
    if let Err(err) = vcpu.set_regs(&snapshot.regs) {
        log::warn!("debugger: vcpu{} restore regs failed: {}", vcpu_id, err);
        return;
    }
    if let Err(err) = vcpu.set_special_regs(&snapshot.special_regs) {
        log::warn!(
            "debugger: vcpu{} restore special regs failed: {}",
            vcpu_id,
            err
        );
    }
}

pub(super) fn arm_single_step(vcpu_id: u32, vcpu: &mut dyn Vcpu) -> Result<()> {
    vcpu.set_trap_debug_exceptions(true).map_err(|err| {
        WinemuError::Hypervisor(format!(
            "vcpu{} enable debug exception trap failed: {}",
            vcpu_id, err
        ))
    })?;
    vcpu.set_guest_single_step(true).map_err(|err| {
        WinemuError::Hypervisor(format!(
            "vcpu{} enable guest single-step failed: {}",
            vcpu_id, err
        ))
    })
}
