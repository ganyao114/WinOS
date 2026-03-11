use crate::arch::contract::TrapFaultInfo;
use crate::arch::trap::SvcFrame;

#[inline(always)]
pub fn interrupted_user_mode(_frame: &SvcFrame) -> bool {
    false
}

#[inline(always)]
pub fn current_fault_info() -> TrapFaultInfo {
    TrapFaultInfo {
        syndrome: super::cpu::fault_syndrome_read(),
        address: super::cpu::fault_address_read(),
    }
}
