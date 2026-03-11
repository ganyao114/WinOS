type Backend = super::backend::ArchBackend;

pub use super::contract::TrapFaultInfo;
pub use super::trap_frame::SvcFrame;

#[inline(always)]
pub fn interrupted_user_mode(frame: &SvcFrame) -> bool {
    <Backend as super::contract::TrapBackend>::interrupted_user_mode(frame)
}

#[inline(always)]
pub fn current_fault_info() -> TrapFaultInfo {
    <Backend as super::contract::TrapBackend>::current_fault_info()
}
