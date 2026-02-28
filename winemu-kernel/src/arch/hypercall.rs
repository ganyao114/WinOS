use crate::nt::SvcFrame;

#[inline(always)]
pub fn invoke6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    super::backend::hypercall::invoke6(nr, a0, a1, a2, a3, a4, a5)
}

#[inline(always)]
pub fn forward_nt_syscall(frame: &SvcFrame, nr: u16, table: u8) -> u64 {
    super::backend::hypercall::forward_nt_syscall(frame, nr, table)
}
