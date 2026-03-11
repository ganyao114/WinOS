use super::trap::SvcFrame;

type Backend = super::backend::ArchBackend;

#[inline(always)]
pub fn invoke6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    <Backend as super::contract::HypercallBackend>::invoke6(nr, a0, a1, a2, a3, a4, a5)
}

#[inline(always)]
pub fn invoke6_pair(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> (u64, u64) {
    <Backend as super::contract::HypercallBackend>::invoke6_pair(nr, a0, a1, a2, a3, a4, a5)
}

#[inline(always)]
pub fn forward_nt_syscall(frame: &SvcFrame, nr: u16, table: u8) -> u64 {
    <Backend as super::contract::HypercallBackend>::forward_nt_syscall(frame, nr, table)
}
