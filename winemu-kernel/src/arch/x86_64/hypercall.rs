use crate::nt::SvcFrame;

#[inline(always)]
fn unsupported() -> ! {
    panic!("x86_64 backend is a stub");
}

#[inline(always)]
pub fn invoke6(_nr: u64, _a0: u64, _a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> u64 {
    unsupported()
}

#[inline(always)]
pub fn forward_nt_syscall(_frame: &SvcFrame, _nr: u16, _table: u8) -> u64 {
    unsupported()
}
