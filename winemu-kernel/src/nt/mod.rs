pub mod common;
pub mod constants;
pub mod dispatch;
pub mod file;
pub mod memory;
pub mod object;
pub mod process;
pub mod registry;
pub mod section;
pub mod status;
pub mod state;
pub mod sync;
pub mod sysno;
pub mod thread;

#[repr(C)]
pub struct SvcFrame {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr: u64,
    pub spsr: u64,
    pub tpidr: u64,
    pub x8_orig: u64,
}

pub const SVC_FRAME_SIZE: usize = 0x120;
const _: [(); SVC_FRAME_SIZE] = [(); core::mem::size_of::<SvcFrame>()];
