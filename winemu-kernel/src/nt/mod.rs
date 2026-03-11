pub mod common;
pub mod constants;
pub mod dispatch;
pub mod file;
pub mod kobject;
pub mod memory;
pub mod named_objects;
pub mod object;
pub mod path;
pub mod process;
pub mod registry;
pub mod section;
pub mod state;
pub mod status;
pub mod sync;
pub mod sysno;
pub mod sysno_table;
pub mod system;
pub mod thread;
pub mod token;
pub mod user_args;
pub mod win32k;

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
