#[repr(C)]
pub struct SvcFrame {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr: u64,
    pub spsr: u64,
    pub tpidr: u64,
    pub x8_orig: u64,
}

impl SvcFrame {
    #[inline(always)]
    pub fn user_sp(&self) -> u64 {
        self.sp_el0
    }

    #[inline(always)]
    pub fn set_user_sp(&mut self, value: u64) {
        self.sp_el0 = value;
    }

    #[inline(always)]
    pub fn program_counter(&self) -> u64 {
        self.elr
    }

    #[inline(always)]
    pub fn set_program_counter(&mut self, value: u64) {
        self.elr = value;
    }

    #[inline(always)]
    pub fn processor_state(&self) -> u64 {
        self.spsr
    }

    #[inline(always)]
    pub fn set_processor_state(&mut self, value: u64) {
        self.spsr = value;
    }

    #[inline(always)]
    pub fn thread_pointer(&self) -> u64 {
        self.tpidr
    }

    #[inline(always)]
    pub fn set_thread_pointer(&mut self, value: u64) {
        self.tpidr = value;
    }
}

pub const SVC_FRAME_SIZE: usize = 0x120;
const _: [(); SVC_FRAME_SIZE] = [(); core::mem::size_of::<SvcFrame>()];
