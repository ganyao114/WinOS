#[repr(C)]
pub struct ThreadContext {
    general_registers: [u64; 31],
    stack_pointer: u64,
    program_counter: u64,
    processor_state: u64,
    thread_pointer: u64,
}

impl ThreadContext {
    pub const fn new() -> Self {
        Self {
            general_registers: [0u64; 31],
            stack_pointer: 0,
            program_counter: 0,
            processor_state: 0,
            thread_pointer: 0,
        }
    }

    #[inline(always)]
    pub fn general_registers(&self) -> &[u64; 31] {
        &self.general_registers
    }

    #[inline(always)]
    pub fn general_registers_mut(&mut self) -> &mut [u64; 31] {
        &mut self.general_registers
    }

    #[inline(always)]
    pub fn copy_general_registers_from(&mut self, registers: &[u64; 31]) {
        self.general_registers.copy_from_slice(registers);
    }

    #[inline(always)]
    pub fn set_general_register(&mut self, index: usize, value: u64) {
        self.general_registers[index] = value;
    }

    #[inline(always)]
    pub fn user_sp(&self) -> u64 {
        self.stack_pointer
    }

    #[inline(always)]
    pub fn set_user_sp(&mut self, value: u64) {
        self.stack_pointer = value;
    }

    #[inline(always)]
    pub fn program_counter(&self) -> u64 {
        self.program_counter
    }

    #[inline(always)]
    pub fn set_program_counter(&mut self, value: u64) {
        self.program_counter = value;
    }

    #[inline(always)]
    pub fn processor_state(&self) -> u64 {
        self.processor_state
    }

    #[inline(always)]
    pub fn set_processor_state(&mut self, value: u64) {
        self.processor_state = value;
    }

    #[inline(always)]
    pub fn thread_pointer(&self) -> u64 {
        self.thread_pointer
    }

    #[inline(always)]
    pub fn set_thread_pointer(&mut self, value: u64) {
        self.thread_pointer = value;
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelContext {
    callee_saved: [u64; 11],
    resume_pc: u64,
    stack_pointer: u64,
}

impl KernelContext {
    pub const fn new() -> Self {
        Self {
            callee_saved: [0u64; 11],
            resume_pc: 0,
            stack_pointer: 0,
        }
    }

    #[inline(always)]
    pub fn has_continuation(&self) -> bool {
        self.stack_pointer != 0 && self.resume_pc != 0
    }

    #[inline(always)]
    pub fn set_continuation(&mut self, stack_top: u64, entry_pc: u64) {
        self.stack_pointer = stack_top;
        self.resume_pc = entry_pc;
        self.callee_saved = [0u64; 11];
    }

    #[inline(always)]
    pub fn stack_pointer(&self) -> u64 {
        self.stack_pointer
    }

    #[inline(always)]
    pub fn resume_pc(&self) -> u64 {
        self.resume_pc
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}
