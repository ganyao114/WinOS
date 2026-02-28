#[inline(always)]
pub fn current_cpu_local() -> u64 {
    super::backend::cpu::cpu_local_read()
}

#[inline(always)]
pub fn set_current_cpu_local(value: u64) {
    super::backend::cpu::cpu_local_write(value);
}

#[inline(always)]
pub fn current_fault_syndrome() -> u64 {
    super::backend::cpu::fault_syndrome_read()
}

#[inline(always)]
pub fn current_fault_address() -> u64 {
    super::backend::cpu::fault_address_read()
}

#[inline(always)]
pub fn wait_for_interrupt() {
    super::backend::cpu::wait_for_interrupt();
}
