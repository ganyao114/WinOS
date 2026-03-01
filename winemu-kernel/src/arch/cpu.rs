type Backend = super::backend::ArchBackend;

#[inline(always)]
pub fn current_cpu_local() -> u64 {
    <Backend as super::contract::CpuBackend>::cpu_local_read()
}

#[inline(always)]
pub fn set_current_cpu_local(value: u64) {
    <Backend as super::contract::CpuBackend>::cpu_local_write(value);
}

#[inline(always)]
pub fn current_fault_syndrome() -> u64 {
    <Backend as super::contract::CpuBackend>::fault_syndrome_read()
}

#[inline(always)]
pub fn current_fault_address() -> u64 {
    <Backend as super::contract::CpuBackend>::fault_address_read()
}

#[inline(always)]
pub fn wait_for_interrupt() {
    <Backend as super::contract::CpuBackend>::wait_for_interrupt();
}

#[inline(always)]
pub fn irq_enable() {
    <Backend as super::contract::CpuBackend>::irq_enable();
}

#[inline(always)]
pub fn irq_disable() {
    <Backend as super::contract::CpuBackend>::irq_disable();
}
