#[inline(always)]
fn unsupported() -> ! {
    panic!("x86_64 backend is a stub");
}

#[inline(always)]
pub fn cpu_local_read() -> u64 {
    unsupported()
}

#[inline(always)]
pub fn cpu_local_write(_value: u64) {
    unsupported()
}

#[inline(always)]
pub fn fault_syndrome_read() -> u64 {
    unsupported()
}

#[inline(always)]
pub fn fault_address_read() -> u64 {
    unsupported()
}

#[inline(always)]
pub fn wait_for_interrupt() {
    unsupported()
}

#[inline(always)]
pub fn wait_for_event() {
    unsupported()
}

#[inline(always)]
pub fn send_event() {
    unsupported()
}

#[inline(always)]
pub fn irq_enable() {
    unsupported()
}

#[inline(always)]
pub fn irq_disable() {
    unsupported()
}
