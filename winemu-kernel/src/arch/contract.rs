use crate::nt::SvcFrame;

pub trait CpuBackend {
    fn cpu_local_read() -> u64;
    fn cpu_local_write(value: u64);
    fn fault_syndrome_read() -> u64;
    fn fault_address_read() -> u64;
    fn wait_for_interrupt();
    fn irq_enable();
    fn irq_disable();
}

pub trait MmuBackend {
    fn memory_features_raw() -> u64;
    fn physical_addr_range(features_raw: u64) -> u8;
    fn supports_4k_granule(features_raw: u64) -> bool;
    fn supports_64k_granule(features_raw: u64) -> bool;
    fn current_user_table_root() -> u64;
    fn set_user_table_root(root: u64);
    fn flush_tlb_global();
    fn apply_translation_config(memory_attrs: u64, translation_control: u64, user_table_root: u64);
    fn read_system_control() -> u64;
    fn write_system_control(value: u64);
    fn instruction_barrier();
}

pub trait HypercallBackend {
    fn invoke6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64;
    fn forward_nt_syscall(frame: &SvcFrame, nr: u16, table: u8) -> u64;
}

pub trait SpinBackend {
    fn lock_word(lock_ptr: *mut u32);
    fn unlock_word(lock_ptr: *mut u32);
}

pub trait TimerBackend {
    const DEFAULT_TIMESLICE_100NS: u64;
    fn schedule_running_slice_100ns(now_100ns: u64, next_deadline_100ns: u64, quantum_100ns: u64);
    fn idle_wait_until_deadline_100ns(now_100ns: u64, next_deadline_100ns: u64);
}

pub trait VectorsBackend {
    fn install_exception_vectors();
}

pub trait KernelArchBackend:
    CpuBackend + MmuBackend + HypercallBackend + SpinBackend + TimerBackend + VectorsBackend
{
}

impl<T> KernelArchBackend for T where
    T: CpuBackend + MmuBackend + HypercallBackend + SpinBackend + TimerBackend + VectorsBackend
{
}
