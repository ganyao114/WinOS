pub mod boot;
pub mod cpu;
pub mod hypercall;
pub mod mmu;
pub mod spin;
pub mod timer;
pub mod vectors;

pub struct ArchBackend;

impl super::contract::CpuBackend for ArchBackend {
    #[inline(always)]
    fn cpu_local_read() -> u64 {
        cpu::cpu_local_read()
    }

    #[inline(always)]
    fn cpu_local_write(value: u64) {
        cpu::cpu_local_write(value);
    }

    #[inline(always)]
    fn fault_syndrome_read() -> u64 {
        cpu::fault_syndrome_read()
    }

    #[inline(always)]
    fn fault_address_read() -> u64 {
        cpu::fault_address_read()
    }

    #[inline(always)]
    fn wait_for_interrupt() {
        cpu::wait_for_interrupt();
    }

    #[inline(always)]
    fn irq_enable() {
        cpu::irq_enable();
    }

    #[inline(always)]
    fn irq_disable() {
        cpu::irq_disable();
    }
}

impl super::contract::MmuBackend for ArchBackend {
    #[inline(always)]
    fn memory_features_raw() -> u64 {
        mmu::memory_features_raw()
    }

    #[inline(always)]
    fn physical_addr_range(features_raw: u64) -> u8 {
        mmu::physical_addr_range(features_raw)
    }

    #[inline(always)]
    fn supports_4k_granule(features_raw: u64) -> bool {
        mmu::supports_4k_granule(features_raw)
    }

    #[inline(always)]
    fn supports_64k_granule(features_raw: u64) -> bool {
        mmu::supports_64k_granule(features_raw)
    }

    #[inline(always)]
    fn current_user_table_root() -> u64 {
        mmu::current_user_table_root()
    }

    #[inline(always)]
    fn set_user_table_root(root: u64) {
        mmu::set_user_table_root(root);
    }

    #[inline(always)]
    fn flush_tlb_global() {
        mmu::flush_tlb_global();
    }

    #[inline(always)]
    fn apply_translation_config(memory_attrs: u64, translation_control: u64, user_table_root: u64) {
        mmu::apply_translation_config(memory_attrs, translation_control, user_table_root);
    }

    #[inline(always)]
    fn read_system_control() -> u64 {
        mmu::read_system_control()
    }

    #[inline(always)]
    fn write_system_control(value: u64) {
        mmu::write_system_control(value);
    }

    #[inline(always)]
    fn instruction_barrier() {
        mmu::instruction_barrier();
    }
}

impl super::contract::HypercallBackend for ArchBackend {
    #[inline(always)]
    fn invoke6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
        hypercall::invoke6(nr, a0, a1, a2, a3, a4, a5)
    }

    #[inline(always)]
    fn forward_nt_syscall(frame: &crate::nt::SvcFrame, nr: u16, table: u8) -> u64 {
        hypercall::forward_nt_syscall(frame, nr, table)
    }
}

impl super::contract::SpinBackend for ArchBackend {
    #[inline(always)]
    fn lock_word(lock_ptr: *mut u32) {
        spin::lock_word(lock_ptr);
    }

    #[inline(always)]
    fn unlock_word(lock_ptr: *mut u32) {
        spin::unlock_word(lock_ptr);
    }
}

impl super::contract::TimerBackend for ArchBackend {
    const DEFAULT_TIMESLICE_100NS: u64 = timer::DEFAULT_TIMESLICE_100NS;

    #[inline(always)]
    fn schedule_running_slice_100ns(now_100ns: u64, next_deadline_100ns: u64, quantum_100ns: u64) {
        timer::schedule_running_slice_100ns(now_100ns, next_deadline_100ns, quantum_100ns);
    }

    #[inline(always)]
    fn idle_wait_until_deadline_100ns(now_100ns: u64, next_deadline_100ns: u64) {
        timer::idle_wait_until_deadline_100ns(now_100ns, next_deadline_100ns);
    }
}

impl super::contract::VectorsBackend for ArchBackend {
    #[inline(always)]
    fn install_exception_vectors() {
        vectors::install_exception_vectors();
    }
}
