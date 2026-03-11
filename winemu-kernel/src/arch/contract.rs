use super::context_types::{KernelContext, ThreadContext};
use super::trap_frame::SvcFrame;

#[derive(Clone, Copy)]
pub struct TrapFaultInfo {
    pub syndrome: u64,
    pub address: u64,
}

pub trait CpuBackend {
    fn boot_vcpu_id() -> u32;
    fn cpu_local_read() -> u64;
    fn cpu_local_write(value: u64);
    fn fault_syndrome_read() -> u64;
    fn fault_address_read() -> u64;
    fn wait_for_interrupt();
    fn wait_for_event();
    fn send_event();
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
    fn invoke6_pair(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> (u64, u64);
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

pub trait TrapBackend {
    fn interrupted_user_mode(frame: &SvcFrame) -> bool;
    fn current_fault_info() -> TrapFaultInfo;
}

pub trait VectorsBackend {
    fn install_exception_vectors();
    fn default_kernel_stack_top() -> u64;
}

pub trait ContextBackend {
    // Capture current kernel continuation into ctx.
    // Returns 0 on initial capture; non-zero when resumed through
    // switch_kernel_context().
    unsafe fn save_kernel_context(ctx: *mut KernelContext) -> u64;

    // Non-local context switch between two kernel continuations.
    // Safety: pointers must refer to valid KernelContext objects that live
    // across switches.
    unsafe fn switch_kernel_context(from: *mut KernelContext, to: *const KernelContext);

    // Enter a kernel continuation directly without saving current context.
    // Safety: ctx must point to a live continuation context prepared by scheduler.
    unsafe fn enter_kernel_context(ctx: *const KernelContext) -> !;

    // Restore full user register state from ThreadContext and enter user mode.
    // Safety: ctx must point to a live thread context owned by scheduler state.
    unsafe fn enter_user_thread_context(ctx: *const ThreadContext) -> !;

    // Apply a guest user CONTEXT record onto the current trap frame.
    // Returns false when the byte layout is invalid for this backend.
    fn restore_user_context_record(frame: &mut SvcFrame, context: &[u8]) -> bool;

    // Initialize a fresh user thread start context using the backend ABI.
    fn initialize_user_thread_context(
        ctx: &mut ThreadContext,
        program_counter: u64,
        stack_pointer: u64,
        thread_pointer: u64,
        arg0: u64,
        arg1: u64,
    );
}

pub trait KernelArchBackend:
    CpuBackend
    + MmuBackend
    + HypercallBackend
    + SpinBackend
    + TimerBackend
    + TrapBackend
    + VectorsBackend
    + ContextBackend
{
}

impl<T> KernelArchBackend for T where
    T: CpuBackend
        + MmuBackend
        + HypercallBackend
        + SpinBackend
        + TimerBackend
        + TrapBackend
        + VectorsBackend
        + ContextBackend
{
}
