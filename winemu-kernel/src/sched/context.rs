// sched/context.rs — Kernel context switch helpers
//
// Provides:
//   ensure_user_entry_continuation_locked(tid)  — set up kctx for first EL0 entry
//   setup_idle_thread_continuation_locked(tid)  — set up kctx for idle loop
//   set_thread_in_kernel_locked(tid, val)        — update in_kernel flag
//
// The actual assembly context-switch routines are in arch/aarch64/context.rs.

use crate::sched::global::with_thread_mut;
use crate::sched::types::KERNEL_STACK_SIZE;

// ── Assembly stubs (defined in arch/aarch64/context.rs) ──────────────────────

extern "C" {
    /// Save callee-saved regs of `from` kctx, restore `to` kctx.
    /// Signature: fn(from_kctx: *mut KernelContext, to_kctx: *const KernelContext) -> !
    pub fn __sched_switch_kernel_context(from: *mut u8, to: *const u8) -> !;

    /// Enter EL0 from a fresh kernel stack (no saved kctx to restore).
    /// Restores ThreadContext and ERETs to EL0.
    pub fn __sched_enter_user_thread(ctx: *const u8) -> !;

    /// Entry point for new threads — called via kctx.lr after context switch.
    pub fn thread_user_entry_continuation() -> !;

    /// Entry point for idle threads.
    pub fn idle_thread_fn() -> !;
}

// ── Continuation setup ────────────────────────────────────────────────────────

/// Ensure a user thread has a valid kernel continuation (kctx) so it can be
/// scheduled by the unlock-edge or a secondary vCPU.
///
/// If the thread already has a kctx (in_kernel=true or kctx.has_continuation()),
/// this is a no-op.
///
/// Must be called with the scheduler lock held.
pub fn ensure_user_entry_continuation_locked(tid: u32) {
    with_thread_mut(tid, |t| {
        if t.in_kernel || t.kctx.has_continuation() {
            return;
        }
        // Set up a fresh kernel continuation that will ERET into EL0.
        let kstack_top = t.kstack_base + t.kstack_size as u64;
        t.kctx.set_continuation(kstack_top, thread_user_entry_continuation as u64);
    });
}

/// Set up the idle thread's kernel continuation.
/// Must be called with the scheduler lock held.
pub fn setup_idle_thread_continuation_locked(tid: u32) {
    with_thread_mut(tid, |t| {
        let kstack_top = t.kstack_base + t.kstack_size as u64;
        t.kctx.set_continuation(kstack_top, idle_thread_fn as u64);
        t.in_kernel = true; // idle thread always lives in EL1
    });
}

/// Update the in_kernel flag for a thread.
/// Idle threads are always in_kernel and this call is a no-op for them.
///
/// Must be called with the scheduler lock held.
pub fn set_thread_in_kernel_locked(tid: u32, in_kernel: bool) {
    with_thread_mut(tid, |t| {
        if t.is_idle_thread {
            return; // idle thread kctx must never be cleared
        }
        t.in_kernel = in_kernel;
        if !in_kernel {
            t.kctx.clear();
        }
    });
}

// ── Kernel stack allocation ───────────────────────────────────────────────────

/// Allocate a kernel stack for a thread.
/// Returns (base_va, size) or panics on OOM.
pub fn alloc_kstack() -> (u64, usize) {
    let size = KERNEL_STACK_SIZE;
    let ptr = crate::mm::kmalloc::alloc(size, 16);
    assert!(!ptr.is_null(), "alloc_kstack: OOM");
    (ptr as u64, size)
}

/// Free a kernel stack previously allocated with alloc_kstack.
pub fn free_kstack(base: u64, _size: usize) {
    crate::mm::kmalloc::dealloc(base as *mut u8);
}

/// Defer a kstack free until after the context switch completes
/// (the stack is still in use until the switch is done).
pub fn defer_kstack_free(base: u64, size: usize) {
    use crate::sched::global::SCHED;
    unsafe { SCHED.deferred_kstacks_mut() }.push(base, size);
}

/// Drain and free all deferred kstacks.
/// Call this at a safe point (e.g., start of scheduler round).
pub fn drain_deferred_kstacks() {
    use crate::sched::global::SCHED;
    unsafe { SCHED.deferred_kstacks_mut() }.drain(|base, size| {
        free_kstack(base, size);
    });
}
