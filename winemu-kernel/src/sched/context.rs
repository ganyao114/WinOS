// sched/context.rs — Kernel context switch helpers
//
// Provides:
//   ensure_user_entry_continuation_locked(tid)  — set up kctx for first user entry
//   setup_idle_thread_continuation_locked(tid)  — set up kctx for idle loop
//   set_thread_in_kernel_locked(tid, val)        — update in_kernel flag
//
// The actual backend context-switch routines live under arch/*/context.rs.

use crate::sched::global::with_thread_mut;
use crate::sched::types::KERNEL_STACK_SIZE;

// ── Context-switch wrappers ───────────────────────────────────────────────────

/// Save `from` kctx, restore `to` kctx.
///
/// This call may return later when another thread switches back to `from`.
#[inline(always)]
pub unsafe fn __sched_switch_kernel_context(from: *mut u8, to: *const u8) {
    use crate::arch::context::switch_kernel_context;
    use crate::arch::context::KernelContext;
    switch_kernel_context(from as *mut KernelContext, to as *const KernelContext);
}

/// Enter user mode from a fresh kernel stack. Does not return.
#[inline(always)]
pub unsafe fn __sched_enter_user_thread(ctx: *const u8) -> ! {
    use crate::arch::context::enter_user_thread_context;
    use crate::arch::context::ThreadContext;
    enter_user_thread_context(ctx as *const ThreadContext)
}

/// Entry point for new user threads — called via kctx.lr after context switch.
#[no_mangle]
pub unsafe extern "C" fn thread_user_entry_continuation() -> ! {
    let tid = crate::sched::cpu::current_tid();
    let ctx_ptr = crate::sched::global::with_thread(tid, |t| {
        &t.ctx as *const crate::arch::context::ThreadContext as usize
    })
    .unwrap_or(0) as *const u8;
    // A fresh user entry can follow a TTBR0 handoff from another process/core.
    // Flush local translations immediately before ERET so the first user fetch
    // cannot observe a stale user translation on this CPU.
    crate::arch::mmu::flush_tlb_global();
    __sched_enter_user_thread(ctx_ptr)
}

/// Entry point for idle threads — kernel loop.
#[no_mangle]
pub unsafe extern "C" fn idle_thread_fn() -> ! {
    loop {
        let vid = crate::sched::vcpu_id() as usize;
        crate::sched::SCHED_LOCK.acquire();
        let from_tid = crate::sched::current_tid();
        match crate::sched::scheduler_round_locked(
            vid as u32,
            from_tid,
            crate::timer::DEFAULT_TIMESLICE_100NS,
            crate::sched::ScheduleReason::Ipi,
        ) {
            crate::sched::SchedulerRoundAction::RunThread {
                now_100ns,
                next_deadline_100ns,
                slice_remaining_100ns,
                from_tid,
                to_tid,
                ..
            } => {
                if from_tid == to_tid {
                    crate::sched::with_thread_mut(to_tid, |t| {
                        t.state = crate::sched::ThreadState::Running;
                    });
                    crate::sched::lock::unlock_after_raw_or_scoped(vid);
                    crate::timer::schedule_running_slice_100ns(
                        now_100ns,
                        next_deadline_100ns,
                        slice_remaining_100ns,
                    );
                    continue;
                }
                crate::sched::execute_kernel_continuation_switch(
                    from_tid,
                    to_tid,
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns,
                    "idle",
                );
            }
            crate::sched::SchedulerRoundAction::ContinueCurrent {
                now_100ns,
                next_deadline_100ns,
                ..
            }
            | crate::sched::SchedulerRoundAction::IdleWait {
                now_100ns,
                next_deadline_100ns,
                ..
            } => {
                crate::sched::lock::unlock_after_raw_or_scoped(vid);
                crate::sched::schedule::idle_wait_or_exit(vid, now_100ns, next_deadline_100ns);
            }
        }
    }
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
        // Set up a fresh kernel continuation that will return into user mode.
        let kstack_top = t.kstack_base + t.kstack_size as u64;
        t.kctx.set_continuation(
            kstack_top,
            thread_user_entry_continuation as *const () as u64,
        );
    });
}

/// Set up the idle thread's kernel continuation.
/// Must be called with the scheduler lock held.
pub fn setup_idle_thread_continuation_locked(tid: u32) {
    with_thread_mut(tid, |t| {
        let kstack_top = t.kstack_base + t.kstack_size as u64;
        t.kctx
            .set_continuation(kstack_top, idle_thread_fn as *const () as u64);
        t.in_kernel = true; // idle thread always stays in kernel mode
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
