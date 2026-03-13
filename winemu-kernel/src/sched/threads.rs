// sched/threads.rs — Thread creation, spawn, terminate
//
// spawn()              — register an already-constructed KThread into the store
// create_kernel_thread — allocate + register a kernel-mode thread
// create_user_thread   — allocate + register a user-mode thread (with TEB)
// exit_thread_locked   — called from thread itself to self-terminate

use crate::sched::context::{
    alloc_kstack, defer_kstack_free, ensure_user_entry_continuation_locked,
    set_thread_in_kernel_locked,
    setup_idle_thread_continuation_locked,
};
use crate::sched::cpu::current_vcpu_index;
use crate::sched::global::{with_thread, with_thread_mut, SCHED};
use crate::sched::thread_control::terminate_thread_locked;
use crate::sched::topology::{bind_running_thread_to_vcpu, set_thread_state_locked};
use crate::sched::types::{KThread, ThreadState, MAX_VCPUS};

// ── spawn ─────────────────────────────────────────────────────────────────────

/// Insert a pre-built KThread into the thread store and make it Ready.
/// Returns the TID on success.
///
/// Must be called with the scheduler lock held.
pub fn spawn_locked(mut thread: KThread) -> Option<u32> {
    let store = unsafe { SCHED.threads_raw_mut() };
    let tid = store.alloc(|id| {
        thread.tid = id;
        thread
    })?;

    // Ensure the thread has a kernel continuation so it can be scheduled
    // by the unlock-edge or a secondary vCPU.
    ensure_user_entry_continuation_locked(tid);

    set_thread_state_locked(tid, ThreadState::Ready);
    Some(tid)
}

// ── create_user_thread ────────────────────────────────────────────────────────

pub struct UserThreadParams {
    pub pid: u32,
    pub entry: u64,      // user entry point (RtlUserThreadStart or similar)
    pub stack_base: u64, // user stack top (high address)
    pub stack_size: u64,
    pub teb_va: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub priority: u8,
}

/// Allocate and register a new user-mode thread.
/// Returns the TID on success.
///
/// Must be called with the scheduler lock held.
pub fn create_user_thread_locked(p: UserThreadParams) -> Option<u32> {
    let pid = p.pid;
    let (kstack_base, kstack_size) = alloc_kstack();

    let mut t = KThread::new(0 /* filled by alloc_with */, p.pid);
    t.stack_base = p.stack_base;
    t.stack_size = p.stack_size;
    t.kstack_base = kstack_base;
    t.kstack_size = kstack_size as u64;
    t.teb_va = p.teb_va;
    t.priority = p.priority;
    t.base_priority = p.priority;
    t.last_vcpu_hint = 0;

    crate::arch::context::initialize_user_thread_context(
        &mut t.ctx,
        crate::arch::context::UserThreadStart {
            program_counter: p.entry,
            stack_pointer: p.stack_base,
            thread_pointer: p.teb_va,
            arg0: p.arg0,
            arg1: p.arg1,
        },
    );

    let tid = spawn_locked(t)?;
    if pid != 0 {
        crate::process::on_thread_created(pid, tid);
    }
    Some(tid)
}

/// Allocate thread0 and bind it to the current vCPU's bootstrap execution
/// context before the first real scheduler entry.
///
/// Must be called with the scheduler lock held.
pub fn create_boot_thread_for_current_vcpu_locked(priority: u8) -> Option<u32> {
    let tid = create_user_thread_locked(UserThreadParams {
        pid: 0,
        entry: 0,
        stack_base: 0,
        stack_size: 0,
        teb_va: 0,
        arg0: 0,
        arg1: 0,
        priority,
    })?;
    let vid = current_vcpu_index();
    set_thread_state_locked(tid, ThreadState::Running);
    bind_running_thread_to_vcpu(vid, tid);
    set_thread_in_kernel_locked(tid, true);
    Some(tid)
}

/// Finalize thread0's first user entry and place it back into the ready queue
/// so the unified scheduler entry can launch it like any other thread.
///
/// Must be called with the scheduler lock held.
pub fn prepare_boot_thread_user_entry_locked(
    tid: u32,
    start: crate::arch::context::UserThreadStart,
    now_100ns: u64,
) {
    with_thread_mut(tid, |t| {
        crate::arch::context::initialize_user_thread_context(&mut t.ctx, start);
        t.slice_remaining_100ns = crate::timer::DEFAULT_TIMESLICE_100NS;
        t.last_start_100ns = now_100ns;
        // Keep the prebuilt kctx continuation for first user entry, but mark
        // the live carrier as user-return so scheduler policy sees a normal
        // ready thread instead of an in-kernel continuation.
        t.in_kernel = false;
    });
    set_thread_state_locked(tid, ThreadState::Ready);
}

// ── register_idle_thread_for_vcpu ─────────────────────────────────────────────

/// Create and register the idle thread for `vcpu_id`.
/// Must be called with the scheduler lock held, before the vCPU starts.
pub fn register_idle_thread_for_vcpu(vcpu_id: u32) -> u32 {
    let (kstack_base, kstack_size) = alloc_kstack();

    let store = unsafe { SCHED.threads_raw_mut() };
    let tid = store
        .alloc(|id| {
            let mut t = KThread::new(id, 0);
            t.is_idle_thread = true;
            t.priority = 31; // lowest priority
            t.base_priority = 31;
            t.last_vcpu_hint = vcpu_id as u8;
            t.kstack_base = kstack_base;
            t.kstack_size = kstack_size as u64;
            t.state = ThreadState::Ready;
            t
        })
        .expect("register_idle_thread_for_vcpu: OOM");

    setup_idle_thread_continuation_locked(tid);

    // Record idle TID in per-vCPU state.
    let vs = unsafe { SCHED.vcpu_raw_mut(vcpu_id as usize) };
    vs.idle_tid = tid;

    // Also update cpu_local if this is the current vCPU.
    use crate::sched::cpu::{cpu_local, vcpu_id as get_vcpu_id};
    if get_vcpu_id() == vcpu_id {
        cpu_local().idle_tid = tid;
    }

    tid
}

/// Ensure `vcpu_id` has an idle thread registered and return its TID.
/// Must be called with the scheduler lock held.
pub fn ensure_idle_thread_for_vcpu_locked(vcpu_id: u32) -> u32 {
    let existing = unsafe { SCHED.vcpu_raw(vcpu_id as usize) }.idle_tid;
    if existing != 0 {
        use crate::sched::cpu::{cpu_local, vcpu_id as get_vcpu_id};
        if get_vcpu_id() == vcpu_id {
            cpu_local().idle_tid = existing;
        }
        return existing;
    }
    register_idle_thread_for_vcpu(vcpu_id)
}

// ── exit_thread_locked ────────────────────────────────────────────────────────

/// Called by a thread to terminate itself.
/// Defers kstack free, marks thread Terminated, then calls schedule().
///
/// Must be called with the scheduler lock held.
/// Does NOT return.
pub fn exit_thread_locked(tid: u32) -> ! {
    // Defer kstack free (still in use until context switch).
    let (kstack_base, kstack_size) =
        with_thread(tid, |t| (t.kstack_base, t.kstack_size as usize)).unwrap_or((0, 0));

    if kstack_base != 0 {
        defer_kstack_free(kstack_base, kstack_size);
    }

    terminate_thread_locked(tid);

    // Drop into the scheduler — it will pick the next thread.
    // schedule_noreturn() releases the lock and switches context.
    crate::sched::schedule::schedule_noreturn_locked(tid)
}

// ── free_terminated_threads ───────────────────────────────────────────────────

/// Remove all Terminated threads from the store.
/// Must be called with the scheduler lock held.
pub fn free_terminated_threads_locked() {
    let mut to_free = [0u32; 64];
    let mut count = 0usize;

    {
        let store = unsafe { SCHED.threads_raw() };
        store.for_each(|tid, t| {
            if t.state != ThreadState::Terminated || t.is_idle_thread || count >= 64 {
                return;
            }
            // Conservative safety gates: a terminated thread can still be
            // transiently referenced by scheduler handoff metadata.
            if t.has_kernel_continuation() {
                return;
            }
            // Do not free a terminated thread that is still the active current
            // thread on any vCPU; its kernel context may still be needed by an
            // in-flight switch path.
            for vid in 0..MAX_VCPUS {
                let vs = unsafe { SCHED.vcpu_raw(vid) };
                if vs.current_tid == tid {
                    return;
                }
            }
            if count < 64 {
                to_free[count] = tid;
                count += 1;
            }
        });
    }

    let store = unsafe { SCHED.threads_raw_mut() };
    for i in 0..count {
        store.free(to_free[i]);
    }
}

/// Collect all TIDs belonging to `pid`. Returns a Vec of TIDs.
pub fn thread_ids_by_pid(pid: u32) -> crate::rust_alloc::vec::Vec<u32> {
    let store = unsafe { SCHED.threads_raw() };
    let mut out = crate::rust_alloc::vec::Vec::new();
    store.for_each(|tid, t| {
        if t.pid == pid {
            out.push(tid);
        }
    });
    out
}

/// Terminate a thread by TID. Returns true if the thread was found and terminated.
pub fn terminate_thread_by_tid(tid: u32) -> bool {
    let _lock = crate::sched::lock::KSchedulerLock::lock();
    if !with_thread(tid, |t| t.state != ThreadState::Terminated).unwrap_or(false) {
        return false;
    }
    terminate_thread_locked(tid);
    true
}
