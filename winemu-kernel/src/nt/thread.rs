use crate::sched::{
    self, alert_thread_by_tid, create_user_thread_locked, current_tid, resume_thread_locked,
    set_thread_affinity_mask_locked, set_thread_priority_locked, suspend_thread_locked,
    terminate_thread_locked, thread_exists, timeout_to_deadline, wait_for_alert_by_tid,
    with_thread, KSchedulerLock, ThreadState, WaitDeadline,
};
use winemu_shared::status;

use super::common::GuestWriter;
use super::constants::{
    THREAD_BASIC_INFORMATION_SIZE, THREAD_INFO_CLASS_AFFINITY_MASK,
    THREAD_INFO_CLASS_BASE_PRIORITY, THREAD_INFO_CLASS_PRIORITY,
};
use super::user_args::{SyscallArgs, UserInPtr, UserOutPtr};
use super::SvcFrame;
use crate::mm::usercopy::read_current_user_bytes;

// ── Handle type constant ──────────────────────────────────────────────────────

pub const HANDLE_TYPE_THREAD: u8 = 3;

// ── Error type ────────────────────────────────────────────────────────────────

pub enum CreateThreadError {
    InvalidParameter,
    NoMemory,
}

#[inline]
fn win_to_sched_priority(prio: u8) -> u8 {
    31u8.saturating_sub(prio.min(31))
}

#[inline]
fn sched_to_win_priority(prio: u8) -> u8 {
    31u8.saturating_sub(prio.min(31))
}

// ── Thread handle resolution ──────────────────────────────────────────────────

/// Resolve a thread handle to a TID.
/// Handle value 0xFFFF_FFFF_FFFF_FFFF (-1) = current thread pseudo-handle.
pub fn resolve_thread_tid_from_handle(handle: u64) -> Option<u32> {
    if handle == u64::MAX {
        let tid = current_tid();
        if tid != 0 {
            Some(tid)
        } else {
            None
        }
    } else {
        let tid = crate::nt::kobject::handle_to_tid(handle)?;
        if thread_exists(tid) {
            Some(tid)
        } else {
            None
        }
    }
}

// ── Thread basic info ─────────────────────────────────────────────────────────

/// Returns a THREAD_BASIC_INFORMATION blob (64 bytes) for the given TID.
pub fn thread_basic_info(tid: u32) -> Option<[u8; THREAD_BASIC_INFORMATION_SIZE]> {
    let _lock = KSchedulerLock::lock();
    let (state, pid, prio, affinity) = with_thread(tid, |t| {
        (t.state, t.pid, t.priority, t.affinity_mask as u64)
    })?;
    let win_prio = sched_to_win_priority(prio);
    let exit_status: u32 = if state == ThreadState::Terminated {
        0
    } else {
        status::STILL_ACTIVE
    };
    let mut buf = [0u8; THREAD_BASIC_INFORMATION_SIZE];
    // THREAD_BASIC_INFORMATION layout (Windows):
    // +0x00  NTSTATUS ExitStatus          (4 bytes)
    // +0x04  pad                          (4 bytes)
    // +0x08  PVOID    TebBaseAddress      (8 bytes)
    // +0x10  CLIENT_ID (UniqueProcess+UniqueThread) (16 bytes)
    // +0x20  KAFFINITY AffinityMask       (8 bytes)
    // +0x28  LONG     Priority            (4 bytes)
    // +0x2C  LONG     BasePriority        (4 bytes)
    // Total = 0x30 = 48 bytes
    let teb = with_thread(tid, |t| t.teb_va).unwrap_or(0);
    buf[0..4].copy_from_slice(&exit_status.to_le_bytes());
    buf[8..16].copy_from_slice(&teb.to_le_bytes());
    buf[16..24].copy_from_slice(&(pid as u64).to_le_bytes());
    buf[24..32].copy_from_slice(&(tid as u64).to_le_bytes());
    buf[32..40].copy_from_slice(&affinity.to_le_bytes());
    buf[40..44].copy_from_slice(&(win_prio as i32).to_le_bytes());
    buf[44..48].copy_from_slice(&(win_prio as i32).to_le_bytes());
    Some(buf)
}

// ── create_user_thread ────────────────────────────────────────────────────────

pub fn create_user_thread(
    pid: u32,
    entry_va: u64,
    arg: u64,
    stack_size: u64,
    _max_stack_size: u64,
    priority: u8,
) -> Result<u32, CreateThreadError> {
    // Allocate user stack via VM.
    let stack_base =
        crate::mm::vm_alloc_stack(pid, stack_size).ok_or(CreateThreadError::NoMemory)?;
    let teb_va = crate::teb::alloc_teb(pid).unwrap_or(0);
    let _lock = KSchedulerLock::lock();
    let params = sched::UserThreadParams {
        pid,
        entry: entry_va,
        arg,
        stack_base,
        stack_size,
        teb_va,
        priority: win_to_sched_priority(priority),
    };
    let tid = create_user_thread_locked(params).ok_or(CreateThreadError::NoMemory)?;
    Ok(tid)
}

// ── terminate_current_thread ──────────────────────────────────────────────────

pub fn terminate_current_thread() -> ! {
    let tid = current_tid();
    if tid == 0 {
        panic!("terminate_current_thread: no current thread");
    }
    let _lock = KSchedulerLock::lock();
    crate::sched::exit_thread_locked(tid);
}

// ── terminate_thread_by_tid ───────────────────────────────────────────────────

pub fn terminate_thread_by_tid(tid: u32) -> Result<(), u32> {
    if tid == 0 {
        return Err(status::INVALID_PARAMETER);
    }
    let _lock = KSchedulerLock::lock();
    if !thread_exists(tid) {
        return Err(status::INVALID_HANDLE);
    }
    terminate_thread_locked(tid);
    Ok(())
}

// ── suspend / resume by handle ────────────────────────────────────────────────

pub fn suspend_thread_by_handle(handle: u64) -> Result<u32, u32> {
    let tid = resolve_thread_tid_from_handle(handle).ok_or(status::INVALID_HANDLE)?;
    let _lock = KSchedulerLock::lock();
    let prev = with_thread(tid, |t| t.suspend_count).unwrap_or(0);
    suspend_thread_locked(tid);
    Ok(prev)
}

pub fn resume_thread_by_handle(handle: u64) -> Result<u32, u32> {
    let tid = resolve_thread_tid_from_handle(handle).ok_or(status::INVALID_HANDLE)?;
    let _lock = KSchedulerLock::lock();
    let prev = with_thread(tid, |t| t.suspend_count).unwrap_or(0);
    resume_thread_locked(tid);
    Ok(prev)
}

// ── set_thread_base_priority_by_handle ───────────────────────────────────────

pub fn set_thread_base_priority_by_handle(handle: u64, prio: i32) -> u32 {
    let Some(tid) = resolve_thread_tid_from_handle(handle) else {
        return status::INVALID_HANDLE;
    };
    let p = win_to_sched_priority(prio.clamp(0, 31) as u8);
    let _lock = KSchedulerLock::lock();
    set_thread_priority_locked(tid, p);
    status::SUCCESS
}

pub fn set_thread_affinity_by_handle(handle: u64, affinity_mask: u64) -> u32 {
    let Some(tid) = resolve_thread_tid_from_handle(handle) else {
        return status::INVALID_HANDLE;
    };
    if affinity_mask == 0 {
        return status::INVALID_PARAMETER;
    }
    let _lock = KSchedulerLock::lock();
    if !set_thread_affinity_mask_locked(tid, affinity_mask) {
        return status::INVALID_PARAMETER;
    }
    status::SUCCESS
}

// ── yield ─────────────────────────────────────────────────────────────────────

pub fn yield_current_thread() {
    let tid = current_tid();
    if tid == 0 {
        return;
    }
    // Voluntary yield should request a reschedule, but keep the current thread
    // in Running until scheduler_round_locked decides whether to switch.
    // This preserves Yield semantics: switch to peer if available, otherwise
    // continue current without transiently self-selecting from ready-queue.
    sched::set_needs_reschedule();
}

// ── thread_notify_terminated ──────────────────────────────────────────────────

pub fn thread_notify_terminated(_tid: u32) {
    // Signal any waiters on this thread's termination event.
    // Currently a no-op; sync objects handle this via wait_for_single_object.
}

// ── Syscall handlers ──────────────────────────────────────────────────────────

pub(crate) fn handle_query_information_thread(frame: &mut SvcFrame) {
    let thread_handle = frame.x[0];
    let info_class = frame.x[1] as u32;
    let buf = frame.x[2] as *mut u8;
    let buf_len = frame.x[3] as usize;
    let ret_len = UserOutPtr::from_raw(frame.x[4] as *mut u32);
    match info_class {
        0 => {
            if buf.is_null() || buf_len < THREAD_BASIC_INFORMATION_SIZE {
                let _ = ret_len.write_current_if_present(THREAD_BASIC_INFORMATION_SIZE as u32);
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            let Some(target_tid) = resolve_thread_tid_from_handle(thread_handle) else {
                frame.x[0] = status::INVALID_HANDLE as u64;
                return;
            };
            let Some(tbi) = thread_basic_info(target_tid) else {
                frame.x[0] = status::INVALID_HANDLE as u64;
                return;
            };
            let Some(mut w) = GuestWriter::new(buf, buf_len, THREAD_BASIC_INFORMATION_SIZE) else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.bytes(&tbi);
            let _ = ret_len.write_current_if_present(THREAD_BASIC_INFORMATION_SIZE as u32);
            frame.x[0] = status::SUCCESS as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

pub(crate) fn handle_set_information_thread(frame: &mut SvcFrame) {
    let thread_handle = frame.x[0];
    let info_class = frame.x[1] as u32;
    let info_ptr = UserInPtr::from_raw(frame.x[2] as *const u8);
    let info_len = frame.x[3] as usize;

    match info_class {
        THREAD_INFO_CLASS_PRIORITY | THREAD_INFO_CLASS_BASE_PRIORITY => {
            if info_ptr.is_null() || info_len < core::mem::size_of::<i32>() {
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            let Some(prio) = UserInPtr::from_raw(info_ptr.as_raw() as *const i32).read_current()
            else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            frame.x[0] = set_thread_base_priority_by_handle(thread_handle, prio) as u64;
        }
        THREAD_INFO_CLASS_AFFINITY_MASK => {
            if info_ptr.is_null() || info_len < core::mem::size_of::<u64>() {
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            let Some(affinity) =
                UserInPtr::from_raw(info_ptr.as_raw() as *const u64).read_current()
            else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            frame.x[0] = set_thread_affinity_by_handle(thread_handle, affinity) as u64;
        }
        _ => {
            frame.x[0] = status::SUCCESS as u64;
        }
    }
}

pub(crate) fn handle_yield(frame: &mut SvcFrame) {
    yield_current_thread();
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_create_thread(frame: &mut SvcFrame) {
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    let process_handle = frame.x[3];
    let entry_va = frame.x[4];
    let arg = frame.x[5];
    let create_flags = frame.x[6] as u32;
    let args = SyscallArgs::new(frame);
    let Some(stack_size_arg) = args.spill_u64(0) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    let Some(max_stack_size_arg) = args.spill_u64(1) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };

    let Some(target_pid) = crate::process::resolve_process_handle(process_handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    let meta = crate::nt::kobject::object_type_meta_for_kind(crate::process::KObjectKind::Thread);
    if (desired_access & !meta.valid_access_mask) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    if !crate::process::process_accepts_new_threads(target_pid) {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
    let tid = match create_user_thread(
        target_pid,
        entry_va,
        arg,
        stack_size_arg,
        max_stack_size_arg,
        8,
    ) {
        Ok(tid) => tid,
        Err(CreateThreadError::InvalidParameter) => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
        Err(CreateThreadError::NoMemory) => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };
    let handle = crate::nt::kobject::make_thread_handle(tid);
    if !out_ptr.write_current_if_present(handle) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    // NtCreateThreadEx: 0x1 = CREATE_SUSPENDED.
    if (create_flags & 0x1) != 0 {
        let _lock = KSchedulerLock::lock();
        suspend_thread_locked(tid);
    }
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_terminate_thread(_frame: &mut SvcFrame) -> ! {
    terminate_current_thread();
}

pub(crate) fn handle_suspend_thread(frame: &mut SvcFrame) {
    let thread_handle = frame.x[0];
    let prev_ptr = UserOutPtr::from_raw(frame.x[1] as *mut u32);
    match suspend_thread_by_handle(thread_handle) {
        Ok(prev) => {
            if !prev_ptr.write_current_if_present(prev) {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        Err(st) => frame.x[0] = st as u64,
    }
}

pub(crate) fn handle_resume_thread(frame: &mut SvcFrame) {
    let thread_handle = frame.x[0];
    let prev_ptr = UserOutPtr::from_raw(frame.x[1] as *mut u32);
    match resume_thread_by_handle(thread_handle) {
        Ok(prev) => {
            if !prev_ptr.write_current_if_present(prev) {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        Err(st) => frame.x[0] = st as u64,
    }
}

// x0=ThreadId
pub(crate) fn handle_alert_thread_by_thread_id(frame: &mut SvcFrame) {
    let tid = frame.x[0] as u32;
    frame.x[0] = alert_thread_by_tid(tid) as u64;
}

// x0=ThreadId, x1=Timeout*
pub(crate) fn handle_wait_for_alert_by_thread_id(frame: &mut SvcFrame) {
    let timeout_ptr = UserInPtr::from_raw(frame.x[1] as *const i64);
    let deadline = if timeout_ptr.is_null() {
        WaitDeadline::Infinite
    } else {
        match timeout_ptr.read_current() {
            Some(raw) => timeout_to_deadline(raw),
            None => WaitDeadline::Immediate,
        }
    };
    frame.x[0] = wait_for_alert_by_tid(deadline) as u64;
}

// x0=ContextRecord*, x1=TestAlert
pub(crate) fn handle_continue(frame: &mut SvcFrame) {
    let ctx_ptr = frame.x[0] as *const u8;
    if ctx_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let Some(ctx) = read_current_user_bytes(ctx_ptr, 272) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    if !crate::arch::context::restore_user_context_record(frame, &ctx) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
    }
}

// x0=ExceptionRecord*, x1=ContextRecord*, x2=FirstChance
pub(crate) fn handle_raise_exception(frame: &mut SvcFrame) {
    use crate::ldr::ImportRef;
    // Resolve KiUserExceptionDispatcher from ntdll (cached by the caller on first use).
    // ARM64 calling convention: x0=ExceptionRecord*, x1=Context*
    // The pointers are already in guest memory (passed by the caller).
    let dispatcher =
        crate::dll::resolve_import("ntdll.dll", ImportRef::Name("KiUserExceptionDispatcher"));
    match dispatcher {
        Some(addr) => {
            // Redirect the next user-mode return to KiUserExceptionDispatcher.
            // x0 and x1 already hold ExceptionRecord* and Context* from the syscall args.
            frame.set_program_counter(addr);
            frame.x[0] = status::SUCCESS as u64;
        }
        None => {
            // ntdll not loaded yet or export missing — terminate.
            let pid = crate::process::current_pid();
            crate::process::terminate_process(pid, 0xC000_001D);
            frame.x[0] = status::SUCCESS as u64;
        }
    }
}
