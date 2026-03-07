use crate::sched::{
    self, current_tid, with_thread,
    create_user_thread_locked, terminate_thread_locked,
    suspend_thread_locked, resume_thread_locked,
    set_thread_priority_locked, ThreadState,
    KSchedulerLock, thread_exists,
};
use winemu_shared::status;

use super::constants::{
    THREAD_BASIC_INFORMATION_SIZE, THREAD_INFO_CLASS_BASE_PRIORITY, THREAD_INFO_CLASS_PRIORITY,
};
use super::SvcFrame;

// ── Handle type constant ──────────────────────────────────────────────────────

pub const HANDLE_TYPE_THREAD: u8 = 3;

// ── Error type ────────────────────────────────────────────────────────────────

pub enum CreateThreadError {
    InvalidParameter,
    NoMemory,
}

// ── Thread handle resolution ──────────────────────────────────────────────────

/// Resolve a thread handle to a TID.
/// Handle value 0xFFFF_FFFF_FFFF_FFFF (-1) = current thread pseudo-handle.
pub fn resolve_thread_tid_from_handle(handle: u64) -> Option<u32> {
    if handle == u64::MAX {
        let tid = current_tid();
        if tid != 0 { Some(tid) } else { None }
    } else {
        let tid = crate::nt::kobject::handle_to_tid(handle)?;
        if thread_exists(tid) { Some(tid) } else { None }
    }
}

// ── Thread basic info ─────────────────────────────────────────────────────────

/// Returns a THREAD_BASIC_INFORMATION blob (64 bytes) for the given TID.
pub fn thread_basic_info(tid: u32) -> Option<[u8; THREAD_BASIC_INFORMATION_SIZE]> {
    let _lock = KSchedulerLock::lock();
    let (state, pid, prio) = with_thread(tid, |t| (t.state, t.pid, t.priority))?;
    let exit_status: u32 = if state == ThreadState::Terminated { 0 } else { status::STILL_ACTIVE };
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
    buf[32..40].copy_from_slice(&1u64.to_le_bytes()); // affinity
    buf[40..44].copy_from_slice(&(prio as i32).to_le_bytes());
    buf[44..48].copy_from_slice(&(prio as i32).to_le_bytes());
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
    let stack_base = crate::nt::state::vm_alloc_stack(pid, stack_size)
        .ok_or(CreateThreadError::NoMemory)?;
    let teb_va = crate::teb::alloc_teb(pid).unwrap_or(0);
    let _lock = KSchedulerLock::lock();
    let params = sched::UserThreadParams {
        pid,
        entry: entry_va,
        arg,
        stack_base,
        stack_size,
        teb_va,
        priority,
    };
    create_user_thread_locked(params).ok_or(CreateThreadError::NoMemory)
}

// ── terminate_current_thread ──────────────────────────────────────────────────

pub fn terminate_current_thread() {
    let tid = current_tid();
    if tid == 0 { return; }
    let _lock = KSchedulerLock::lock();
    terminate_thread_locked(tid);
}

// ── terminate_thread_by_tid ───────────────────────────────────────────────────

pub fn terminate_thread_by_tid(tid: u32) -> Result<(), u32> {
    if tid == 0 { return Err(status::INVALID_PARAMETER); }
    let _lock = KSchedulerLock::lock();
    if !thread_exists(tid) { return Err(status::INVALID_HANDLE); }
    terminate_thread_locked(tid);
    Ok(())
}

// ── suspend / resume by handle ────────────────────────────────────────────────

pub fn suspend_thread_by_handle(handle: u64) -> Result<u32, u32> {
    let tid = resolve_thread_tid_from_handle(handle)
        .ok_or(status::INVALID_HANDLE)?;
    let _lock = KSchedulerLock::lock();
    let prev = with_thread(tid, |t| t.suspend_count).unwrap_or(0);
    suspend_thread_locked(tid);
    Ok(prev)
}

pub fn resume_thread_by_handle(handle: u64) -> Result<u32, u32> {
    let tid = resolve_thread_tid_from_handle(handle)
        .ok_or(status::INVALID_HANDLE)?;
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
    let p = prio.clamp(0, 31) as u8;
    let _lock = KSchedulerLock::lock();
    set_thread_priority_locked(tid, p);
    status::SUCCESS
}

// ── yield ─────────────────────────────────────────────────────────────────────

pub fn yield_current_thread() {
    let tid = current_tid();
    if tid == 0 { return; }
    let _lock = KSchedulerLock::lock();
    sched::set_thread_state_locked(tid, ThreadState::Ready);
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
    let ret_len = frame.x[4] as *mut u32;
    match info_class {
        0 => {
            if buf.is_null() || buf_len < THREAD_BASIC_INFORMATION_SIZE {
                if !ret_len.is_null() {
                    unsafe { ret_len.write_volatile(THREAD_BASIC_INFORMATION_SIZE as u32) };
                }
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
            unsafe {
                core::ptr::copy_nonoverlapping(tbi.as_ptr(), buf, THREAD_BASIC_INFORMATION_SIZE)
            };
            if !ret_len.is_null() {
                unsafe { ret_len.write_volatile(THREAD_BASIC_INFORMATION_SIZE as u32) };
            }
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
    let info_ptr = frame.x[2] as *const u8;
    let info_len = frame.x[3] as usize;

    if info_class != THREAD_INFO_CLASS_PRIORITY && info_class != THREAD_INFO_CLASS_BASE_PRIORITY {
        frame.x[0] = status::SUCCESS as u64;
        return;
    }

    if info_ptr.is_null() || info_len < core::mem::size_of::<i32>() {
        frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
        return;
    }

    let prio = unsafe { (info_ptr as *const i32).read_volatile() };
    frame.x[0] = set_thread_base_priority_by_handle(thread_handle, prio) as u64;
}

pub(crate) fn handle_yield(frame: &mut SvcFrame) {
    yield_current_thread();
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_create_thread(frame: &mut SvcFrame) {
    let out_ptr = frame.x[0] as *mut u64;
    let desired_access = frame.x[1] as u32;
    let process_handle = frame.x[3];
    let entry_va = frame.x[4];
    let arg = frame.x[5];
    let create_flags = frame.x[6] as u32;
    let stack_size_arg = unsafe { (frame.sp_el0 as *const u64).read_volatile() };
    let max_stack_size_arg = unsafe { (frame.sp_el0 as *const u64).add(1).read_volatile() };

    let Some(target_pid) = crate::process::resolve_process_handle(process_handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
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
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(handle) };
    }
    // NtCreateThreadEx: 0x1 = CREATE_SUSPENDED.
    if (create_flags & 0x1) != 0 {
        let _lock = KSchedulerLock::lock();
        suspend_thread_locked(tid);
    }
    let _ = desired_access;
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_terminate_thread(frame: &mut SvcFrame) {
    let cur = current_tid();
    terminate_current_thread();
    thread_notify_terminated(cur);
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_suspend_thread(frame: &mut SvcFrame) {
    let thread_handle = frame.x[0];
    let prev_ptr = frame.x[1] as *mut u32;
    match suspend_thread_by_handle(thread_handle) {
        Ok(prev) => {
            if !prev_ptr.is_null() {
                unsafe { prev_ptr.write_volatile(prev) };
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        Err(st) => frame.x[0] = st as u64,
    }
}

pub(crate) fn handle_resume_thread(frame: &mut SvcFrame) {
    let thread_handle = frame.x[0];
    let prev_ptr = frame.x[1] as *mut u32;
    match resume_thread_by_handle(thread_handle) {
        Ok(prev) => {
            if !prev_ptr.is_null() {
                unsafe { prev_ptr.write_volatile(prev) };
            }
            frame.x[0] = status::SUCCESS as u64;
        }
        Err(st) => frame.x[0] = st as u64,
    }
}
