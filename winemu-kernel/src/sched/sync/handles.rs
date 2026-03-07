// sched/sync/handles.rs — NT-level sync handle operations
//
// These are called from nt/sync.rs syscall handlers.
// All functions require the scheduler lock to be held.

use crate::sched::sync::primitives_api::{KEvent, KMutex, KSemaphore};
use crate::sched::sync::state::{sync_alloc, sync_free, sync_get, sync_get_mut, SyncObject};
use crate::sched::types::WaitDeadline;
use crate::sched::wait::{STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_PENDING};
use crate::sched::cpu::current_tid;
use crate::sched::lock::SchedLockAndSleep;
use crate::sched::global::with_thread;

pub const STATUS_INVALID_HANDLE:    u32 = 0xC000_0008;
pub const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;

// ── Event ─────────────────────────────────────────────────────────────────────

pub fn create_event(auto_reset: bool, initial_state: bool) -> Option<u64> {
    sync_alloc(SyncObject::Event(KEvent::new(auto_reset, initial_state)))
}

pub fn set_event(handle: u64) -> u32 {
    match sync_get_mut(handle) {
        Some(SyncObject::Event(e)) => { e.signal(); STATUS_SUCCESS }
        Some(_) => STATUS_OBJECT_TYPE_MISMATCH,
        None    => STATUS_INVALID_HANDLE,
    }
}

pub fn reset_event(handle: u64) -> u32 {
    match sync_get_mut(handle) {
        Some(SyncObject::Event(e)) => { e.clear(); STATUS_SUCCESS }
        Some(_) => STATUS_OBJECT_TYPE_MISMATCH,
        None    => STATUS_INVALID_HANDLE,
    }
}

pub fn query_event(handle: u64) -> (u32, bool) {
    match sync_get(handle) {
        Some(SyncObject::Event(e)) => (STATUS_SUCCESS, e.is_signaled()),
        Some(_) => (STATUS_OBJECT_TYPE_MISMATCH, false),
        None    => (STATUS_INVALID_HANDLE, false),
    }
}

// ── Mutex ─────────────────────────────────────────────────────────────────────

pub fn create_mutex(initial_owner: bool) -> Option<u64> {
    let mut m = KMutex::new();
    if initial_owner {
        let tid = current_tid();
        m.owner_tid  = tid;
        m.recursion  = 1;
    }
    sync_alloc(SyncObject::Mutex(m))
}

pub fn release_mutex(handle: u64) -> u32 {
    let tid = current_tid();
    match sync_get_mut(handle) {
        Some(SyncObject::Mutex(m)) => m.release(tid),
        Some(_) => STATUS_OBJECT_TYPE_MISMATCH,
        None    => STATUS_INVALID_HANDLE,
    }
}

// ── Semaphore ─────────────────────────────────────────────────────────────────

pub fn create_semaphore(initial: i32, maximum: i32) -> Option<u64> {
    sync_alloc(SyncObject::Semaphore(KSemaphore::new(initial, maximum)))
}

pub fn release_semaphore(handle: u64, count: i32) -> (u32, i32) {
    match sync_get_mut(handle) {
        Some(SyncObject::Semaphore(s)) => {
            let prev = s.count;
            let status = s.release(count);
            (status, prev)
        }
        Some(_) => (STATUS_OBJECT_TYPE_MISMATCH, 0),
        None    => (STATUS_INVALID_HANDLE, 0),
    }
}

// ── Wait ──────────────────────────────────────────────────────────────────────

/// Wait on a single handle. Returns NTSTATUS.
///
/// Uses SchedLockAndSleep: acquires the scheduler lock, checks/enqueues,
/// then drops the lock (triggering unlock-edge context switch if needed).
/// After the thread is unblocked, reads wait.result for the final status.
pub fn wait_for_single_object(handle: u64, deadline: WaitDeadline) -> u32 {
    let tid = current_tid();
    let status = {
        let mut slp = SchedLockAndSleep::new();
        let result = match sync_get_mut(handle) {
            Some(SyncObject::Event(e))     => e.wait(tid, deadline),
            Some(SyncObject::Mutex(m))     => m.acquire(tid, deadline),
            Some(SyncObject::Semaphore(s)) => s.wait(tid, deadline),
            None => { slp.cancel(); STATUS_INVALID_HANDLE }
        };
        if result != STATUS_PENDING {
            slp.cancel();
        }
        result
        // slp drops here → if not cancelled, unlock-edge fires → thread switches out
    };
    if status == STATUS_PENDING {
        // Thread was unblocked; read the result written by unblock_thread_locked.
        with_thread(tid, |t| t.wait.result).unwrap_or(STATUS_TIMEOUT)
    } else {
        status
    }
}

/// Wait on multiple handles (WaitAny / WaitAll). Returns NTSTATUS.
pub fn wait_for_multiple_objects(
    handles: &[u64],
    wait_all: bool,
    deadline: WaitDeadline,
) -> u32 {
    const STATUS_WAIT_0: u32 = 0x0000_0000;
    let tid = current_tid();

    let status = {
        let mut slp = SchedLockAndSleep::new();

        if !wait_all {
            // WaitAny: check if any is already signaled.
            let mut found = None;
            for (i, &h) in handles.iter().enumerate() {
                if sync_get(h).map(|o| o.is_signaled()).unwrap_or(false) {
                    found = Some(i);
                    break;
                }
            }
            if let Some(i) = found {
                let h = handles[i];
                if let Some(obj) = sync_get_mut(h) {
                    match obj {
                        SyncObject::Event(e)     => { if e.auto_reset { e.clear(); } }
                        SyncObject::Mutex(m)     => { m.owner_tid = tid; m.recursion = 1; }
                        SyncObject::Semaphore(s) => { s.count -= 1; }
                    }
                }
                slp.cancel();
                STATUS_WAIT_0 + i as u32
            } else if deadline == WaitDeadline::Immediate {
                slp.cancel();
                STATUS_TIMEOUT
            } else if let Some(&h) = handles.first() {
                // Block on first handle.
                let r = match sync_get_mut(h) {
                    Some(SyncObject::Event(e))     => e.wait(tid, deadline),
                    Some(SyncObject::Mutex(m))     => m.acquire(tid, deadline),
                    Some(SyncObject::Semaphore(s)) => s.wait(tid, deadline),
                    None => { slp.cancel(); STATUS_INVALID_HANDLE }
                };
                if r != STATUS_PENDING { slp.cancel(); }
                r
            } else {
                slp.cancel();
                STATUS_TIMEOUT
            }
        } else {
            // WaitAll: check if all are signaled.
            let all = handles.iter().all(|&h| {
                sync_get(h).map(|o| o.is_signaled()).unwrap_or(false)
            });
            if all {
                for &h in handles {
                    if let Some(obj) = sync_get_mut(h) {
                        match obj {
                            SyncObject::Event(e)     => { if e.auto_reset { e.clear(); } }
                            SyncObject::Mutex(m)     => { m.owner_tid = tid; m.recursion = 1; }
                            SyncObject::Semaphore(s) => { s.count -= 1; }
                        }
                    }
                }
                slp.cancel();
                STATUS_WAIT_0
            } else if deadline == WaitDeadline::Immediate {
                slp.cancel();
                STATUS_TIMEOUT
            } else {
                // Block on first unsignaled handle.
                let mut blocked = STATUS_TIMEOUT;
                for &h in handles {
                    if !sync_get(h).map(|o| o.is_signaled()).unwrap_or(false) {
                        blocked = match sync_get_mut(h) {
                            Some(SyncObject::Event(e))     => e.wait(tid, deadline),
                            Some(SyncObject::Mutex(m))     => m.acquire(tid, deadline),
                            Some(SyncObject::Semaphore(s)) => s.wait(tid, deadline),
                            None => STATUS_INVALID_HANDLE,
                        };
                        break;
                    }
                }
                if blocked != STATUS_PENDING { slp.cancel(); }
                blocked
            }
        }
        // slp drops here → unlock-edge if STATUS_PENDING
    };

    if status == STATUS_PENDING {
        with_thread(tid, |t| t.wait.result).unwrap_or(STATUS_TIMEOUT)
    } else {
        status
    }
}

// ── Close ─────────────────────────────────────────────────────────────────────

pub fn close_handle(handle: u64) -> u32 {
    if sync_free(handle) { STATUS_SUCCESS } else { STATUS_INVALID_HANDLE }
}
