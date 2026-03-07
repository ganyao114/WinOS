// sched/sync/handles.rs — NT-level sync handle operations
//
// create_* : sync_alloc → obj_idx → KHandleTable.add → handle
// set/wait  : KHandleTable.get → obj_idx → sync_get_mut_by_idx
// close     : KHandleTable.remove → sync_free_idx  (via kobject drain)

use crate::sched::sync::primitives_api::{KEvent, KMutex, KSemaphore};
use crate::sched::sync::state::{sync_alloc, sync_get_by_idx, sync_get_mut_by_idx, SyncObject};
use crate::sched::types::WaitDeadline;
use crate::sched::wait::{STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_PENDING};
use crate::sched::cpu::current_tid;
use crate::sched::lock::SchedLockAndSleep;
use crate::sched::global::with_thread;
use crate::process::{KObjectRef, current_pid, with_process_mut};

pub const STATUS_INVALID_HANDLE:       u32 = 0xC000_0008;
pub const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;

// ── Internal: resolve handle → SyncObject ────────────────────────────────────

fn resolve_sync(handle: u64) -> Option<(u32, &'static SyncObject)> {
    let pid = current_pid();
    let obj = with_process_mut(pid, |p| p.handle_table.get(handle as u32)).flatten()?;
    let so  = sync_get_by_idx(obj.obj_idx)?;
    Some((obj.obj_idx, so))
}

fn resolve_sync_mut(handle: u64) -> Option<(u32, &'static mut SyncObject)> {
    let pid = current_pid();
    let obj = with_process_mut(pid, |p| p.handle_table.get(handle as u32)).flatten()?;
    let so  = sync_get_mut_by_idx(obj.obj_idx)?;
    Some((obj.obj_idx, so))
}

// ── Event ─────────────────────────────────────────────────────────────────────

pub fn create_event(auto_reset: bool, initial_state: bool) -> Option<u64> {
    let obj_idx = sync_alloc(SyncObject::Event(KEvent::new(auto_reset, initial_state)))? as u32;
    let pid = current_pid();
    with_process_mut(pid, |p| p.handle_table.add(KObjectRef::event(obj_idx)))
        .flatten().map(|h| h as u64)
}

pub fn set_event(handle: u64) -> u32 {
    match resolve_sync_mut(handle) {
        Some((_, SyncObject::Event(e))) => { e.signal(); STATUS_SUCCESS }
        Some(_) => STATUS_OBJECT_TYPE_MISMATCH,
        None    => STATUS_INVALID_HANDLE,
    }
}

pub fn reset_event(handle: u64) -> u32 {
    match resolve_sync_mut(handle) {
        Some((_, SyncObject::Event(e))) => { e.clear(); STATUS_SUCCESS }
        Some(_) => STATUS_OBJECT_TYPE_MISMATCH,
        None    => STATUS_INVALID_HANDLE,
    }
}

pub fn query_event(handle: u64) -> (u32, bool) {
    match resolve_sync(handle) {
        Some((_, SyncObject::Event(e))) => (STATUS_SUCCESS, e.is_signaled()),
        Some(_) => (STATUS_OBJECT_TYPE_MISMATCH, false),
        None    => (STATUS_INVALID_HANDLE, false),
    }
}

// ── Mutex ─────────────────────────────────────────────────────────────────────

pub fn create_mutex(initial_owner: bool) -> Option<u64> {
    let mut m = KMutex::new();
    if initial_owner {
        let tid = current_tid();
        m.owner_tid = tid;
        m.recursion = 1;
    }
    let obj_idx = sync_alloc(SyncObject::Mutex(m))? as u32;
    let pid = current_pid();
    with_process_mut(pid, |p| p.handle_table.add(KObjectRef::mutex(obj_idx)))
        .flatten().map(|h| h as u64)
}

pub fn release_mutex(handle: u64) -> u32 {
    let tid = current_tid();
    match resolve_sync_mut(handle) {
        Some((_, SyncObject::Mutex(m))) => m.release(tid),
        Some(_) => STATUS_OBJECT_TYPE_MISMATCH,
        None    => STATUS_INVALID_HANDLE,
    }
}

// ── Semaphore ─────────────────────────────────────────────────────────────────

pub fn create_semaphore(initial: i32, maximum: i32) -> Option<u64> {
    let obj_idx = sync_alloc(SyncObject::Semaphore(KSemaphore::new(initial, maximum)))? as u32;
    let pid = current_pid();
    with_process_mut(pid, |p| p.handle_table.add(KObjectRef::semaphore(obj_idx)))
        .flatten().map(|h| h as u64)
}

pub fn release_semaphore(handle: u64, count: i32) -> (u32, i32) {
    match resolve_sync_mut(handle) {
        Some((_, SyncObject::Semaphore(s))) => {
            let prev = s.count;
            (s.release(count), prev)
        }
        Some(_) => (STATUS_OBJECT_TYPE_MISMATCH, 0),
        None    => (STATUS_INVALID_HANDLE, 0),
    }
}

// ── Wait ──────────────────────────────────────────────────────────────────────

pub fn wait_for_single_object(handle: u64, deadline: WaitDeadline) -> u32 {
    let tid = current_tid();
    let status = {
        let mut slp = SchedLockAndSleep::new();
        let result = match resolve_sync_mut(handle) {
            Some((_, SyncObject::Event(e)))     => e.wait(tid, deadline),
            Some((_, SyncObject::Mutex(m)))     => m.acquire(tid, deadline),
            Some((_, SyncObject::Semaphore(s))) => s.wait(tid, deadline),
            None => { slp.cancel(); STATUS_INVALID_HANDLE }
        };
        if result != STATUS_PENDING { slp.cancel(); }
        result
    };
    if status == STATUS_PENDING {
        with_thread(tid, |t| t.wait.result).unwrap_or(STATUS_TIMEOUT)
    } else {
        status
    }
}

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
            let mut found = None;
            for (i, &h) in handles.iter().enumerate() {
                if resolve_sync(h).map(|(_, o)| o.is_signaled()).unwrap_or(false) {
                    found = Some(i); break;
                }
            }
            if let Some(i) = found {
                if let Some((_, obj)) = resolve_sync_mut(handles[i]) {
                    match obj {
                        SyncObject::Event(e)     => { if e.auto_reset { e.clear(); } }
                        SyncObject::Mutex(m)     => { m.owner_tid = tid; m.recursion = 1; }
                        SyncObject::Semaphore(s) => { s.count -= 1; }
                    }
                }
                slp.cancel();
                STATUS_WAIT_0 + i as u32
            } else if deadline == WaitDeadline::Immediate {
                slp.cancel(); STATUS_TIMEOUT
            } else if let Some(&h) = handles.first() {
                let r = match resolve_sync_mut(h) {
                    Some((_, SyncObject::Event(e)))     => e.wait(tid, deadline),
                    Some((_, SyncObject::Mutex(m)))     => m.acquire(tid, deadline),
                    Some((_, SyncObject::Semaphore(s))) => s.wait(tid, deadline),
                    None => { slp.cancel(); STATUS_INVALID_HANDLE }
                };
                if r != STATUS_PENDING { slp.cancel(); }
                r
            } else {
                slp.cancel(); STATUS_TIMEOUT
            }
        } else {
            let all = handles.iter().all(|&h| {
                resolve_sync(h).map(|(_, o)| o.is_signaled()).unwrap_or(false)
            });
            if all {
                for &h in handles {
                    if let Some((_, obj)) = resolve_sync_mut(h) {
                        match obj {
                            SyncObject::Event(e)     => { if e.auto_reset { e.clear(); } }
                            SyncObject::Mutex(m)     => { m.owner_tid = tid; m.recursion = 1; }
                            SyncObject::Semaphore(s) => { s.count -= 1; }
                        }
                    }
                }
                slp.cancel(); STATUS_WAIT_0
            } else if deadline == WaitDeadline::Immediate {
                slp.cancel(); STATUS_TIMEOUT
            } else {
                let mut blocked = STATUS_TIMEOUT;
                for &h in handles {
                    if !resolve_sync(h).map(|(_, o)| o.is_signaled()).unwrap_or(false) {
                        blocked = match resolve_sync_mut(h) {
                            Some((_, SyncObject::Event(e)))     => e.wait(tid, deadline),
                            Some((_, SyncObject::Mutex(m)))     => m.acquire(tid, deadline),
                            Some((_, SyncObject::Semaphore(s))) => s.wait(tid, deadline),
                            None => STATUS_INVALID_HANDLE,
                        };
                        break;
                    }
                }
                if blocked != STATUS_PENDING { slp.cancel(); }
                blocked
            }
        }
    };

    if status == STATUS_PENDING {
        with_thread(tid, |t| t.wait.result).unwrap_or(STATUS_TIMEOUT)
    } else {
        status
    }
}

// ── Delay / sleep ─────────────────────────────────────────────────────────────

pub fn delay_current_thread_sync(deadline: WaitDeadline) -> u32 {
    use crate::sched::wait::block_thread_delay_locked;
    let tid = current_tid();
    if tid == 0 || deadline == WaitDeadline::Immediate {
        return STATUS_SUCCESS;
    }
    {
        let _slp = SchedLockAndSleep::new();
        block_thread_delay_locked(tid, deadline);
    }
    with_thread(tid, |t| t.wait.result).unwrap_or(STATUS_SUCCESS)
}

pub fn event_set_by_handle_for_pid(_owner_pid: u32, handle: u64) -> u32 {
    set_event(handle)
}

// ── Close ─────────────────────────────────────────────────────────────────────

/// Close a handle — removes from process handle table and frees the sync object.
pub fn close_handle(handle: u64) -> u32 {
    use crate::nt::kobject::close_handle_for_current;
    close_handle_for_current(handle)
}
