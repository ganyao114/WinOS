// sched/sync/handles.rs — NT-level sync handle operations
//
// create_* : sync_alloc → obj_idx → KHandleTable.add → handle
// set/wait  : KHandleTable.get → obj_idx → sync_get_mut_by_idx
// close     : KHandleTable.remove → sync_free_idx  (via kobject drain)

use crate::sched::sync::primitives_api::{KEvent, KMutex, KSemaphore};
use crate::sched::sync::state::{sync_alloc, sync_get_by_idx, sync_get_mut_by_idx, SyncObject};
use crate::sched::types::{
    ThreadState, WaitDeadline, MAX_WAIT_HANDLES, WAIT_KIND_MULTIPLE, WAIT_KIND_NONE,
    WAIT_KIND_SINGLE,
};
use crate::sched::wait::{STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_PENDING};
use crate::sched::cpu::current_tid;
use crate::sched::lock::SchedLockAndSleep;
use crate::sched::global::{with_thread, with_thread_mut};
use crate::process::{KObjectRef, current_pid, with_process_mut};
use winemu_shared::status;

pub const STATUS_INVALID_HANDLE:       u32 = status::INVALID_HANDLE;
pub const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const WAITABLE_POLL_REL_100NS: i64 = -10_000; // 1ms

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

fn waitable_handle_signaled(handle: u64) -> Option<bool> {
    let (kind, obj_idx) = crate::nt::kobject::resolve_handle_target(handle)?;
    match kind {
        crate::process::KObjectKind::Thread => {
            Some(with_thread(obj_idx, |t| t.state == ThreadState::Terminated).unwrap_or(true))
        }
        crate::process::KObjectKind::Process => Some(crate::process::process_signaled(obj_idx)),
        _ => None,
    }
}

fn next_waitable_poll_deadline(deadline: WaitDeadline) -> WaitDeadline {
    match deadline {
        WaitDeadline::Immediate => WaitDeadline::Immediate,
        WaitDeadline::Infinite => crate::sched::wait::timeout_to_deadline(WAITABLE_POLL_REL_100NS),
        WaitDeadline::DeadlineTicks(limit) => match crate::sched::wait::timeout_to_deadline(
            WAITABLE_POLL_REL_100NS,
        ) {
            WaitDeadline::DeadlineTicks(poll) => WaitDeadline::DeadlineTicks(core::cmp::min(
                limit, poll,
            )),
            _ => WaitDeadline::DeadlineTicks(limit),
        },
    }
}

fn wait_for_process_or_thread(handle: u64, deadline: WaitDeadline) -> u32 {
    let tid = current_tid();
    loop {
        match waitable_handle_signaled(handle) {
            Some(true) => return STATUS_SUCCESS,
            Some(false) => {}
            None => return STATUS_INVALID_HANDLE,
        }

        match deadline {
            WaitDeadline::Immediate => return STATUS_TIMEOUT,
            WaitDeadline::DeadlineTicks(limit) if crate::sched::wait::current_ticks() >= limit => {
                return STATUS_TIMEOUT;
            }
            WaitDeadline::Infinite | WaitDeadline::DeadlineTicks(_) => {}
        }

        let poll_deadline = next_waitable_poll_deadline(deadline);
        {
            let _slp = SchedLockAndSleep::new();
            crate::sched::wait::block_thread_delay_locked(tid, poll_deadline);
        }
    }
}

#[inline]
fn clear_sync_wait_state_locked(tid: u32) {
    with_thread_mut(tid, |t| {
        t.wait.kind = WAIT_KIND_NONE;
        t.wait.handle_count = 0;
        t.wait.wait_all = false;
        t.wait.signaled_mask = 0;
        t.wait.wait_next = 0;
    });
}

#[inline]
fn set_sync_wait_single_locked(tid: u32, obj_idx: u32) {
    with_thread_mut(tid, |t| {
        t.wait.kind = WAIT_KIND_SINGLE;
        t.wait.handle_count = 1;
        t.wait.handles[0] = obj_idx as u64;
        t.wait.wait_all = false;
        t.wait.signaled_mask = 0;
        t.wait.wait_next = 0;
    });
}

#[inline]
fn set_sync_wait_multiple_locked(tid: u32, obj_idx: u32, wait_all: bool) {
    with_thread_mut(tid, |t| {
        t.wait.kind = WAIT_KIND_MULTIPLE;
        t.wait.handle_count = 1;
        t.wait.handles[0] = obj_idx as u64;
        t.wait.wait_all = wait_all;
        t.wait.signaled_mask = 0;
        t.wait.wait_next = 0;
    });
}

/// Remove `tid` from all sync-object wait queues recorded in `t.wait`.
/// Must be called with scheduler lock held.
pub fn detach_thread_sync_wait_links_locked(tid: u32) {
    let mut obj_idxs = [0u32; MAX_WAIT_HANDLES];
    let Some((wait_kind, count)) = with_thread(tid, |t| {
        let count = core::cmp::min(t.wait.handle_count as usize, MAX_WAIT_HANDLES);
        for (i, slot) in obj_idxs.iter_mut().enumerate().take(count) {
            *slot = t.wait.handles[i] as u32;
        }
        (t.wait.kind, count)
    }) else {
        return;
    };

    if wait_kind != WAIT_KIND_SINGLE && wait_kind != WAIT_KIND_MULTIPLE {
        return;
    }

    for obj_idx in obj_idxs.iter().take(count).copied() {
        if obj_idx == 0 {
            continue;
        }
        let Some(obj) = sync_get_mut_by_idx(obj_idx) else {
            continue;
        };
        match obj {
            SyncObject::Event(e) => {
                let _ = e.waiters.remove(tid);
            }
            SyncObject::Mutex(m) => {
                let _ = m.waiters.remove(tid);
            }
            SyncObject::Semaphore(s) => {
                let _ = s.waiters.remove(tid);
            }
        }
    }
}

// ── Event ─────────────────────────────────────────────────────────────────────

pub fn create_event(auto_reset: bool, initial_state: bool) -> Option<u64> {
    let _lock = crate::sched::lock::KSchedulerLock::lock();
    let obj_idx = sync_alloc(SyncObject::Event(KEvent::new(auto_reset, initial_state)))? as u32;
    let pid = current_pid();
    with_process_mut(pid, |p| p.handle_table.add(KObjectRef::event(obj_idx)))
        .flatten().map(|h| h as u64)
}

pub fn set_event(handle: u64) -> u32 {
    let _lock = crate::sched::lock::KSchedulerLock::lock();
    match resolve_sync_mut(handle) {
        Some((_, SyncObject::Event(e))) => { e.signal(); STATUS_SUCCESS }
        Some(_) => STATUS_OBJECT_TYPE_MISMATCH,
        None    => STATUS_INVALID_HANDLE,
    }
}

pub fn reset_event(handle: u64) -> u32 {
    let _lock = crate::sched::lock::KSchedulerLock::lock();
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
    let _lock = crate::sched::lock::KSchedulerLock::lock();
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
    let _lock = crate::sched::lock::KSchedulerLock::lock();
    let tid = current_tid();
    match resolve_sync_mut(handle) {
        Some((_, SyncObject::Mutex(m))) => m.release(tid),
        Some(_) => STATUS_OBJECT_TYPE_MISMATCH,
        None    => STATUS_INVALID_HANDLE,
    }
}

// ── Semaphore ─────────────────────────────────────────────────────────────────

pub fn create_semaphore(initial: i32, maximum: i32) -> Option<u64> {
    let _lock = crate::sched::lock::KSchedulerLock::lock();
    let obj_idx = sync_alloc(SyncObject::Semaphore(KSemaphore::new(initial, maximum)))? as u32;
    let pid = current_pid();
    with_process_mut(pid, |p| p.handle_table.add(KObjectRef::semaphore(obj_idx)))
        .flatten().map(|h| h as u64)
}

pub fn release_semaphore(handle: u64, count: i32) -> (u32, i32) {
    let _lock = crate::sched::lock::KSchedulerLock::lock();
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
    if waitable_handle_signaled(handle).is_some() {
        return wait_for_process_or_thread(handle, deadline);
    }

    let tid = current_tid();
    let status = {
        let mut slp = SchedLockAndSleep::new();
        clear_sync_wait_state_locked(tid);
        let mut pending_idx = 0u32;
        let result = match resolve_sync_mut(handle) {
            Some((obj_idx, SyncObject::Event(e))) => {
                let r = e.wait(tid, deadline);
                if r == STATUS_PENDING {
                    pending_idx = obj_idx;
                }
                r
            }
            Some((obj_idx, SyncObject::Mutex(m))) => {
                let r = m.acquire(tid, deadline);
                if r == STATUS_PENDING {
                    pending_idx = obj_idx;
                }
                r
            }
            Some((obj_idx, SyncObject::Semaphore(s))) => {
                let r = s.wait(tid, deadline);
                if r == STATUS_PENDING {
                    pending_idx = obj_idx;
                }
                r
            }
            None => {
                slp.cancel();
                STATUS_INVALID_HANDLE
            }
        };
        if result == STATUS_PENDING {
            set_sync_wait_single_locked(tid, pending_idx);
        } else {
            clear_sync_wait_state_locked(tid);
            slp.cancel();
        }
        result
    };
    if status == STATUS_PENDING {
        loop {
            let (state, r) = with_thread(tid, |t| (t.state, t.wait.result))
                .unwrap_or((ThreadState::Terminated, STATUS_TIMEOUT));
            if state != ThreadState::Waiting {
                break r;
            }
            // Defensive: if we resumed before the wait state was cleared,
            // immediately sleep again until a real wake/timeout transition.
            let _slp = SchedLockAndSleep::new();
        }
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
        clear_sync_wait_state_locked(tid);
        let mut pending_idx = 0u32;

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
                    Some((obj_idx, SyncObject::Event(e))) => {
                        let r = e.wait(tid, deadline);
                        if r == STATUS_PENDING {
                            pending_idx = obj_idx;
                        }
                        r
                    }
                    Some((obj_idx, SyncObject::Mutex(m))) => {
                        let r = m.acquire(tid, deadline);
                        if r == STATUS_PENDING {
                            pending_idx = obj_idx;
                        }
                        r
                    }
                    Some((obj_idx, SyncObject::Semaphore(s))) => {
                        let r = s.wait(tid, deadline);
                        if r == STATUS_PENDING {
                            pending_idx = obj_idx;
                        }
                        r
                    }
                    None => { slp.cancel(); STATUS_INVALID_HANDLE }
                };
                if r == STATUS_PENDING {
                    set_sync_wait_multiple_locked(tid, pending_idx, wait_all);
                } else {
                    clear_sync_wait_state_locked(tid);
                    slp.cancel();
                }
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
                            Some((obj_idx, SyncObject::Event(e))) => {
                                let r = e.wait(tid, deadline);
                                if r == STATUS_PENDING {
                                    pending_idx = obj_idx;
                                }
                                r
                            }
                            Some((obj_idx, SyncObject::Mutex(m))) => {
                                let r = m.acquire(tid, deadline);
                                if r == STATUS_PENDING {
                                    pending_idx = obj_idx;
                                }
                                r
                            }
                            Some((obj_idx, SyncObject::Semaphore(s))) => {
                                let r = s.wait(tid, deadline);
                                if r == STATUS_PENDING {
                                    pending_idx = obj_idx;
                                }
                                r
                            }
                            None => STATUS_INVALID_HANDLE,
                        };
                        break;
                    }
                }
                if blocked == STATUS_PENDING {
                    set_sync_wait_multiple_locked(tid, pending_idx, wait_all);
                } else {
                    clear_sync_wait_state_locked(tid);
                    slp.cancel();
                }
                blocked
            }
        }
    };

    if status == STATUS_PENDING {
        loop {
            let (state, r) = with_thread(tid, |t| (t.state, t.wait.result))
                .unwrap_or((ThreadState::Terminated, STATUS_TIMEOUT));
            if state != ThreadState::Waiting {
                break r;
            }
            // Defensive: don't let a spurious resume complete the syscall while
            // still logically blocked.
            let _slp = SchedLockAndSleep::new();
        }
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
