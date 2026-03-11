use core::cell::UnsafeCell;

use crate::hypercall;
use crate::kobj::ObjectStore;
use crate::rust_alloc::vec::Vec;
use crate::sched;
use crate::sched::WaitDeadline;
use winemu_shared::hostcall as hc;
use winemu_shared::status;

const STATUS_PENDING: u32 = 0x0000_0103;
const REQUEST_BUCKETS: usize = 256;
const SYNC_DONE_BUCKETS: usize = 128;

#[derive(Clone, Copy)]
struct PendingWaiter {
    owner_pid: u32,
    request_id: u64,
    waiter_tid: u32,
    need_submit_done: bool,
    req_next: u32,
}

#[derive(Clone, Copy)]
struct SyncCompletion {
    request_id: u64,
    host_result: u64,
    value0: u64,
    req_next: u32,
}

#[derive(Clone, Copy)]
pub struct SubmitArgs {
    pub opcode: u64,
    pub flags: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub user_tag: u64,
}

#[derive(Clone, Copy)]
pub struct SubmitDone {
    pub host_result: u64,
    pub value0: u64,
}

#[derive(Clone, Copy)]
pub enum SubmitOutcome {
    Completed(SubmitDone),
    Pending { request_id: u64 },
}

struct HostCallState {
    requests: ObjectStore<PendingWaiter>,
    request_heads: [u32; REQUEST_BUCKETS],
    sync_done: ObjectStore<SyncCompletion>,
    sync_done_heads: [u32; SYNC_DONE_BUCKETS],
}

struct HostCallStateCell(UnsafeCell<Option<HostCallState>>);

unsafe impl Sync for HostCallStateCell {}

static HOSTCALL_STATE: HostCallStateCell = HostCallStateCell(UnsafeCell::new(None));

fn state_mut() -> &'static mut HostCallState {
    // SAFETY: Hostcall runtime state is a single global cell. Callers already
    // serialize access through the existing kernel execution model; this only
    // removes `static mut` references without changing that protocol.
    unsafe {
        let slot = &mut *HOSTCALL_STATE.0.get();
        if slot.is_none() {
            *slot = Some(HostCallState {
                requests: ObjectStore::new(),
                request_heads: [0u32; REQUEST_BUCKETS],
                sync_done: ObjectStore::new(),
                sync_done_heads: [0u32; SYNC_DONE_BUCKETS],
            });
        }
        slot.as_mut().unwrap()
    }
}

#[inline(always)]
fn request_bucket(request_id: u64) -> usize {
    ((request_id ^ (request_id >> 32)).wrapping_mul(0x9E37_79B1u64) as usize) % REQUEST_BUCKETS
}

#[inline(always)]
fn sync_done_bucket(request_id: u64) -> usize {
    ((request_id ^ (request_id >> 29)).wrapping_mul(0x85EB_CA77u64) as usize) % SYNC_DONE_BUCKETS
}

pub fn init() {
    let _ = state_mut();
}

pub fn submit(args: SubmitArgs) -> SubmitOutcome {
    let (ret, aux) = hypercall::hostcall_submit_tagged(
        args.opcode,
        args.flags,
        args.arg0,
        args.arg1,
        args.arg2,
        args.arg3,
        args.user_tag,
    );
    if ret == hc::PENDING_RESULT {
        SubmitOutcome::Pending { request_id: aux }
    } else {
        SubmitOutcome::Completed(SubmitDone {
            host_result: ret,
            value0: aux,
        })
    }
}

pub fn call_sync(owner_pid: u32, args: SubmitArgs) -> Result<SubmitDone, u32> {
    let cur_tid = sched::current_tid();
    if cur_tid == 0 || !sched::thread_exists(cur_tid) {
        return Err(status::INVALID_PARAMETER);
    }
    match submit(args) {
        SubmitOutcome::Completed(done) => Ok(done),
        SubmitOutcome::Pending { request_id } => {
            if request_id == 0 {
                return Err(status::INVALID_PARAMETER);
            }
            if !register_request(owner_pid, request_id, cur_tid, true) {
                let _ = hypercall::hostcall_cancel(request_id);
                return Err(status::NO_MEMORY);
            }
            // Block current thread; unlock-edge fires on SchedLockAndSleep drop.
            // Thread resumes here after pump_completions → sched::wake().
            wait_current_for_request_pending(request_id, WaitDeadline::Infinite);
            // Read the completion stored by pump_completions.
            if let Some(done) = take_sync_completion(request_id) {
                let mapped = map_host_result_to_status(done.host_result);
                if mapped != status::SUCCESS {
                    return Err(mapped);
                }
                Ok(done)
            } else {
                cleanup_request(request_id, true);
                let wake_result = sched::with_thread(cur_tid, |t| t.wait.result)
                    .unwrap_or(status::INVALID_PARAMETER);
                Err(wake_result)
            }
        }
    }
}

pub fn register_request(
    owner_pid: u32,
    request_id: u64,
    waiter_tid: u32,
    need_submit_done: bool,
) -> bool {
    if request_id == 0 {
        return false;
    }
    if request_lookup_id(request_id) != 0 {
        return false;
    }
    let bucket = request_bucket(request_id);
    let state = state_mut();
    let head = state.request_heads[bucket];
    let Some(id) = state.requests.alloc_with(|_| PendingWaiter {
        owner_pid,
        request_id,
        waiter_tid,
        need_submit_done,
        req_next: head,
    }) else {
        return false;
    };
    state.request_heads[bucket] = id;
    true
}

fn store_sync_completion(request_id: u64, host_result: u64, value0: u64) -> bool {
    if request_id == 0 {
        return false;
    }
    let _ = sync_done_remove_by_request(request_id);
    let bucket = sync_done_bucket(request_id);
    let state = state_mut();
    let head = state.sync_done_heads[bucket];
    let Some(id) = state.sync_done.alloc_with(|_| SyncCompletion {
        request_id,
        host_result,
        value0,
        req_next: head,
    }) else {
        return false;
    };
    state.sync_done_heads[bucket] = id;
    true
}

fn take_sync_completion(request_id: u64) -> Option<SubmitDone> {
    let done = sync_done_remove_by_request(request_id)?;
    Some(SubmitDone {
        host_result: done.host_result,
        value0: done.value0,
    })
}

pub fn submit_tracked(
    owner_pid: u32,
    waiter_tid: u32,
    args: SubmitArgs,
) -> Result<SubmitOutcome, u32> {
    let out = submit(args);
    let SubmitOutcome::Pending { request_id } = out else {
        return Ok(out);
    };
    if request_id == 0 {
        return Err(status::INVALID_PARAMETER);
    }
    if register_request(owner_pid, request_id, waiter_tid, false) {
        return Ok(out);
    }
    let _ = hypercall::hostcall_cancel(request_id);
    Err(status::NO_MEMORY)
}

pub fn unregister_pending_request(request_id: u64) -> bool {
    request_remove_by_request(request_id).is_some()
}

fn request_lookup_id(request_id: u64) -> u32 {
    if request_id == 0 {
        return 0;
    }
    let state = state_mut();
    let mut cur = state.request_heads[request_bucket(request_id)];
    while cur != 0 {
        let ptr = state.requests.get_ptr(cur);
        if ptr.is_null() {
            break;
        }
        let node = unsafe { &*ptr };
        if node.request_id == request_id {
            return cur;
        }
        cur = node.req_next;
    }
    0
}

fn request_remove_by_request(request_id: u64) -> Option<PendingWaiter> {
    if request_id == 0 {
        return None;
    }
    let bucket = request_bucket(request_id);
    let state = state_mut();
    let mut prev = 0u32;
    let mut cur = state.request_heads[bucket];
    while cur != 0 {
        let ptr = state.requests.get_ptr(cur);
        if ptr.is_null() {
            break;
        }
        let node = unsafe { *ptr };
        let next = node.req_next;
        if node.request_id == request_id {
            if prev == 0 {
                state.request_heads[bucket] = next;
            } else {
                let prev_ptr = state.requests.get_ptr(prev);
                if !prev_ptr.is_null() {
                    unsafe { (*prev_ptr).req_next = next };
                }
            }
            let _ = state.requests.free(cur);
            return Some(node);
        }
        prev = cur;
        cur = next;
    }
    None
}

fn sync_done_remove_by_request(request_id: u64) -> Option<SyncCompletion> {
    if request_id == 0 {
        return None;
    }
    let bucket = sync_done_bucket(request_id);
    let state = state_mut();
    let mut prev = 0u32;
    let mut cur = state.sync_done_heads[bucket];
    while cur != 0 {
        let ptr = state.sync_done.get_ptr(cur);
        if ptr.is_null() {
            break;
        }
        let node = unsafe { *ptr };
        let next = node.req_next;
        if node.request_id == request_id {
            if prev == 0 {
                state.sync_done_heads[bucket] = next;
            } else {
                let prev_ptr = state.sync_done.get_ptr(prev);
                if !prev_ptr.is_null() {
                    unsafe { (*prev_ptr).req_next = next };
                }
            }
            let _ = state.sync_done.free(cur);
            return Some(node);
        }
        prev = cur;
        cur = next;
    }
    None
}

pub fn wait_current_for_request_pending(request_id: u64, timeout: WaitDeadline) -> u32 {
    let cur = sched::current_tid();
    if cur == 0 || !sched::thread_exists(cur) || request_id == 0 {
        return status::INVALID_PARAMETER;
    }
    if timeout == WaitDeadline::Immediate {
        cleanup_request(request_id, true);
        return status::TIMEOUT;
    }
    let deadline = match timeout {
        WaitDeadline::Infinite => WaitDeadline::Infinite,
        WaitDeadline::Immediate => WaitDeadline::Immediate,
        WaitDeadline::DeadlineTicks(t) => WaitDeadline::DeadlineTicks(t),
    };
    {
        let _slp = sched::lock::SchedLockAndSleep::new();
        sched::with_thread_mut(cur, |t| t.wait.kind = sched::WAIT_KIND_HOSTCALL);
        sched::block_thread_locked(cur, deadline);
        // _slp drops here → flush_unlock_edge → thread switches out
    }
    // Thread resumes here after pump_completions calls sched::wake().
    STATUS_PENDING
}

fn take_waiter_by_request(request_id: u64) -> Option<PendingWaiter> {
    request_remove_by_request(request_id)
}

fn cleanup_request(request_id: u64, cancel_host: bool) {
    if request_id == 0 {
        return;
    }
    if cancel_host {
        let _ = hypercall::hostcall_cancel(request_id);
    }
    let _ = unregister_pending_request(request_id);
    let _ = take_sync_completion(request_id);
}

pub fn pump_completions() {
    const CPL_POLL_LIMIT: usize = 32;
    let mut cpl = hypercall::HostCallCompletion::default();
    let mut processed = 0usize;
    loop {
        if processed >= CPL_POLL_LIMIT {
            break;
        }
        let got = hypercall::hostcall_poll_batch(&mut cpl as *mut _, 1);
        if got == 0 {
            break;
        }
        let cpl = cpl;
        let waiter = match take_waiter_by_request(cpl.request_id) {
            Some(w) => w,
            None => {
                processed = processed.saturating_add(1);
                continue;
            }
        };

        if waiter.waiter_tid == 0 {
            let _ = crate::nt::file::dispatch_async_hostcall_completion(cpl);
            processed = processed.saturating_add(1);
            continue;
        }
        if crate::nt::file::dispatch_async_hostcall_completion(cpl) {
            processed = processed.saturating_add(1);
            continue;
        }
        let host_result = if cpl.host_result < 0 {
            hc::HC_INVALID
        } else {
            cpl.host_result as u64
        };
        let mut wake_st = map_host_result_to_status(host_result);
        if waiter.need_submit_done && wake_st == status::SUCCESS {
            if !store_sync_completion(cpl.request_id, host_result, cpl.value0) {
                wake_st = status::NO_MEMORY;
            }
        }
        if crate::process::process_exists(waiter.owner_pid) {
            sched::wake(waiter.waiter_tid, wake_st);
        }
        processed = processed.saturating_add(1);
    }
}

fn collect_requests_for_waiter_tid(waiter_tid: u32, out: &mut Vec<u64>) {
    state_mut().requests.for_each_live_ptr(|_id, ptr| unsafe {
        let p = *ptr;
        if p.waiter_tid == waiter_tid && p.request_id != 0 {
            let _ = out.try_reserve(1);
            out.push(p.request_id);
        }
    });
}

fn collect_requests_for_owner_pid(owner_pid: u32, out: &mut Vec<u64>) {
    state_mut().requests.for_each_live_ptr(|_id, ptr| unsafe {
        let p = *ptr;
        if p.owner_pid == owner_pid && p.request_id != 0 {
            let _ = out.try_reserve(1);
            out.push(p.request_id);
        }
    });
}

pub fn cancel_requests_for_waiter_tid(waiter_tid: u32) -> usize {
    if waiter_tid == 0 {
        return 0;
    }
    let mut reqs = Vec::new();
    collect_requests_for_waiter_tid(waiter_tid, &mut reqs);
    let mut canceled = 0usize;
    for req in reqs {
        cleanup_request(req, true);
        canceled = canceled.saturating_add(1);
    }
    canceled
}

pub fn cancel_requests_for_owner_pid(owner_pid: u32) -> usize {
    if owner_pid == 0 {
        return 0;
    }
    let mut reqs = Vec::new();
    collect_requests_for_owner_pid(owner_pid, &mut reqs);
    let mut canceled = 0usize;
    for req in reqs {
        cleanup_request(req, true);
        canceled = canceled.saturating_add(1);
    }
    canceled
}

pub fn map_host_result_to_status(host_result: u64) -> u32 {
    match host_result {
        v if v == hc::HC_OK => winemu_shared::status::SUCCESS,
        v if v == hc::HC_BUSY => winemu_shared::status::NO_MEMORY,
        v if v == hc::HC_NO_MEMORY => winemu_shared::status::NO_MEMORY,
        v if v == hc::HC_CANCELED => winemu_shared::status::INVALID_HANDLE,
        v if v == hc::HC_IO_ERROR => winemu_shared::status::OBJECT_NAME_NOT_FOUND,
        _ => winemu_shared::status::INVALID_PARAMETER,
    }
}
