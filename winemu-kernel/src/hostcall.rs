use crate::hypercall;
use crate::kobj::ObjectStore;
use crate::rust_alloc::vec::Vec;
use crate::sched;
use crate::sched::sync::WaitDeadline;
use winemu_shared::hostcall as hc;
use winemu_shared::status;

const STATUS_PENDING: u32 = 0x0000_0103;

#[derive(Clone, Copy)]
struct PendingWaiter {
    owner_pid: u32,
    request_id: u64,
    waiter_tid: u32,
}

#[derive(Clone, Copy)]
struct CompletedHostCall {
    request_id: u64,
    cpl: hypercall::HostCallCompletion,
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
    completions: ObjectStore<CompletedHostCall>,
}

static mut HOSTCALL_STATE: Option<HostCallState> = None;

fn state_mut() -> &'static mut HostCallState {
    unsafe {
        if HOSTCALL_STATE.is_none() {
            HOSTCALL_STATE = Some(HostCallState {
                requests: ObjectStore::new(),
                completions: ObjectStore::new(),
            });
        }
        HOSTCALL_STATE.as_mut().unwrap()
    }
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
    if register_request(owner_pid, request_id, waiter_tid) {
        return Ok(out);
    }
    let _ = hypercall::hostcall_cancel(request_id);
    Err(status::NO_MEMORY)
}

fn to_submit_done(cpl: hypercall::HostCallCompletion) -> SubmitDone {
    SubmitDone {
        host_result: (cpl.host_result as u32) as u64,
        value0: cpl.value0,
    }
}

fn wait_sync_completion(request_id: u64, timeout: WaitDeadline) -> Result<SubmitDone, u32> {
    if request_id == 0 {
        return Err(status::INVALID_PARAMETER);
    }
    if timeout == WaitDeadline::Immediate {
        let _ = hypercall::hostcall_cancel(request_id);
        let _ = unregister_pending_request(request_id);
        return Err(status::TIMEOUT);
    }
    let st = wait_current_for_request(request_id, timeout);
    if st != status::SUCCESS {
        return Err(st);
    }
    take_completion(request_id)
        .map(to_submit_done)
        .ok_or(status::NO_MEMORY)
}

pub fn call_sync(
    owner_pid: u32,
    args: SubmitArgs,
    timeout: WaitDeadline,
) -> Result<SubmitDone, u32> {
    let cur_tid = sched::current_tid();
    if cur_tid == 0 || !sched::thread_exists(cur_tid) {
        return Err(status::INVALID_PARAMETER);
    }
    match submit_tracked(owner_pid, cur_tid, args)? {
        SubmitOutcome::Completed(done) => Ok(done),
        SubmitOutcome::Pending { request_id } => wait_sync_completion(request_id, timeout),
    }
}

pub fn register_request(owner_pid: u32, request_id: u64, waiter_tid: u32) -> bool {
    if request_id == 0 {
        return false;
    }
    state_mut()
        .requests
        .alloc_with(|_| PendingWaiter {
            owner_pid,
            request_id,
            waiter_tid,
        })
        .is_some()
}

fn wait_deadline_ticks(timeout: WaitDeadline) -> u64 {
    match timeout {
        WaitDeadline::Infinite | WaitDeadline::Immediate => 0,
        WaitDeadline::DeadlineTicks(t) => t,
    }
}

pub fn wait_current_for_request(request_id: u64, timeout: WaitDeadline) -> u32 {
    let cur = sched::current_tid();
    if cur == 0 || !sched::thread_exists(cur) || request_id == 0 {
        return status::INVALID_PARAMETER;
    }
    if timeout == WaitDeadline::Immediate {
        let _ = hypercall::hostcall_cancel(request_id);
        let _ = unregister_pending_request(request_id);
        return status::TIMEOUT;
    }
    let deadline = wait_deadline_ticks(timeout);
    let wait_status = sched::block_current_and_resched(
        sched::WAIT_KIND_HOSTCALL,
        core::slice::from_ref(&request_id),
        deadline,
        STATUS_PENDING,
    );
    if wait_status != status::SUCCESS {
        let _ = hypercall::hostcall_cancel(request_id);
        let _ = unregister_pending_request(request_id);
        return wait_status;
    }
    let resolved = sched::consume_current_wait_result();
    if resolved == status::TIMEOUT {
        let _ = hypercall::hostcall_cancel(request_id);
        let _ = unregister_pending_request(request_id);
    }
    resolved
}

fn find_waiter_id_by_request(request_id: u64) -> u32 {
    let mut found = 0u32;
    state_mut().requests.for_each_live_ptr(|id, ptr| unsafe {
        if found == 0 && (*ptr).request_id == request_id {
            found = id;
        }
    });
    found
}

fn find_completion_id_by_request(request_id: u64) -> u32 {
    let mut found = 0u32;
    state_mut().completions.for_each_live_ptr(|id, ptr| unsafe {
        if found == 0 && (*ptr).request_id == request_id {
            found = id;
        }
    });
    found
}

pub fn unregister_pending_request(request_id: u64) -> bool {
    if request_id == 0 {
        return false;
    }
    let mut changed = false;
    let waiter_id = find_waiter_id_by_request(request_id);
    if waiter_id != 0 {
        let _ = state_mut().requests.free(waiter_id);
        changed = true;
    }
    let cpl_id = find_completion_id_by_request(request_id);
    if cpl_id != 0 {
        let _ = state_mut().completions.free(cpl_id);
        changed = true;
    }
    changed
}

pub fn take_completion(request_id: u64) -> Option<hypercall::HostCallCompletion> {
    if request_id == 0 {
        return None;
    }
    let cpl_id = find_completion_id_by_request(request_id);
    if cpl_id == 0 {
        return None;
    }
    let ptr = state_mut().completions.get_ptr(cpl_id);
    if ptr.is_null() {
        let _ = state_mut().completions.free(cpl_id);
        return None;
    }
    let out = unsafe { (*ptr).cpl };
    let _ = state_mut().completions.free(cpl_id);
    Some(out)
}

fn waiter_still_pending(waiter_tid: u32, request_id: u64) -> bool {
    if waiter_tid == 0 || request_id == 0 || !sched::thread_exists(waiter_tid) {
        return false;
    }
    sched::sched_lock_acquire();
    let keep = sched::with_thread(waiter_tid, |t| {
        t.state == sched::ThreadState::Waiting
            && t.wait_kind == sched::WAIT_KIND_HOSTCALL
            && t.wait_count != 0
            && t.wait_handles[0] == request_id
    });
    sched::sched_lock_release();
    keep
}

fn take_waiter_by_request(request_id: u64) -> Option<PendingWaiter> {
    let waiter_id = find_waiter_id_by_request(request_id);
    if waiter_id == 0 {
        return None;
    }
    let ptr = state_mut().requests.get_ptr(waiter_id);
    if ptr.is_null() {
        let _ = state_mut().requests.free(waiter_id);
        return None;
    }
    let waiter = unsafe { *ptr };
    let _ = state_mut().requests.free(waiter_id);
    Some(waiter)
}

fn reap_stale_waiters() {
    let mut stale = Vec::new();
    state_mut().requests.for_each_live_ptr(|_id, ptr| unsafe {
        let p = *ptr;
        if p.waiter_tid != 0 && !waiter_still_pending(p.waiter_tid, p.request_id) {
            let _ = stale.try_reserve(1);
            stale.push(p.request_id);
        }
    });
    for req in stale {
        if req != 0 {
            let _ = hypercall::hostcall_cancel(req);
            let _ = unregister_pending_request(req);
        }
    }
}

fn store_completion(cpl: hypercall::HostCallCompletion) -> bool {
    let _ = unregister_pending_request(cpl.request_id);
    state_mut()
        .completions
        .alloc_with(|_| CompletedHostCall {
            request_id: cpl.request_id,
            cpl,
        })
        .is_some()
}

pub fn pump_completions() {
    reap_stale_waiters();

    const CPL_BATCH: usize = 32;
    let mut cpls = [hypercall::HostCallCompletion::default(); CPL_BATCH];
    let got = hypercall::hostcall_poll_batch(cpls.as_mut_ptr(), cpls.len());
    if got == 0 {
        return;
    }

    for cpl in cpls.iter().take(got.min(cpls.len())) {
        let Some(waiter) = take_waiter_by_request(cpl.request_id) else {
            continue;
        };
        let completion_stored = store_completion(*cpl);
        if crate::process::process_exists(waiter.owner_pid) && waiter.waiter_tid != 0 {
            // Hostcall sync waiter consumes real host result from completion payload.
            // Wake status only represents scheduler wait lifecycle progress.
            let st = if completion_stored {
                status::SUCCESS
            } else {
                status::NO_MEMORY
            };
            sched::wake(waiter.waiter_tid, st);
        }
    }
}

pub fn map_host_result_to_status(host_result: u64) -> u32 {
    match host_result {
        v if v == hc::HC_OK => winemu_shared::status::SUCCESS,
        v if v == hc::HC_BUSY => winemu_shared::status::NO_MEMORY,
        v if v == hc::HC_NO_MEMORY => winemu_shared::status::NO_MEMORY,
        v if v == hc::HC_CANCELED => winemu_shared::status::INVALID_HANDLE,
        _ => winemu_shared::status::INVALID_PARAMETER,
    }
}
