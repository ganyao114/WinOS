use winemu_core::addr::Gpa;
use winemu_shared::status;

use crate::sched::sync::{EventObj, SyncHandle, SyncObject};
use crate::sched::Scheduler;

use super::{DispatchContext, DispatchResult, SyscallArgs};

fn read_timeout_ptr(call: &SyscallArgs<'_>, timeout_ptr: u64) -> i64 {
    if timeout_ptr == 0 {
        // NT: NULL timeout pointer means infinite wait.
        return i64::MIN;
    }
    let mem = call.memory().read().unwrap();
    let bytes = mem.read_bytes(Gpa(timeout_ptr), 8);
    let raw: [u8; 8] = bytes.try_into().unwrap_or([0; 8]);
    i64::from_le_bytes(raw)
}

pub(super) fn nt_create_event(call: &SyscallArgs<'_>, ctx: &DispatchContext<'_>) -> DispatchResult {
    // NtCreateEvent(OUT PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE, BOOLEAN)
    // x0=EventHandle ptr, x1=DesiredAccess, x2=ObjectAttributes, x3=EventType, x4=InitialState
    let handle_gpa = call.get(0);
    let event_type = call.get(3) as u32; // 0=NotificationEvent(manual), 1=SynchronizationEvent(auto)
    let initial = call.get(4) != 0;
    let manual_reset = event_type == 0;
    let h = ctx.sched.alloc_handle();
    ctx.sched
        .insert_object(h, SyncObject::Event(EventObj::new(manual_reset, initial)));
    if handle_gpa != 0 {
        ctx.memory
            .write()
            .unwrap()
            .write_bytes(Gpa(handle_gpa), &(h.0 as u64).to_le_bytes());
    }
    DispatchResult::Sync(status::SUCCESS as u64)
}

pub(super) fn nt_wait_for_single_object(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    let handle = SyncHandle(call.get(0) as u32);
    let alertable = call.get(1) != 0;
    let timeout = read_timeout_ptr(call, call.get(2));
    let _ = alertable; // Phase 3: APC
    DispatchResult::Sched(ctx.sched.wait_single(ctx.tid, handle, timeout))
}

pub(super) fn nt_set_event(call: &SyscallArgs<'_>, ctx: &DispatchContext<'_>) -> DispatchResult {
    // NtSetEvent(EventHandle, OUT PLONG PreviousState)
    let handle = SyncHandle(call.get(0) as u32);
    let prev_gpa = call.get(1);
    let shard = Scheduler::object_shard_pub(handle);
    let mut map = ctx.sched.objects[shard].lock().unwrap();
    if let Some(SyncObject::Event(ref mut evt)) = map.get_mut(&handle) {
        let prev = if evt.signaled { 1u64 } else { 0u64 };
        let wakeups = evt.set();
        drop(map);
        for wake_tid in wakeups {
            ctx.sched.push_ready(wake_tid);
        }
        if prev_gpa != 0 {
            ctx.memory
                .write()
                .unwrap()
                .write_bytes(Gpa(prev_gpa), &(prev as u32).to_le_bytes());
        }
        DispatchResult::Sync(status::SUCCESS as u64)
    } else {
        drop(map);
        DispatchResult::Sync(status::INVALID_HANDLE as u64)
    }
}

pub(super) fn nt_reset_event(call: &SyscallArgs<'_>, ctx: &DispatchContext<'_>) -> DispatchResult {
    // NtResetEvent(EventHandle, OUT PLONG PreviousState)
    let handle = SyncHandle(call.get(0) as u32);
    let prev_gpa = call.get(1);
    let shard = Scheduler::object_shard_pub(handle);
    let mut map = ctx.sched.objects[shard].lock().unwrap();
    if let Some(SyncObject::Event(ref mut evt)) = map.get_mut(&handle) {
        let prev = if evt.signaled { 1u64 } else { 0u64 };
        evt.reset();
        if prev_gpa != 0 {
            ctx.memory
                .write()
                .unwrap()
                .write_bytes(Gpa(prev_gpa), &(prev as u32).to_le_bytes());
        }
        DispatchResult::Sync(status::SUCCESS as u64)
    } else {
        DispatchResult::Sync(status::INVALID_HANDLE as u64)
    }
}

pub(super) fn nt_wait_for_multiple_objects(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    let count = call.get(0) as usize;
    let arr_gpa = Gpa(call.get(1));
    let wait_all = call.get(2) != 0;
    let timeout = read_timeout_ptr(call, call.get(4));
    if count == 0 || count > 64 {
        return DispatchResult::Sync(status::INVALID_PARAMETER as u64);
    }
    let handles: Vec<SyncHandle> = {
        let mem = ctx.memory.read().unwrap();
        (0..count)
            .map(|i| {
                let bytes = mem.read_bytes(Gpa(arr_gpa.0 + i as u64 * 4), 4);
                SyncHandle(u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])))
            })
            .collect()
    };
    DispatchResult::Sched(ctx.sched.wait_multiple(ctx.tid, handles, wait_all, timeout))
}
