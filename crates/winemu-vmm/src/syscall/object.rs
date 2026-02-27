use winemu_core::addr::Gpa;
use winemu_shared::status;

use crate::sched::sync::{EventObj, SyncHandle, SyncObject};
use crate::sched::Scheduler;

use super::{DispatchContext, DispatchResult, SyscallArgs};

pub(super) fn nt_duplicate_object(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // a[0]=SrcProcess, a[1]=SrcHandle, a[2]=DstProcess
    // a[3]=*DstHandle, a[4]=DesiredAccess, a[5]=HandleAttributes, a[6]=Options
    let src_h = SyncHandle(call.get(1) as u32);
    let dst_gpa = call.get(3);
    let shard = Scheduler::object_shard_pub(src_h);
    let map = ctx.sched.objects[shard].lock().unwrap();
    let cloned = match map.get(&src_h) {
        Some(SyncObject::Event(e)) => {
            Some(SyncObject::Event(EventObj::new(e.manual_reset, e.signaled)))
        }
        _ => None,
    };
    drop(map);
    if let Some(obj) = cloned {
        let new_h = ctx.sched.alloc_handle();
        ctx.sched.insert_object(new_h, obj);
        if dst_gpa != 0 {
            ctx.memory
                .write()
                .unwrap()
                .write_bytes(Gpa(dst_gpa), &(new_h.0 as u64).to_le_bytes());
        }
        DispatchResult::Sync(status::SUCCESS as u64)
    } else {
        DispatchResult::Sync(status::INVALID_HANDLE as u64)
    }
}

pub(super) fn nt_query_object(call: &SyscallArgs<'_>, ctx: &DispatchContext<'_>) -> DispatchResult {
    // Return minimal info; most callers just check status.
    let ret_len_gpa = call.get(4);
    if ret_len_gpa != 0 {
        ctx.memory
            .write()
            .unwrap()
            .write_bytes(Gpa(ret_len_gpa), &0u32.to_le_bytes());
    }
    DispatchResult::Sync(status::SUCCESS as u64)
}

pub(super) fn nt_query_system_information(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // a[0]=SystemInformationClass, a[1]=buf, a[2]=len, a[3]=*ReturnLength
    let ret_len_gpa = call.get(3);
    if ret_len_gpa != 0 {
        ctx.memory
            .write()
            .unwrap()
            .write_bytes(Gpa(ret_len_gpa), &0u32.to_le_bytes());
    }
    log::debug!("NtQuerySystemInformation: class={}", call.get(0) as u32);
    DispatchResult::Sync(status::SUCCESS as u64)
}
