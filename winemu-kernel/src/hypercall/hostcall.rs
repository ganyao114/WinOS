use winemu_shared::hostcall as hc;
use winemu_shared::nr;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HostCallCompletion {
    pub request_id: u64,
    pub host_result: i32,
    pub flags: u32,
    pub value0: u64,
    pub value1: u64,
    pub user_tag: u64,
}

#[inline(always)]
pub fn hostcall_setup() -> u64 {
    super::hypercall6(nr::HOSTCALL_SETUP, 0, 0, 0, 0, 0, 0)
}

#[inline(always)]
pub fn hostcall_submit(
    opcode: u64,
    flags: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> (u64, u64) {
    super::hypercall6_pair(nr::HOSTCALL_SUBMIT, opcode, flags, arg0, arg1, arg2, arg3)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HostCallSubmitExt {
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    user_tag: u64,
}

#[inline(always)]
pub fn hostcall_submit_tagged(
    opcode: u64,
    flags: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    user_tag: u64,
) -> (u64, u64) {
    if user_tag == 0 {
        return hostcall_submit(opcode, flags, arg0, arg1, arg2, arg3);
    }
    let ext = HostCallSubmitExt {
        arg0,
        arg1,
        arg2,
        arg3,
        user_tag,
    };
    super::hypercall6_pair(
        nr::HOSTCALL_SUBMIT,
        opcode,
        flags | hc::FLAG_EXT_BUF,
        &ext as *const HostCallSubmitExt as u64,
        hc::EXT_SUBMIT_SIZE as u64,
        0,
        0,
    )
}

#[inline(always)]
pub fn hostcall_poll(dst: *mut HostCallCompletion) -> usize {
    super::hypercall6(nr::HOSTCALL_POLL, dst as u64, 1, 0, 0, 0, 0) as usize
}

#[inline(always)]
pub fn hostcall_cancel(request_id: u64) -> u64 {
    super::hypercall6(nr::HOSTCALL_CANCEL, request_id, 0, 0, 0, 0, 0)
}

#[inline(always)]
pub fn hostcall_poll_batch(dst: *mut HostCallCompletion, cap_entries: usize) -> usize {
    super::hypercall6(
        nr::HOSTCALL_POLL_BATCH,
        dst as u64,
        cap_entries as u64,
        0,
        0,
        0,
        0,
    ) as usize
}

#[inline(always)]
pub fn hostcall_query_stats(dst: *mut u8, len: usize, flags: u64) -> usize {
    super::hypercall6(
        nr::HOSTCALL_QUERY_STATS,
        dst as u64,
        len as u64,
        flags,
        0,
        0,
        0,
    ) as usize
}

#[inline(always)]
pub fn hostcall_query_sched_wake_stats(dst: *mut u8, len: usize, flags: u64) -> usize {
    super::hypercall6(
        nr::HOSTCALL_QUERY_SCHED_WAKE_STATS,
        dst as u64,
        len as u64,
        flags,
        0,
        0,
        0,
    ) as usize
}
