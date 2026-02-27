use winemu_core::addr::Gpa;
use winemu_shared::status;

use crate::sched::sync::SyncHandle;

use super::{read_unicode_string, DispatchContext, DispatchResult, SyscallArgs};

pub(super) fn nt_create_file(call: &SyscallArgs<'_>, ctx: &DispatchContext<'_>) -> DispatchResult {
    // Simplified: args map to our NT_CREATE_FILE hypercall layout
    // a[0]=ObjectAttributes*, a[1]=access, a[2]=..., a[3]=disposition
    // Full NtCreateFile has 11 params; we handle the common subset
    let access = call.get(1) as u32;
    let disposition = call.get(7) as u32;
    let oa_gpa = call.get(2);
    let path = read_unicode_string(ctx.memory, oa_gpa);
    let (st, h) = ctx.files.create(&path, access, disposition);
    log::debug!("NtCreateFile: path={} status={:#x} handle={}", path, st, h);
    DispatchResult::Sync((st << 32) | h)
}

pub(super) fn nt_read_file(call: &SyscallArgs<'_>, ctx: &DispatchContext<'_>) -> DispatchResult {
    let handle = call.get(0);
    let buf_gpa = Gpa(call.get(5));
    let length = call.get(6) as usize;
    let offset = if call.get(7) == u64::MAX {
        None
    } else {
        Some(call.get(7))
    };
    if length == 0 || length > 64 * 1024 * 1024 {
        return DispatchResult::Sync(status::INVALID_PARAMETER as u64);
    }
    let mut buf = vec![0u8; length];
    let (st, n) = ctx.files.read(handle, &mut buf, offset);
    if st == status::SUCCESS as u64 && n > 0 {
        ctx.memory.write().unwrap().write_bytes(buf_gpa, &buf[..n]);
    }
    DispatchResult::Sync((st << 32) | n as u64)
}

pub(super) fn nt_write_file(call: &SyscallArgs<'_>, ctx: &DispatchContext<'_>) -> DispatchResult {
    let handle = call.get(0);
    let buf_gpa = Gpa(call.get(5));
    let length = call.get(6) as usize;
    let offset = if call.get(7) == u64::MAX {
        None
    } else {
        Some(call.get(7))
    };
    log::debug!(
        "NtWriteFile: handle={:#x} buf={:#x} len={}",
        handle,
        buf_gpa.0,
        length
    );
    if length == 0 || length > 64 * 1024 * 1024 {
        return DispatchResult::Sync(status::INVALID_PARAMETER as u64);
    }
    let buf = ctx
        .memory
        .read()
        .unwrap()
        .read_bytes(buf_gpa, length)
        .to_vec();
    let (st, _n) = ctx.files.write(handle, &buf, offset);
    DispatchResult::Sync(st)
}

pub(super) fn nt_close(call: &SyscallArgs<'_>, ctx: &DispatchContext<'_>) -> DispatchResult {
    let handle = call.get(0);
    // Try file handle first, then section handle, then sync handle.
    let st = if ctx.files.close(handle) == status::SUCCESS as u64 {
        status::SUCCESS as u64
    } else if ctx.sections.close(handle) {
        status::SUCCESS as u64
    } else if ctx.sched.close_handle(SyncHandle(handle as u32)) {
        status::SUCCESS as u64
    } else {
        status::INVALID_HANDLE as u64
    };
    DispatchResult::Sync(st)
}

pub(super) fn nt_open_file(call: &SyscallArgs<'_>, ctx: &DispatchContext<'_>) -> DispatchResult {
    // a[0]=*FileHandle, a[1]=DesiredAccess, a[2]=ObjectAttributes
    // a[3]=IoStatusBlock, a[4]=ShareAccess, a[5]=OpenOptions
    let handle_out_gpa = call.get(0);
    let access = call.get(1) as u32;
    let oa_gpa = call.get(2);
    let path = read_unicode_string(ctx.memory, oa_gpa);
    log::debug!("NtOpenFile: {}", path);
    let (st, h) = ctx.files.create(&path, access, 1 /* FILE_OPEN */);
    if st == 0 && handle_out_gpa != 0 {
        ctx.memory
            .write()
            .unwrap()
            .write_bytes(Gpa(handle_out_gpa), &h.to_le_bytes());
    }
    DispatchResult::Sync(st)
}

pub(super) fn nt_set_information_file(
    call: &SyscallArgs<'_>,
    _ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // Stub — most callers don't check return value for non-critical ops.
    log::debug!("NtSetInformationFile: class={}", call.get(4) as u32);
    DispatchResult::Sync(status::SUCCESS as u64)
}

pub(super) fn nt_query_directory_file(
    _call: &SyscallArgs<'_>,
    _ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // Stub — return STATUS_NO_MORE_FILES so callers stop iterating.
    DispatchResult::Sync(status::NO_MORE_FILES as u64)
}
