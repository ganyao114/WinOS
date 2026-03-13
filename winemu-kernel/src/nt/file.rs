use core::cell::UnsafeCell;

use crate::fs::{
    FsAsyncCompletion, FsAsyncSubmit, FsDeviceIoctlRequest, FsDeviceIoctlSubmit, FsFileHandle,
    FsIoctlOutput, FsNotifyRecord, FsVolumeTarget, WinEmuHostcallRequest, WinEmuHostcallResponse,
    IOCTL_WINEMU_HOSTCALL_SYNC, IOCTL_WINEMU_HOST_PING,
};
use crate::hostcall;
use crate::kobj::ObjectStore;
use crate::mm::{PhysAddr, UserVa};
use crate::process::{with_process_mut, KObjectKind, KObjectRef};
use crate::rust_alloc::vec::Vec;
use crate::sched::sync::event_set_by_handle_for_pid;
use winemu_shared::status;

fn handle_kind_for_pid(handle: u64, pid: u32) -> Option<KObjectKind> {
    with_process_mut(pid, |p| p.handle_table.get(handle as u32))
        .flatten()
        .map(|o| o.kind)
}

fn handle_idx_for_pid(handle: u64, pid: u32) -> u32 {
    with_process_mut(pid, |p| p.handle_table.get(handle as u32))
        .flatten()
        .map(|o| o.obj_idx)
        .unwrap_or(0)
}

use super::common::{
    file_handle_target, map_file_generic_access, map_open_mode, GuestWriter, IoStatusBlock,
    IoStatusBlockPtr, NtFileHandleTarget, FILE_OPEN, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE,
};
use super::path::{ObjectAttributesView, UnicodeStringView};
use super::user_args::{SyscallArgs, UserInPtr, UserOutPtr};
use super::SvcFrame;
use crate::mm::usercopy::{copy_from_phys_to_process_user, copy_from_process_user_to_phys};

const FILE_BASIC_INFORMATION_SIZE: usize = 40;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_STANDARD_INFORMATION_CLASS: u32 = 5;
const FILE_POSITION_INFORMATION_CLASS: u32 = 14;
const FILE_ALLOCATION_INFORMATION_CLASS: u32 = 19;
const FILE_END_OF_FILE_INFORMATION_CLASS: u32 = 20;
const FILE_POSITION_INFORMATION_SIZE: usize = 8;
const FILE_END_OF_FILE_INFORMATION_SIZE: usize = 8;

const FILE_DIRECTORY_INFORMATION: u32 = 1;
const FILE_FULL_DIRECTORY_INFORMATION: u32 = 2;
const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 3;
const FILE_NAMES_INFORMATION: u32 = 12;
const FILE_DIRECTORY_INFORMATION_BASE: usize = 64;
const FILE_FULL_DIRECTORY_INFORMATION_BASE: usize = 68;
const FILE_BOTH_DIRECTORY_INFORMATION_BASE: usize = 94;
const FILE_NAMES_INFORMATION_BASE: usize = 12;

const FILE_NOTIFY_INFORMATION_BASE: usize = 12;
const STATUS_PENDING: u32 = 0x0000_0103;
const FILE_IO_BOUNCE_PAGE_SIZE: usize = crate::nt::constants::PAGE_SIZE_4K as usize;

const FILE_FS_SIZE_INFORMATION: u32 = 3;
const FILE_FS_DEVICE_INFORMATION: u32 = 4;
const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 5;
const FILE_FS_SIZE_INFORMATION_SIZE: usize = 24;
const FILE_FS_DEVICE_INFORMATION_SIZE: usize = 8;
const FILE_FS_ATTRIBUTE_INFORMATION_SIZE: usize = 12;

#[inline(always)]
fn is_std_file_handle(h: u64) -> bool {
    matches!(h, STD_INPUT_HANDLE | STD_OUTPUT_HANDLE | STD_ERROR_HANDLE)
}

#[derive(Clone, Copy)]
struct PendingDirNotify {
    owner_pid: u32,
    file: FsFileHandle,
    waiter_tid: u32,
    event_handle: u64,
    iosb_ptr: IoStatusBlockPtr,
    out_ptr: *mut u8,
    out_len: usize,
    request_id: u64,
}

#[derive(Clone, Copy)]
struct PendingFileIo {
    owner_pid: u32,
    file: FsFileHandle,
    event_handle: u64,
    iosb_ptr: IoStatusBlockPtr,
    user_buffer: UserVa,
    request_id: u64,
    requested_len: usize,
    bounce_pa: PhysAddr,
    bounce_pages: usize,
}

#[derive(Clone, Copy)]
struct PendingHostIoctl {
    owner_pid: u32,
    file: FsFileHandle,
    waiter_tid: u32,
    event_handle: u64,
    iosb_ptr: IoStatusBlockPtr,
    out_ptr: *mut u8,
    out_len: usize,
    request_id: u64,
}

struct FileAsyncState {
    pending_dir_notify: ObjectStore<PendingDirNotify>,
    pending_file_io: ObjectStore<PendingFileIo>,
    pending_host_ioctl: ObjectStore<PendingHostIoctl>,
}

struct FileAsyncStateCell(UnsafeCell<Option<FileAsyncState>>);

unsafe impl Sync for FileAsyncStateCell {}

static FILE_ASYNC_STATE: FileAsyncStateCell = FileAsyncStateCell(UnsafeCell::new(None));

fn async_state_mut() -> &'static mut FileAsyncState {
    // SAFETY: Async file state is a single global cell. This preserves the
    // existing serialization assumptions while avoiding `static mut` borrows.
    unsafe {
        let slot = &mut *FILE_ASYNC_STATE.0.get();
        if slot.is_none() {
            *slot = Some(FileAsyncState {
                pending_dir_notify: ObjectStore::new(),
                pending_file_io: ObjectStore::new(),
                pending_host_ioctl: ObjectStore::new(),
            });
        }
        slot.as_mut().unwrap()
    }
}

fn file_io_bounce_pages(len: usize) -> Option<usize> {
    if len == 0 {
        return Some(0);
    }
    len.checked_add(FILE_IO_BOUNCE_PAGE_SIZE - 1)
        .map(|n| n / FILE_IO_BOUNCE_PAGE_SIZE)
}

fn alloc_file_io_bounce(len: usize) -> Option<(PhysAddr, usize)> {
    let pages = file_io_bounce_pages(len)?;
    if pages == 0 {
        return Some((PhysAddr::default(), 0));
    }
    crate::mm::phys::alloc_pages(pages).map(|pa| (pa, pages))
}

fn free_file_io_bounce(pa: PhysAddr, pages: usize) {
    if !pa.is_null() && pages != 0 {
        crate::mm::phys::free_pages(pa, pages);
    }
}

fn free_pending_file_io_resources(req: &PendingFileIo) {
    free_file_io_bounce(req.bounce_pa, req.bounce_pages);
}

fn complete_inline_file_io(
    owner_pid: u32,
    event_handle: u64,
    iosb_ptr: IoStatusBlockPtr,
    st: u32,
    info: u64,
) {
    let _ = iosb_ptr.write_for_pid(owner_pid, st, info);
    if event_handle != 0 {
        let _ = event_set_by_handle_for_pid(owner_pid, event_handle);
    }
}

fn complete_pending_notify(req: &PendingDirNotify, st: u32, info: u64, signal_event: bool) {
    if !crate::process::process_exists(req.owner_pid) {
        return;
    }
    let _ = req.iosb_ptr.write_for_pid(req.owner_pid, st, info);
    if signal_event && req.event_handle != 0 {
        let _ = event_set_by_handle_for_pid(req.owner_pid, req.event_handle);
    }
    if req.waiter_tid != 0 {
        crate::sched::wake(req.waiter_tid, st);
    }
}

fn write_file_basic_information(
    pid: u32,
    out_ptr: *mut u8,
    out_len: usize,
    file_attributes: u32,
) -> bool {
    let Some(mut w) = GuestWriter::for_pid(pid, out_ptr, out_len, FILE_BASIC_INFORMATION_SIZE)
    else {
        return false;
    };
    w.zeros(32).u32(file_attributes).u32(0);
    true
}

#[inline(always)]
fn align_up_8(v: usize) -> usize {
    (v + 7) & !7
}

#[inline(always)]
fn lower_ascii(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

fn eq_ascii_ci(a: &str, b: &str) -> bool {
    let aa = a.as_bytes();
    let bb = b.as_bytes();
    if aa.len() != bb.len() {
        return false;
    }
    let mut i = 0usize;
    while i < aa.len() {
        if lower_ascii(aa[i]) != lower_ascii(bb[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn wildcard_match_ci(name: &[u8], pattern: &[u8]) -> bool {
    let mut n = 0usize;
    let mut p = 0usize;
    let mut star: Option<usize> = None;
    let mut match_n = 0usize;

    while n < name.len() {
        if p < pattern.len()
            && (pattern[p] == b'?' || lower_ascii(pattern[p]) == lower_ascii(name[n]))
        {
            n += 1;
            p += 1;
            continue;
        }
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            match_n = n;
            continue;
        }
        if let Some(star_pos) = star {
            p = star_pos + 1;
            match_n += 1;
            n = match_n;
            continue;
        }
        return false;
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn dir_record_base(info_class: u32) -> Option<usize> {
    match info_class {
        FILE_DIRECTORY_INFORMATION => Some(FILE_DIRECTORY_INFORMATION_BASE),
        FILE_FULL_DIRECTORY_INFORMATION => Some(FILE_FULL_DIRECTORY_INFORMATION_BASE),
        FILE_BOTH_DIRECTORY_INFORMATION => Some(FILE_BOTH_DIRECTORY_INFORMATION_BASE),
        FILE_NAMES_INFORMATION => Some(FILE_NAMES_INFORMATION_BASE),
        _ => None,
    }
}

fn dir_record_len(info_class: u32, name_len_bytes: usize) -> Option<usize> {
    let base = dir_record_base(info_class)?;
    let name_utf16_bytes = name_len_bytes.checked_mul(2)?;
    Some(align_up_8(base.checked_add(name_utf16_bytes)?))
}

fn write_name_utf16(w: &mut GuestWriter, name: &[u8]) {
    for b in name.iter() {
        let ch = if *b < 0x80 { *b as u16 } else { b'?' as u16 };
        w.u16(ch);
    }
}

fn write_directory_record(
    pid: u32,
    info_class: u32,
    out_ptr: *mut u8,
    out_len: usize,
    name: &[u8],
    is_dir: bool,
) -> Result<usize, u32> {
    let rec_len = dir_record_len(info_class, name.len()).ok_or(status::INVALID_PARAMETER)?;
    let name_len_utf16 = (name.len() * 2) as u32;
    let attrs = if is_dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    if out_len < rec_len {
        return Err(status::BUFFER_TOO_SMALL);
    }
    let Some(mut w) = GuestWriter::for_pid(pid, out_ptr, out_len, rec_len) else {
        return Err(status::INVALID_PARAMETER);
    };

    match info_class {
        FILE_NAMES_INFORMATION => {
            w.u32(0).u32(0).u32(name_len_utf16);
            write_name_utf16(&mut w, name);
        }
        FILE_DIRECTORY_INFORMATION => {
            w.u32(0).u32(0).zeros(48).u32(attrs).u32(name_len_utf16);
            write_name_utf16(&mut w, name);
        }
        FILE_FULL_DIRECTORY_INFORMATION => {
            w.u32(0)
                .u32(0)
                .zeros(48)
                .u32(attrs)
                .u32(name_len_utf16)
                .u32(0);
            write_name_utf16(&mut w, name);
        }
        FILE_BOTH_DIRECTORY_INFORMATION => {
            w.u32(0)
                .u32(0)
                .zeros(48)
                .u32(attrs)
                .u32(name_len_utf16)
                .u32(0)
                .u8(0)
                .u8(0)
                .zeros(24);
            write_name_utf16(&mut w, name);
        }
        _ => return Err(status::INVALID_PARAMETER),
    }

    Ok(rec_len)
}

fn write_notify_record(
    pid: u32,
    out_ptr: *mut u8,
    out_len: usize,
    action: u32,
    name: &[u8],
) -> Result<usize, u32> {
    let name_utf16_len = name.len().checked_mul(2).ok_or(status::INVALID_PARAMETER)?;
    let rec_len = align_up_8(
        FILE_NOTIFY_INFORMATION_BASE
            .checked_add(name_utf16_len)
            .ok_or(status::INVALID_PARAMETER)?,
    );
    if out_len < rec_len {
        return Err(status::BUFFER_TOO_SMALL);
    }
    let Some(mut w) = GuestWriter::for_pid(pid, out_ptr, out_len, rec_len) else {
        return Err(status::INVALID_PARAMETER);
    };
    w.u32(0).u32(action).u32(name_utf16_len as u32);
    write_name_utf16(&mut w, name);
    Ok(rec_len)
}

fn queue_pending_dir_notify(req: PendingDirNotify) -> u32 {
    let state = async_state_mut();
    if state.pending_dir_notify.alloc_with(|_| req).is_some() {
        status::SUCCESS
    } else {
        status::NO_MEMORY
    }
}

fn cancel_pending_dir_notify_for_file(owner_pid: u32, file: FsFileHandle) {
    let mut to_remove = Vec::new();
    async_state_mut()
        .pending_dir_notify
        .for_each_live_ptr(|id, ptr| unsafe {
            let req = *ptr;
            if req.owner_pid == owner_pid && req.file == file {
                if req.request_id != 0 {
                    let _ = crate::fs::cancel_async_request(req.request_id);
                }
                complete_pending_notify(&req, status::INVALID_HANDLE, 0, true);
                let _ = to_remove.try_reserve(1);
                to_remove.push(id);
            }
        });
    for id in to_remove {
        let _ = async_state_mut().pending_dir_notify.free(id);
    }
}

fn cancel_pending_file_io_for_file(owner_pid: u32, file: FsFileHandle) {
    let mut to_remove = Vec::new();
    async_state_mut()
        .pending_file_io
        .for_each_live_ptr(|id, ptr| unsafe {
            let req = *ptr;
            if req.owner_pid == owner_pid && req.file == file {
                if req.request_id != 0 {
                    let _ = crate::fs::cancel_async_request(req.request_id);
                }
                free_pending_file_io_resources(&req);
                complete_inline_file_io(
                    req.owner_pid,
                    req.event_handle,
                    req.iosb_ptr,
                    status::INVALID_HANDLE,
                    0,
                );
                let _ = to_remove.try_reserve(1);
                to_remove.push(id);
            }
        });
    for id in to_remove {
        let _ = async_state_mut().pending_file_io.free(id);
    }
}

fn cancel_pending_host_ioctl_for_file(owner_pid: u32, file: FsFileHandle) {
    let mut to_remove = Vec::new();
    async_state_mut()
        .pending_host_ioctl
        .for_each_live_ptr(|id, ptr| unsafe {
            let req = *ptr;
            if req.owner_pid == owner_pid && req.file == file {
                if req.request_id != 0 {
                    let _ = crate::fs::cancel_async_request(req.request_id);
                }
                complete_pending_host_ioctl(
                    &req,
                    status::INVALID_HANDLE,
                    None,
                );
                let _ = to_remove.try_reserve(1);
                to_remove.push(id);
            }
        });
    for id in to_remove {
        let _ = async_state_mut().pending_host_ioctl.free(id);
    }
}

pub(crate) fn cancel_pending_dir_notify_for_pid(owner_pid: u32) {
    let mut to_remove = Vec::new();
    async_state_mut()
        .pending_dir_notify
        .for_each_live_ptr(|id, ptr| unsafe {
            let req = *ptr;
            if req.owner_pid == owner_pid {
                if req.request_id != 0 {
                    let _ = crate::fs::cancel_async_request(req.request_id);
                }
                complete_pending_notify(&req, status::INVALID_HANDLE, 0, true);
                let _ = to_remove.try_reserve(1);
                to_remove.push(id);
            }
        });
    for id in to_remove {
        let _ = async_state_mut().pending_dir_notify.free(id);
    }

    let mut io_remove = Vec::new();
    async_state_mut()
        .pending_file_io
        .for_each_live_ptr(|id, ptr| unsafe {
            let req = *ptr;
            if req.owner_pid == owner_pid {
                if req.request_id != 0 {
                    let _ = crate::fs::cancel_async_request(req.request_id);
                }
                free_pending_file_io_resources(&req);
                complete_inline_file_io(
                    req.owner_pid,
                    req.event_handle,
                    req.iosb_ptr,
                    status::INVALID_HANDLE,
                    0,
                );
                let _ = io_remove.try_reserve(1);
                io_remove.push(id);
            }
        });
    for id in io_remove {
        let _ = async_state_mut().pending_file_io.free(id);
    }

    let mut ioctl_remove = Vec::new();
    async_state_mut()
        .pending_host_ioctl
        .for_each_live_ptr(|id, ptr| unsafe {
            let req = *ptr;
            if req.owner_pid == owner_pid {
                if req.request_id != 0 {
                    let _ = crate::fs::cancel_async_request(req.request_id);
                }
                complete_pending_host_ioctl(
                    &req,
                    status::INVALID_HANDLE,
                    None,
                );
                let _ = ioctl_remove.try_reserve(1);
                ioctl_remove.push(id);
            }
        });
    for id in ioctl_remove {
        let _ = async_state_mut().pending_host_ioctl.free(id);
    }
}

fn queue_pending_file_io(req: PendingFileIo) -> u32 {
    let state = async_state_mut();
    if state.pending_file_io.alloc_with(|_| req).is_some() {
        status::SUCCESS
    } else {
        status::NO_MEMORY
    }
}

fn queue_pending_host_ioctl(req: PendingHostIoctl) -> u32 {
    let state = async_state_mut();
    if state.pending_host_ioctl.alloc_with(|_| req).is_some() {
        status::SUCCESS
    } else {
        status::NO_MEMORY
    }
}

fn fs_error_to_status(err: crate::fs::FsError) -> u32 {
    match err {
        crate::fs::FsError::Unsupported => status::NOT_IMPLEMENTED,
        crate::fs::FsError::NoMemory => status::NO_MEMORY,
        crate::fs::FsError::InvalidHandle => status::INVALID_HANDLE,
        crate::fs::FsError::AlreadyExists => status::OBJECT_NAME_COLLISION,
        crate::fs::FsError::NotFound | crate::fs::FsError::IoError => status::INVALID_PARAMETER,
    }
}

fn fs_file_is_device(file: crate::fs::FsFileHandle) -> bool {
    matches!(crate::fs::file_kind(file), Ok(crate::fs::FsFileKind::Device))
}

fn write_device_ioctl_output_for_pid(
    owner_pid: u32,
    out_ptr: *mut u8,
    out_len: usize,
    output: &FsIoctlOutput,
) -> Option<Result<u64, u32>> {
    let need = output.len();
    if need == 0 {
        return Some(Ok(0));
    }
    if out_ptr.is_null() || out_len < need {
        return Some(Err(status::BUFFER_TOO_SMALL));
    }

    let mut w = GuestWriter::for_pid(owner_pid, out_ptr, out_len, need)?;
    w.bytes(output.as_slice());
    Some(Ok(need as u64))
}

fn complete_pending_host_ioctl(
    req: &PendingHostIoctl,
    mut st: u32,
    output: Option<&FsIoctlOutput>,
) {
    if !crate::process::process_exists(req.owner_pid) {
        return;
    }

    let mut info = 0u64;
    if st == status::SUCCESS {
        let Some(output) = output else {
            let _ = req.iosb_ptr.write_for_pid(req.owner_pid, st, info);
            if req.event_handle != 0 {
                let _ = event_set_by_handle_for_pid(req.owner_pid, req.event_handle);
            }
            if req.waiter_tid != 0 {
                crate::sched::wake(req.waiter_tid, st);
            }
            return;
        };
        match write_device_ioctl_output_for_pid(req.owner_pid, req.out_ptr, req.out_len, output) {
            Some(Ok(written)) => {
                info = written;
            }
            Some(Err(err)) => st = err,
            None => return,
        }
    }

    let _ = req.iosb_ptr.write_for_pid(req.owner_pid, st, info);
    if req.event_handle != 0 {
        let _ = event_set_by_handle_for_pid(req.owner_pid, req.event_handle);
    }
    if req.waiter_tid != 0 {
        crate::sched::wake(req.waiter_tid, st);
    }
}

fn complete_pending_file_io(req: &PendingFileIo, st: u32, info: u64) {
    if !crate::process::process_exists(req.owner_pid) {
        return;
    }
    complete_inline_file_io(req.owner_pid, req.event_handle, req.iosb_ptr, st, info);
}

fn on_async_dir_notify(request_id: u64, result: Result<FsNotifyRecord, crate::fs::FsError>) {
    let cookie = find_pending_dir_notify_id_by_request(request_id);
    if cookie == 0 {
        return;
    }
    let req_ptr = async_state_mut().pending_dir_notify.get_ptr(cookie);
    if req_ptr.is_null() {
        return;
    }
    let req = unsafe { *req_ptr };
    let _ = async_state_mut().pending_dir_notify.free(cookie);
    if !crate::process::process_exists(req.owner_pid) {
        return;
    }
    match result {
        Ok(record) => match write_notify_record(
            req.owner_pid,
            req.out_ptr,
            req.out_len,
            record.action(),
            record.name(),
        ) {
            Ok(written) => complete_pending_notify(&req, status::SUCCESS, written as u64, true),
            Err(st) => complete_pending_notify(&req, st, 0, true),
        },
        Err(err) => complete_pending_notify(&req, fs_error_to_status(err), 0, true),
    }
}

fn on_async_file_read(request_id: u64, result: Result<usize, crate::fs::FsError>) {
    let cookie = find_pending_file_io_id_by_request(request_id);
    if cookie == 0 {
        return;
    }
    let req_ptr = async_state_mut().pending_file_io.get_ptr(cookie);
    if req_ptr.is_null() {
        return;
    }
    let req = unsafe { *req_ptr };
    let _ = async_state_mut().pending_file_io.free(cookie);
    if !crate::process::process_exists(req.owner_pid) {
        free_pending_file_io_resources(&req);
        return;
    }
    let read = match result {
        Ok(read) => read,
        Err(err) => {
            complete_pending_file_io(&req, fs_error_to_status(err), 0);
            free_pending_file_io_resources(&req);
            return;
        }
    };
    if read != 0
        && !copy_from_phys_to_process_user(req.owner_pid, req.user_buffer, req.bounce_pa, read)
    {
        complete_pending_file_io(&req, status::INVALID_PARAMETER, 0);
        free_pending_file_io_resources(&req);
        return;
    }
    let st = if read == 0 && req.requested_len != 0 {
        status::END_OF_FILE
    } else {
        status::SUCCESS
    };
    complete_pending_file_io(&req, st, read as u64);
    free_pending_file_io_resources(&req);
}

fn on_async_file_write(request_id: u64, result: Result<usize, crate::fs::FsError>) {
    let cookie = find_pending_file_io_id_by_request(request_id);
    if cookie == 0 {
        return;
    }
    let req_ptr = async_state_mut().pending_file_io.get_ptr(cookie);
    if req_ptr.is_null() {
        return;
    }
    let req = unsafe { *req_ptr };
    let _ = async_state_mut().pending_file_io.free(cookie);
    if !crate::process::process_exists(req.owner_pid) {
        free_pending_file_io_resources(&req);
        return;
    }
    match result {
        Ok(written) => complete_pending_file_io(&req, status::SUCCESS, written as u64),
        Err(err) => complete_pending_file_io(&req, fs_error_to_status(err), 0),
    }
    free_pending_file_io_resources(&req);
}

fn prepare_async_file_io(
    owner_pid: u32,
    file: FsFileHandle,
    copy_from_user: bool,
    event_handle: u64,
    iosb_ptr: IoStatusBlockPtr,
    user_buffer: UserVa,
    len: usize,
) -> Result<PendingFileIo, u32> {
    let Some((bounce_pa, bounce_pages)) = alloc_file_io_bounce(len) else {
        return Err(status::NO_MEMORY);
    };
    if copy_from_user && !copy_from_process_user_to_phys(owner_pid, user_buffer, bounce_pa, len) {
        free_file_io_bounce(bounce_pa, bounce_pages);
        return Err(status::INVALID_PARAMETER);
    }
    Ok(PendingFileIo {
        owner_pid,
        file,
        event_handle,
        iosb_ptr,
        user_buffer,
        request_id: 0,
        requested_len: len,
        bounce_pa,
        bounce_pages,
    })
}

fn sync_write_user_buffer_to_std(
    owner_pid: u32,
    std_handle: crate::fs::FsStdHandle,
    user_buffer: UserVa,
    len: usize,
    offset: u64,
) -> Result<u64, u32> {
    if len == 0 {
        return Ok(0);
    }
    let Some((bounce_pa, bounce_pages)) = alloc_file_io_bounce(FILE_IO_BOUNCE_PAGE_SIZE) else {
        return Err(status::NO_MEMORY);
    };
    let mut done = 0usize;
    while done < len {
        let chunk = core::cmp::min(len - done, FILE_IO_BOUNCE_PAGE_SIZE);
        let Some(cur_user) = user_buffer.checked_add(done as u64) else {
            free_file_io_bounce(bounce_pa, bounce_pages);
            return Err(status::INVALID_PARAMETER);
        };
        if !copy_from_process_user_to_phys(owner_pid, cur_user, bounce_pa, chunk) {
            free_file_io_bounce(bounce_pa, bounce_pages);
            return Err(status::INVALID_PARAMETER);
        }
        let cur_offset = if offset == u64::MAX {
            u64::MAX
        } else {
            let Some(cur) = offset.checked_add(done as u64) else {
                free_file_io_bounce(bounce_pa, bounce_pages);
                return Err(status::INVALID_PARAMETER);
            };
            cur
        };
        let written = crate::fs::write_std_at_phys(std_handle, bounce_pa, chunk, cur_offset)
            .map_err(fs_error_to_status)?;
        done += written;
        if written < chunk {
            break;
        }
    }
    free_file_io_bounce(bounce_pa, bounce_pages);
    Ok(done as u64)
}

fn sync_write_user_buffer_to_fs_file(
    owner_pid: u32,
    file: crate::fs::FsFileHandle,
    user_buffer: UserVa,
    len: usize,
    offset: u64,
) -> Result<u64, u32> {
    if len == 0 {
        return Ok(0);
    }
    let Some((bounce_pa, bounce_pages)) = alloc_file_io_bounce(FILE_IO_BOUNCE_PAGE_SIZE) else {
        return Err(status::NO_MEMORY);
    };
    let mut done = 0usize;
    while done < len {
        let chunk = core::cmp::min(len - done, FILE_IO_BOUNCE_PAGE_SIZE);
        let Some(cur_user) = user_buffer.checked_add(done as u64) else {
            free_file_io_bounce(bounce_pa, bounce_pages);
            return Err(status::INVALID_PARAMETER);
        };
        if !copy_from_process_user_to_phys(owner_pid, cur_user, bounce_pa, chunk) {
            free_file_io_bounce(bounce_pa, bounce_pages);
            return Err(status::INVALID_PARAMETER);
        }
        let cur_offset = if offset == u64::MAX {
            u64::MAX
        } else {
            let Some(cur) = offset.checked_add(done as u64) else {
                free_file_io_bounce(bounce_pa, bounce_pages);
                return Err(status::INVALID_PARAMETER);
            };
            cur
        };
        let written = crate::fs::write_at_phys(crate::fs::FsWritePhysRequest {
            file,
            src: bounce_pa,
            len: chunk,
            offset: cur_offset,
        })
        .map_err(fs_error_to_status)?;
        done += written;
        if written < chunk {
            break;
        }
    }
    free_file_io_bounce(bounce_pa, bounce_pages);
    Ok(done as u64)
}

fn sync_read_std_to_user_buffer(
    owner_pid: u32,
    std_handle: crate::fs::FsStdHandle,
    user_buffer: UserVa,
    len: usize,
    offset: u64,
) -> Result<u64, u32> {
    if len == 0 {
        return Ok(0);
    }
    let Some((bounce_pa, bounce_pages)) = alloc_file_io_bounce(FILE_IO_BOUNCE_PAGE_SIZE) else {
        return Err(status::NO_MEMORY);
    };
    let mut done = 0usize;
    while done < len {
        let chunk = core::cmp::min(len - done, FILE_IO_BOUNCE_PAGE_SIZE);
        let cur_offset = if offset == u64::MAX {
            u64::MAX
        } else {
            let Some(cur) = offset.checked_add(done as u64) else {
                free_file_io_bounce(bounce_pa, bounce_pages);
                return Err(status::INVALID_PARAMETER);
            };
            cur
        };
        let read = crate::fs::read_std_at_phys(std_handle, bounce_pa, chunk, cur_offset)
            .map_err(fs_error_to_status)?;
        if read != 0 {
            let Some(cur_user) = user_buffer.checked_add(done as u64) else {
                free_file_io_bounce(bounce_pa, bounce_pages);
                return Err(status::INVALID_PARAMETER);
            };
            if !copy_from_phys_to_process_user(owner_pid, cur_user, bounce_pa, read) {
                free_file_io_bounce(bounce_pa, bounce_pages);
                return Err(status::INVALID_PARAMETER);
            }
        }
        done += read;
        if read < chunk {
            break;
        }
    }
    free_file_io_bounce(bounce_pa, bounce_pages);
    Ok(done as u64)
}

fn sync_read_fs_file_to_user_buffer(
    owner_pid: u32,
    file: crate::fs::FsFileHandle,
    user_buffer: UserVa,
    len: usize,
    offset: u64,
) -> Result<u64, u32> {
    if len == 0 {
        return Ok(0);
    }
    let Some((bounce_pa, bounce_pages)) = alloc_file_io_bounce(FILE_IO_BOUNCE_PAGE_SIZE) else {
        return Err(status::NO_MEMORY);
    };
    let mut done = 0usize;
    while done < len {
        let chunk = core::cmp::min(len - done, FILE_IO_BOUNCE_PAGE_SIZE);
        let cur_offset = if offset == u64::MAX {
            u64::MAX
        } else {
            let Some(cur) = offset.checked_add(done as u64) else {
                free_file_io_bounce(bounce_pa, bounce_pages);
                return Err(status::INVALID_PARAMETER);
            };
            cur
        };
        let read = crate::fs::read_at_phys(crate::fs::FsReadPhysRequest {
            file,
            dst: bounce_pa,
            len: chunk,
            offset: cur_offset,
        })
        .map_err(fs_error_to_status)?;
        if read != 0 {
            let Some(cur_user) = user_buffer.checked_add(done as u64) else {
                free_file_io_bounce(bounce_pa, bounce_pages);
                return Err(status::INVALID_PARAMETER);
            };
            if !copy_from_phys_to_process_user(owner_pid, cur_user, bounce_pa, read) {
                free_file_io_bounce(bounce_pa, bounce_pages);
                return Err(status::INVALID_PARAMETER);
            }
        }
        done += read;
        if read < chunk {
            break;
        }
    }
    free_file_io_bounce(bounce_pa, bounce_pages);
    Ok(done as u64)
}

fn on_async_host_ioctl(request_id: u64, result: Result<FsIoctlOutput, crate::fs::FsError>) {
    let cookie = find_pending_host_ioctl_id_by_request(request_id);
    if cookie == 0 {
        return;
    }
    let req_ptr = async_state_mut().pending_host_ioctl.get_ptr(cookie);
    if req_ptr.is_null() {
        return;
    }
    let req = unsafe { *req_ptr };
    let _ = async_state_mut().pending_host_ioctl.free(cookie);
    if !crate::process::process_exists(req.owner_pid) {
        return;
    }
    match result {
        Ok(output) => complete_pending_host_ioctl(&req, status::SUCCESS, Some(&output)),
        Err(err) => complete_pending_host_ioctl(&req, fs_error_to_status(err), None),
    }
}

fn find_pending_dir_notify_id_by_request(request_id: u64) -> u32 {
    let mut found = 0u32;
    async_state_mut()
        .pending_dir_notify
        .for_each_live_ptr(|id, ptr| unsafe {
            if found == 0 && (*ptr).request_id == request_id {
                found = id;
            }
        });
    found
}

fn find_pending_file_io_id_by_request(request_id: u64) -> u32 {
    let mut found = 0u32;
    async_state_mut()
        .pending_file_io
        .for_each_live_ptr(|id, ptr| unsafe {
            if found == 0 && (*ptr).request_id == request_id {
                found = id;
            }
        });
    found
}

fn find_pending_host_ioctl_id_by_request(request_id: u64) -> u32 {
    let mut found = 0u32;
    async_state_mut()
        .pending_host_ioctl
        .for_each_live_ptr(|id, ptr| unsafe {
            if found == 0 && (*ptr).request_id == request_id {
                found = id;
            }
        });
    found
}

pub(crate) fn dispatch_async_hostcall_completion(cpl: crate::hypercall::HostCallCompletion) -> bool {
    let Some(done) = crate::fs::dispatch_async_completion(cpl) else {
        return false;
    };
    match done {
        FsAsyncCompletion::FileRead { request_id, result } => {
            on_async_file_read(request_id, result);
        }
        FsAsyncCompletion::FileWrite { request_id, result } => {
            on_async_file_write(request_id, result);
        }
        FsAsyncCompletion::DirNotify { request_id, result } => {
            on_async_dir_notify(request_id, result);
        }
        FsAsyncCompletion::DeviceIoControl { request_id, result } => {
            on_async_host_ioctl(request_id, result);
        }
    }
    true
}

// x0=*FileHandle, x1=DesiredAccess, x2=ObjectAttributes, x3=*IoStatusBlock
// x7=CreateDisposition
pub(crate) fn handle_create_file(frame: &mut SvcFrame) {
    const FILE_SUPERSEDE: u32 = 0;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_OPEN_IF: u32 = 3;
    const FILE_OVERWRITE: u32 = 4;
    const FILE_OVERWRITE_IF: u32 = 5;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;

    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let access = map_file_generic_access(frame.x[1] as u32);
    let oa = ObjectAttributesView::from_ptr(frame.x[2]);
    let iosb_ptr = frame.x[3] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let disposition = frame.x[7] as u32;
    let create_options =
        UserInPtr::from_raw(frame.user_sp() as *const u64).read_current().unwrap_or(0) as u32;
    let mut path_buf = [0u8; 512];

    let meta = super::kobject::object_type_meta_for_kind(crate::process::KObjectKind::File);
    if (access & !meta.valid_access_mask) != 0 {
        iosb.write_current(status::ACCESS_DENIED, 0);
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    if out_ptr.is_null() {
        iosb.write_current(status::INVALID_PARAMETER, 0);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let path_len = oa.map_or(0, |oa| oa.read_path(&mut path_buf));
    if path_len == 0 {
        iosb.write_current(status::OBJECT_NAME_NOT_FOUND, 0);
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    let path = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => {
            iosb.write_current(status::INVALID_PARAMETER, 0);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
    };
    if disposition != FILE_OPEN || create_options != 0 {
        crate::kdebug!(
            "nt:file create tid={} pc={:#x} sp={:#x} path={} disp={} create_options={:#x}",
            crate::sched::current_tid(),
            frame.program_counter(),
            frame.user_sp(),
            path,
            disposition,
            create_options
        );
    }
    if (create_options & FILE_DIRECTORY_FILE) != 0 {
        match disposition {
            FILE_OPEN => {}
            FILE_CREATE | FILE_OPEN_IF => {
                if let Err(err) = crate::fs::create_dir(path) {
                    crate::kdebug!("nt:file create_dir failed path={} err={:?}", path, err);
                    let st = fs_error_to_status(err);
                    iosb.write_current(st, 0);
                    frame.x[0] = st as u64;
                    return;
                }
            }
            FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                iosb.write_current(status::INVALID_PARAMETER, 0);
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            _ => {
                iosb.write_current(status::INVALID_PARAMETER, 0);
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
        }
    }
    let file = match crate::fs::open(&crate::fs::FsOpenRequest {
        path,
        mode: if (create_options & FILE_DIRECTORY_FILE) != 0 {
            crate::fs::FsOpenMode::Read
        } else {
            map_open_mode(access, disposition)
        },
    }) {
        Ok(v) => v,
        Err(crate::fs::FsError::NoMemory) => {
            iosb.write_current(status::NO_MEMORY, 0);
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
        Err(_) => {
            iosb.write_current(status::OBJECT_NAME_NOT_FOUND, 0);
            frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
            return;
        }
    };
    {
        let pid = crate::process::current_pid();
        if let Err(st) =
            super::kobject::install_handle_for_pid(pid, KObjectRef::file(file.raw()), out_ptr)
        {
            crate::fs::close(file);
            iosb.write_current(st, 0);
            frame.x[0] = st as u64;
            return;
        }
    }
    iosb.write_current(status::SUCCESS, 0);
    frame.x[0] = status::SUCCESS as u64;
}

// x0=*FileHandle, x1=DesiredAccess, x2=ObjectAttributes, x3=*IoStatusBlock
pub(crate) fn handle_open_file(frame: &mut SvcFrame) {
    frame.x[7] = FILE_OPEN as u64;
    handle_create_file(frame);
}

// x0=FileHandle, x4=IoStatusBlock*, x5=Buffer, x6=Length, x7=ByteOffset*
pub(crate) fn handle_write_file(frame: &mut SvcFrame) {
    let owner_pid = crate::process::current_pid();
    let file_handle = frame.x[0];
    let event_handle = frame.x[1];
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let user_buf = UserVa::new(frame.x[5]);
    let len = frame.x[6] as usize;
    let byte_offset_ptr = UserInPtr::from_raw(frame.x[7] as *const u64);

    if event_handle != 0 && handle_kind_for_pid(event_handle, owner_pid) != Some(KObjectKind::Event)
    {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }

    let file_idx = handle_idx_for_pid(file_handle, owner_pid);

    let target = match file_handle_target(file_handle) {
        Some(v) => v,
        None => {
            iosb.write_current(status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };
    if file_idx == 0 && !is_std_file_handle(file_handle) {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }

    let offset = if byte_offset_ptr.is_null() {
        u64::MAX
    } else {
        let Some(v) = byte_offset_ptr.read_current() else {
            iosb.write_current(status::INVALID_PARAMETER, 0);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };
        v
    };

    if event_handle != 0 && len != 0 && file_idx != 0 {
        let file = match target {
            NtFileHandleTarget::Fs(file) if !fs_file_is_device(file) => file,
            NtFileHandleTarget::Std(_) | NtFileHandleTarget::Fs(_) => {
                iosb.write_current(status::INVALID_HANDLE, 0);
                frame.x[0] = status::INVALID_HANDLE as u64;
                return;
            }
        };
        let mut req = match prepare_async_file_io(
            owner_pid,
            file,
            true,
            event_handle,
            iosb,
            user_buf,
            len,
        ) {
            Ok(req) => req,
            Err(st) => {
                iosb.write_current(st, 0);
                frame.x[0] = st as u64;
                return;
            }
        };
        let submit = crate::fs::write_at_phys_async(
            crate::fs::FsWritePhysRequest {
                file,
                src: req.bounce_pa,
                len,
                offset,
            },
            owner_pid,
            0,
        );
        match submit {
            Ok(FsAsyncSubmit::Pending { request_id }) => {
                req.request_id = request_id;
                let st = queue_pending_file_io(req);
                if st != status::SUCCESS {
                    free_pending_file_io_resources(&req);
                    let _ = crate::fs::cancel_async_request(request_id);
                    complete_inline_file_io(owner_pid, event_handle, iosb, st, 0);
                    frame.x[0] = st as u64;
                    return;
                }
                let _ = iosb.write_for_pid(owner_pid, STATUS_PENDING, 0);
                frame.x[0] = STATUS_PENDING as u64;
                return;
            }
            Ok(FsAsyncSubmit::Completed(written)) => {
                free_pending_file_io_resources(&req);
                complete_inline_file_io(
                    owner_pid,
                    event_handle,
                    iosb,
                    status::SUCCESS,
                    written as u64,
                );
                frame.x[0] = status::SUCCESS as u64;
                return;
            }
            Err(err) => {
                free_pending_file_io_resources(&req);
                let st = fs_error_to_status(err);
                complete_inline_file_io(owner_pid, event_handle, iosb, st, 0);
                frame.x[0] = st as u64;
                return;
            }
        }
    }

    let written = match target {
        NtFileHandleTarget::Std(std_handle) => {
            match sync_write_user_buffer_to_std(owner_pid, std_handle, user_buf, len, offset) {
                Ok(v) => v,
                Err(st) => {
                    complete_inline_file_io(owner_pid, event_handle, iosb, st, 0);
                    frame.x[0] = st as u64;
                    return;
                }
            }
        }
        NtFileHandleTarget::Fs(file) => {
            if fs_file_is_device(file) {
                complete_inline_file_io(
                    owner_pid,
                    event_handle,
                    iosb,
                    status::NOT_IMPLEMENTED,
                    0,
                );
                frame.x[0] = status::NOT_IMPLEMENTED as u64;
                return;
            }
            match sync_write_user_buffer_to_fs_file(owner_pid, file, user_buf, len, offset) {
                Ok(v) => v,
                Err(st) => {
                    complete_inline_file_io(owner_pid, event_handle, iosb, st, 0);
                    frame.x[0] = st as u64;
                    return;
                }
            }
        }
    };
    complete_inline_file_io(owner_pid, event_handle, iosb, status::SUCCESS, written);
    frame.x[0] = status::SUCCESS as u64;
}

// x0=FileHandle, x4=IoStatusBlock*, x5=Buffer, x6=Length, x7=ByteOffset*
pub(crate) fn handle_read_file(frame: &mut SvcFrame) {
    let owner_pid = crate::process::current_pid();
    let file_handle = frame.x[0];
    let event_handle = frame.x[1];
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let user_buf = UserVa::new(frame.x[5]);
    let len = frame.x[6] as usize;
    let byte_offset_ptr = UserInPtr::from_raw(frame.x[7] as *const u64);

    if event_handle != 0 && handle_kind_for_pid(event_handle, owner_pid) != Some(KObjectKind::Event)
    {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }

    let file_idx = handle_idx_for_pid(file_handle, owner_pid);

    let target = match file_handle_target(file_handle) {
        Some(v) => v,
        None => {
            iosb.write_current(status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };
    if file_idx == 0 && !is_std_file_handle(file_handle) {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }

    let offset = if byte_offset_ptr.is_null() {
        u64::MAX
    } else {
        let Some(v) = byte_offset_ptr.read_current() else {
            iosb.write_current(status::INVALID_PARAMETER, 0);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };
        v
    };

    if event_handle != 0 && len != 0 && file_idx != 0 {
        let file = match target {
            NtFileHandleTarget::Fs(file) if !fs_file_is_device(file) => file,
            NtFileHandleTarget::Std(_) | NtFileHandleTarget::Fs(_) => {
                iosb.write_current(status::INVALID_HANDLE, 0);
                frame.x[0] = status::INVALID_HANDLE as u64;
                return;
            }
        };
        let mut req = match prepare_async_file_io(
            owner_pid,
            file,
            false,
            event_handle,
            iosb,
            user_buf,
            len,
        ) {
            Ok(req) => req,
            Err(st) => {
                iosb.write_current(st, 0);
                frame.x[0] = st as u64;
                return;
            }
        };
        let submit = crate::fs::read_at_phys_async(
            crate::fs::FsReadPhysRequest {
                file,
                dst: req.bounce_pa,
                len,
                offset,
            },
            owner_pid,
            0,
        );
        match submit {
            Ok(FsAsyncSubmit::Pending { request_id }) => {
                req.request_id = request_id;
                let st = queue_pending_file_io(req);
                if st != status::SUCCESS {
                    free_pending_file_io_resources(&req);
                    let _ = crate::fs::cancel_async_request(request_id);
                    complete_inline_file_io(owner_pid, event_handle, iosb, st, 0);
                    frame.x[0] = st as u64;
                    return;
                }
                let _ = iosb.write_for_pid(owner_pid, STATUS_PENDING, 0);
                frame.x[0] = STATUS_PENDING as u64;
                return;
            }
            Ok(FsAsyncSubmit::Completed(read)) => {
                let st = if read != 0
                    && !copy_from_phys_to_process_user(
                        owner_pid,
                        req.user_buffer,
                        req.bounce_pa,
                        read,
                    )
                {
                    status::INVALID_PARAMETER
                } else if read == 0 {
                    status::END_OF_FILE
                } else {
                    status::SUCCESS
                };
                free_pending_file_io_resources(&req);
                let info = if st == status::SUCCESS || st == status::END_OF_FILE {
                    read as u64
                } else {
                    0
                };
                complete_inline_file_io(owner_pid, event_handle, iosb, st, info);
                frame.x[0] = st as u64;
                return;
            }
            Err(err) => {
                free_pending_file_io_resources(&req);
                let st = fs_error_to_status(err);
                complete_inline_file_io(owner_pid, event_handle, iosb, st, 0);
                frame.x[0] = st as u64;
                return;
            }
        }
    }

    let read = match target {
        NtFileHandleTarget::Std(std_handle) => {
            match sync_read_std_to_user_buffer(owner_pid, std_handle, user_buf, len, offset) {
                Ok(v) => v,
                Err(st) => {
                    complete_inline_file_io(owner_pid, event_handle, iosb, st, 0);
                    frame.x[0] = st as u64;
                    return;
                }
            }
        }
        NtFileHandleTarget::Fs(file) => {
            if fs_file_is_device(file) {
                complete_inline_file_io(
                    owner_pid,
                    event_handle,
                    iosb,
                    status::NOT_IMPLEMENTED,
                    0,
                );
                frame.x[0] = status::NOT_IMPLEMENTED as u64;
                return;
            }
            match sync_read_fs_file_to_user_buffer(owner_pid, file, user_buf, len, offset) {
                Ok(v) => v,
                Err(st) => {
                    complete_inline_file_io(owner_pid, event_handle, iosb, st, 0);
                    frame.x[0] = st as u64;
                    return;
                }
            }
        }
    };
    let st = if read == 0 && len != 0 {
        status::END_OF_FILE
    } else {
        status::SUCCESS
    };
    complete_inline_file_io(owner_pid, event_handle, iosb, st, read);
    frame.x[0] = st as u64;
}

// x0=FileHandle, x1=*IoStatusBlock, x2=FileInformation, x3=Length, x4=Class
pub(crate) fn handle_query_information_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[1] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let out_ptr = frame.x[2] as *mut u8;
    let out_len = frame.x[3] as usize;
    let info_class = frame.x[4] as u32;
    let owner_pid = crate::process::current_pid();
    let target = match file_handle_target(file_handle) {
        Some(v) => v,
        None => {
            iosb.write_current(status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };
    if info_class == FILE_STANDARD_INFORMATION_CLASS {
        if out_ptr.is_null() || out_len < 24 {
            iosb.write_current(status::INFO_LENGTH_MISMATCH, 0);
            frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
            return;
        }
        let info = match target {
            NtFileHandleTarget::Std(std_handle) => Ok(crate::fs::query_std_standard_info(std_handle)),
            NtFileHandleTarget::Fs(file) => crate::fs::query_standard_info(file),
        };
        let std_info = match info {
            Ok(info) => info,
            Err(err) => {
                let st = fs_error_to_status(err);
                iosb.write_current(st, 0);
                frame.x[0] = st as u64;
                return;
            }
        };
        let mut info = [0u8; 24];
        info[0..8].copy_from_slice(&std_info.allocation_size().to_le_bytes());
        info[8..16].copy_from_slice(&std_info.end_of_file().to_le_bytes());
        info[16..20].copy_from_slice(&std_info.number_of_links().to_le_bytes());
        info[20] = u8::from(std_info.delete_pending());
        info[21] = u8::from(std_info.directory());
        let Some(mut w) = GuestWriter::for_pid(owner_pid, out_ptr, out_len, 24) else {
            iosb.write_current(status::INVALID_PARAMETER, 0);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };
        w.bytes(&info);
        iosb.write_current(status::SUCCESS, 24);
        frame.x[0] = status::SUCCESS as u64;
        return;
    }
    if info_class == FILE_POSITION_INFORMATION_CLASS {
        if out_ptr.is_null() || out_len < FILE_POSITION_INFORMATION_SIZE {
            iosb.write_current(status::INFO_LENGTH_MISMATCH, 0);
            frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
            return;
        }
        let pos = match target {
            NtFileHandleTarget::Std(_) => {
                iosb.write_current(status::INVALID_HANDLE, 0);
                frame.x[0] = status::INVALID_HANDLE as u64;
                return;
            }
            NtFileHandleTarget::Fs(file) => {
                if fs_file_is_device(file) {
                    iosb.write_current(status::INVALID_HANDLE, 0);
                    frame.x[0] = status::INVALID_HANDLE as u64;
                    return;
                }
                match crate::fs::seek(file, 0, 1) {
                    Ok(pos) => pos,
                    Err(err) => {
                        let st = fs_error_to_status(err);
                        iosb.write_current(st, 0);
                        frame.x[0] = st as u64;
                        return;
                    }
                }
            }
        };
        let Some(mut w) =
            GuestWriter::for_pid(owner_pid, out_ptr, out_len, FILE_POSITION_INFORMATION_SIZE)
        else {
            iosb.write_current(status::INVALID_PARAMETER, 0);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };
        w.u64(pos);
        iosb.write_current(status::SUCCESS, FILE_POSITION_INFORMATION_SIZE as u64);
        frame.x[0] = status::SUCCESS as u64;
        return;
    }
    if !out_ptr.is_null() && out_len != 0 {
        let Some(mut w) = GuestWriter::for_pid(owner_pid, out_ptr, out_len, out_len) else {
            iosb.write_current(status::INVALID_PARAMETER, 0);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };
        w.zeros(out_len);
    }
    iosb.write_current(status::SUCCESS, 0);
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_set_information_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[1] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let info_ptr = frame.x[2] as *const u8;
    let info_len = frame.x[3] as usize;
    let info_class = frame.x[4] as u32;
    let target = match file_handle_target(file_handle) {
        Some(v) => v,
        None => {
            iosb.write_current(status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let file = match target {
        NtFileHandleTarget::Std(_) => {
            iosb.write_current(status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
        NtFileHandleTarget::Fs(file) => {
            if fs_file_is_device(file) {
                iosb.write_current(status::INVALID_HANDLE, 0);
                frame.x[0] = status::INVALID_HANDLE as u64;
                return;
            }
            file
        }
    };

    let result = match info_class {
        FILE_POSITION_INFORMATION_CLASS => {
            if info_ptr.is_null() || info_len < FILE_POSITION_INFORMATION_SIZE {
                Err(status::INVALID_PARAMETER)
            } else {
                match UserInPtr::from_raw(info_ptr as *const u64).read_current() {
                    Some(pos) => {
                        if pos > i64::MAX as u64 {
                            Err(status::INVALID_PARAMETER)
                        } else {
                            crate::fs::seek(file, pos as i64, 0)
                            .map(|_| ())
                            .map_err(fs_error_to_status)
                        }
                    }
                    None => Err(status::INVALID_PARAMETER),
                }
            }
        }
        FILE_ALLOCATION_INFORMATION_CLASS | FILE_END_OF_FILE_INFORMATION_CLASS => {
            if info_ptr.is_null() || info_len < FILE_END_OF_FILE_INFORMATION_SIZE {
                Err(status::INVALID_PARAMETER)
            } else {
                match UserInPtr::from_raw(info_ptr as *const u64).read_current() {
                    Some(len) => crate::fs::set_len(file, len).map_err(fs_error_to_status),
                    None => Err(status::INVALID_PARAMETER),
                }
            }
        }
        _ => Ok(()),
    };

    match result {
        Ok(()) => {
            iosb.write_current(status::SUCCESS, 0);
            frame.x[0] = status::SUCCESS as u64;
        }
        Err(st) => {
            iosb.write_current(st, 0);
            frame.x[0] = st as u64;
        }
    }
}

pub(crate) fn handle_query_directory_file(frame: &mut SvcFrame) {
    let owner_pid = crate::process::current_pid();
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let out_ptr = frame.x[5] as *mut u8;
    let out_len = frame.x[6] as usize;
    let info_class = frame.x[7] as u32;

    let args = SyscallArgs::new(frame);
    let _return_single_entry = args.spill_bool(0).unwrap_or(false);
    let file_name_ptr = args.spill_u64(1).unwrap_or(0);
    let restart_scan = args.spill_bool(2).unwrap_or(false);

    let target = match file_handle_target(file_handle) {
        Some(v) => v,
        None => {
            iosb.write_current(status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    if out_ptr.is_null() || out_len == 0 || dir_record_base(info_class).is_none() {
        iosb.write_current(status::INVALID_PARAMETER, 0);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let mut pattern_buf = [0u8; 260];
    let pattern_len =
        UnicodeStringView::from_ptr(file_name_ptr).map_or(0, |us| us.read_ascii(&mut pattern_buf));

    let mut first_read = true;
    loop {
        let entry = match target {
            NtFileHandleTarget::Std(std_handle) => {
                crate::fs::readdir_std(std_handle, first_read && restart_scan)
            }
            NtFileHandleTarget::Fs(file) => crate::fs::readdir(file, first_read && restart_scan),
        };
        first_read = false;

        let entry = match entry {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                iosb.write_current(status::NO_MORE_FILES, 0);
                frame.x[0] = status::NO_MORE_FILES as u64;
                return;
            }
            Err(err) => {
                let st = fs_error_to_status(err);
                iosb.write_current(st, 0);
                frame.x[0] = st as u64;
                return;
            }
        };

        let name = entry.name();
        let name_len = name.len();

        if pattern_len != 0 && !wildcard_match_ci(name, &pattern_buf[..pattern_len]) {
            continue;
        }

        let Some(rec_len) = dir_record_len(info_class, name_len) else {
            iosb.write_current(status::INVALID_PARAMETER, 0);
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };

        if out_len < rec_len {
            iosb.write_current(status::BUFFER_TOO_SMALL, 0);
            frame.x[0] = status::BUFFER_TOO_SMALL as u64;
            return;
        }

        let written = match write_directory_record(
            owner_pid,
            info_class,
            out_ptr,
            out_len,
            name,
            entry.is_dir(),
        ) {
            Ok(len) => len,
            Err(st) => {
                iosb.write_current(st, 0);
                frame.x[0] = st as u64;
                return;
            }
        };

        debug_assert_eq!(written, rec_len);
        iosb.write_current(status::SUCCESS, written as u64);
        frame.x[0] = status::SUCCESS as u64;
        return;
    }
}

// x0=FileHandle, x1=Event, x2=ApcRoutine, x3=ApcContext, x4=*IoStatusBlock
// x5=Buffer, x6=Length, x7=CompletionFilter, stack0=WatchTree
pub(crate) fn handle_notify_change_directory_file(frame: &mut SvcFrame) {
    let owner_pid = crate::process::current_pid();
    let file_handle = frame.x[0];
    let event_handle = frame.x[1];
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let out_ptr = frame.x[5] as *mut u8;
    let out_len = frame.x[6] as usize;
    let completion_filter = frame.x[7] as u32;
    let watch_tree = SyscallArgs::new(frame).spill_bool(0).unwrap_or(false);

    if handle_kind_for_pid(file_handle, owner_pid) != Some(KObjectKind::File) {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
    if event_handle != 0 && handle_kind_for_pid(event_handle, owner_pid) != Some(KObjectKind::Event)
    {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
    let file_idx = handle_idx_for_pid(file_handle, owner_pid);
    if file_idx == 0 {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }

    let file = match file_handle_target(file_handle) {
        Some(NtFileHandleTarget::Fs(file)) => file,
        Some(NtFileHandleTarget::Std(_)) | None => {
            iosb.write_current(status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };
    if fs_file_is_device(file) {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }

    if out_ptr.is_null() || out_len < FILE_NOTIFY_INFORMATION_BASE {
        iosb.write_current(status::INVALID_PARAMETER, 0);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let record = crate::fs::notify_dir(file, watch_tree, completion_filter);

    match record {
        Ok(Some(record)) => {
            match write_notify_record(owner_pid, out_ptr, out_len, record.action(), record.name()) {
                Ok(written) => {
                    iosb.write_current(status::SUCCESS, written as u64);
                    frame.x[0] = status::SUCCESS as u64;
                }
                Err(st) => {
                    iosb.write_current(st, 0);
                    frame.x[0] = st as u64;
                }
            }
            return;
        }
        Ok(None) => {}
        Err(err) => {
            let st = fs_error_to_status(err);
            iosb.write_current(st, 0);
            frame.x[0] = st as u64;
            return;
        }
    }

    let req = PendingDirNotify {
        owner_pid,
        file,
        waiter_tid: if event_handle == 0 {
            crate::sched::current_tid()
        } else {
            0
        },
        event_handle,
        iosb_ptr: iosb,
        out_ptr,
        out_len,
        request_id: 0,
    };
    let submit = crate::fs::notify_dir_async(file, owner_pid, 0, watch_tree, completion_filter);
    let request_id = match submit {
        Ok(FsAsyncSubmit::Pending { request_id }) => {
            let mut req = req;
            req.request_id = request_id;
            let st = queue_pending_dir_notify(req);
            if st != status::SUCCESS {
                let _ = crate::fs::cancel_async_request(request_id);
                iosb.write_current(st, 0);
                frame.x[0] = st as u64;
                return;
            }
            request_id
        }
        Ok(FsAsyncSubmit::Completed(record)) => {
            match write_notify_record(
                owner_pid,
                out_ptr,
                out_len,
                record.action(),
                record.name(),
            ) {
                Ok(written) => {
                    iosb.write_current(status::SUCCESS, written as u64);
                    frame.x[0] = status::SUCCESS as u64;
                }
                Err(st) => {
                    iosb.write_current(st, 0);
                    frame.x[0] = st as u64;
                }
            }
            return;
        }
        Err(err) => {
            let st = fs_error_to_status(err);
            iosb.write_current(st, 0);
            frame.x[0] = st as u64;
            return;
        }
    };

    if event_handle == 0 {
        let st = hostcall::wait_current_for_request_pending(
            request_id,
            crate::sched::WaitDeadline::Infinite,
        );
        frame.x[0] = st as u64;
        return;
    }

    iosb.write_current(STATUS_PENDING, 0);
    frame.x[0] = STATUS_PENDING as u64;
}

// x0=ObjectAttributes, x1=FileInformation
pub(crate) fn handle_query_attributes_file(frame: &mut SvcFrame) {
    let oa = ObjectAttributesView::from_ptr(frame.x[0]);
    let out_ptr = frame.x[1] as *mut u8;
    let mut path_buf = [0u8; 512];

    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let path_len = oa.map_or(0, |oa| oa.read_path(&mut path_buf));
    if path_len == 0 {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    let path = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
    };

    let Ok(info) = crate::fs::query_path_info(path) else {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    };

    let owner_pid = crate::process::current_pid();
    if !write_file_basic_information(
        owner_pid,
        out_ptr,
        FILE_BASIC_INFORMATION_SIZE,
        if info.directory() {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        },
    ) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    frame.x[0] = status::SUCCESS as u64;
}

// x0=ObjectAttributes, x1=FileInformation (FILE_NETWORK_OPEN_INFORMATION, 56 bytes)
pub(crate) fn handle_query_full_attributes_file(frame: &mut SvcFrame) {
    let oa = ObjectAttributesView::from_ptr(frame.x[0]);
    let out_ptr = frame.x[1] as *mut u8;
    let mut path_buf = [0u8; 512];

    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let path_len = oa.map_or(0, |oa| oa.read_path(&mut path_buf));
    if path_len == 0 {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }
    let path = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
    };

    let Ok(info) = crate::fs::query_path_info(path) else {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    };

    // FILE_NETWORK_OPEN_INFORMATION: 56 bytes
    // CreationTime(8)+LastAccessTime(8)+LastWriteTime(8)+ChangeTime(8)
    // +AllocationSize(8)+EndOfFile(8)+FileAttributes(4)+pad(4)
    let owner_pid = crate::process::current_pid();
    let Some(mut w) = GuestWriter::for_pid(owner_pid, out_ptr, 56, 56) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    let attrs = if info.directory() {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    w.zeros(32)
        .u64(info.size())
        .u64(info.size())
        .u32(attrs)
        .u32(0);
    frame.x[0] = status::SUCCESS as u64;
}

// x0=FileHandle, x1=Event, x2=ApcRoutine, x3=ApcCtx, x4=IoStatusBlock*
// x5=ByteOffset(u64*), x6=Length(u64*), x7=Key, stack[0]=FailImmediately, stack[1]=ExclusiveLock
pub(crate) fn handle_lock_file(frame: &mut SvcFrame) {
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let Some(_target) = file_handle_target(frame.x[0]) else {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    // File locking is advisory in our single-process model — always succeed.
    iosb.write_current(status::SUCCESS, 0);
    frame.x[0] = status::SUCCESS as u64;
}

// x0=FileHandle, x1=IoStatusBlock*, x2=ByteOffset(u64*), x3=Length(u64*), x4=Key
pub(crate) fn handle_unlock_file(frame: &mut SvcFrame) {
    let iosb_ptr = frame.x[1] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let Some(_target) = file_handle_target(frame.x[0]) else {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };
    iosb.write_current(status::SUCCESS, 0);
    frame.x[0] = status::SUCCESS as u64;
}

// x0=FileHandle, x4=*IoStatusBlock
pub(crate) fn handle_device_io_control_file(frame: &mut SvcFrame) {
    let owner_pid = crate::process::current_pid();
    let file_handle = frame.x[0];
    let event_handle = frame.x[1];
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let io_control_code = frame.x[5] as u32;
    let input_ptr = UserInPtr::from_raw(frame.x[6] as *const u8);
    let input_len = frame.x[7] as usize;
    let args = SyscallArgs::new(frame);
    let output_ptr = args.spill_u64(0).unwrap_or(0) as *mut u8;
    let output_len = args.spill_u64(1).unwrap_or(0) as usize;

    if event_handle != 0 && handle_kind_for_pid(event_handle, owner_pid) != Some(KObjectKind::Event)
    {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }

    let Some(target) = file_handle_target(file_handle) else {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let Some(file) = (match target {
        NtFileHandleTarget::Fs(file) if fs_file_is_device(file) => Some(file),
        _ => None,
    }) else {
        iosb.write_current(status::NOT_IMPLEMENTED, 0);
        frame.x[0] = status::NOT_IMPLEMENTED as u64;
        return;
    };
    let file_idx = handle_idx_for_pid(file_handle, owner_pid);
    if file_idx == 0 {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }

    let hostcall_request = match io_control_code {
        IOCTL_WINEMU_HOST_PING => None,
        IOCTL_WINEMU_HOSTCALL_SYNC => {
            if input_ptr.is_null() || input_len < core::mem::size_of::<WinEmuHostcallRequest>() {
                iosb.write_current(status::INVALID_PARAMETER, 0);
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
            if output_ptr.is_null() || output_len < core::mem::size_of::<WinEmuHostcallResponse>() {
                iosb.write_current(status::BUFFER_TOO_SMALL, 0);
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            }
            let Some(req) = UserInPtr::from_raw(input_ptr.as_raw() as *const WinEmuHostcallRequest)
                .read_current()
            else {
                iosb.write_current(status::INVALID_PARAMETER, 0);
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            Some(req)
        }
        _ => None,
    };

    let waiter_tid = if event_handle == 0 {
        crate::sched::current_tid()
    } else {
        0
    };

    let submit = match crate::fs::device_io_control(FsDeviceIoctlRequest {
        file,
        code: io_control_code,
        owner_pid,
        waiter_tid,
        hostcall_request,
    }) {
        Ok(v) => v,
        Err(err) => {
            let st = fs_error_to_status(err);
            iosb.write_current(st, 0);
            frame.x[0] = st as u64;
            return;
        }
    };

    match submit {
        FsDeviceIoctlSubmit::Completed(output) => {
            let written = match write_device_ioctl_output_for_pid(
                owner_pid,
                output_ptr,
                output_len,
                &output,
            ) {
                Some(Ok(info)) => info,
                Some(Err(st)) => {
                    if io_control_code == IOCTL_WINEMU_HOST_PING && st == status::BUFFER_TOO_SMALL {
                        0
                    } else {
                        iosb.write_current(st, 0);
                        frame.x[0] = st as u64;
                        return;
                    }
                }
                None => {
                    if io_control_code == IOCTL_WINEMU_HOST_PING
                        && (output_ptr.is_null() || output_len < output.len())
                    {
                        0
                    } else {
                        iosb.write_current(status::INVALID_PARAMETER, 0);
                        frame.x[0] = status::INVALID_PARAMETER as u64;
                        return;
                    }
                }
            };
            complete_inline_file_io(owner_pid, event_handle, iosb, status::SUCCESS, written);
            frame.x[0] = status::SUCCESS as u64;
        }
        FsDeviceIoctlSubmit::Pending { request_id } => {
            let pending = PendingHostIoctl {
                owner_pid,
                file,
                waiter_tid,
                event_handle,
                iosb_ptr: iosb,
                out_ptr: output_ptr,
                out_len: output_len,
                request_id,
            };
            let st = queue_pending_host_ioctl(pending);
            if st != status::SUCCESS {
                let _ = crate::fs::cancel_async_request(request_id);
                iosb.write_current(st, 0);
                frame.x[0] = st as u64;
                return;
            }

            if event_handle == 0 {
                let st = hostcall::wait_current_for_request_pending(
                    request_id,
                    crate::sched::WaitDeadline::Infinite,
                );
                frame.x[0] = st as u64;
            } else {
                iosb.write_current(STATUS_PENDING, 0);
                frame.x[0] = STATUS_PENDING as u64;
            }
        }
    }
}

// x0=FileHandle, x4=*IoStatusBlock
pub(crate) fn handle_fs_control_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[4] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);

    if file_handle_target(file_handle).is_none() {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }

    iosb.write_current(status::NOT_IMPLEMENTED, 0);
    frame.x[0] = status::NOT_IMPLEMENTED as u64;
}

// x0=FileHandle, x1=*IoStatusBlock, x2=FsInformation, x3=Length, x4=FsInformationClass
pub(crate) fn handle_query_volume_information_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[1] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let out_ptr = frame.x[2] as *mut u8;
    let out_len = frame.x[3] as usize;
    let info_class = frame.x[4] as u32;
    let owner_pid = crate::process::current_pid();

    let target = match file_handle_target(file_handle) {
        Some(v) => v,
        None => {
            iosb.write_current(status::INVALID_HANDLE, 0);
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    match info_class {
        FILE_FS_DEVICE_INFORMATION => {
            let info = match target {
                NtFileHandleTarget::Std(std_handle) => {
                    crate::fs::query_volume_device_info(FsVolumeTarget::Std(std_handle))
                }
                NtFileHandleTarget::Fs(file) => {
                    crate::fs::query_volume_device_info(FsVolumeTarget::File(file))
                }
            };
            let info = match info {
                Ok(info) => info,
                Err(err) => {
                    let st = fs_error_to_status(err);
                    iosb.write_current(st, 0);
                    frame.x[0] = st as u64;
                    return;
                }
            };
            if out_ptr.is_null() || out_len < FILE_FS_DEVICE_INFORMATION_SIZE {
                iosb.write_current(status::INFO_LENGTH_MISMATCH, 0);
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            let Some(mut w) =
                GuestWriter::for_pid(owner_pid, out_ptr, out_len, FILE_FS_DEVICE_INFORMATION_SIZE)
            else {
                iosb.write_current(status::INVALID_PARAMETER, 0);
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.u32(info.device_type()).u32(info.characteristics());
            iosb.write_current(status::SUCCESS, FILE_FS_DEVICE_INFORMATION_SIZE as u64);
            frame.x[0] = status::SUCCESS as u64;
        }
        FILE_FS_ATTRIBUTE_INFORMATION => {
            let info = match target {
                NtFileHandleTarget::Std(std_handle) => {
                    crate::fs::query_volume_attribute_info(FsVolumeTarget::Std(std_handle))
                }
                NtFileHandleTarget::Fs(file) => {
                    crate::fs::query_volume_attribute_info(FsVolumeTarget::File(file))
                }
            };
            let info = match info {
                Ok(info) => info,
                Err(err) => {
                    let st = fs_error_to_status(err);
                    iosb.write_current(st, 0);
                    frame.x[0] = st as u64;
                    return;
                }
            };
            let fs_name = info.fs_name().as_bytes();
            let fs_name_bytes = fs_name.len() * 2;
            let need = FILE_FS_ATTRIBUTE_INFORMATION_SIZE + fs_name_bytes;
            if out_ptr.is_null() || out_len < need {
                iosb.write_current(status::INFO_LENGTH_MISMATCH, 0);
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            let Some(mut w) = GuestWriter::for_pid(owner_pid, out_ptr, out_len, need) else {
                iosb.write_current(status::INVALID_PARAMETER, 0);
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.u32(info.attributes())
                .u32(info.max_component_name_len())
                .u32(fs_name_bytes as u32);
            for ch in fs_name {
                w.u16(*ch as u16);
            }
            iosb.write_current(status::SUCCESS, need as u64);
            frame.x[0] = status::SUCCESS as u64;
        }
        FILE_FS_SIZE_INFORMATION => {
            let info = match target {
                NtFileHandleTarget::Std(std_handle) => {
                    crate::fs::query_volume_size_info(FsVolumeTarget::Std(std_handle))
                }
                NtFileHandleTarget::Fs(file) => {
                    crate::fs::query_volume_size_info(FsVolumeTarget::File(file))
                }
            };
            let info = match info {
                Ok(info) => info,
                Err(err) => {
                    let st = fs_error_to_status(err);
                    iosb.write_current(st, 0);
                    frame.x[0] = st as u64;
                    return;
                }
            };
            if out_ptr.is_null() || out_len < FILE_FS_SIZE_INFORMATION_SIZE {
                iosb.write_current(status::INFO_LENGTH_MISMATCH, 0);
                frame.x[0] = status::INFO_LENGTH_MISMATCH as u64;
                return;
            }
            let Some(mut w) =
                GuestWriter::for_pid(owner_pid, out_ptr, out_len, FILE_FS_SIZE_INFORMATION_SIZE)
            else {
                iosb.write_current(status::INVALID_PARAMETER, 0);
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.u64(info.total_units())
                .u64(info.avail_units())
                .u32(info.sectors_per_alloc())
                .u32(info.bytes_per_sector());
            iosb.write_current(status::SUCCESS, FILE_FS_SIZE_INFORMATION_SIZE as u64);
            frame.x[0] = status::SUCCESS as u64;
        }
        _ => {
            iosb.write_current(status::INVALID_PARAMETER, 0);
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

pub(crate) fn close_file_handle_for_pid(owner_pid: u32, file_idx: u32) {
    let file = FsFileHandle::from_raw(file_idx);
    cancel_pending_dir_notify_for_file(owner_pid, file);
    cancel_pending_file_io_for_file(owner_pid, file);
    cancel_pending_host_ioctl_for_file(owner_pid, file);
    crate::fs::close(file);
}

// x0=FileHandle, x1=*IoStatusBlock
pub(crate) fn handle_flush_buffers_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[1] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let pid = crate::process::current_pid();
    if handle_idx_for_pid(file_handle, pid) == 0 && !is_std_file_handle(file_handle) {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
    // Host VFS handles durability; stub as success.
    iosb.write_current(status::SUCCESS, 0);
    frame.x[0] = status::SUCCESS as u64;
}

// x0=FileHandle, x1=*IoStatusBlock
pub(crate) fn handle_cancel_io_file(frame: &mut SvcFrame) {
    let file_handle = frame.x[0];
    let iosb_ptr = frame.x[1] as *mut IoStatusBlock;
    let iosb = IoStatusBlockPtr::from_raw(iosb_ptr);
    let pid = crate::process::current_pid();
    let file_idx = handle_idx_for_pid(file_handle, pid);
    if file_idx == 0 {
        iosb.write_current(status::INVALID_HANDLE, 0);
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
    let file = FsFileHandle::from_raw(file_idx);
    cancel_pending_file_io_for_file(pid, file);
    cancel_pending_host_ioctl_for_file(pid, file);
    iosb.write_current(status::SUCCESS, 0);
    frame.x[0] = status::SUCCESS as u64;
}
