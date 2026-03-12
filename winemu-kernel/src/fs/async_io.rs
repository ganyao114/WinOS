use core::cell::UnsafeCell;

use crate::hostcall;
use crate::hypercall::HostCallCompletion;
use crate::kobj::ObjectStore;
use winemu_shared::hostcall as hc;

use super::device::FsIoctlOutput;
use super::object::{self, FsBackendKind};
use super::types::{
    FsAsyncSubmit, FsError, FsFileHandle, FsNotifyRecord, FsReadPhysRequest, FsWritePhysRequest,
};

const HOST_DIRENT_NAME_LEN_MASK: u64 = 0x0000_0000_FFFF_FFFF;
const HOST_NOTIFY_ACTION_MASK: u64 = 0x0000_00FF_0000_0000;
const HOST_NOTIFY_ACTION_SHIFT: u64 = 32;

#[derive(Clone, Copy)]
enum FsAsyncKind {
    FileRead,
    FileWrite,
    DirNotify,
    DeviceIoControl,
}

#[derive(Clone, Copy)]
struct FsAsyncRequest {
    request_id: u64,
    kind: FsAsyncKind,
    name_buf: [u8; 512],
}

struct FsAsyncState {
    requests: UnsafeCell<Option<ObjectStore<FsAsyncRequest>>>,
}

unsafe impl Sync for FsAsyncState {}

static FS_ASYNC_STATE: FsAsyncState = FsAsyncState {
    requests: UnsafeCell::new(None),
};

pub enum FsAsyncCompletion {
    FileRead {
        request_id: u64,
        result: Result<usize, FsError>,
    },
    FileWrite {
        request_id: u64,
        result: Result<usize, FsError>,
    },
    DirNotify {
        request_id: u64,
        result: Result<FsNotifyRecord, FsError>,
    },
    DeviceIoControl {
        request_id: u64,
        result: Result<FsIoctlOutput, FsError>,
    },
}

fn requests_mut() -> &'static mut ObjectStore<FsAsyncRequest> {
    // SAFETY: async fs backend state follows the same globally serialized
    // object-store model as the rest of the kernel runtime metadata.
    unsafe {
        let slot = &mut *FS_ASYNC_STATE.requests.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn status_to_fs_error(st: u32) -> FsError {
    match st {
        winemu_shared::status::NO_MEMORY => FsError::NoMemory,
        winemu_shared::status::INVALID_HANDLE => FsError::InvalidHandle,
        winemu_shared::status::NOT_IMPLEMENTED => FsError::Unsupported,
        winemu_shared::status::OBJECT_NAME_NOT_FOUND => FsError::NotFound,
        _ => FsError::IoError,
    }
}

fn host_result_to_fs_error(host_result: u64) -> FsError {
    status_to_fs_error(hostcall::map_host_result_to_status(host_result))
}

fn submit_status_to_fs_error(st: u32) -> FsError {
    status_to_fs_error(st)
}

fn completion_host_result(cpl: &HostCallCompletion) -> u64 {
    if cpl.host_result < 0 {
        hc::HC_INVALID
    } else {
        cpl.host_result as u64
    }
}

fn cancel_hostcall_pending(request_id: u64) {
    let _ = crate::hypercall::hostcall_cancel(request_id);
    let _ = crate::hostcall::unregister_pending_request(request_id);
}

fn alloc_request(kind: FsAsyncKind) -> Result<u32, FsError> {
    requests_mut()
        .alloc_with(|_| FsAsyncRequest {
            request_id: 0,
            kind,
            name_buf: [0u8; 512],
        })
        .ok_or(FsError::NoMemory)
}

fn free_request(id: u32) {
    let _ = requests_mut().free(id);
}

fn remove_request_by_request_id(request_id: u64) -> Option<FsAsyncRequest> {
    if request_id == 0 {
        return None;
    }
    let store = requests_mut();
    let mut found = 0u32;
    store.for_each_live_ptr(|id, ptr| unsafe {
        if found == 0 && (*ptr).request_id == request_id {
            found = id;
        }
    });
    if found == 0 {
        return None;
    }
    let ptr = store.get_ptr(found);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `found` refers to a live request entry in the same store.
    let req = unsafe { *ptr };
    let _ = store.free(found);
    Some(req)
}

pub(crate) fn cancel_request(request_id: u64) -> bool {
    remove_request_by_request_id(request_id).is_some()
}

fn store_pending_request(kind: FsAsyncKind, request_id: u64) -> Result<(), FsError> {
    let id = alloc_request(kind)?;
    let ptr = requests_mut().get_ptr(id);
    if ptr.is_null() {
        free_request(id);
        return Err(FsError::NoMemory);
    }
    // SAFETY: `id` refers to a live entry we just allocated.
    unsafe {
        (*ptr).request_id = request_id;
    }
    Ok(())
}

fn set_pending_request_id(id: u32, request_id: u64) -> bool {
    let ptr = requests_mut().get_ptr(id);
    if ptr.is_null() {
        return false;
    }
    // SAFETY: `id` refers to a live entry in this store.
    unsafe {
        (*ptr).request_id = request_id;
    }
    true
}

fn request_name_buf(id: u32) -> Option<(*mut u8, usize)> {
    let ptr = requests_mut().get_ptr(id);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `id` refers to a live entry in this store.
    let req = unsafe { &mut *ptr };
    Some((req.name_buf.as_mut_ptr(), req.name_buf.len()))
}

fn decode_file_submit(
    kind: FsAsyncKind,
    out: hostcall::SubmitOutcome,
) -> Result<FsAsyncSubmit<usize>, FsError> {
    match out {
        hostcall::SubmitOutcome::Completed(done) => {
            if done.host_result == hc::HC_OK {
                Ok(FsAsyncSubmit::Completed(done.value0 as usize))
            } else {
                Err(host_result_to_fs_error(done.host_result))
            }
        }
        hostcall::SubmitOutcome::Pending { request_id } => {
            store_pending_request(kind, request_id)?;
            Ok(FsAsyncSubmit::Pending { request_id })
        }
    }
}

pub(crate) fn submit_async_read(
    req: FsReadPhysRequest,
    owner_pid: u32,
    waiter_tid: u32,
) -> Result<FsAsyncSubmit<usize>, FsError> {
    let record = object::file_record(req.file).ok_or(FsError::InvalidHandle)?;
    match record.backend {
        FsBackendKind::HostFs => {
            let out = super::hostfs::submit_async_read(
                record.backend_idx,
                owner_pid,
                waiter_tid,
                req.dst,
                req.len,
                req.offset,
            )
            .map_err(submit_status_to_fs_error)?;
            decode_file_submit(FsAsyncKind::FileRead, out)
        }
        FsBackendKind::WinEmuHost => Err(FsError::Unsupported),
    }
}

pub(crate) fn submit_async_write(
    req: FsWritePhysRequest,
    owner_pid: u32,
    waiter_tid: u32,
) -> Result<FsAsyncSubmit<usize>, FsError> {
    let record = object::file_record(req.file).ok_or(FsError::InvalidHandle)?;
    match record.backend {
        FsBackendKind::HostFs => {
            let out = super::hostfs::submit_async_write(
                record.backend_idx,
                owner_pid,
                waiter_tid,
                req.src,
                req.len,
                req.offset,
            )
            .map_err(submit_status_to_fs_error)?;
            decode_file_submit(FsAsyncKind::FileWrite, out)
        }
        FsBackendKind::WinEmuHost => Err(FsError::Unsupported),
    }
}

pub(crate) fn submit_async_notify_dir(
    file: FsFileHandle,
    owner_pid: u32,
    waiter_tid: u32,
    watch_tree: bool,
    completion_filter: u32,
) -> Result<FsAsyncSubmit<FsNotifyRecord>, FsError> {
    let record = object::file_record(file).ok_or(FsError::InvalidHandle)?;
    match record.backend {
        FsBackendKind::HostFs => {
            let id = alloc_request(FsAsyncKind::DirNotify)?;
            let Some((name_ptr, name_cap)) = request_name_buf(id) else {
                free_request(id);
                return Err(FsError::NoMemory);
            };
            let out = super::hostfs::submit_async_notify_dir(
                record.backend_idx,
                owner_pid,
                waiter_tid,
                name_ptr as u64,
                name_cap as u64,
                watch_tree,
                completion_filter,
            )
            .map_err(submit_status_to_fs_error);
            match out {
                Ok(hostcall::SubmitOutcome::Completed(done)) => {
                    let ptr = requests_mut().get_ptr(id);
                    if ptr.is_null() {
                        free_request(id);
                        return Err(FsError::IoError);
                    }
                    // SAFETY: `id` still refers to the live notify request entry.
                    let name_buf = unsafe { (*ptr).name_buf };
                    free_request(id);
                    if done.host_result != hc::HC_OK {
                        return Err(host_result_to_fs_error(done.host_result));
                    }
                    decode_notify_packed(done.value0, &name_buf).map(FsAsyncSubmit::Completed)
                }
                Ok(hostcall::SubmitOutcome::Pending { request_id }) => {
                    if !set_pending_request_id(id, request_id) {
                        free_request(id);
                        cancel_hostcall_pending(request_id);
                        return Err(FsError::NoMemory);
                    }
                    Ok(FsAsyncSubmit::Pending { request_id })
                }
                Err(err) => {
                    free_request(id);
                    Err(err)
                }
            }
        }
        FsBackendKind::WinEmuHost => Err(FsError::Unsupported),
    }
}

pub(crate) fn register_pending_device_io_control(request_id: u64) -> Result<(), FsError> {
    store_pending_request(FsAsyncKind::DeviceIoControl, request_id)
}

fn decode_notify_packed(packed: u64, name_buf: &[u8; 512]) -> Result<FsNotifyRecord, FsError> {
    let action = ((packed & HOST_NOTIFY_ACTION_MASK) >> HOST_NOTIFY_ACTION_SHIFT) as u32;
    let name_len = (packed & HOST_DIRENT_NAME_LEN_MASK) as usize;
    if action == 0 || name_len == 0 || name_len > name_buf.len() {
        return Err(FsError::IoError);
    }
    FsNotifyRecord::new(action, &name_buf[..name_len])
}

pub(crate) fn dispatch_async_completion(cpl: HostCallCompletion) -> Option<FsAsyncCompletion> {
    let request_id = cpl.request_id;
    let req = remove_request_by_request_id(request_id)?;
    Some(match req.kind {
        FsAsyncKind::FileRead => FsAsyncCompletion::FileRead {
            request_id,
            result: if completion_host_result(&cpl) == hc::HC_OK {
                Ok(cpl.value0 as usize)
            } else {
                Err(host_result_to_fs_error(completion_host_result(&cpl)))
            },
        },
        FsAsyncKind::FileWrite => FsAsyncCompletion::FileWrite {
            request_id,
            result: if completion_host_result(&cpl) == hc::HC_OK {
                Ok(cpl.value0 as usize)
            } else {
                Err(host_result_to_fs_error(completion_host_result(&cpl)))
            },
        },
        FsAsyncKind::DirNotify => FsAsyncCompletion::DirNotify {
            request_id,
            result: if completion_host_result(&cpl) == hc::HC_OK {
                decode_notify_packed(cpl.value0, &req.name_buf)
            } else {
                Err(host_result_to_fs_error(completion_host_result(&cpl)))
            },
        },
        FsAsyncKind::DeviceIoControl => FsAsyncCompletion::DeviceIoControl {
            request_id,
            // WinEmuHost async ioctl mirrors the sync ioctl contract: the ioctl
            // transport itself completes successfully and the hostcall result is
            // reported inside the response payload.
            result: Ok(super::complete_async_device_io_control(cpl)),
        },
    })
}
