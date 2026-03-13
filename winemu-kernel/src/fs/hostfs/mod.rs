use crate::hypercall;
use crate::kobj::ObjectStore;
use crate::mm::PhysAddr;
use core::cell::UnsafeCell;
use winemu_shared::hostcall as hc;

use super::types::{FsDirEntry, FsError, FsFileInfo, FsNotifyRecord, FsOpenMode, FsOpenRequest};

const HOST_OPEN_READ: u64 = 0;
const HOST_OPEN_WRITE: u64 = 1;
const HOST_OPEN_RW: u64 = 2;
const HOST_OPEN_CREATE: u64 = 3;
const HOST_DIRENT_FLAG_IS_DIR: u64 = 1u64 << 63;
const HOST_DIRENT_NAME_LEN_MASK: u64 = 0x0000_0000_FFFF_FFFF;
const HOST_NOTIFY_ACTION_MASK: u64 = 0x0000_00FF_0000_0000;
const HOST_NOTIFY_ACTION_SHIFT: u64 = 32;

#[derive(Clone, Copy)]
struct HostFsFile {
    fd: u64,
    size_hint: u64,
    refs: u32,
}

struct HostFsState {
    files: UnsafeCell<Option<ObjectStore<HostFsFile>>>,
}

unsafe impl Sync for HostFsState {}

static HOSTFS_STATE: HostFsState = HostFsState {
    files: UnsafeCell::new(None),
};

fn files_mut() -> &'static mut ObjectStore<HostFsFile> {
    // SAFETY: hostfs backend state is currently managed under the kernel's
    // existing global serialization model.
    unsafe {
        let slot = &mut *HOSTFS_STATE.files.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn alloc_host_file(fd: u64, size_hint: u64) -> Result<u32, FsError> {
    files_mut()
        .alloc_with(|_| HostFsFile {
            fd,
            size_hint,
            refs: 1,
        })
        .ok_or(FsError::NoMemory)
}

fn host_file(id: u32) -> Result<HostFsFile, FsError> {
    let ptr = files_mut().get_ptr(id);
    if ptr.is_null() {
        Err(FsError::InvalidHandle)
    } else {
        // SAFETY: object store returns a stable live pointer for the duration
        // of the call; `HostFsFile` is `Copy`.
        Ok(unsafe { *ptr })
    }
}

pub(crate) fn open(req: &FsOpenRequest<'_>) -> Result<u32, FsError> {
    let flags = match req.mode {
        FsOpenMode::Read => HOST_OPEN_READ,
        FsOpenMode::Write => HOST_OPEN_WRITE,
        FsOpenMode::ReadWrite => HOST_OPEN_RW,
        FsOpenMode::Create => HOST_OPEN_CREATE,
    };
    let fd = hypercall::host_open(req.path, flags);
    if fd == u64::MAX {
        return Err(FsError::NotFound);
    }
    alloc_host_file(fd, 0)
}

pub(crate) fn create_dir(path: &str) -> Result<(), FsError> {
    crate::hypercall::host_mkdir(path)
}

pub(crate) fn import_existing(fd: u64, size_hint: u64) -> Result<u32, FsError> {
    if fd == u64::MAX {
        return Err(FsError::InvalidHandle);
    }
    alloc_host_file(fd, size_hint)
}

fn std_fd(std: super::types::FsStdHandle) -> u64 {
    match std {
        super::types::FsStdHandle::Input => 0,
        super::types::FsStdHandle::Output => 1,
        super::types::FsStdHandle::Error => 2,
    }
}

pub(crate) fn close(id: u32) {
    release(id);
}

pub(crate) fn retain(id: u32) -> Result<(), FsError> {
    let store = files_mut();
    let ptr = store.get_ptr(id);
    if ptr.is_null() {
        return Err(FsError::InvalidHandle);
    }
    // SAFETY: object store returns a stable live pointer for this id.
    unsafe {
        (*ptr).refs = (*ptr).refs.saturating_add(1);
    }
    Ok(())
}

pub(crate) fn release(id: u32) {
    let store = files_mut();
    let ptr = store.get_ptr(id);
    if ptr.is_null() {
        return;
    }
    // SAFETY: object store returns a stable live pointer for this id.
    let entry = unsafe { &mut *ptr };
    if entry.refs > 1 {
        entry.refs -= 1;
        return;
    }
    let fd = entry.fd;
    hypercall::host_close(fd);
    let _ = store.free(id);
}

pub(crate) fn query_info(id: u32) -> Result<FsFileInfo, FsError> {
    let ptr = files_mut().get_ptr(id);
    if ptr.is_null() {
        return Err(FsError::InvalidHandle);
    }
    let entry = unsafe { &mut *ptr };
    let size = if entry.size_hint != 0 {
        entry.size_hint
    } else {
        let size = hypercall::host_stat(entry.fd);
        entry.size_hint = size;
        size
    };
    Ok(FsFileInfo { size })
}

pub(crate) fn seek(id: u32, offset: i64, whence: u32) -> Result<u64, FsError> {
    let ptr = files_mut().get_ptr(id);
    if ptr.is_null() {
        return Err(FsError::InvalidHandle);
    }
    // SAFETY: object store returns a stable live pointer for this id.
    let entry = unsafe { &mut *ptr };
    crate::hypercall::host_seek(entry.fd, offset, whence).ok_or(FsError::IoError)
}

pub(crate) fn set_len(id: u32, len: u64) -> Result<(), FsError> {
    let ptr = files_mut().get_ptr(id);
    if ptr.is_null() {
        return Err(FsError::InvalidHandle);
    }
    // SAFETY: object store returns a stable live pointer for this id.
    let entry = unsafe { &mut *ptr };
    if crate::hypercall::host_set_len(entry.fd, len) {
        entry.size_hint = len;
        Ok(())
    } else {
        Err(FsError::IoError)
    }
}

pub(crate) fn read_at(id: u32, dst: *mut u8, len: usize, offset: u64) -> Result<usize, FsError> {
    let fd = host_file(id)?.fd;
    Ok(hypercall::host_read(fd, dst, len, offset))
}

pub(crate) fn read_at_phys(
    id: u32,
    dst: PhysAddr,
    len: usize,
    offset: u64,
) -> Result<usize, FsError> {
    let fd = host_file(id)?.fd;
    Ok(hypercall::host_read_phys(fd, dst, len, offset))
}

pub(crate) fn read_std_at_phys(
    std: super::types::FsStdHandle,
    dst: PhysAddr,
    len: usize,
    offset: u64,
) -> Result<usize, FsError> {
    Ok(hypercall::host_read_phys(std_fd(std), dst, len, offset))
}

pub(crate) fn write_at(id: u32, src: *const u8, len: usize, offset: u64) -> Result<usize, FsError> {
    let fd = host_file(id)?.fd;
    Ok(hypercall::host_write(fd, src, len, offset))
}

pub(crate) fn write_at_phys(
    id: u32,
    src: PhysAddr,
    len: usize,
    offset: u64,
) -> Result<usize, FsError> {
    let fd = host_file(id)?.fd;
    Ok(hypercall::host_write_phys(fd, src, len, offset))
}

pub(crate) fn write_std_at_phys(
    std: super::types::FsStdHandle,
    src: PhysAddr,
    len: usize,
    offset: u64,
) -> Result<usize, FsError> {
    Ok(hypercall::host_write_phys(std_fd(std), src, len, offset))
}

fn decode_dir_entry(packed: u64, name_buf: &[u8]) -> Result<Option<FsDirEntry>, FsError> {
    if packed == u64::MAX {
        return Err(FsError::IoError);
    }
    if packed == 0 {
        return Ok(None);
    }
    let name_len = (packed & HOST_DIRENT_NAME_LEN_MASK) as usize;
    if name_len == 0 || name_len > name_buf.len() {
        return Err(FsError::IoError);
    }
    Ok(Some(FsDirEntry::new(
        &name_buf[..name_len],
        (packed & HOST_DIRENT_FLAG_IS_DIR) != 0,
    )?))
}

pub(crate) fn readdir(id: u32, restart: bool) -> Result<Option<FsDirEntry>, FsError> {
    let fd = host_file(id)?.fd;
    let mut name_buf = [0u8; 512];
    let packed = hypercall::host_readdir(fd, name_buf.as_mut_ptr(), name_buf.len(), restart);
    decode_dir_entry(packed, &name_buf)
}

pub(crate) fn readdir_std(
    std: super::types::FsStdHandle,
    restart: bool,
) -> Result<Option<FsDirEntry>, FsError> {
    let mut name_buf = [0u8; 512];
    let packed =
        hypercall::host_readdir(std_fd(std), name_buf.as_mut_ptr(), name_buf.len(), restart);
    decode_dir_entry(packed, &name_buf)
}

fn decode_notify_record(packed: u64, name_buf: &[u8]) -> Result<Option<FsNotifyRecord>, FsError> {
    if packed == u64::MAX {
        return Err(FsError::IoError);
    }
    if packed == 0 {
        return Ok(None);
    }
    let action = ((packed & HOST_NOTIFY_ACTION_MASK) >> HOST_NOTIFY_ACTION_SHIFT) as u32;
    let name_len = (packed & HOST_DIRENT_NAME_LEN_MASK) as usize;
    if action == 0 || name_len == 0 || name_len > name_buf.len() {
        return Err(FsError::IoError);
    }
    Ok(Some(FsNotifyRecord::new(action, &name_buf[..name_len])?))
}

pub(crate) fn notify_dir(
    id: u32,
    watch_tree: bool,
    completion_filter: u32,
) -> Result<Option<FsNotifyRecord>, FsError> {
    let fd = host_file(id)?.fd;
    let mut name_buf = [0u8; 512];
    let packed = hypercall::host_notify_dir(
        fd,
        name_buf.as_mut_ptr(),
        name_buf.len(),
        watch_tree,
        completion_filter,
    );
    decode_notify_record(packed, &name_buf)
}

pub(crate) fn submit_async_read(
    id: u32,
    owner_pid: u32,
    waiter_tid: u32,
    dst: PhysAddr,
    len: usize,
    offset: u64,
) -> Result<crate::hostcall::SubmitOutcome, u32> {
    let fd = host_file(id)
        .map_err(|_| winemu_shared::status::INVALID_HANDLE)?
        .fd;
    crate::hostcall::submit_tracked(
        owner_pid,
        waiter_tid,
        crate::hostcall::SubmitArgs {
            opcode: hc::OP_READ,
            flags: hc::FLAG_ALLOW_ASYNC,
            arg0: fd,
            arg1: dst.get(),
            arg2: len as u64,
            arg3: offset,
            user_tag: 0,
        },
    )
}

pub(crate) fn submit_async_write(
    id: u32,
    owner_pid: u32,
    waiter_tid: u32,
    src: PhysAddr,
    len: usize,
    offset: u64,
) -> Result<crate::hostcall::SubmitOutcome, u32> {
    let fd = host_file(id)
        .map_err(|_| winemu_shared::status::INVALID_HANDLE)?
        .fd;
    crate::hostcall::submit_tracked(
        owner_pid,
        waiter_tid,
        crate::hostcall::SubmitArgs {
            opcode: hc::OP_WRITE,
            flags: hc::FLAG_ALLOW_ASYNC,
            arg0: fd,
            arg1: src.get(),
            arg2: len as u64,
            arg3: offset,
            user_tag: 0,
        },
    )
}

pub(crate) fn submit_async_notify_dir(
    id: u32,
    owner_pid: u32,
    waiter_tid: u32,
    name_ptr: u64,
    name_cap: u64,
    watch_tree: bool,
    completion_filter: u32,
) -> Result<crate::hostcall::SubmitOutcome, u32> {
    let fd = host_file(id)
        .map_err(|_| winemu_shared::status::INVALID_HANDLE)?
        .fd;
    let mut notify_opts = completion_filter as u64;
    if watch_tree {
        notify_opts |= 1u64 << 63;
    }
    crate::hostcall::submit_tracked(
        owner_pid,
        waiter_tid,
        crate::hostcall::SubmitArgs {
            opcode: hc::OP_NOTIFY_DIR,
            flags: hc::FLAG_FORCE_ASYNC,
            arg0: fd,
            arg1: name_ptr,
            arg2: name_cap,
            arg3: notify_opts,
            user_tag: 0,
        },
    )
}
