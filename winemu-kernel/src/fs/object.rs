use crate::kobj::ObjectStore;
use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;

use super::types::{FsError, FsFileHandle};

const MAX_FILE_PATH_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FsBackendKind {
    HostFs,
    WinEmuHost,
}

#[derive(Clone, Copy)]
pub(crate) struct FsFileRecord {
    pub(crate) backend: FsBackendKind,
    pub(crate) backend_idx: u32,
    refs: u32,
    path_len: u16,
    path: [u8; MAX_FILE_PATH_BYTES],
}

struct FsObjectState {
    files: UnsafeCell<Option<ObjectStore<FsFileRecord>>>,
}

unsafe impl Sync for FsObjectState {}

static FS_OBJECT_STATE: FsObjectState = FsObjectState {
    files: UnsafeCell::new(None),
};

fn files_mut() -> &'static mut ObjectStore<FsFileRecord> {
    // SAFETY: FS object storage follows the same global serialization model as
    // the rest of the kernel object stores.
    unsafe {
        let slot = &mut *FS_OBJECT_STATE.files.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

pub(crate) fn alloc_file(
    backend: FsBackendKind,
    backend_idx: u32,
    path: &[u8],
) -> Result<FsFileHandle, FsError> {
    let path_len = core::cmp::min(path.len(), MAX_FILE_PATH_BYTES);
    let mut stored_path = [0u8; MAX_FILE_PATH_BYTES];
    if path_len != 0 {
        stored_path[..path_len].copy_from_slice(&path[..path_len]);
    }
    let id = files_mut()
        .alloc_with(|_| FsFileRecord {
            backend,
            backend_idx,
            refs: 1,
            path_len: path_len as u16,
            path: stored_path,
        })
        .ok_or(FsError::NoMemory)?;
    Ok(FsFileHandle::from_raw(id))
}

pub(crate) fn file_record(file: FsFileHandle) -> Option<FsFileRecord> {
    let ptr = files_mut().get_ptr(file.raw());
    if ptr.is_null() {
        None
    } else {
        // SAFETY: object store returns a stable live pointer for the duration
        // of the call; `FsFileRecord` is `Copy`.
        Some(unsafe { *ptr })
    }
}

pub(crate) fn free_file(file: FsFileHandle) -> bool {
    let store = files_mut();
    let ptr = store.get_ptr(file.raw());
    if ptr.is_null() {
        return false;
    }
    // SAFETY: pointer comes from the live file store entry.
    let entry = unsafe { &mut *ptr };
    if entry.refs > 1 {
        entry.refs -= 1;
        return false;
    }
    store.free(file.raw())
}

pub(crate) fn retain_file(file: FsFileHandle) -> bool {
    let ptr = files_mut().get_ptr(file.raw());
    if ptr.is_null() {
        return false;
    }
    // SAFETY: pointer comes from the live file store entry.
    unsafe {
        (*ptr).refs = (*ptr).refs.saturating_add(1);
    }
    true
}

pub(crate) fn file_ref_count(file: FsFileHandle) -> u32 {
    let ptr = files_mut().get_ptr(file.raw());
    if ptr.is_null() {
        0
    } else {
        // SAFETY: pointer comes from the live file store entry.
        unsafe { (*ptr).refs }
    }
}

pub(crate) fn file_name_utf16(file: FsFileHandle) -> Option<Vec<u16>> {
    let record = file_record(file)?;
    let len = record.path_len as usize;
    if len == 0 || len > MAX_FILE_PATH_BYTES {
        return None;
    }
    let mut out = Vec::<u16>::new();
    if out.try_reserve(len).is_err() {
        return None;
    }
    let mut i = 0usize;
    while i < len {
        out.push(record.path[i] as u16);
        i += 1;
    }
    Some(out)
}
