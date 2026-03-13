use core::cell::UnsafeCell;

use crate::kobj::ObjectStore;
use crate::mm::PhysAddr;

use super::object::{self, FsBackendKind};
use super::types::{FsBackingHandle, FsError, FsFileHandle};

#[derive(Clone, Copy)]
struct FsBackingRecord {
    backend: FsBackendKind,
    backend_idx: u32,
    file_offset: u64,
    size: u64,
    is_image: bool,
    refs: u32,
}

struct FsBackingState {
    backings: UnsafeCell<Option<ObjectStore<FsBackingRecord>>>,
}

unsafe impl Sync for FsBackingState {}

static FS_BACKING_STATE: FsBackingState = FsBackingState {
    backings: UnsafeCell::new(None),
};

fn backings_mut() -> &'static mut ObjectStore<FsBackingRecord> {
    // SAFETY: backing metadata follows the same globally serialized object-store
    // model as the rest of the kernel runtime state.
    unsafe {
        let slot = &mut *FS_BACKING_STATE.backings.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn alloc_backing(
    backend: FsBackendKind,
    backend_idx: u32,
    file_offset: u64,
    size: u64,
    is_image: bool,
) -> Result<FsBackingHandle, FsError> {
    let id = backings_mut()
        .alloc_with(|_| FsBackingRecord {
            backend,
            backend_idx,
            file_offset,
            size,
            is_image,
            refs: 1,
        })
        .ok_or(FsError::NoMemory)?;
    Ok(FsBackingHandle::from_raw(id))
}

fn backing_record(backing: FsBackingHandle) -> Option<FsBackingRecord> {
    let ptr = backings_mut().get_ptr(backing.raw());
    if ptr.is_null() {
        None
    } else {
        // SAFETY: object store returns a stable live pointer for the duration
        // of the call; `FsBackingRecord` is `Copy`.
        Some(unsafe { *ptr })
    }
}

pub(crate) fn create_from_file(
    file: FsFileHandle,
    file_offset: u64,
    size: u64,
    is_image: bool,
) -> Result<FsBackingHandle, FsError> {
    let record = object::file_record(file).ok_or(FsError::InvalidHandle)?;
    match record.backend {
        FsBackendKind::HostFs => {
            super::hostfs::retain(record.backend_idx)?;
            match alloc_backing(
                record.backend,
                record.backend_idx,
                file_offset,
                size,
                is_image,
            ) {
                Ok(backing) => Ok(backing),
                Err(err) => {
                    super::hostfs::release(record.backend_idx);
                    Err(err)
                }
            }
        }
        FsBackendKind::WinEmuHost => Err(FsError::Unsupported),
    }
}

pub(crate) fn retain(backing: FsBackingHandle) -> bool {
    let ptr = backings_mut().get_ptr(backing.raw());
    if ptr.is_null() {
        return false;
    }
    // SAFETY: pointer comes from the live backing store entry.
    unsafe {
        (*ptr).refs = (*ptr).refs.saturating_add(1);
    }
    true
}

pub(crate) fn release(backing: FsBackingHandle) {
    let store = backings_mut();
    let ptr = store.get_ptr(backing.raw());
    if ptr.is_null() {
        return;
    }

    // SAFETY: pointer comes from the live backing store entry.
    let entry = unsafe { &mut *ptr };
    if entry.refs > 1 {
        entry.refs -= 1;
        return;
    }

    let backend = entry.backend;
    let backend_idx = entry.backend_idx;
    let _ = store.free(backing.raw());
    match backend {
        FsBackendKind::HostFs => super::hostfs::release(backend_idx),
        FsBackendKind::WinEmuHost => {}
    }
}

pub(crate) fn pager_read_into_phys(
    backing: FsBackingHandle,
    file_off: u64,
    dst: PhysAddr,
    len: usize,
) -> Result<usize, FsError> {
    let record = backing_record(backing).ok_or(FsError::InvalidHandle)?;
    let _ = record.is_image;
    if file_off >= record.size {
        return Ok(0);
    }

    let remain = record.size.saturating_sub(file_off);
    let read_len = core::cmp::min(remain.min(len as u64), usize::MAX as u64) as usize;
    let abs_off = record.file_offset.saturating_add(file_off);
    match record.backend {
        FsBackendKind::HostFs => {
            super::hostfs::read_at_phys(record.backend_idx, dst, read_len, abs_off)
        }
        FsBackendKind::WinEmuHost => Err(FsError::Unsupported),
    }
}

pub(crate) fn pager_write_from_phys(
    backing: FsBackingHandle,
    file_off: u64,
    src: PhysAddr,
    len: usize,
) -> Result<usize, FsError> {
    let record = backing_record(backing).ok_or(FsError::InvalidHandle)?;
    let _ = record.is_image;
    if file_off >= record.size {
        return Ok(0);
    }

    let remain = record.size.saturating_sub(file_off);
    let write_len = core::cmp::min(remain.min(len as u64), usize::MAX as u64) as usize;
    let abs_off = record.file_offset.saturating_add(file_off);
    match record.backend {
        FsBackendKind::HostFs => {
            super::hostfs::write_at_phys(record.backend_idx, src, write_len, abs_off)
        }
        FsBackendKind::WinEmuHost => Err(FsError::Unsupported),
    }
}
