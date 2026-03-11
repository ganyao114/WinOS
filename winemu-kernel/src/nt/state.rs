use crate::hypercall;
use crate::kobj::ObjectStore;
use crate::mm::vm_sanitize_nt_prot;
use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;

use super::common::HOST_PSEUDO_FD_WINEMU_HOST;

pub(crate) const VM_FILE_MAPPING_DEFAULT_PROT: u32 = 0x20; // PAGE_EXECUTE_READ

#[derive(Clone, Copy)]
pub(crate) struct GuestSection {
    pub(crate) owner_pid: u32,
    pub(crate) size: u64,
    pub(crate) prot: u32,
    pub(crate) file_fd: u64,
    pub(crate) file_backed: bool,
    pub(crate) alloc_attrs: u32,
    pub(crate) is_image: bool,
}

#[derive(Clone, Copy)]
struct GuestFile {
    owner_pid: u32,
    host_fd: u64,
    path_len: u16,
    path: [u8; MAX_FILE_PATH_BYTES],
}

#[derive(Clone, Copy)]
struct GuestView {
    owner_pid: u32,
    base: u64,
    size: u64,
}

struct NtState {
    files: UnsafeCell<Option<ObjectStore<GuestFile>>>,
    sections: UnsafeCell<Option<ObjectStore<GuestSection>>>,
    views: UnsafeCell<Option<ObjectStore<GuestView>>>,
}

unsafe impl Sync for NtState {}

static NT_STATE: NtState = NtState {
    files: UnsafeCell::new(None),
    sections: UnsafeCell::new(None),
    views: UnsafeCell::new(None),
};

const MAX_FILE_PATH_BYTES: usize = 512;

fn files_store_mut() -> &'static mut ObjectStore<GuestFile> {
    unsafe {
        let slot = &mut *NT_STATE.files.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn sections_store_mut() -> &'static mut ObjectStore<GuestSection> {
    unsafe {
        let slot = &mut *NT_STATE.sections.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn views_store_mut() -> &'static mut ObjectStore<GuestView> {
    unsafe {
        let slot = &mut *NT_STATE.views.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

// ─── 文件管理 ─────────────────────────────────────────────────────────────────

pub(crate) fn file_alloc(owner_pid: u32, host_fd: u64, path: &[u8]) -> Option<u32> {
    let path_len = core::cmp::min(path.len(), MAX_FILE_PATH_BYTES);
    let mut name = [0u8; MAX_FILE_PATH_BYTES];
    if path_len != 0 {
        name[..path_len].copy_from_slice(&path[..path_len]);
    }
    files_store_mut().alloc_with(|_| GuestFile {
        owner_pid,
        host_fd,
        path_len: path_len as u16,
        path: name,
    })
}

pub(crate) fn file_host_fd(idx: u32) -> Option<u64> {
    let ptr = files_store_mut().get_ptr(idx);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { (*ptr).host_fd })
    }
}

pub(crate) fn file_owner_pid(idx: u32) -> Option<u32> {
    let ptr = files_store_mut().get_ptr(idx);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { (*ptr).owner_pid })
    }
}

pub(crate) fn file_name_utf16(idx: u32) -> Option<Vec<u16>> {
    let ptr = files_store_mut().get_ptr(idx);
    if ptr.is_null() {
        return None;
    }
    let file = unsafe { &*ptr };
    let len = file.path_len as usize;
    if len == 0 || len > MAX_FILE_PATH_BYTES {
        return None;
    }
    let mut out = Vec::<u16>::new();
    if out.try_reserve(len).is_err() {
        return None;
    }
    let mut i = 0usize;
    while i < len {
        out.push(file.path[i] as u16);
        i += 1;
    }
    Some(out)
}

pub(crate) fn file_free(idx: u32) {
    let store = files_store_mut();
    let ptr = store.get_ptr(idx);
    if ptr.is_null() {
        return;
    }
    unsafe {
        if (*ptr).host_fd != HOST_PSEUDO_FD_WINEMU_HOST {
            hypercall::host_close((*ptr).host_fd);
        }
    }
    let _ = store.free(idx);
}

// ─── Section 管理 ────────────────────────────────────────────────────────────

pub(crate) fn section_alloc(
    owner_pid: u32,
    size: u64,
    prot: u32,
    file_fd: Option<u64>,
    alloc_attrs: u32,
) -> Option<u32> {
    let is_image = (alloc_attrs & 0x0100_0000) != 0;
    sections_store_mut().alloc_with(|_| GuestSection {
        owner_pid,
        size,
        prot: vm_sanitize_nt_prot(prot),
        file_fd: file_fd.unwrap_or(0),
        file_backed: file_fd.is_some(),
        alloc_attrs,
        is_image,
    })
}

pub(crate) fn section_get(idx: u32) -> Option<GuestSection> {
    let ptr = sections_store_mut().get_ptr(idx);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { *ptr })
    }
}

pub(crate) fn section_free(idx: u32) {
    let _ = sections_store_mut().free(idx);
}

// ─── View 管理 ───────────────────────────────────────────────────────────────

pub(crate) fn view_alloc(owner_pid: u32, base: u64, size: u64) -> bool {
    views_store_mut()
        .alloc_with(|_| GuestView {
            owner_pid,
            base,
            size,
        })
        .is_some()
}

pub(crate) fn view_free(owner_pid: u32, base: u64) -> bool {
    let store = views_store_mut();
    let mut id = 0u32;
    store.for_each_live_ptr(|cur_id, ptr| unsafe {
        if (*ptr).owner_pid == owner_pid && (*ptr).base == base {
            id = cur_id;
        }
    });
    if id == 0 {
        return false;
    }
    store.free(id)
}

// ─── 进程资源清理 ─────────────────────────────────────────────────────────────

pub(crate) fn cleanup_process_owned_resources(owner_pid: u32) {
    if owner_pid == 0 {
        return;
    }

    let mut file_ids = Vec::new();
    files_store_mut().for_each_live_ptr(|id, ptr| unsafe {
        if (*ptr).owner_pid == owner_pid {
            let _ = file_ids.try_reserve(1);
            file_ids.push(id);
        }
    });
    for id in file_ids {
        file_free(id);
    }

    let mut section_ids = Vec::new();
    sections_store_mut().for_each_live_ptr(|id, ptr| unsafe {
        if (*ptr).owner_pid == owner_pid {
            let _ = section_ids.try_reserve(1);
            section_ids.push(id);
        }
    });
    for id in section_ids {
        section_free(id);
    }

    let mut view_ids = Vec::new();
    views_store_mut().for_each_live_ptr(|id, ptr| unsafe {
        if (*ptr).owner_pid == owner_pid {
            let _ = view_ids.try_reserve(1);
            view_ids.push(id);
        }
    });
    for id in view_ids {
        let _ = views_store_mut().free(id);
    }

    // Cleanup VM regions owned by KProcess.vm
    let _ = crate::process::with_process_mut(owner_pid, |p| {
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.cleanup_all(aspace);
    });
}
