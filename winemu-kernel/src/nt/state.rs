use crate::hypercall;
use crate::kobj::ObjectStore;
use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;

use super::common::align_up_4k;
use super::constants::PAGE_SIZE_4K;

#[derive(Clone, Copy)]
pub(crate) struct GuestSection {
    pub(crate) owner_pid: u32,
    pub(crate) size: u64,
    pub(crate) prot: u32,
    pub(crate) file_handle: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct VmRegion {
    pub(crate) owner_pid: u32,
    pub(crate) base: u64,
    pub(crate) size: u64,
    pub(crate) prot: u32,
}

#[derive(Clone, Copy)]
struct GuestFile {
    owner_pid: u32,
    host_fd: u64,
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
    regions: UnsafeCell<Option<ObjectStore<VmRegion>>>,
}

unsafe impl Sync for NtState {}

static NT_STATE: NtState = NtState {
    files: UnsafeCell::new(None),
    sections: UnsafeCell::new(None),
    views: UnsafeCell::new(None),
    regions: UnsafeCell::new(None),
};

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

fn regions_store_mut() -> &'static mut ObjectStore<VmRegion> {
    unsafe {
        let slot = &mut *NT_STATE.regions.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

pub(crate) fn vm_alloc_region(owner_pid: u32, size: u64, prot: u32) -> Option<u64> {
    let size = align_up_4k(size.max(PAGE_SIZE_4K));
    let base =
        crate::alloc::alloc_zeroed(size as usize, PAGE_SIZE_4K as usize).map(|p| p as u64)?;
    let id = regions_store_mut().alloc_with(|_| VmRegion {
        owner_pid,
        base,
        size,
        prot,
    })?;
    let _ = id;
    Some(base)
}

pub(crate) fn vm_find_region(owner_pid: u32, base_or_addr: u64) -> Option<(u32, VmRegion)> {
    let store = regions_store_mut();
    let mut found: Option<(u32, VmRegion)> = None;
    store.for_each_live_ptr(|id, ptr| unsafe {
        let r = *ptr;
        if r.owner_pid == owner_pid
            && base_or_addr >= r.base
            && base_or_addr < r.base.saturating_add(r.size)
        {
            found = Some((id, r));
        }
    });
    found
}

pub(crate) fn vm_set_region_prot(id: u32, prot: u32) {
    let ptr = regions_store_mut().get_ptr(id);
    if !ptr.is_null() {
        unsafe {
            (*ptr).prot = prot;
        }
    }
}

pub(crate) fn vm_free_region(owner_pid: u32, base: u64) -> bool {
    let store = regions_store_mut();
    let mut id = 0u32;
    let mut region_base = 0u64;
    store.for_each_live_ptr(|cur_id, ptr| unsafe {
        if (*ptr).owner_pid == owner_pid && (*ptr).base == base {
            id = cur_id;
            region_base = (*ptr).base;
        }
    });
    if id == 0 {
        return false;
    }
    if region_base != 0 {
        crate::alloc::dealloc(region_base as *mut u8);
    }
    store.free(id)
}

pub(crate) fn file_alloc(owner_pid: u32, host_fd: u64) -> Option<u32> {
    files_store_mut().alloc_with(|_| GuestFile { owner_pid, host_fd })
}

pub(crate) fn file_host_fd(idx: u32) -> Option<u64> {
    let ptr = files_store_mut().get_ptr(idx);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { (*ptr).host_fd })
    }
}

pub(crate) fn file_free(idx: u32) {
    let store = files_store_mut();
    let ptr = store.get_ptr(idx);
    if ptr.is_null() {
        return;
    }
    unsafe {
        hypercall::host_close((*ptr).host_fd);
    }
    let _ = store.free(idx);
}

pub(crate) fn section_alloc(owner_pid: u32, size: u64, prot: u32, file_handle: u64) -> Option<u32> {
    sections_store_mut().alloc_with(|_| GuestSection {
        owner_pid,
        size,
        prot,
        file_handle,
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

    let mut region_ids = Vec::new();
    regions_store_mut().for_each_live_ptr(|id, ptr| unsafe {
        if (*ptr).owner_pid == owner_pid {
            let _ = region_ids.try_reserve(1);
            region_ids.push(id);
        }
    });
    for id in region_ids {
        let ptr = regions_store_mut().get_ptr(id);
        if !ptr.is_null() {
            unsafe {
                crate::alloc::dealloc((*ptr).base as *mut u8);
            }
        }
        let _ = regions_store_mut().free(id);
    }
}
