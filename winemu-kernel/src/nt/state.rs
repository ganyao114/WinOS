use crate::hypercall;
use crate::kobj::ObjectStore;
use core::cell::UnsafeCell;

use super::common::align_up_4k;

#[derive(Clone, Copy)]
pub(crate) struct GuestSection {
    pub(crate) size: u64,
    pub(crate) prot: u32,
    pub(crate) file_handle: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct VmRegion {
    pub(crate) base: u64,
    pub(crate) size: u64,
    pub(crate) prot: u32,
}

#[derive(Clone, Copy)]
struct GuestFile {
    host_fd: u64,
}

#[derive(Clone, Copy)]
struct GuestView {
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

pub(crate) fn vm_alloc_region(size: u64, prot: u32) -> Option<u64> {
    let size = align_up_4k(size.max(0x1000));
    let base = crate::alloc::alloc_zeroed(size as usize, 0x1000).map(|p| p as u64)?;
    let id = regions_store_mut().alloc_with(|_| VmRegion { base, size, prot })?;
    let _ = id;
    Some(base)
}

pub(crate) fn vm_find_region(base_or_addr: u64) -> Option<(u32, VmRegion)> {
    let store = regions_store_mut();
    let mut found: Option<(u32, VmRegion)> = None;
    store.for_each_live_ptr(|id, ptr| unsafe {
        let r = *ptr;
        if base_or_addr >= r.base && base_or_addr < r.base.saturating_add(r.size) {
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

pub(crate) fn vm_free_region(base: u64) -> bool {
    let store = regions_store_mut();
    let mut id = 0u32;
    store.for_each_live_ptr(|cur_id, ptr| unsafe {
        if (*ptr).base == base {
            id = cur_id;
        }
    });
    if id == 0 {
        return false;
    }
    store.free(id)
}

pub(crate) fn file_alloc(host_fd: u64) -> Option<u32> {
    files_store_mut().alloc_with(|_| GuestFile { host_fd })
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

pub(crate) fn section_alloc(size: u64, prot: u32, file_handle: u64) -> Option<u32> {
    sections_store_mut().alloc_with(|_| GuestSection {
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

pub(crate) fn view_alloc(base: u64, size: u64) -> bool {
    views_store_mut()
        .alloc_with(|_| GuestView { base, size })
        .is_some()
}

pub(crate) fn view_free(base: u64) -> bool {
    let store = views_store_mut();
    let mut id = 0u32;
    store.for_each_live_ptr(|cur_id, ptr| unsafe {
        if (*ptr).base == base {
            id = cur_id;
        }
    });
    if id == 0 {
        return false;
    }
    store.free(id)
}

pub(crate) fn duplicate_handle(src: u64) -> u64 {
    src
}
