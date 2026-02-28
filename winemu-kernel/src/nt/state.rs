use crate::hypercall;
use crate::kobj::ObjectStore;
use crate::mm::vaspace::VmaType;
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
    pub(crate) phys_base: u64,
    pub(crate) page_count: usize,
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
    vm_alloc_region_typed(owner_pid, 0, size, prot, VmaType::Private)
}

pub(crate) fn vm_alloc_region_typed(
    owner_pid: u32,
    hint: u64,
    size: u64,
    prot: u32,
    _vma_type: VmaType,
) -> Option<u64> {
    let size = align_up_4k(size.max(PAGE_SIZE_4K));
    let page_count = (size / PAGE_SIZE_4K) as usize;
    if page_count == 0 {
        return None;
    }

    let base = vm_find_free_base(owner_pid, hint, size)?;

    let phys_base = match crate::mm::phys::alloc_pages(page_count) {
        Some(v) => v,
        None => return None,
    };

    let mapped = crate::process::with_process_mut(owner_pid, |p| {
        p.address_space.map_user_range(base, phys_base, size, prot)
    })
    .unwrap_or(false);
    if !mapped {
        crate::mm::phys::free_pages(phys_base, page_count);
        return None;
    }

    let id = regions_store_mut().alloc_with(|_| VmRegion {
        owner_pid,
        base,
        size,
        prot,
        phys_base,
        page_count,
    })?;

    if id == 0 {
        release_vm_region(owner_pid, base, size, phys_base, page_count);
        return None;
    }

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

pub(crate) fn vm_set_region_prot(id: u32, prot: u32) -> bool {
    let ptr = regions_store_mut().get_ptr(id);
    if !ptr.is_null() {
        let (owner_pid, base, size) = unsafe { ((*ptr).owner_pid, (*ptr).base, (*ptr).size) };
        let ok = crate::process::with_process_mut(owner_pid, |p| {
            p.address_space.protect_user_range(base, size, prot)
        })
        .unwrap_or(false);
        if !ok {
            return false;
        }
        unsafe {
            (*ptr).prot = prot;
        }
        return true;
    }
    false
}

pub(crate) fn vm_free_region(owner_pid: u32, base: u64) -> bool {
    let store = regions_store_mut();
    let mut id = 0u32;
    let mut region = None;
    store.for_each_live_ptr(|cur_id, ptr| unsafe {
        if (*ptr).owner_pid == owner_pid && (*ptr).base == base {
            id = cur_id;
            region = Some(*ptr);
        }
    });
    if id == 0 {
        return false;
    }
    if let Some(r) = region {
        release_vm_region(r.owner_pid, r.base, r.size, r.phys_base, r.page_count);
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
        let region = {
            let ptr = regions_store_mut().get_ptr(id);
            if ptr.is_null() {
                None
            } else {
                Some(unsafe { *ptr })
            }
        };
        if let Some(r) = region {
            release_vm_region(r.owner_pid, r.base, r.size, r.phys_base, r.page_count);
        }
        let _ = regions_store_mut().free(id);
    }
}

fn release_vm_region(owner_pid: u32, base: u64, size: u64, phys_base: u64, page_count: usize) {
    let _ = crate::process::with_process_mut(owner_pid, |p| {
        let _ = p.address_space.unmap_user_range(base, size);
    });
    if phys_base != 0 && page_count != 0 {
        crate::mm::phys::free_pages(phys_base, page_count);
    }
}

fn vm_find_free_base(owner_pid: u32, hint: u64, size: u64) -> Option<u64> {
    if hint != 0 {
        let base = hint & !(PAGE_SIZE_4K - 1);
        if !vm_range_valid(base, size) || vm_region_overlaps(owner_pid, base, size) {
            return None;
        }
        return Some(base);
    }

    let mut cursor = crate::process::USER_VA_BASE;
    loop {
        if !vm_range_valid(cursor, size) {
            return None;
        }

        let mut overlapped = false;
        let mut next_cursor = cursor;
        regions_store_mut().for_each_live_ptr(|_, ptr| unsafe {
            let r = *ptr;
            if r.owner_pid != owner_pid {
                return;
            }
            let r_end = r.base.saturating_add(r.size);
            let req_end = cursor.saturating_add(size);
            if cursor < r_end && req_end > r.base {
                overlapped = true;
                if r_end > next_cursor {
                    next_cursor = align_up_4k(r_end);
                }
            }
        });

        if !overlapped {
            return Some(cursor);
        }
        if next_cursor <= cursor {
            return None;
        }
        cursor = next_cursor;
    }
}

fn vm_region_overlaps(owner_pid: u32, base: u64, size: u64) -> bool {
    let req_end = base.saturating_add(size);
    let mut overlaps = false;
    regions_store_mut().for_each_live_ptr(|_, ptr| unsafe {
        if overlaps {
            return;
        }
        let r = *ptr;
        if r.owner_pid != owner_pid {
            return;
        }
        let r_end = r.base.saturating_add(r.size);
        if base < r_end && req_end > r.base {
            overlaps = true;
        }
    });
    overlaps
}

fn vm_range_valid(base: u64, size: u64) -> bool {
    if size == 0 || (base & (PAGE_SIZE_4K - 1)) != 0 || (size & (PAGE_SIZE_4K - 1)) != 0 {
        return false;
    }
    if base < crate::process::USER_VA_BASE || base >= crate::process::USER_VA_LIMIT {
        return false;
    }
    let Some(end) = base.checked_add(size) else {
        return false;
    };
    end <= crate::process::USER_VA_LIMIT
}
