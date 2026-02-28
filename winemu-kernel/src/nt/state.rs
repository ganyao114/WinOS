use crate::hypercall;
use crate::kobj::ObjectStore;
use crate::mm::vaspace::VmaType;
use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::{align_of, size_of};

use super::common::align_up_4k;
use super::constants::PAGE_SIZE_4K;
use winemu_shared::status;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

const VM_KIND_PRIVATE: u8 = 1;
const VM_KIND_SECTION: u8 = 2;
const VM_KIND_THREAD_STACK: u8 = 3;
const VM_KIND_OTHER: u8 = 4;

pub(crate) const VM_ACCESS_READ: u8 = 1;
pub(crate) const VM_ACCESS_WRITE: u8 = 2;
pub(crate) const VM_ACCESS_EXEC: u8 = 3;

#[derive(Clone, Copy)]
pub(crate) struct GuestSection {
    pub(crate) owner_pid: u32,
    pub(crate) size: u64,
    pub(crate) prot: u32,
    pub(crate) file_fd: u64,
    pub(crate) file_backed: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct VmRegion {
    pub(crate) owner_pid: u32,
    pub(crate) base: u64,
    pub(crate) size: u64,
    pub(crate) default_prot: u32,
    pub(crate) kind: u8,
    pub(crate) page_count: usize,
    pub(crate) phys_pages: *mut u64,  // per-page GPA; 0 => not mapped
    pub(crate) prot_pages: *mut u32,  // per-page NT protection
    pub(crate) commit_bits: *mut u64, // bit=1 => committed
    pub(crate) commit_words: usize,
    pub(crate) section_file_fd: u64,
    pub(crate) section_file_offset: u64,
    pub(crate) section_view_size: u64,
    pub(crate) section_file_backed: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct VmQueryInfo {
    pub(crate) base: u64,
    pub(crate) size: u64,
    pub(crate) prot: u32,
    pub(crate) state: u32,
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
    vma_type: VmaType,
) -> Option<u64> {
    let size = align_up_4k(size.max(PAGE_SIZE_4K));
    let prot = vm_sanitize_nt_prot(prot);
    let base = vm_find_free_base(owner_pid, hint, size)?;
    let kind = vm_kind_from_vma_type(vma_type);
    let Some(id) = vm_create_region(owner_pid, base, size, prot, kind) else {
        return None;
    };
    let eager_map = kind != VM_KIND_SECTION && kind != VM_KIND_THREAD_STACK;
    if !vm_commit_region_pages(owner_pid, id, base, size, prot, eager_map) {
        let _ = vm_release_region_by_id(id);
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
    if ptr.is_null() {
        return false;
    }

    let prot = vm_sanitize_nt_prot(prot);
    let region = unsafe { &mut *ptr };
    region.default_prot = prot;
    unsafe {
        for i in 0..region.page_count {
            *region.prot_pages.add(i) = prot;
            if *region.phys_pages.add(i) != 0 {
                let va = region.base + (i as u64) * PAGE_SIZE_4K;
                if !vm_apply_page_prot(region.owner_pid, va, prot) {
                    return false;
                }
            }
        }
    }
    true
}

pub(crate) fn vm_make_guard_page(owner_pid: u32, page_va: u64) -> bool {
    let page_va = page_va & !(PAGE_SIZE_4K - 1);
    let Some((id, region)) = vm_find_region(owner_pid, page_va) else {
        return false;
    };
    if !vm_range_within_region(&region, page_va, PAGE_SIZE_4K) {
        return false;
    }
    if !vm_decommit_region_pages(id, page_va, PAGE_SIZE_4K) {
        return false;
    }
    let ptr = regions_store_mut().get_ptr(id);
    if ptr.is_null() {
        return false;
    }
    let region_mut = unsafe { &mut *ptr };
    let idx = ((page_va - region_mut.base) / PAGE_SIZE_4K) as usize;
    if idx >= region_mut.page_count {
        return false;
    }
    unsafe {
        *region_mut.prot_pages.add(idx) = PAGE_NOACCESS;
    }
    true
}

pub(crate) fn vm_set_section_backing(
    owner_pid: u32,
    base: u64,
    file_fd: Option<u64>,
    file_offset: u64,
    view_size: u64,
) -> bool {
    let Some((id, region)) = vm_find_region_by_base(owner_pid, base) else {
        return false;
    };
    if region.kind != VM_KIND_SECTION {
        return false;
    }
    let ptr = regions_store_mut().get_ptr(id);
    if ptr.is_null() {
        return false;
    }
    let region_mut = unsafe { &mut *ptr };
    region_mut.section_file_backed = file_fd.is_some();
    region_mut.section_file_fd = file_fd.unwrap_or(0);
    region_mut.section_file_offset = file_offset;
    region_mut.section_view_size = view_size.min(region_mut.size);
    true
}

pub(crate) fn vm_free_region(owner_pid: u32, base: u64) -> bool {
    let Some((id, _)) = vm_find_region_by_base(owner_pid, base) else {
        return false;
    };
    vm_release_region_by_id(id)
}

pub(crate) fn vm_reserve_private(
    owner_pid: u32,
    hint: u64,
    size: u64,
    prot: u32,
) -> Result<u64, u32> {
    let size = align_up_4k(size.max(PAGE_SIZE_4K));
    let prot = vm_sanitize_nt_prot(prot);
    let Some(base) = vm_find_free_base(owner_pid, hint, size) else {
        return Err(status::NO_MEMORY);
    };
    let Some(_id) = vm_create_region(owner_pid, base, size, prot, VM_KIND_PRIVATE) else {
        return Err(status::NO_MEMORY);
    };
    Ok(base)
}

pub(crate) fn vm_commit_private(owner_pid: u32, base: u64, size: u64, prot: u32) -> u32 {
    let size = align_up_4k(size.max(PAGE_SIZE_4K));
    let prot = vm_sanitize_nt_prot(prot);
    let Some((id, region)) = vm_find_region(owner_pid, base) else {
        return status::INVALID_PARAMETER;
    };
    if region.kind != VM_KIND_PRIVATE {
        return status::INVALID_PARAMETER;
    }
    if !vm_range_within_region(&region, base, size) {
        return status::INVALID_PARAMETER;
    }
    if vm_commit_region_pages(owner_pid, id, base, size, prot, false) {
        status::SUCCESS
    } else {
        status::NO_MEMORY
    }
}

pub(crate) fn vm_decommit_private(owner_pid: u32, base: u64, size: u64) -> u32 {
    let size = align_up_4k(size.max(PAGE_SIZE_4K));
    let Some((id, region)) = vm_find_region(owner_pid, base) else {
        return status::INVALID_PARAMETER;
    };
    if region.kind != VM_KIND_PRIVATE {
        return status::INVALID_PARAMETER;
    }
    if !vm_range_within_region(&region, base, size) {
        return status::INVALID_PARAMETER;
    }
    if vm_decommit_region_pages(id, base, size) {
        status::SUCCESS
    } else {
        status::INVALID_PARAMETER
    }
}

pub(crate) fn vm_release_private(owner_pid: u32, base: u64) -> u32 {
    let Some((id, region)) = vm_find_region_by_base(owner_pid, base) else {
        return status::INVALID_PARAMETER;
    };
    if region.kind != VM_KIND_PRIVATE {
        return status::INVALID_PARAMETER;
    }
    if vm_release_region_by_id(id) {
        status::SUCCESS
    } else {
        status::INVALID_PARAMETER
    }
}

pub(crate) fn vm_protect_range(
    owner_pid: u32,
    base: u64,
    size: u64,
    prot: u32,
) -> Result<u32, u32> {
    let size = align_up_4k(size.max(PAGE_SIZE_4K));
    let prot = vm_sanitize_nt_prot(prot);
    let Some((id, region)) = vm_find_region(owner_pid, base) else {
        return Err(status::INVALID_PARAMETER);
    };
    if !vm_range_within_region(&region, base, size) {
        return Err(status::INVALID_PARAMETER);
    }

    let start_idx = ((base - region.base) / PAGE_SIZE_4K) as usize;
    let page_count = (size / PAGE_SIZE_4K) as usize;
    let ptr = regions_store_mut().get_ptr(id);
    if ptr.is_null() {
        return Err(status::INVALID_PARAMETER);
    }

    let old = unsafe { *(*ptr).prot_pages.add(start_idx) };
    let region_mut = unsafe { &mut *ptr };
    for i in 0..page_count {
        let idx = start_idx + i;
        unsafe { *region_mut.prot_pages.add(idx) = prot };
        let gpa = unsafe { *region_mut.phys_pages.add(idx) };
        if gpa != 0 {
            let va = region_mut.base + (idx as u64) * PAGE_SIZE_4K;
            if !vm_apply_page_prot(owner_pid, va, prot) {
                return Err(status::INVALID_PARAMETER);
            }
        }
    }
    if start_idx == 0 && page_count == region_mut.page_count {
        region_mut.default_prot = prot;
    }
    Ok(old)
}

pub(crate) fn vm_query_region(owner_pid: u32, addr: u64) -> Option<VmQueryInfo> {
    let (_, region) = vm_find_region(owner_pid, addr)?;
    let idx = ((addr - region.base) / PAGE_SIZE_4K) as usize;
    if idx >= region.page_count {
        return None;
    }

    let committed = vm_region_page_committed(&region, idx);
    let prot = unsafe { *region.prot_pages.add(idx) };
    let state = if committed { MEM_COMMIT } else { MEM_RESERVE };

    let mut start = idx;
    while start > 0 {
        let prev = start - 1;
        let prev_committed = vm_region_page_committed(&region, prev);
        let prev_prot = unsafe { *region.prot_pages.add(prev) };
        if prev_committed != committed || prev_prot != prot {
            break;
        }
        start = prev;
    }

    let mut end = idx + 1;
    while end < region.page_count {
        let next_committed = vm_region_page_committed(&region, end);
        let next_prot = unsafe { *region.prot_pages.add(end) };
        if next_committed != committed || next_prot != prot {
            break;
        }
        end += 1;
    }

    Some(VmQueryInfo {
        base: region.base + (start as u64) * PAGE_SIZE_4K,
        size: ((end - start) as u64) * PAGE_SIZE_4K,
        prot: if committed { prot } else { 0 },
        state,
    })
}

pub(crate) fn vm_handle_page_fault(owner_pid: u32, fault_addr: u64, access: u8) -> bool {
    let page_va = fault_addr & !(PAGE_SIZE_4K - 1);
    let Some((id, region)) = vm_find_region(owner_pid, page_va) else {
        return false;
    };
    let idx = ((page_va - region.base) / PAGE_SIZE_4K) as usize;
    if idx >= region.page_count {
        return false;
    }
    if !vm_region_page_committed(&region, idx) {
        return false;
    }

    let prot = vm_sanitize_nt_prot(unsafe { *region.prot_pages.add(idx) });
    if !vm_access_allowed(prot, access) {
        return false;
    }

    let ptr = regions_store_mut().get_ptr(id);
    if ptr.is_null() {
        return false;
    }
    let region_mut = unsafe { &mut *ptr };
    let gpa = unsafe { *region_mut.phys_pages.add(idx) };
    if gpa != 0 {
        return crate::process::with_process_mut(owner_pid, |p| {
            p.address_space
                .map_user_range(page_va, gpa, PAGE_SIZE_4K, prot)
        })
        .unwrap_or(false);
    }

    let Some(new_gpa) = crate::mm::phys::alloc_pages(1) else {
        return false;
    };
    unsafe {
        core::ptr::write_bytes(new_gpa as *mut u8, 0, PAGE_SIZE_4K as usize);
    }
    if region_mut.kind == VM_KIND_SECTION && !vm_fill_section_page(region_mut, idx, new_gpa) {
        crate::mm::phys::free_pages(new_gpa, 1);
        return false;
    }
    let mapped = crate::process::with_process_mut(owner_pid, |p| {
        p.address_space
            .map_user_range(page_va, new_gpa, PAGE_SIZE_4K, prot)
    })
    .unwrap_or(false);
    if !mapped {
        crate::mm::phys::free_pages(new_gpa, 1);
        return false;
    }

    unsafe {
        *region_mut.phys_pages.add(idx) = new_gpa;
    }
    true
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

pub(crate) fn section_alloc(
    owner_pid: u32,
    size: u64,
    prot: u32,
    file_fd: Option<u64>,
) -> Option<u32> {
    sections_store_mut().alloc_with(|_| GuestSection {
        owner_pid,
        size,
        prot: vm_sanitize_nt_prot(prot),
        file_fd: file_fd.unwrap_or(0),
        file_backed: file_fd.is_some(),
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
        let _ = vm_release_region_by_id(id);
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

fn vm_kind_from_vma_type(vma_type: VmaType) -> u8 {
    match vma_type {
        VmaType::Private => VM_KIND_PRIVATE,
        VmaType::Section | VmaType::FileMapped => VM_KIND_SECTION,
        VmaType::ThreadStack => VM_KIND_THREAD_STACK,
        _ => VM_KIND_OTHER,
    }
}

fn vm_find_region_by_base(owner_pid: u32, base: u64) -> Option<(u32, VmRegion)> {
    let mut out = None;
    regions_store_mut().for_each_live_ptr(|id, ptr| unsafe {
        let r = *ptr;
        if r.owner_pid == owner_pid && r.base == base {
            out = Some((id, r));
        }
    });
    out
}

fn vm_create_region(owner_pid: u32, base: u64, size: u64, prot: u32, kind: u8) -> Option<u32> {
    let page_count = (size / PAGE_SIZE_4K) as usize;
    if page_count == 0 {
        return None;
    }
    let prot = vm_sanitize_nt_prot(prot);
    let phys_pages = vm_alloc_zeroed_array::<u64>(page_count)?;
    let prot_pages = match vm_alloc_zeroed_array::<u32>(page_count) {
        Some(v) => v,
        None => {
            vm_free_array(phys_pages as *mut u8);
            return None;
        }
    };
    let commit_words = (page_count + 63) / 64;
    let commit_bits = match vm_alloc_zeroed_array::<u64>(commit_words.max(1)) {
        Some(v) => v,
        None => {
            vm_free_array(prot_pages as *mut u8);
            vm_free_array(phys_pages as *mut u8);
            return None;
        }
    };

    unsafe {
        for i in 0..page_count {
            *prot_pages.add(i) = prot;
        }
    }

    let id = regions_store_mut().alloc_with(|_| VmRegion {
        owner_pid,
        base,
        size,
        default_prot: prot,
        kind,
        page_count,
        phys_pages,
        prot_pages,
        commit_bits,
        commit_words: commit_words.max(1),
        section_file_fd: 0,
        section_file_offset: 0,
        section_view_size: 0,
        section_file_backed: false,
    });

    if id.is_none() {
        vm_free_array(commit_bits as *mut u8);
        vm_free_array(prot_pages as *mut u8);
        vm_free_array(phys_pages as *mut u8);
    }
    id
}

fn vm_release_region_by_id(id: u32) -> bool {
    let store = regions_store_mut();
    let ptr = store.get_ptr(id);
    if ptr.is_null() {
        return false;
    }
    let region = unsafe { *ptr };
    vm_release_region(region);
    store.free(id)
}

fn vm_release_region(region: VmRegion) {
    for i in 0..region.page_count {
        let va = region.base + (i as u64) * PAGE_SIZE_4K;
        vm_unmap_free_page(region.owner_pid, &region, i, va);
    }
    vm_free_array(region.commit_bits as *mut u8);
    vm_free_array(region.prot_pages as *mut u8);
    vm_free_array(region.phys_pages as *mut u8);
}

fn vm_commit_region_pages(
    owner_pid: u32,
    id: u32,
    base: u64,
    size: u64,
    prot: u32,
    eager_map: bool,
) -> bool {
    let ptr = regions_store_mut().get_ptr(id);
    if ptr.is_null() {
        return false;
    }
    let region = unsafe { &mut *ptr };
    if !vm_range_within_region(region, base, size) {
        return false;
    }

    let prot = vm_sanitize_nt_prot(prot);
    let start_idx = ((base - region.base) / PAGE_SIZE_4K) as usize;
    let page_count = (size / PAGE_SIZE_4K) as usize;
    for i in 0..page_count {
        let idx = start_idx + i;
        unsafe { *region.prot_pages.add(idx) = prot };
        vm_set_region_page_committed(region, idx, true);

        if eager_map {
            let va = region.base + (idx as u64) * PAGE_SIZE_4K;
            let gpa = unsafe { *region.phys_pages.add(idx) };
            if gpa == 0 {
                if !vm_map_new_page(owner_pid, region, idx, va, prot) {
                    for rb in start_idx..=idx {
                        let rb_va = region.base + (rb as u64) * PAGE_SIZE_4K;
                        vm_unmap_free_page(owner_pid, region, rb, rb_va);
                        vm_set_region_page_committed(region, rb, false);
                    }
                    return false;
                }
            } else if !vm_apply_page_prot(owner_pid, va, prot) {
                return false;
            }
        }
    }
    if start_idx == 0 && page_count == region.page_count {
        region.default_prot = prot;
    }
    true
}

fn vm_decommit_region_pages(id: u32, base: u64, size: u64) -> bool {
    let ptr = regions_store_mut().get_ptr(id);
    if ptr.is_null() {
        return false;
    }
    let region = unsafe { &mut *ptr };
    if !vm_range_within_region(region, base, size) {
        return false;
    }

    let start_idx = ((base - region.base) / PAGE_SIZE_4K) as usize;
    let page_count = (size / PAGE_SIZE_4K) as usize;
    for i in 0..page_count {
        let idx = start_idx + i;
        let va = region.base + (idx as u64) * PAGE_SIZE_4K;
        vm_unmap_free_page(region.owner_pid, region, idx, va);
        vm_set_region_page_committed(region, idx, false);
    }
    true
}

fn vm_map_new_page(owner_pid: u32, region: &mut VmRegion, idx: usize, va: u64, prot: u32) -> bool {
    let prot = vm_sanitize_nt_prot(prot);
    let Some(gpa) = crate::mm::phys::alloc_pages(1) else {
        return false;
    };
    unsafe {
        core::ptr::write_bytes(gpa as *mut u8, 0, PAGE_SIZE_4K as usize);
    }
    let mapped = crate::process::with_process_mut(owner_pid, |p| {
        p.address_space.map_user_range(va, gpa, PAGE_SIZE_4K, prot)
    })
    .unwrap_or(false);
    if !mapped {
        crate::mm::phys::free_pages(gpa, 1);
        return false;
    }
    unsafe {
        *region.phys_pages.add(idx) = gpa;
    }
    true
}

fn vm_unmap_free_page(owner_pid: u32, region: &VmRegion, idx: usize, va: u64) {
    if idx >= region.page_count {
        return;
    }
    let gpa = unsafe { *region.phys_pages.add(idx) };
    if gpa == 0 {
        return;
    }
    let _ = crate::process::with_process_mut(owner_pid, |p| {
        p.address_space.unmap_user_range(va, PAGE_SIZE_4K)
    });
    crate::mm::phys::free_pages(gpa, 1);
    unsafe {
        *(region.phys_pages.add(idx)) = 0;
    }
}

fn vm_apply_page_prot(owner_pid: u32, va: u64, prot: u32) -> bool {
    let prot = vm_sanitize_nt_prot(prot);
    crate::process::with_process_mut(owner_pid, |p| {
        p.address_space.protect_user_range(va, PAGE_SIZE_4K, prot)
    })
    .unwrap_or(false)
}

fn vm_region_page_committed(region: &VmRegion, idx: usize) -> bool {
    if idx >= region.page_count {
        return false;
    }
    let word = idx / 64;
    let bit = idx % 64;
    if word >= region.commit_words {
        return false;
    }
    unsafe { (*region.commit_bits.add(word) & (1u64 << bit)) != 0 }
}

fn vm_set_region_page_committed(region: &mut VmRegion, idx: usize, committed: bool) {
    if idx >= region.page_count {
        return;
    }
    let word = idx / 64;
    let bit = idx % 64;
    if word >= region.commit_words {
        return;
    }
    unsafe {
        let slot = region.commit_bits.add(word);
        if committed {
            *slot |= 1u64 << bit;
        } else {
            *slot &= !(1u64 << bit);
        }
    }
}

fn vm_range_within_region(region: &VmRegion, base: u64, size: u64) -> bool {
    let Some(end) = base.checked_add(size) else {
        return false;
    };
    base >= region.base && end <= region.base.saturating_add(region.size)
}

fn vm_access_allowed(prot: u32, access: u8) -> bool {
    let (read, write, exec) = vm_decode_nt_prot(prot);
    match access {
        VM_ACCESS_READ => read,
        VM_ACCESS_WRITE => write,
        VM_ACCESS_EXEC => exec,
        _ => false,
    }
}

fn vm_decode_nt_prot(prot: u32) -> (bool, bool, bool) {
    match prot & 0xFF {
        0x01 => (false, false, false),
        0x02 => (true, false, false),
        0x04 | 0x08 => (true, true, false),
        0x10 => (false, false, true),
        0x20 => (true, false, true),
        0x40 | 0x80 => (true, false, true),
        _ => (true, true, false),
    }
}

fn vm_sanitize_nt_prot(prot: u32) -> u32 {
    let base = prot & 0xFF;
    let sanitized_base = match base {
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => PAGE_EXECUTE_READ,
        0 => 0x04,
        _ => base,
    };
    (prot & !0xFF) | sanitized_base
}

fn vm_fill_section_page(region: &VmRegion, idx: usize, gpa: u64) -> bool {
    if !region.section_file_backed {
        return true;
    }
    let page_off = (idx as u64) * PAGE_SIZE_4K;
    if page_off >= region.section_view_size {
        return true;
    }
    let remain = region.section_view_size - page_off;
    let read_len = core::cmp::min(PAGE_SIZE_4K, remain) as usize;
    let file_off = region.section_file_offset.saturating_add(page_off);
    let read = hypercall::host_read(region.section_file_fd, gpa as *mut u8, read_len, file_off);
    if read < read_len {
        unsafe {
            core::ptr::write_bytes((gpa as *mut u8).add(read), 0, read_len - read);
        }
    }
    true
}

fn vm_alloc_zeroed_array<T>(count: usize) -> Option<*mut T> {
    if count == 0 {
        return None;
    }
    let bytes = count.checked_mul(size_of::<T>())?;
    crate::alloc::alloc_zeroed(bytes, align_of::<T>()).map(|p| p as *mut T)
}

fn vm_free_array(ptr: *mut u8) {
    if !ptr.is_null() {
        crate::alloc::dealloc(ptr);
    }
}
