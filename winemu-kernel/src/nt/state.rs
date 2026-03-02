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
const MEM_FREE: u32 = 0x1_0000;
const MEM_PRIVATE_TYPE: u32 = 0x0002_0000;
const MEM_MAPPED_TYPE: u32 = 0x0004_0000;
const MEM_IMAGE_TYPE: u32 = 0x0100_0000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_GUARD: u32 = 0x100;
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
    pub(crate) alloc_attrs: u32,
    pub(crate) is_image: bool,
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
    pub(crate) section_is_image: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct VmQueryInfo {
    pub(crate) base: u64,
    pub(crate) size: u64,
    pub(crate) allocation_base: u64,
    pub(crate) allocation_prot: u32,
    pub(crate) prot: u32,
    pub(crate) state: u32,
    pub(crate) mem_type: u32,
}

#[derive(Clone, Copy)]
struct PhysPageRef {
    gpa: u64,
    refs: u32,
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
    regions: UnsafeCell<Option<ObjectStore<VmRegion>>>,
    page_refs: UnsafeCell<Option<ObjectStore<PhysPageRef>>>,
}

unsafe impl Sync for NtState {}

static NT_STATE: NtState = NtState {
    files: UnsafeCell::new(None),
    sections: UnsafeCell::new(None),
    views: UnsafeCell::new(None),
    regions: UnsafeCell::new(None),
    page_refs: UnsafeCell::new(None),
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

fn regions_store_mut() -> &'static mut ObjectStore<VmRegion> {
    unsafe {
        let slot = &mut *NT_STATE.regions.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn page_refs_store_mut() -> &'static mut ObjectStore<PhysPageRef> {
    unsafe {
        let slot = &mut *NT_STATE.page_refs.get();
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

pub(crate) fn vm_debug_find_region_any(addr: u64) -> Option<(u32, u64, u64, u8)> {
    let mut out = None;
    regions_store_mut().for_each_live_ptr(|_, ptr| unsafe {
        if out.is_some() {
            return;
        }
        let r = *ptr;
        if addr >= r.base && addr < r.base.saturating_add(r.size) {
            out = Some((r.owner_pid, r.base, r.size, r.kind));
        }
    });
    out
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
    let idx = ((page_va - region.base) / PAGE_SIZE_4K) as usize;
    if idx >= region.page_count {
        return false;
    }
    let ptr = regions_store_mut().get_ptr(id);
    if ptr.is_null() {
        return false;
    }
    let region_mut = unsafe { &mut *ptr };
    if !vm_region_page_committed(region_mut, idx) {
        return false;
    }
    // We emulate one-shot PAGE_GUARD in software:
    // keep the page committed, clear stage-1 mapping to force a fault once,
    // then clear PAGE_GUARD in the fault path and remap with normal protection.
    vm_unmap_page_only(region_mut.owner_pid, page_va);
    unsafe {
        let base_prot = vm_sanitize_nt_prot(*region_mut.prot_pages.add(idx)) & !PAGE_GUARD;
        *region_mut.prot_pages.add(idx) = base_prot | PAGE_GUARD;
    }
    true
}

pub(crate) fn vm_set_section_backing(
    owner_pid: u32,
    base: u64,
    file_fd: Option<u64>,
    file_offset: u64,
    view_size: u64,
    is_image: bool,
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
    region_mut.section_is_image = is_image;
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

    let region_mut = unsafe { &mut *ptr };
    let mut old_page_prots = Vec::new();
    if old_page_prots.try_reserve(page_count).is_err() {
        return Err(status::NO_MEMORY);
    }
    for i in 0..page_count {
        let idx = start_idx + i;
        if !vm_region_page_committed(region_mut, idx) {
            return Err(status::NOT_COMMITTED);
        }
        old_page_prots.push(unsafe { *region_mut.prot_pages.add(idx) });
    }
    let old = old_page_prots[0];

    for i in 0..page_count {
        let idx = start_idx + i;
        let prev = old_page_prots[i];
        if prev == prot {
            continue;
        }
        unsafe { *region_mut.prot_pages.add(idx) = prot };
        let gpa = unsafe { *region_mut.phys_pages.add(idx) };
        if gpa != 0 {
            let va = region_mut.base + (idx as u64) * PAGE_SIZE_4K;
            if !vm_apply_page_prot(owner_pid, va, prot) {
                // Roll back all pages already touched in this protect call.
                for rb in 0..=i {
                    let rb_idx = start_idx + rb;
                    let rollback_prot = old_page_prots[rb];
                    unsafe {
                        *region_mut.prot_pages.add(rb_idx) = rollback_prot;
                    }
                    let rb_gpa = unsafe { *region_mut.phys_pages.add(rb_idx) };
                    if rb_gpa != 0 {
                        let rb_va = region_mut.base + (rb_idx as u64) * PAGE_SIZE_4K;
                        let _ = vm_apply_page_prot(owner_pid, rb_va, rollback_prot);
                    }
                }
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
    let page_addr = addr & !(PAGE_SIZE_4K - 1);
    if page_addr < crate::process::USER_VA_BASE || page_addr >= crate::process::USER_VA_LIMIT {
        return None;
    }

    if let Some((_, region)) = vm_find_region(owner_pid, page_addr) {
        let idx = ((page_addr - region.base) / PAGE_SIZE_4K) as usize;
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
            if prev_committed != committed {
                break;
            }
            if committed {
                let prev_prot = unsafe { *region.prot_pages.add(prev) };
                if prev_prot != prot {
                    break;
                }
            }
            start = prev;
        }

        let mut end = idx + 1;
        while end < region.page_count {
            let next_committed = vm_region_page_committed(&region, end);
            if next_committed != committed {
                break;
            }
            if committed {
                let next_prot = unsafe { *region.prot_pages.add(end) };
                if next_prot != prot {
                    break;
                }
            }
            end += 1;
        }

        return Some(VmQueryInfo {
            base: region.base + (start as u64) * PAGE_SIZE_4K,
            size: ((end - start) as u64) * PAGE_SIZE_4K,
            allocation_base: region.base,
            allocation_prot: region.default_prot,
            prot: if committed { prot } else { 0 },
            state,
            mem_type: vm_region_mem_type(&region),
        });
    }

    let mut free_start = crate::process::USER_VA_BASE;
    let mut free_end = crate::process::USER_VA_LIMIT;
    regions_store_mut().for_each_live_ptr(|_, ptr| unsafe {
        let r = *ptr;
        if r.owner_pid != owner_pid {
            return;
        }
        let r_start = r.base;
        let r_end = r.base.saturating_add(r.size);
        if r_end <= page_addr && r_end > free_start {
            free_start = align_up_4k(r_end);
        }
        if r_start > page_addr && r_start < free_end {
            free_end = r_start;
        }
    });
    if free_end <= free_start || page_addr < free_start || page_addr >= free_end {
        return None;
    }

    Some(VmQueryInfo {
        base: free_start,
        size: free_end - free_start,
        allocation_base: 0,
        allocation_prot: 0,
        prot: 0,
        state: MEM_FREE,
        mem_type: 0,
    })
}

fn vm_update_current_thread_stack_limit(owner_pid: u32, new_limit: u64) {
    let tid = crate::sched::current_tid();
    if tid == 0 || !crate::sched::thread_exists(tid) {
        return;
    }
    let teb_va = crate::sched::with_thread(tid, |t| if t.pid == owner_pid { t.teb_va } else { 0 });
    if teb_va == 0 {
        return;
    }
    unsafe {
        ((teb_va + winemu_shared::teb::STACK_LIMIT as u64) as *mut u64).write_volatile(new_limit);
    }
}

fn vm_on_thread_stack_guard_hit(owner_pid: u32, region: &mut VmRegion, idx: usize, page_va: u64) {
    vm_update_current_thread_stack_limit(owner_pid, page_va);
    if idx == 0 {
        return;
    }
    let next_idx = idx - 1;
    if !vm_region_page_committed(region, next_idx) {
        return;
    }
    let next_va = region.base + (next_idx as u64) * PAGE_SIZE_4K;
    let next_prot = vm_sanitize_nt_prot(unsafe { *region.prot_pages.add(next_idx) }) & !PAGE_GUARD;
    unsafe {
        *region.prot_pages.add(next_idx) = next_prot | PAGE_GUARD;
    }
    // Force a one-shot fault when stack grows into the next page.
    vm_unmap_page_only(owner_pid, next_va);
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

    let ptr = regions_store_mut().get_ptr(id);
    if ptr.is_null() {
        return false;
    }
    let region_mut = unsafe { &mut *ptr };

    let mut prot = vm_sanitize_nt_prot(unsafe { *region_mut.prot_pages.add(idx) });
    let had_guard = (prot & PAGE_GUARD) != 0;
    if (prot & PAGE_GUARD) != 0 {
        prot &= !PAGE_GUARD;
        unsafe {
            *region_mut.prot_pages.add(idx) = prot;
        }
    }

    if access == VM_ACCESS_WRITE && vm_is_copy_on_write_prot(prot) {
        return vm_handle_cow_fault(owner_pid, region_mut, idx, page_va, prot);
    }
    if !vm_access_allowed(prot, access) {
        return false;
    }

    let gpa = unsafe { *region_mut.phys_pages.add(idx) };
    if gpa != 0 {
        let mapped = crate::process::with_process_mut(owner_pid, |p| {
            p.address_space
                .map_user_range(page_va, gpa, PAGE_SIZE_4K, prot)
        })
        .unwrap_or(false);
        if mapped && had_guard && region_mut.kind == VM_KIND_THREAD_STACK {
            vm_on_thread_stack_guard_hit(owner_pid, region_mut, idx, page_va);
        }
        return mapped;
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

    vm_phys_page_add_ref(new_gpa);
    unsafe {
        *region_mut.phys_pages.add(idx) = new_gpa;
    }
    if had_guard && region_mut.kind == VM_KIND_THREAD_STACK {
        vm_on_thread_stack_guard_hit(owner_pid, region_mut, idx, page_va);
    }
    true
}

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
        hypercall::host_close((*ptr).host_fd);
    }
    let _ = store.free(idx);
}

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
        section_is_image: false,
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
    vm_phys_page_add_ref(gpa);
    unsafe {
        *region.phys_pages.add(idx) = gpa;
    }
    true
}

fn vm_unmap_page_only(owner_pid: u32, va: u64) {
    let _ = crate::process::with_process_mut(owner_pid, |p| {
        p.address_space.unmap_user_range(va, PAGE_SIZE_4K)
    });
}

fn vm_unmap_free_page(owner_pid: u32, region: &VmRegion, idx: usize, va: u64) {
    if idx >= region.page_count {
        return;
    }
    let gpa = unsafe { *region.phys_pages.add(idx) };
    if gpa == 0 {
        return;
    }
    vm_unmap_page_only(owner_pid, va);
    vm_phys_page_release(gpa);
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
    if access == VM_ACCESS_WRITE && vm_is_copy_on_write_prot(prot) {
        return true;
    }
    let (read, write, exec) = vm_decode_nt_prot(prot);
    match access {
        VM_ACCESS_READ => read,
        VM_ACCESS_WRITE => write,
        VM_ACCESS_EXEC => exec,
        _ => false,
    }
}

fn vm_region_mem_type(region: &VmRegion) -> u32 {
    match region.kind {
        VM_KIND_SECTION => {
            if region.section_is_image {
                MEM_IMAGE_TYPE
            } else {
                MEM_MAPPED_TYPE
            }
        }
        _ => MEM_PRIVATE_TYPE,
    }
}

fn vm_is_copy_on_write_prot(prot: u32) -> bool {
    matches!(prot & 0xFF, PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)
}

fn vm_promote_cow_prot(prot: u32) -> u32 {
    match prot & 0xFF {
        PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY => (prot & !0xFF) | 0x04, // PAGE_READWRITE
        _ => prot,
    }
}

fn vm_handle_cow_fault(
    owner_pid: u32,
    region: &mut VmRegion,
    idx: usize,
    page_va: u64,
    prot: u32,
) -> bool {
    let old_gpa = unsafe { *region.phys_pages.add(idx) };
    let Some(new_gpa) = crate::mm::phys::alloc_pages(1) else {
        return false;
    };

    if old_gpa != 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(old_gpa as *const u8, new_gpa as *mut u8, PAGE_SIZE_4K as usize);
        }
    } else {
        unsafe {
            core::ptr::write_bytes(new_gpa as *mut u8, 0, PAGE_SIZE_4K as usize);
        }
        if region.kind == VM_KIND_SECTION && !vm_fill_section_page(region, idx, new_gpa) {
            crate::mm::phys::free_pages(new_gpa, 1);
            return false;
        }
    }

    let promoted_prot = vm_promote_cow_prot(prot);
    let mapped = crate::process::with_process_mut(owner_pid, |p| {
        p.address_space
            .map_user_range(page_va, new_gpa, PAGE_SIZE_4K, promoted_prot)
    })
    .unwrap_or(false);
    if !mapped {
        crate::mm::phys::free_pages(new_gpa, 1);
        return false;
    }
    vm_phys_page_add_ref(new_gpa);

    if old_gpa != 0 {
        vm_phys_page_release(old_gpa);
    }
    unsafe {
        *region.phys_pages.add(idx) = new_gpa;
        *region.prot_pages.add(idx) = promoted_prot;
    }
    true
}

fn vm_decode_nt_prot(prot: u32) -> (bool, bool, bool) {
    match prot & 0xFF {
        0x01 => (false, false, false),
        0x02 => (true, false, false),
        0x04 => (true, true, false),
        0x08 => (true, false, false),
        0x10 => (false, false, true),
        0x20 => (true, false, true),
        0x40 | 0x80 => (true, false, true),
        _ => (true, true, false),
    }
}

fn vm_sanitize_nt_prot(prot: u32) -> u32 {
    let base = prot & 0xFF;
    let sanitized_base = match base {
        PAGE_EXECUTE_READWRITE => PAGE_EXECUTE_READ,
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

fn vm_phys_page_add_ref(gpa: u64) {
    if gpa == 0 {
        return;
    }
    let store = page_refs_store_mut();
    let mut found = 0u32;
    store.for_each_live_ptr(|id, ptr| unsafe {
        if (*ptr).gpa == gpa {
            found = id;
        }
    });
    if found != 0 {
        let ptr = store.get_ptr(found);
        if !ptr.is_null() {
            unsafe {
                (*ptr).refs = (*ptr).refs.saturating_add(1);
            }
        }
        return;
    }
    let _ = store.alloc_with(|_| PhysPageRef { gpa, refs: 1 });
}

fn vm_phys_page_release(gpa: u64) {
    if gpa == 0 {
        return;
    }
    let store = page_refs_store_mut();
    let mut found = 0u32;
    let mut refs = 0u32;
    store.for_each_live_ptr(|id, ptr| unsafe {
        if (*ptr).gpa == gpa {
            found = id;
            refs = (*ptr).refs;
        }
    });

    if found == 0 {
        crate::mm::phys::free_pages(gpa, 1);
        return;
    }

    if refs > 1 {
        let ptr = store.get_ptr(found);
        if !ptr.is_null() {
            unsafe {
                (*ptr).refs = refs - 1;
            }
        }
        return;
    }

    let _ = store.free(found);
    crate::mm::phys::free_pages(gpa, 1);
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
