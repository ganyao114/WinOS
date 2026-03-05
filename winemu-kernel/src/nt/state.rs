use crate::hypercall;
use crate::kobj::ObjectStore;
use crate::mm::vaspace::{vm_kind_from_vma_type, vm_sanitize_nt_prot, VmaType};
use crate::mm::vm_area::VmKind;
use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;

use super::common::HOST_PSEUDO_FD_WINEMU_HOST;
use super::constants::PAGE_SIZE_4K;
use winemu_shared::status;

pub(crate) const VM_ACCESS_READ: u8 = 1;
pub(crate) const VM_ACCESS_WRITE: u8 = 2;
pub(crate) const VM_ACCESS_EXEC: u8 = 3;
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
    page_refs: UnsafeCell<Option<ObjectStore<PhysPageRef>>>,
}

unsafe impl Sync for NtState {}

static NT_STATE: NtState = NtState {
    files: UnsafeCell::new(None),
    sections: UnsafeCell::new(None),
    views: UnsafeCell::new(None),
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

fn page_refs_store_mut() -> &'static mut ObjectStore<PhysPageRef> {
    unsafe {
        let slot = &mut *NT_STATE.page_refs.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

// ─── 物理页引用计数（供 mm::vaspace 调用）────────────────────────────────────

pub(crate) fn vm_phys_page_add_ref(gpa: u64) {
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

pub(crate) fn vm_phys_page_release(gpa: u64) {
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

// ─── 线程栈 limit 更新（供 mm::vaspace 调用）─────────────────────────────────

pub(crate) fn vm_update_current_thread_stack_limit(owner_pid: u32, new_limit: u64) {
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

// ─── VM 公共接口（thin wrappers → p.vm.*）────────────────────────────────────

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
    let size = super::common::align_up_4k(size.max(PAGE_SIZE_4K));
    let prot = vm_sanitize_nt_prot(prot);
    let kind = vm_kind_from_vma_type(vma_type);
    let eager = kind != VmKind::Section && kind != VmKind::ThreadStack;

    crate::process::with_process_mut(owner_pid, |p| {
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        let base = vm.find_and_reserve(hint, size, prot, kind)?;
        if vm.commit_pages(aspace, owner_pid, base, size, prot, eager) {
            Some(base)
        } else {
            let _ = vm.release_region(aspace, owner_pid, base);
            None
        }
    })
    .flatten()
}

pub(crate) fn vm_debug_find_region_any(addr: u64) -> Option<(u32, u64, u64, u8)> {
    let mut out = None;
    crate::process::for_each_process(|pid, p| {
        if out.is_some() {
            return;
        }
        let seg = p.vm.find_seg_at(addr);
        if seg.ok() {
            let r = seg.range();
            let kind_byte: u8 = match seg.value().kind {
                VmKind::Private => 1,
                VmKind::Section => 2,
                VmKind::ThreadStack => 3,
                VmKind::Other => 4,
            };
            out = Some((pid, r.start, r.len, kind_byte));
        }
    });
    out
}

pub(crate) fn vm_make_guard_page(owner_pid: u32, page_va: u64) -> bool {
    crate::process::with_process_mut(owner_pid, |p| {
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.make_guard_page(aspace, owner_pid, page_va)
    })
    .unwrap_or(false)
}

pub(crate) fn vm_set_section_backing(
    owner_pid: u32,
    base: u64,
    file_fd: Option<u64>,
    file_offset: u64,
    view_size: u64,
    is_image: bool,
) -> bool {
    crate::process::with_process_mut(owner_pid, |p| {
        p.vm.set_section_backing(base, file_fd, file_offset, view_size, is_image)
    })
    .unwrap_or(false)
}

pub(crate) fn vm_track_existing_file_mapping(
    owner_pid: u32,
    base: u64,
    size: u64,
    prot: u32,
) -> bool {
    if owner_pid == 0 {
        return false;
    }
    let size = super::common::align_up_4k(size.max(PAGE_SIZE_4K));
    crate::process::with_process_mut(owner_pid, |p| {
        p.vm.track_file_mapping(owner_pid, base, size, prot)
    })
    .unwrap_or(false)
}

pub(crate) fn vm_clone_external_mappings(src_pid: u32, dst_pid: u32) -> bool {
    if src_pid == 0 || dst_pid == 0 {
        return false;
    }
    // Collect file mappings from src (non-owning, i.e. external)
    let mappings: Vec<(u64, u64, u32)> = crate::process::with_process(src_pid, |p| {
        p.vm.collect_file_mappings()
    })
    .unwrap_or_default();

    for (base, size, prot) in mappings {
        if !vm_track_existing_file_mapping(dst_pid, base, size, prot) {
            return false;
        }
    }
    true
}

pub(crate) fn vm_free_region(owner_pid: u32, base: u64) -> bool {
    crate::process::with_process_mut(owner_pid, |p| {
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.release_region(aspace, owner_pid, base)
    })
    .unwrap_or(false)
}

pub(crate) fn vm_reserve_private(
    owner_pid: u32,
    hint: u64,
    size: u64,
    prot: u32,
) -> Result<u64, u32> {
    let size = super::common::align_up_4k(size.max(PAGE_SIZE_4K));
    let prot = vm_sanitize_nt_prot(prot);
    crate::process::with_process_mut(owner_pid, |p| {
        p.vm.find_and_reserve(hint, size, prot, VmKind::Private)
    })
    .flatten()
    .ok_or(status::NO_MEMORY)
}

pub(crate) fn vm_commit_private(owner_pid: u32, base: u64, size: u64, prot: u32) -> u32 {
    let size = super::common::align_up_4k(size.max(PAGE_SIZE_4K));
    let prot = vm_sanitize_nt_prot(prot);
    let ok = crate::process::with_process_mut(owner_pid, |p| {
        let seg = p.vm.find_seg_at(base);
        if !seg.ok() {
            return false;
        }
        if seg.value().kind != VmKind::Private {
            return false;
        }
        let r = seg.range();
        if base < r.start || base.saturating_add(size) > r.end() {
            return false;
        }
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.commit_pages(aspace, owner_pid, base, size, prot, false)
    })
    .unwrap_or(false);
    if ok { status::SUCCESS } else { status::NO_MEMORY }
}

pub(crate) fn vm_decommit_private(owner_pid: u32, base: u64, size: u64) -> u32 {
    let size = super::common::align_up_4k(size.max(PAGE_SIZE_4K));
    let ok = crate::process::with_process_mut(owner_pid, |p| {
        let seg = p.vm.find_seg_at(base);
        if !seg.ok() {
            return false;
        }
        if seg.value().kind != VmKind::Private {
            return false;
        }
        let r = seg.range();
        if base < r.start || base.saturating_add(size) > r.end() {
            return false;
        }
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.decommit_pages(aspace, owner_pid, base, size)
    })
    .unwrap_or(false);
    if ok { status::SUCCESS } else { status::INVALID_PARAMETER }
}

pub(crate) fn vm_release_private(owner_pid: u32, base: u64) -> u32 {
    let ok = crate::process::with_process_mut(owner_pid, |p| {
        let seg = p.vm.find_seg_by_base(base);
        if !seg.ok() {
            return false;
        }
        if seg.value().kind != VmKind::Private {
            return false;
        }
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.release_at_base(aspace, owner_pid, base, Some(VmKind::Private))
    })
    .unwrap_or(false);
    if ok { status::SUCCESS } else { status::INVALID_PARAMETER }
}

pub(crate) fn vm_protect_range(
    owner_pid: u32,
    base: u64,
    size: u64,
    prot: u32,
) -> Result<u32, u32> {
    let size = super::common::align_up_4k(size.max(PAGE_SIZE_4K));
    let prot = vm_sanitize_nt_prot(prot);
    crate::process::with_process_mut(owner_pid, |p| {
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.protect_range(aspace, owner_pid, base, size, prot)
    })
    .unwrap_or(Err(status::INVALID_PARAMETER))
}

pub(crate) fn vm_query_region(
    owner_pid: u32,
    addr: u64,
) -> Option<crate::mm::vaspace::VmQueryInfo> {
    crate::process::with_process(owner_pid, |p| p.vm.query(addr)).flatten()
}

pub(crate) fn vm_handle_page_fault(owner_pid: u32, fault_addr: u64, access: u8) -> bool {
    crate::process::with_process_mut(owner_pid, |p| {
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.handle_page_fault(aspace, owner_pid, fault_addr, access)
    })
    .unwrap_or(false)
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
