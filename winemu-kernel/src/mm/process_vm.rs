use crate::fs::FsBackingHandle;
use crate::mm::vm_area::{VmKind, PAGE_SIZE};
use crate::mm::{vm_kind_from_vma_type, vm_sanitize_nt_prot, UserVa, VmQueryInfo, VmaType};
use winemu_shared::status;

#[inline]
fn align_up_page(value: u64) -> u64 {
    (value + (PAGE_SIZE - 1)) & !(PAGE_SIZE - 1)
}

pub(crate) fn vm_alloc_region(owner_pid: u32, size: u64, prot: u32) -> Option<u64> {
    vm_alloc_region_typed(owner_pid, 0, size, prot, VmaType::Private)
}

pub(crate) fn vm_alloc_stack(owner_pid: u32, size: u64) -> Option<u64> {
    let size = size.max(0x10_0000);
    let base = vm_alloc_region_typed(owner_pid, 0, size, 0x04, VmaType::ThreadStack)?;
    Some(base + size)
}

pub(crate) fn vm_alloc_region_typed(
    owner_pid: u32,
    hint: u64,
    size: u64,
    prot: u32,
    vma_type: VmaType,
) -> Option<u64> {
    let size = align_up_page(size.max(PAGE_SIZE));
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
                VmKind::Image => 2,
                VmKind::Section => 3,
                VmKind::ThreadStack => 4,
                VmKind::Other => 5,
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
    backing: Option<FsBackingHandle>,
    file_offset: u64,
    view_size: u64,
    is_image: bool,
) -> bool {
    crate::process::with_process_mut(owner_pid, |p| {
        p.vm.set_section_backing(base, backing, file_offset, view_size, is_image)
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
    let size = align_up_page(size.max(PAGE_SIZE));
    crate::process::with_process_mut(owner_pid, |p| {
        p.vm.track_file_mapping(owner_pid, base, size, prot)
    })
    .unwrap_or(false)
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
    let size = align_up_page(size.max(PAGE_SIZE));
    let prot = vm_sanitize_nt_prot(prot);
    crate::process::with_process_mut(owner_pid, |p| {
        p.vm.find_and_reserve(hint, size, prot, VmKind::Private)
    })
    .flatten()
    .ok_or(status::NO_MEMORY)
}

pub(crate) fn vm_commit_private(owner_pid: u32, base: u64, size: u64, prot: u32) -> u32 {
    let size = align_up_page(size.max(PAGE_SIZE));
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
    if ok {
        status::SUCCESS
    } else {
        status::NO_MEMORY
    }
}

pub(crate) fn vm_decommit_private(owner_pid: u32, base: u64, size: u64) -> u32 {
    let size = align_up_page(size.max(PAGE_SIZE));
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
    if ok {
        status::SUCCESS
    } else {
        status::INVALID_PARAMETER
    }
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
    if ok {
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
    let size = align_up_page(size.max(PAGE_SIZE));
    let prot = vm_sanitize_nt_prot(prot);
    crate::process::with_process_mut(owner_pid, |p| {
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.protect_range(aspace, owner_pid, base, size, prot)
    })
    .unwrap_or(Err(status::INVALID_PARAMETER))
}

pub(crate) fn vm_query_region(owner_pid: u32, addr: UserVa) -> Option<VmQueryInfo> {
    crate::process::with_process(owner_pid, |p| p.vm.query(addr)).flatten()
}
