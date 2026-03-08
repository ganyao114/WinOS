use crate::kobj::ObjectStore;
use crate::process::{KObjectKind, KObjectRef, with_process_mut};
use crate::rust_alloc::vec::Vec;
use winemu_shared::status;

use super::common::{align_up_4k, GuestWriter};
use super::constants::PAGE_SIZE_4K;
use super::path::read_oa_path;
use super::state::{
    file_host_fd, section_alloc, section_free, section_get, view_alloc, view_free,
    vm_alloc_region_typed, vm_free_region, vm_set_section_backing,
};
use super::SvcFrame;
use crate::mm::vaspace::VmaType;

// ── Guest-memory layout structs ───────────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone)]
struct SectionBasicInformation {
    base_address:         u64,
    allocation_attributes: u32,
    _pad:                 u32,
    maximum_size:         u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SectionImageInformation {
    _data: [u8; 40],
}

const SEC_IMAGE: u32 = 0x0100_0000;
const PAGE_EXECUTE_READ: u32 = 0x20;
const MAX_SECTION_NAME: usize = 256;

#[derive(Clone, Copy)]
struct NamedSection {
    section_idx: u32,
    name_len: u16,
    name: [u8; MAX_SECTION_NAME],
}

static mut NAMED_SECTIONS: Option<ObjectStore<NamedSection>> = None;

fn named_sections_mut() -> &'static mut ObjectStore<NamedSection> {
    unsafe {
        if NAMED_SECTIONS.is_none() {
            NAMED_SECTIONS = Some(ObjectStore::new());
        }
        NAMED_SECTIONS.as_mut().unwrap()
    }
}

fn ascii_lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

fn section_name_from_oa(oa_ptr: u64, out: &mut [u8; MAX_SECTION_NAME]) -> usize {
    if oa_ptr == 0 {
        return 0;
    }
    let len = read_oa_path(oa_ptr, out);
    if len == 0 {
        return 0;
    }
    for b in out.iter_mut().take(len) {
        *b = ascii_lower(*b);
    }
    len
}

fn named_section_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    let mut i = 0usize;
    while i < lhs.len() {
        if lhs[i] != rhs[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn named_section_gc_stale() {
    let store = named_sections_mut();
    let mut stale = Vec::<u32>::new();
    store.for_each_live_ptr(|id, ptr| unsafe {
        if section_get((*ptr).section_idx).is_none() {
            let _ = stale.try_reserve(1);
            stale.push(id);
        }
    });
    for id in stale {
        let _ = store.free(id);
    }
}

fn named_section_find(name: &[u8]) -> Option<u32> {
    let store = named_sections_mut();
    let mut found = None;
    store.for_each_live_ptr(|_, ptr| unsafe {
        let entry = &*ptr;
        let len = entry.name_len as usize;
        if len == 0 || len > MAX_SECTION_NAME {
            return;
        }
        if named_section_eq(name, &entry.name[..len]) {
            found = Some(entry.section_idx);
        }
    });
    found
}

fn named_section_insert(name: &[u8], section_idx: u32) -> bool {
    if name.is_empty() || name.len() > MAX_SECTION_NAME {
        return false;
    }
    let mut name_buf = [0u8; MAX_SECTION_NAME];
    name_buf[..name.len()].copy_from_slice(name);
    named_sections_mut()
        .alloc_with(|_| NamedSection {
            section_idx,
            name_len: name.len() as u16,
            name: name_buf,
        })
        .is_some()
}

fn named_section_remove_by_section(section_idx: u32) {
    let store = named_sections_mut();
    let mut remove_ids = Vec::<u32>::new();
    store.for_each_live_ptr(|id, ptr| unsafe {
        if (*ptr).section_idx == section_idx {
            let _ = remove_ids.try_reserve(1);
            remove_ids.push(id);
        }
    });
    for id in remove_ids {
        let _ = store.free(id);
    }
}

// x0=*SectionHandle, x3=*MaximumSize, x4=Protection, x6=FileHandle
pub(crate) fn handle_create_section(frame: &mut SvcFrame) {
    let out_ptr = frame.x[0] as *mut u64;
    let desired_access = frame.x[1] as u32;
    let oa_ptr = frame.x[2];
    let max_size_ptr = frame.x[3] as *const u64;
    let prot = frame.x[4] as u32;
    let alloc_attrs = frame.x[5] as u32;
    let file_handle = frame.x[6];

    let meta = super::kobject::object_type_meta_for_kind(KObjectKind::Section);
    if (desired_access & !meta.valid_access_mask) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }

    let mut section_name = [0u8; MAX_SECTION_NAME];
    let section_name_len = section_name_from_oa(oa_ptr, &mut section_name);
    named_section_gc_stale();
    if section_name_len != 0 && named_section_find(&section_name[..section_name_len]).is_some() {
        frame.x[0] = status::OBJECT_NAME_COLLISION as u64;
        return;
    }

    let size = if max_size_ptr.is_null() {
        PAGE_SIZE_4K
    } else {
        align_up_4k(unsafe { max_size_ptr.read_volatile().max(PAGE_SIZE_4K) })
    };
    let owner_pid = crate::process::current_pid();
    let is_image = (alloc_attrs & SEC_IMAGE) != 0;
    let file_fd = if file_handle == 0 {
        None
    } else {
        let pid = crate::process::current_pid();
        let obj = with_process_mut(pid, |p| p.handle_table.get(file_handle as u32)).flatten();
        match obj {
            Some(o) if o.kind == KObjectKind::File => file_host_fd(o.obj_idx),
            _ => { frame.x[0] = status::INVALID_HANDLE as u64; return; }
        }
    };
    if file_handle != 0 && file_fd.is_none() {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
    if is_image && file_fd.is_none() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let idx = match section_alloc(owner_pid, size, prot, file_fd, alloc_attrs) {
        Some(i) => i,
        None => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };
    if section_name_len != 0 && !named_section_insert(&section_name[..section_name_len], idx) {
        section_free(idx);
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    }
    let pid = crate::process::current_pid();
    let Some(handle) = with_process_mut(pid, |p| {
        p.handle_table.add(KObjectRef::section(idx)).map(|v| v as u64)
    }).flatten() else {
        named_section_remove_by_section(idx);
        section_free(idx);
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(handle) };
    }
    frame.x[0] = status::SUCCESS as u64;
}

// x0=*SectionHandle, x1=DesiredAccess, x2=ObjectAttributes
pub(crate) fn handle_open_section(frame: &mut SvcFrame) {
    let out_ptr = frame.x[0] as *mut u64;
    let desired_access = frame.x[1] as u32;
    let oa_ptr = frame.x[2];

    let meta = super::kobject::object_type_meta_for_kind(KObjectKind::Section);
    if (desired_access & !meta.valid_access_mask) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }

    let mut section_name = [0u8; MAX_SECTION_NAME];
    let section_name_len = section_name_from_oa(oa_ptr, &mut section_name);
    if section_name_len == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    named_section_gc_stale();
    let Some(section_idx) = named_section_find(&section_name[..section_name_len]) else {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    };
    if section_get(section_idx).is_none() {
        named_section_remove_by_section(section_idx);
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }

    let pid = crate::process::current_pid();
    let Some(handle) = with_process_mut(pid, |p| {
        p.handle_table.add(KObjectRef::section(section_idx)).map(|v| v as u64)
    }).flatten() else {
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(handle) };
    }
    frame.x[0] = status::SUCCESS as u64;
}

// x0=SectionHandle, x2=*BaseAddress, x5=*SectionOffset, x6=*ViewSize
// stack[0]=AllocationType, stack[1]=Win32Protect
pub(crate) fn handle_map_view_of_section(frame: &mut SvcFrame) {
    let h = frame.x[0];
    let pid = crate::process::current_pid();
    let obj = with_process_mut(pid, |p| p.handle_table.get(h as u32)).flatten();
    let sec_idx = match obj {
        Some(o) if o.kind == KObjectKind::Section => o.obj_idx,
        _ => { frame.x[0] = status::INVALID_HANDLE as u64; return; }
    };
    let sec = match section_get(sec_idx) {
        Some(s) => s,
        None => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let base_ptr = frame.x[2] as *mut u64;
    let view_size_ptr = frame.x[6] as *mut u64;
    let offset_ptr = frame.x[5] as *const u64;
    let win32_protect = unsafe { (frame.sp_el0 as *const u64).add(1).read_volatile() } as u32;
    let section_offset = if offset_ptr.is_null() {
        0
    } else {
        unsafe { offset_ptr.read_volatile() }
    };
    if sec.is_image && section_offset != 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if (section_offset & (PAGE_SIZE_4K - 1)) != 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let req_size = if view_size_ptr.is_null() {
        0
    } else {
        unsafe { view_size_ptr.read_volatile() }
    };
    if section_offset >= sec.size {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let max_size = sec.size - section_offset;
    let raw_size = if req_size == 0 { max_size } else { req_size };
    if raw_size == 0 || raw_size > max_size {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let map_size = align_up_4k(raw_size.max(PAGE_SIZE_4K));
    let prot = if sec.is_image {
        PAGE_EXECUTE_READ
    } else if win32_protect == 0 {
        sec.prot
    } else {
        win32_protect
    };
    let owner_pid = crate::process::current_pid();
    let hint = if !base_ptr.is_null() {
        unsafe { base_ptr.read_volatile() }
    } else {
        0
    };

    let base = match vm_alloc_region_typed(owner_pid, hint, map_size, prot, VmaType::Section) {
        Some(v) => v,
        None => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };
    let backing_fd = if sec.file_backed {
        Some(sec.file_fd)
    } else {
        None
    };
    if !vm_set_section_backing(
        owner_pid,
        base,
        backing_fd,
        section_offset,
        map_size,
        sec.is_image,
    ) {
        let _ = vm_free_region(owner_pid, base);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    if !view_alloc(owner_pid, base, map_size) {
        let _ = vm_free_region(owner_pid, base);
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    }

    if !base_ptr.is_null() {
        unsafe { base_ptr.write_volatile(base) };
    }
    if !view_size_ptr.is_null() {
        unsafe { view_size_ptr.write_volatile(map_size) };
    }
    frame.x[0] = status::SUCCESS as u64;
}

// x1=BaseAddress
pub(crate) fn handle_unmap_view_of_section(frame: &mut SvcFrame) {
    let base = frame.x[1];
    let owner_pid = crate::process::current_pid();
    let _ = view_free(owner_pid, base);
    let _ = vm_free_region(owner_pid, base);
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn close_section_idx(idx: u32) {
    named_section_remove_by_section(idx);
    section_free(idx);
}

pub(crate) fn section_name_utf16(section_idx: u32) -> Option<Vec<u16>> {
    if section_idx == 0 {
        return None;
    }
    named_section_gc_stale();
    let store = named_sections_mut();
    let mut out = None;
    store.for_each_live_ptr(|_id, ptr| unsafe {
        let entry = &*ptr;
        if entry.section_idx != section_idx {
            return;
        }
        let len = entry.name_len as usize;
        if len == 0 || len > MAX_SECTION_NAME {
            return;
        }
        let mut name = Vec::<u16>::new();
        if name.try_reserve(len).is_err() {
            return;
        }
        let mut i = 0usize;
        while i < len {
            name.push(entry.name[i] as u16);
            i += 1;
        }
        out = Some(name);
    });
    out
}

// x0=SectionHandle, x1=SectionInformationClass, x2=Buffer, x3=Length, x4=*ReturnLength
pub(crate) fn handle_query_section(frame: &mut SvcFrame) {
    let h = frame.x[0];
    let info_class = frame.x[1] as u32;
    let buf = frame.x[2] as *mut u8;
    let len = frame.x[3] as usize;
    let ret_len = frame.x[4] as *mut u32;

    let pid = crate::process::current_pid();
    let obj = with_process_mut(pid, |p| p.handle_table.get(h as u32)).flatten();
    let sec_idx = match obj {
        Some(o) if o.kind == KObjectKind::Section => o.obj_idx,
        _ => { frame.x[0] = status::INVALID_HANDLE as u64; return; }
    };
    let sec = match section_get(sec_idx) {
        Some(s) => s,
        None => { frame.x[0] = status::INVALID_HANDLE as u64; return; }
    };

    match info_class {
        0 => {
            let required = core::mem::size_of::<SectionBasicInformation>();
            let Some(mut w) = GuestWriter::new(buf, len, required) else {
                if !ret_len.is_null() { unsafe { ret_len.write_volatile(required as u32) }; }
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            };
            w.write_struct(SectionBasicInformation {
                base_address: 0,
                allocation_attributes: sec.alloc_attrs,
                _pad: 0,
                maximum_size: sec.size,
            });
            if !ret_len.is_null() { unsafe { ret_len.write_volatile(required as u32) }; }
            frame.x[0] = status::SUCCESS as u64;
        }
        1 => {
            let required = core::mem::size_of::<SectionImageInformation>();
            let Some(mut w) = GuestWriter::new(buf, len, required) else {
                if !ret_len.is_null() { unsafe { ret_len.write_volatile(required as u32) }; }
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            };
            w.write_struct(SectionImageInformation { _data: [0u8; 40] });
            if !ret_len.is_null() { unsafe { ret_len.write_volatile(required as u32) }; }
            frame.x[0] = status::SUCCESS as u64;
        }
        _ => { frame.x[0] = status::INVALID_PARAMETER as u64; }
    }
}
