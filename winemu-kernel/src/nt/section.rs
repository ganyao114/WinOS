use core::cell::UnsafeCell;

use crate::fs::FsError;
use crate::kobj::ObjectStore;
use crate::mm::{vm_alloc_region_typed, vm_free_region, vm_set_section_backing, VmaType};
use crate::process::{with_process_mut, KObjectKind, KObjectRef};
use crate::rust_alloc::vec::Vec;
use winemu_shared::status;

use super::common::{align_up_4k, file_handle_target, GuestWriter, NtFileHandleTarget};
use super::constants::PAGE_SIZE_4K;
use super::path::ObjectAttributesView;
use super::state::{
    section_alloc, section_exists, section_free, section_get, section_retain, view_alloc,
    view_free,
};
use super::user_args::{SyscallArgs, UserInPtr, UserOutPtr};
use super::SvcFrame;
// ── Guest-memory layout structs ───────────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone)]
struct SectionBasicInformation {
    base_address: u64,
    allocation_attributes: u32,
    _pad: u32,
    maximum_size: u64,
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

struct NamedSectionsCell(UnsafeCell<Option<ObjectStore<NamedSection>>>);

unsafe impl Sync for NamedSectionsCell {}

static NAMED_SECTIONS: NamedSectionsCell = NamedSectionsCell(UnsafeCell::new(None));

fn named_sections_mut() -> &'static mut ObjectStore<NamedSection> {
    // SAFETY: Named section bookkeeping remains globally serialized by the
    // existing kernel path; this narrows storage to UnsafeCell without altering
    // runtime ownership rules.
    unsafe {
        let slot = &mut *NAMED_SECTIONS.0.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn ascii_lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

fn section_name_from_oa(
    oa: Option<ObjectAttributesView>,
    out: &mut [u8; MAX_SECTION_NAME],
) -> usize {
    let Some(oa) = oa else {
        return 0;
    };
    let len = oa.read_path(out);
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
        if !section_exists((*ptr).section_idx) {
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
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    let oa = ObjectAttributesView::from_ptr(frame.x[2]);
    let max_size_ptr = UserInPtr::from_raw(frame.x[3] as *const u64);
    let prot = frame.x[4] as u32;
    let alloc_attrs = frame.x[5] as u32;
    let file_handle = frame.x[6];

    let meta = super::kobject::object_type_meta_for_kind(KObjectKind::Section);
    if (desired_access & !meta.valid_access_mask) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let mut section_name = [0u8; MAX_SECTION_NAME];
    let section_name_len = section_name_from_oa(oa, &mut section_name);
    named_section_gc_stale();
    if section_name_len != 0 && named_section_find(&section_name[..section_name_len]).is_some() {
        frame.x[0] = status::OBJECT_NAME_COLLISION as u64;
        return;
    }

    let file = if file_handle == 0 {
        None
    } else {
        match file_handle_target(file_handle) {
            Some(NtFileHandleTarget::Fs(file)) => Some(file),
            _ => {
                frame.x[0] = status::INVALID_HANDLE as u64;
                return;
            }
        }
    };
    if file_handle != 0 && file.is_none() {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    }
    let size = if max_size_ptr.is_null() {
        match file {
            Some(file) => match crate::fs::file_size(file) {
                Ok(size) => align_up_4k(size.max(PAGE_SIZE_4K)),
                Err(_) => {
                    frame.x[0] = status::INVALID_HANDLE as u64;
                    return;
                }
            },
            None => PAGE_SIZE_4K,
        }
    } else {
        let Some(max_size) = max_size_ptr.read_current() else {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };
        align_up_4k(max_size.max(PAGE_SIZE_4K))
    };
    let is_image = (alloc_attrs & SEC_IMAGE) != 0;
    if is_image && file.is_none() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let backing = match file {
        Some(file) => match crate::fs::create_backing_from_file(file, 0, size, is_image) {
            Ok(backing) => Some(backing),
            Err(FsError::NoMemory) => {
                frame.x[0] = status::NO_MEMORY as u64;
                return;
            }
            Err(FsError::Unsupported | FsError::InvalidHandle) => {
                frame.x[0] = status::INVALID_HANDLE as u64;
                return;
            }
            Err(FsError::NotFound | FsError::IoError) => {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            }
        },
        None => None,
    };

    let idx = match section_alloc(size, prot, backing, alloc_attrs) {
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
    if let Err(st) = super::kobject::install_handle_for_pid(pid, KObjectRef::section(idx), out_ptr)
    {
        named_section_remove_by_section(idx);
        let _ = section_free(idx);
        frame.x[0] = st as u64;
        return;
    }
    frame.x[0] = status::SUCCESS as u64;
}

// x0=*SectionHandle, x1=DesiredAccess, x2=ObjectAttributes
pub(crate) fn handle_open_section(frame: &mut SvcFrame) {
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    let oa = ObjectAttributesView::from_ptr(frame.x[2]);

    let meta = super::kobject::object_type_meta_for_kind(KObjectKind::Section);
    if (desired_access & !meta.valid_access_mask) != 0 {
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }
    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let mut section_name = [0u8; MAX_SECTION_NAME];
    let section_name_len = section_name_from_oa(oa, &mut section_name);
    if section_name_len == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    named_section_gc_stale();
    let Some(section_idx) = named_section_find(&section_name[..section_name_len]) else {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    };
    if !section_retain(section_idx) {
        named_section_remove_by_section(section_idx);
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }

    let pid = crate::process::current_pid();
    if let Err(st) =
        super::kobject::install_handle_for_pid(pid, KObjectRef::section(section_idx), out_ptr)
    {
        let _ = section_free(section_idx);
        frame.x[0] = st as u64;
        return;
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
        _ => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };
    let sec = match section_get(sec_idx) {
        Some(s) => s,
        None => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let base_ptr = UserOutPtr::from_raw(frame.x[2] as *mut u64);
    let view_size_ptr = UserOutPtr::from_raw(frame.x[6] as *mut u64);
    let offset_ptr = UserInPtr::from_raw(frame.x[5] as *const u64);
    let Some(win32_protect) = SyscallArgs::new(frame).spill_u64(1) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    let win32_protect = win32_protect as u32;
    let section_offset = if offset_ptr.is_null() {
        0
    } else {
        let Some(offset) = offset_ptr.read_current() else {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };
        offset
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
        let Some(size) = view_size_ptr.read_current() else {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };
        size
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
        let Some(base) = base_ptr.read_current() else {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };
        base
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
    if !vm_set_section_backing(
        owner_pid,
        base,
        sec.backing,
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

    if !base_ptr.write_current_if_present(base) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if !view_size_ptr.write_current_if_present(map_size) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
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
    if section_free(idx) {
        named_section_remove_by_section(idx);
    }
}

pub(crate) fn retain_section_idx(idx: u32) -> bool {
    section_retain(idx)
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
    let ret_len = UserOutPtr::from_raw(frame.x[4] as *mut u32);

    let pid = crate::process::current_pid();
    let obj = with_process_mut(pid, |p| p.handle_table.get(h as u32)).flatten();
    let sec_idx = match obj {
        Some(o) if o.kind == KObjectKind::Section => o.obj_idx,
        _ => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };
    let sec = match section_get(sec_idx) {
        Some(s) => s,
        None => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    match info_class {
        0 => {
            let required = core::mem::size_of::<SectionBasicInformation>();
            let Some(mut w) = GuestWriter::new(buf, len, required) else {
                let _ = ret_len.write_current_if_present(required as u32);
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            };
            w.write_struct(SectionBasicInformation {
                base_address: 0,
                allocation_attributes: sec.alloc_attrs,
                _pad: 0,
                maximum_size: sec.size,
            });
            let _ = ret_len.write_current_if_present(required as u32);
            frame.x[0] = status::SUCCESS as u64;
        }
        1 => {
            let required = core::mem::size_of::<SectionImageInformation>();
            let Some(mut w) = GuestWriter::new(buf, len, required) else {
                let _ = ret_len.write_current_if_present(required as u32);
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            };
            w.write_struct(SectionImageInformation { _data: [0u8; 40] });
            let _ = ret_len.write_current_if_present(required as u32);
            frame.x[0] = status::SUCCESS as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}
