use core::cell::UnsafeCell;

use winemu_shared::pe;

use crate::hypercall;
use crate::ldr::{self, ImportRef};

const MAX_DLLS: usize = 32;
const MAX_DLL_NAME: usize = 96;
const MAX_DLL_PATH: usize = 192;
const HOST_OPEN_READ: u64 = 0;
const GUEST_RAM_BASE: u64 = 0x4000_0000;
const ENTRY_EMPTY: u8 = 0;
const ENTRY_READY: u8 = 1;

#[derive(Clone, Copy)]
struct DllEntry {
    state: u8,
    name_len: u8,
    name: [u8; MAX_DLL_NAME],
    base: u64,
}

impl DllEntry {
    const fn empty() -> Self {
        Self {
            state: ENTRY_EMPTY,
            name_len: 0,
            name: [0; MAX_DLL_NAME],
            base: 0,
        }
    }

    fn matches_name(&self, name: &str) -> bool {
        if self.state != ENTRY_READY {
            return false;
        }
        let bytes = name.as_bytes();
        if bytes.len() != self.name_len as usize {
            return false;
        }
        for (i, b) in bytes.iter().enumerate() {
            if self.name[i] != b.to_ascii_lowercase() {
                return false;
            }
        }
        true
    }
}

struct DllRuntime {
    entries: UnsafeCell<[DllEntry; MAX_DLLS]>,
}

unsafe impl Sync for DllRuntime {}

static DLL_RUNTIME: DllRuntime = DllRuntime {
    entries: UnsafeCell::new([DllEntry::empty(); MAX_DLLS]),
};

pub fn resolve_import(dll_name: &str, imp: ImportRef<'_>) -> Option<u64> {
    let dll_base = ensure_loaded(dll_name)?;
    match imp {
        ImportRef::Name(fn_name) => resolve_export_by_name(dll_base, fn_name),
        ImportRef::Ordinal(ord) => resolve_export_by_ordinal(dll_base, ord as u64),
    }
}

fn ensure_loaded(dll_name: &str) -> Option<u64> {
    if let Some(base) = find_loaded_base(dll_name) {
        return Some(base);
    }

    let fd = open_dll_file(dll_name);
    if fd == u64::MAX {
        return None;
    }
    let file_size = hypercall::host_stat(fd);
    if file_size == 0 {
        hypercall::host_close(fd);
        return None;
    }

    let loaded = load_mapped_dll(fd, file_size);
    hypercall::host_close(fd);

    let loaded = loaded.ok()?;
    if !remember_loaded(dll_name, loaded.base) {
        return None;
    }
    Some(loaded.base)
}

fn find_loaded_base(dll_name: &str) -> Option<u64> {
    let entries = unsafe { &*DLL_RUNTIME.entries.get() };
    for entry in entries.iter() {
        if entry.matches_name(dll_name) {
            return Some(entry.base);
        }
    }
    None
}

fn remember_loaded(dll_name: &str, base: u64) -> bool {
    let mut normalized = [0u8; MAX_DLL_NAME];
    let Some(name_len) = normalize_lower_ascii(dll_name, &mut normalized) else {
        return false;
    };

    let entries = unsafe { &mut *DLL_RUNTIME.entries.get() };
    for entry in entries.iter_mut() {
        if entry.matches_name(dll_name) {
            entry.base = base;
            entry.state = ENTRY_READY;
            return true;
        }
    }
    for entry in entries.iter_mut() {
        if entry.state == ENTRY_EMPTY {
            entry.state = ENTRY_READY;
            entry.base = base;
            entry.name_len = name_len as u8;
            entry.name[..name_len].copy_from_slice(&normalized[..name_len]);
            return true;
        }
    }
    false
}

fn open_dll_file(dll_name: &str) -> u64 {
    let mut lower_name = [0u8; MAX_DLL_NAME];
    let lower_len = normalize_lower_ascii(dll_name, &mut lower_name);

    let mut path = [0u8; MAX_DLL_PATH];
    if let Some(path_len) = build_sysroot_path(dll_name, &mut path) {
        let p = unsafe { core::str::from_utf8_unchecked(&path[..path_len]) };
        if let Some(fd) = try_open_path(p) {
            return fd;
        }
    }
    if let Some(lower_len) = lower_len {
        let lower = unsafe { core::str::from_utf8_unchecked(&lower_name[..lower_len]) };
        if let Some(path_len) = build_sysroot_path(lower, &mut path) {
            let p = unsafe { core::str::from_utf8_unchecked(&path[..path_len]) };
            if let Some(fd) = try_open_path(p) {
                return fd;
            }
        }
    }

    let has_path = dll_name
        .as_bytes()
        .iter()
        .any(|b| *b == b'/' || *b == b'\\' || *b == b':');
    if has_path {
        if let Some(fd) = try_open_path(dll_name) {
            return fd;
        }
        if let Some(len) = lower_len {
            let lower = unsafe { core::str::from_utf8_unchecked(&lower_name[..len]) };
            if let Some(fd) = try_open_path(lower) {
                return fd;
            }
        }
    }

    u64::MAX
}

fn load_mapped_dll(fd: u64, file_size: u64) -> Result<ldr::LoadedImage, ldr::LdrError> {
    let map_base = hypercall::host_mmap(fd, 0, file_size, 0x02);
    if map_base == 0 || map_base < GUEST_RAM_BASE {
        if map_base != 0 {
            let _ = hypercall::host_munmap(map_base, file_size);
        }
        return unsafe { ldr::load_from_fd(fd, file_size, |dep_name, dep_imp| resolve_import(dep_name, dep_imp)) };
    }

    let image = unsafe { core::slice::from_raw_parts(map_base as *const u8, file_size as usize) };
    let loaded = unsafe { ldr::load(image, |dep_name, dep_imp| resolve_import(dep_name, dep_imp)) };
    let _ = hypercall::host_munmap(map_base, file_size);
    loaded
}

fn try_open_path(path: &str) -> Option<u64> {
    let fd = hypercall::host_open(path, HOST_OPEN_READ);
    if fd == u64::MAX {
        None
    } else {
        Some(fd)
    }
}

fn build_sysroot_path(name: &str, out: &mut [u8; MAX_DLL_PATH]) -> Option<usize> {
    const PREFIX: &[u8] = b"guest/sysroot/";
    let name_bytes = name.as_bytes();
    let total = PREFIX.len().saturating_add(name_bytes.len());
    if total > out.len() {
        return None;
    }
    out[..PREFIX.len()].copy_from_slice(PREFIX);
    out[PREFIX.len()..total].copy_from_slice(name_bytes);
    Some(total)
}

fn normalize_lower_ascii(name: &str, out: &mut [u8; MAX_DLL_NAME]) -> Option<usize> {
    let bytes = name.as_bytes();
    if bytes.len() > out.len() {
        return None;
    }
    for (i, b) in bytes.iter().enumerate() {
        out[i] = b.to_ascii_lowercase();
    }
    Some(bytes.len())
}

fn resolve_export_by_name(base: u64, name: &str) -> Option<u64> {
    let (fn_rva_tbl, name_tbl, ord_tbl, num_names, num_funcs, _ord_base) = read_export_dir(base)?;
    let target = name.as_bytes();
    unsafe {
        let image = base as *const u8;
        for i in 0..num_names {
            let name_rva = pe::ru32(image.add(name_tbl + i * 4)) as usize;
            let export_name = cstr_bytes(image.add(name_rva));
            if export_name == target {
                let ord = pe::ru16(image.add(ord_tbl + i * 2)) as usize;
                if ord >= num_funcs {
                    return None;
                }
                let fn_rva = pe::ru32(image.add(fn_rva_tbl + ord * 4)) as u64;
                if fn_rva == 0 {
                    return None;
                }
                return Some(base + fn_rva);
            }
        }
    }
    None
}

fn resolve_export_by_ordinal(base: u64, ordinal: u64) -> Option<u64> {
    let (fn_rva_tbl, _name_tbl, _ord_tbl, _num_names, num_funcs, ord_base) = read_export_dir(base)?;
    let idx = ordinal.wrapping_sub(ord_base) as usize;
    if idx >= num_funcs {
        return None;
    }
    unsafe {
        let image = base as *const u8;
        let fn_rva = pe::ru32(image.add(fn_rva_tbl + idx * 4)) as u64;
        if fn_rva == 0 {
            return None;
        }
        Some(base + fn_rva)
    }
}

fn read_export_dir(base: u64) -> Option<(usize, usize, usize, usize, usize, u64)> {
    unsafe {
        let image = base as *const u8;
        if pe::ru16(image) != pe::MZ_MAGIC {
            return None;
        }
        let lfanew = pe::ru32(image.add(60)) as usize;
        if pe::ru32(image.add(lfanew)) != pe::PE_MAGIC {
            return None;
        }

        let oh = image.add(lfanew + 24);
        let exp_rva = pe::ru32(oh.add(112)) as usize;
        let exp_size = pe::ru32(oh.add(116));
        if exp_rva == 0 || exp_size == 0 {
            return None;
        }

        let exp = image.add(exp_rva);
        let ord_base = pe::ru32(exp.add(16)) as u64;
        let num_funcs = pe::ru32(exp.add(20)) as usize;
        let num_names = pe::ru32(exp.add(24)) as usize;
        let fn_rva_tbl = pe::ru32(exp.add(28)) as usize;
        let name_tbl = pe::ru32(exp.add(32)) as usize;
        let ord_tbl = pe::ru32(exp.add(36)) as usize;
        Some((fn_rva_tbl, name_tbl, ord_tbl, num_names, num_funcs, ord_base))
    }
}

unsafe fn cstr_bytes<'a>(p: *const u8) -> &'a [u8] {
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
        if len >= 512 {
            break;
        }
    }
    core::slice::from_raw_parts(p, len)
}
