use core::cell::UnsafeCell;

use winemu_shared::pe;

use crate::hypercall;
use crate::ldr::{self, ImportRef};

const MAX_DLLS: usize = 512;
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
    size: u32,
    entry: u64,
}

impl DllEntry {
    const fn empty() -> Self {
        Self {
            state: ENTRY_EMPTY,
            name_len: 0,
            name: [0; MAX_DLL_NAME],
            base: 0,
            size: 0,
            entry: 0,
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
    resolve_import_depth(dll_name, imp, 0)
}

fn resolve_import_depth(dll_name: &str, imp: ImportRef<'_>, depth: u8) -> Option<u64> {
    if depth > 16 {
        return None;
    }
    let dll_base = ensure_loaded(dll_name)?;
    match imp {
        ImportRef::Name(fn_name) => resolve_export_by_name(dll_base, fn_name, depth),
        ImportRef::Ordinal(ord) => resolve_export_by_ordinal(dll_base, ord as u64, depth),
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

    let loaded = load_mapped_dll(fd, file_size, dll_name);
    hypercall::host_close(fd);

    loaded.ok().map(|img| img.base)
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

fn remember_loaded(dll_name: &str, base: u64, size: u32, entry_va: u64) -> bool {
    let mut normalized = [0u8; MAX_DLL_NAME];
    let Some(name_len) = normalize_lower_ascii(dll_name, &mut normalized) else {
        return false;
    };

    let entries = unsafe { &mut *DLL_RUNTIME.entries.get() };
    for slot in entries.iter_mut() {
        if slot.matches_name(dll_name) {
            slot.base = base;
            slot.size = size;
            slot.entry = entry_va;
            slot.state = ENTRY_READY;
            return true;
        }
    }
    for slot in entries.iter_mut() {
        if slot.state == ENTRY_EMPTY {
            slot.state = ENTRY_READY;
            slot.base = base;
            slot.size = size;
            slot.entry = entry_va;
            slot.name_len = name_len as u8;
            slot.name[..name_len].copy_from_slice(&normalized[..name_len]);
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

fn load_mapped_dll(fd: u64, file_size: u64, dll_name: &str) -> Result<ldr::LoadedImage, ldr::LdrError> {
    let map_base = hypercall::host_mmap(fd, 0, file_size, 0x02);
    let loaded = if map_base == 0 || map_base < GUEST_RAM_BASE {
        if map_base != 0 {
            let _ = hypercall::host_munmap(map_base, file_size);
        }
        unsafe { ldr::load_from_fd_unlinked(fd, file_size) }
    } else {
        let image = unsafe { core::slice::from_raw_parts(map_base as *const u8, file_size as usize) };
        let out = unsafe { ldr::load_unlinked(image) };
        let _ = hypercall::host_munmap(map_base, file_size);
        out
    }?;

    // Register before linking imports to break recursive DLL cycles
    // (e.g. user32 <-> gdi32) during resolve_import().
    let entry = if loaded.entry_rva == 0 {
        0
    } else {
        loaded.base.saturating_add(loaded.entry_rva as u64)
    };
    if !remember_loaded(dll_name, loaded.base, loaded.size as u32, entry) {
        return Err(ldr::LdrError::BadImport);
    }
    hypercall::debug_print("dll: loaded ");
    hypercall::debug_print(dll_name);
    hypercall::debug_print(" base=");
    hypercall::debug_u64(loaded.base);
    hypercall::debug_print(" size=");
    hypercall::debug_u64(loaded.size as u64);
    hypercall::debug_print("\n");

    let linked = unsafe { ldr::link_imports(loaded.base, |dep_name, dep_imp| resolve_import(dep_name, dep_imp)) };
    if linked.is_err() {
        forget_loaded(dll_name);
        return linked.map(|_| loaded);
    }

    apply_runtime_compat_bootstrap(dll_name, loaded.base, loaded.size as u64);

    Ok(loaded)
}

fn apply_runtime_compat_bootstrap(dll_name: &str, base: u64, size: u64) {
    if dll_name.eq_ignore_ascii_case("kernelbase.dll") {
        // Some ARM64X builds read this import via an alternate .rdata slot
        // (base + 0xE47C0) instead of the primary FirstThunk slot.
        const ALT_IAT_RTL_OPEN_CROSS: u64 = 0xE47C0;
        let slot_va = base.saturating_add(ALT_IAT_RTL_OPEN_CROSS);
        if slot_va >= base && slot_va.saturating_add(8) <= base.saturating_add(size) {
            if let Some(addr) =
                resolve_import("ntdll.dll", ImportRef::Name("RtlOpenCrossProcessEmulatorWorkConnection"))
            {
                unsafe {
                    (slot_va as *mut u64).write_volatile(addr);
                }
            }
        }
    }

    if !dll_name.eq_ignore_ascii_case("ucrtbase.dll") {
        return;
    }

    // ucrt _lock() uses lock[17] as bootstrap lock. If runtime init did not
    // run yet, lock[17].flag can stay zero and recurse indefinitely.
    const UCRT_LOCK_TABLE_RVA: u64 = 0x1668A0;
    const UCRT_LOCK_ENTRY_SIZE: u64 = 0x30;
    const UCRT_LOCK_BOOTSTRAP_INDEX: u64 = 17;
    const UCRT_DBG_FLAGS_RVA: u64 = 0x163810;

    let lock_flag_va = base
        .saturating_add(UCRT_LOCK_TABLE_RVA)
        .saturating_add(UCRT_LOCK_BOOTSTRAP_INDEX.saturating_mul(UCRT_LOCK_ENTRY_SIZE));
    if lock_flag_va >= base && lock_flag_va.saturating_add(4) <= base.saturating_add(size) {
        unsafe {
            (lock_flag_va as *mut u32).write_volatile(1);
        }
    }

    let dbg_flags_va = base.saturating_add(UCRT_DBG_FLAGS_RVA);
    if dbg_flags_va >= base && dbg_flags_va < base.saturating_add(size) {
        unsafe {
            (dbg_flags_va as *mut u8).write_volatile(0);
        }
    }
}

fn forget_loaded(dll_name: &str) {
    let entries = unsafe { &mut *DLL_RUNTIME.entries.get() };
    for entry in entries.iter_mut() {
        if entry.matches_name(dll_name) {
            *entry = DllEntry::empty();
            return;
        }
    }
}

pub fn for_each_loaded(mut f: impl FnMut(&str, u64, u32, u64)) {
    let entries = unsafe { &*DLL_RUNTIME.entries.get() };
    for entry in entries.iter() {
        if entry.state != ENTRY_READY || entry.name_len == 0 || entry.base == 0 {
            continue;
        }
        let len = entry.name_len as usize;
        if len > entry.name.len() {
            continue;
        }
        if let Ok(name) = core::str::from_utf8(&entry.name[..len]) {
            f(name, entry.base, entry.size, entry.entry);
        }
    }
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

fn resolve_export_by_name(base: u64, name: &str, depth: u8) -> Option<u64> {
    let (fn_rva_tbl, name_tbl, ord_tbl, num_names, num_funcs, _ord_base, exp_rva, exp_size) =
        read_export_dir(base)?;
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
                let fn_rva = pe::ru32(image.add(fn_rva_tbl + ord * 4));
                if fn_rva == 0 {
                    return None;
                }
                return resolve_export_target(base, fn_rva, exp_rva, exp_size, depth);
            }
        }
    }
    None
}

fn resolve_export_by_ordinal(base: u64, ordinal: u64, depth: u8) -> Option<u64> {
    let (fn_rva_tbl, _name_tbl, _ord_tbl, _num_names, num_funcs, ord_base, exp_rva, exp_size) =
        read_export_dir(base)?;
    let idx = ordinal.wrapping_sub(ord_base) as usize;
    if idx >= num_funcs {
        return None;
    }
    unsafe {
        let image = base as *const u8;
        let fn_rva = pe::ru32(image.add(fn_rva_tbl + idx * 4));
        if fn_rva == 0 {
            return None;
        }
        resolve_export_target(base, fn_rva, exp_rva, exp_size, depth)
    }
}

fn read_export_dir(base: u64) -> Option<(usize, usize, usize, usize, usize, u64, u32, u32)> {
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
        Some((
            fn_rva_tbl,
            name_tbl,
            ord_tbl,
            num_names,
            num_funcs,
            ord_base,
            exp_rva as u32,
            exp_size as u32,
        ))
    }
}

fn resolve_export_target(base: u64, fn_rva: u32, exp_rva: u32, exp_size: u32, depth: u8) -> Option<u64> {
    let fn_rva_u64 = fn_rva as u64;
    let exp_lo = exp_rva as u64;
    let exp_hi = exp_lo.saturating_add(exp_size as u64);
    if fn_rva_u64 < exp_lo || fn_rva_u64 >= exp_hi {
        return Some(base + fn_rva_u64);
    }

    let forward = unsafe { cstr_bytes((base + fn_rva_u64) as *const u8) };
    resolve_forwarder(forward, depth + 1)
}

fn resolve_forwarder(forward: &[u8], depth: u8) -> Option<u64> {
    const MAX_FORWARD_DLL: usize = MAX_DLL_NAME;
    const MAX_FORWARD_NAME: usize = 128;

    if depth > 16 {
        return None;
    }
    let split = forward.iter().position(|b| *b == b'.')?;
    if split == 0 || split + 1 >= forward.len() {
        return None;
    }

    let mut dll_buf = [0u8; MAX_FORWARD_DLL];
    let mut dll_len = split;
    if dll_len + 4 > dll_buf.len() {
        return None;
    }
    dll_buf[..dll_len].copy_from_slice(&forward[..split]);
    if !dll_buf[..dll_len].ends_with(b".dll") {
        dll_buf[dll_len..dll_len + 4].copy_from_slice(b".dll");
        dll_len += 4;
    }
    let dll_name = core::str::from_utf8(&dll_buf[..dll_len]).ok()?;

    let sym = &forward[split + 1..];
    if sym.is_empty() {
        return None;
    }
    if sym[0] == b'#' {
        let ordinal = parse_decimal_u16(&sym[1..])?;
        return resolve_import_depth(dll_name, ImportRef::Ordinal(ordinal), depth);
    }

    if sym.len() > MAX_FORWARD_NAME {
        return None;
    }
    let mut sym_buf = [0u8; MAX_FORWARD_NAME];
    sym_buf[..sym.len()].copy_from_slice(sym);
    let sym_name = core::str::from_utf8(&sym_buf[..sym.len()]).ok()?;
    resolve_import_depth(dll_name, ImportRef::Name(sym_name), depth)
}

fn parse_decimal_u16(bytes: &[u8]) -> Option<u16> {
    if bytes.is_empty() {
        return None;
    }
    let mut val: u32 = 0;
    for b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.saturating_mul(10).saturating_add((b - b'0') as u32);
        if val > u16::MAX as u32 {
            return None;
        }
    }
    Some(val as u16)
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
