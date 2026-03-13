use core::cell::UnsafeCell;
use core::mem::size_of;

use winemu_shared::{pe, status};

use crate::fs::{self, FsFileHandle};
use crate::ldr::{self, ImportRef};
use crate::mm::usercopy::{
    current_pid as current_user_pid, read_current_user_mapped_value,
    with_current_process_user_slice, write_current_user_mapped_value,
};
use crate::mm::{UserVa, VM_ACCESS_READ};

const MAX_DLLS: usize = 512;
const MAX_DLL_NAME: usize = 96;
const MAX_DLL_PATH: usize = 192;
const ENTRY_EMPTY: u8 = 0;
const ENTRY_READY: u8 = 1;

#[derive(Clone, Copy)]
struct DllEntry {
    state: u8,
    name_len: u8,
    user_backed: u8,
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
            user_backed: 0,
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

pub struct LoadedModuleInfo {
    pub base: u64,
    pub size: u32,
    pub entry: u64,
}

pub fn resolve_import(dll_name: &str, imp: ImportRef<'_>) -> Option<u64> {
    resolve_import_depth(dll_name, imp, 0)
}

pub fn load_module(dll_name: &str) -> Result<LoadedModuleInfo, u32> {
    const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;
    const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_007B;

    let mut key_buf = [0u8; MAX_DLL_NAME];
    let Some(key_name) = module_key_name(dll_name, &mut key_buf) else {
        return Err(status::INVALID_PARAMETER);
    };

    if let Some(base) = find_loaded_base(key_name) {
        return loaded_module_info(base).ok_or(STATUS_DLL_NOT_FOUND);
    }

    let Some(file) = open_dll_file(dll_name) else {
        return Err(STATUS_DLL_NOT_FOUND);
    };
    let Some(file_size) = fs::file_size(file).ok() else {
        fs::close(file);
        return Err(STATUS_DLL_NOT_FOUND);
    };
    if file_size == 0 {
        fs::close(file);
        return Err(STATUS_DLL_NOT_FOUND);
    }

    let loaded = load_dll_file(file, file_size, key_name, dll_name);
    fs::close(file);

    match loaded {
        Ok(img) => loaded_module_info(img.base).ok_or(STATUS_INVALID_IMAGE_FORMAT),
        Err(ldr::LdrError::AllocFailed) => Err(status::NO_MEMORY),
        Err(ldr::LdrError::IoError) => Err(STATUS_DLL_NOT_FOUND),
        Err(_) => Err(STATUS_INVALID_IMAGE_FORMAT),
    }
}

pub fn find_loaded_base_for_addr(addr: u64) -> Option<u64> {
    let entries = unsafe { &*DLL_RUNTIME.entries.get() };
    for entry in entries.iter() {
        if entry.state != ENTRY_READY {
            continue;
        }
        let base = entry.base;
        let end = base.saturating_add(entry.size as u64);
        if addr >= base && addr < end {
            return Some(base);
        }
    }
    None
}

pub fn resolve_loaded_export(base: u64, name: &str) -> Option<u64> {
    resolve_export_by_name(base, name, 0)
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
    let mut key_buf = [0u8; MAX_DLL_NAME];
    let key_name = module_key_name(dll_name, &mut key_buf)?;
    if let Some(base) = find_loaded_base(key_name) {
        return Some(base);
    }

    let file = open_dll_file(dll_name)?;
    let file_size = fs::file_size(file).ok()?;
    if file_size == 0 {
        fs::close(file);
        return None;
    }

    let loaded = load_dll_file(file, file_size, key_name, dll_name);
    fs::close(file);

    match loaded {
        Ok(img) => Some(img.base),
        Err(err) => {
            crate::kdebug!("dll: load failed {}: {:?}", dll_name, err);
            None
        }
    }
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

fn remember_loaded(dll_name: &str, base: u64, size: u32, entry_va: u64, user_backed: bool) -> bool {
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
            slot.user_backed = u8::from(user_backed);
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
            slot.user_backed = u8::from(user_backed);
            slot.name_len = name_len as u8;
            slot.name[..name_len].copy_from_slice(&normalized[..name_len]);
            return true;
        }
    }
    false
}

fn loaded_module_info(base: u64) -> Option<LoadedModuleInfo> {
    let entries = unsafe { &*DLL_RUNTIME.entries.get() };
    for entry in entries.iter() {
        if entry.state != ENTRY_READY || entry.base != base {
            continue;
        }
        return Some(LoadedModuleInfo {
            base: entry.base,
            size: entry.size,
            entry: entry.entry,
        });
    }
    None
}

fn open_dll_file(dll_name: &str) -> Option<FsFileHandle> {
    let canonical_name = canonical_dll_name(dll_name);
    let mut lower_name = [0u8; MAX_DLL_NAME];
    let lower_len = normalize_lower_ascii(canonical_name, &mut lower_name);

    let mut path = [0u8; MAX_DLL_PATH];
    if let Some(path_len) = build_sysroot_path(canonical_name, &mut path) {
        let p = unsafe { core::str::from_utf8_unchecked(&path[..path_len]) };
        if let Some(fd) = try_open_path(p) {
            return Some(fd);
        }
    }
    if let Some(lower_len) = lower_len {
        let lower = unsafe { core::str::from_utf8_unchecked(&lower_name[..lower_len]) };
        if let Some(path_len) = build_sysroot_path(lower, &mut path) {
            let p = unsafe { core::str::from_utf8_unchecked(&path[..path_len]) };
            if let Some(fd) = try_open_path(p) {
                return Some(fd);
            }
        }
    }

    let has_path = dll_name
        .as_bytes()
        .iter()
        .any(|b| *b == b'/' || *b == b'\\' || *b == b':');
    if has_path {
        let leaf = dll_leaf_name(dll_name);
        if leaf != dll_name {
            if let Some(path_len) = build_sysroot_path(leaf, &mut path) {
                let p = unsafe { core::str::from_utf8_unchecked(&path[..path_len]) };
                if let Some(fd) = try_open_path(p) {
                    return Some(fd);
                }
            }
            if let Some(len) = normalize_lower_ascii(leaf, &mut lower_name) {
                let lower = unsafe { core::str::from_utf8_unchecked(&lower_name[..len]) };
                if let Some(path_len) = build_sysroot_path(lower, &mut path) {
                    let p = unsafe { core::str::from_utf8_unchecked(&path[..path_len]) };
                    if let Some(fd) = try_open_path(p) {
                        return Some(fd);
                    }
                }
            }
        }
        if let Some(fd) = try_open_path(dll_name) {
            return Some(fd);
        }
        if let Some(len) = lower_len {
            let lower = unsafe { core::str::from_utf8_unchecked(&lower_name[..len]) };
            if let Some(fd) = try_open_path(lower) {
                return Some(fd);
            }
        }
    }

    None
}

fn dll_leaf_name(name: &str) -> &str {
    let bytes = name.as_bytes();
    let mut start = 0usize;
    for (idx, b) in bytes.iter().enumerate() {
        if *b == b'/' || *b == b'\\' || *b == b':' {
            start = idx.saturating_add(1);
        }
    }
    &name[start..]
}

fn canonical_dll_name(name: &str) -> &str {
    let leaf = dll_leaf_name(name);
    remap_api_set_name(leaf).unwrap_or(leaf)
}

fn remap_api_set_name(name: &str) -> Option<&'static str> {
    if name.eq_ignore_ascii_case("api-ms-win-core-synch-l1-2-0")
        || name.eq_ignore_ascii_case("api-ms-win-core-synch-l1-2-0.dll")
    {
        return Some("kernelbase.dll");
    }
    if name.eq_ignore_ascii_case("api-ms-win-appmodel-runtime-l1-1-2")
        || name.eq_ignore_ascii_case("api-ms-win-appmodel-runtime-l1-1-2.dll")
    {
        return Some("kernelbase.dll");
    }
    if name.eq_ignore_ascii_case("api-ms-win-appmodel-runtime-internal-l1-1-1")
        || name.eq_ignore_ascii_case("api-ms-win-appmodel-runtime-internal-l1-1-1.dll")
    {
        return Some("kernelbase.dll");
    }
    None
}

fn normalize_module_name(name: &str, out: &mut [u8; MAX_DLL_NAME]) -> Option<usize> {
    let bytes = name.as_bytes();
    let needs_dll_suffix = !bytes.iter().any(|b| *b == b'.');
    let extra = if needs_dll_suffix { 4 } else { 0 };
    if bytes.len().saturating_add(extra) > out.len() {
        return None;
    }
    for (i, b) in bytes.iter().enumerate() {
        out[i] = b.to_ascii_lowercase();
    }
    if needs_dll_suffix {
        out[bytes.len()..bytes.len() + 4].copy_from_slice(b".dll");
    }
    Some(bytes.len() + extra)
}

fn module_key_name<'a>(name: &str, buf: &'a mut [u8; MAX_DLL_NAME]) -> Option<&'a str> {
    let canonical = canonical_dll_name(name);
    let len = normalize_module_name(canonical, buf)?;
    core::str::from_utf8(&buf[..len]).ok()
}

fn load_dll_file(
    file: FsFileHandle,
    file_size: u64,
    key_name: &str,
    display_name: &str,
) -> Result<ldr::LoadedImage, ldr::LdrError> {
    crate::ktrace!(
        "dll: load start {} size={:#x}",
        display_name,
        file_size
    );
    let loaded =
        unsafe { ldr::load_from_file_unlinked(file, file_size, crate::mm::VmaType::DllImage) }?;
    crate::ktrace!(
        "dll: unlinked ok {} base={:#x} size={:#x} entry_rva={:#x}",
        display_name,
        loaded.base,
        loaded.size,
        loaded.entry_rva
    );

    // Register before linking imports to break recursive DLL cycles
    // (e.g. user32 <-> gdi32) during resolve_import().
    let entry = if loaded.entry_rva == 0 {
        0
    } else {
        loaded.base.saturating_add(loaded.entry_rva as u64)
    };
    let user_backed = current_user_pid().is_some();
    if !remember_loaded(
        key_name,
        loaded.base,
        loaded.size as u32,
        entry,
        user_backed,
    ) {
        return Err(ldr::LdrError::BadImport);
    }
    let linked = unsafe {
        ldr::link_imports(loaded.base, |dep_name, dep_imp| {
            resolve_import(dep_name, dep_imp)
        })
    };
    if linked.is_err() {
        crate::kdebug!("dll: link failed {}: {:?}", display_name, linked);
        forget_loaded(key_name);
        return linked.map(|_| loaded);
    }

    apply_runtime_compat_bootstrap(key_name, loaded.base, loaded.size as u64);
    if ldr::finalize_loaded_image(loaded.base).is_err() {
        crate::kdebug!("dll: finalize failed {}", display_name);
        forget_loaded(key_name);
        return Err(ldr::LdrError::ProtectFailed);
    }

    crate::ktrace!("dll: load complete {}", display_name);

    Ok(loaded)
}

fn apply_runtime_compat_bootstrap(dll_name: &str, base: u64, size: u64) {
    if dll_name.eq_ignore_ascii_case("win32u.dll") {
        const WIN32U_SYSCALL_SLOT_NATIVE: u64 = 0x43060;
        const WIN32U_SYSCALL_SLOT_ARM64EC: u64 = 0x43068;
        const WIN32U_UNIX_SLOT_NATIVE: u64 = 0x43058;
        const WIN32U_UNIX_SLOT_ARM64EC: u64 = 0x43048;

        let export_target = |name: &str| {
            resolve_import("ntdll.dll", ImportRef::Name(name))
                .and_then(read_mapped_value::<u64>)
                .unwrap_or(0)
        };
        let syscall_value = {
            let value = export_target("__winemu_syscall_dispatcher");
            if value != 0 {
                value
            } else {
                export_target("__wine_syscall_dispatcher")
            }
        };
        let unix_value = export_target("__wine_unix_call_dispatcher");

        let patch_slot = |slot_off: u64, value: u64| {
            if value == 0 {
                return;
            }
            let slot_va = base.saturating_add(slot_off);
            if slot_va < base || slot_va.saturating_add(8) > base.saturating_add(size) {
                return;
            }
            let cur = read_mapped_value::<u64>(slot_va).unwrap_or(0);
            if cur == 0 {
                let _ = write_mapped_value(slot_va, value);
            }
        };

        patch_slot(WIN32U_SYSCALL_SLOT_NATIVE, syscall_value);
        patch_slot(WIN32U_SYSCALL_SLOT_ARM64EC, syscall_value);
        patch_slot(WIN32U_UNIX_SLOT_NATIVE, unix_value);
        patch_slot(WIN32U_UNIX_SLOT_ARM64EC, unix_value);
    }

    if dll_name.eq_ignore_ascii_case("kernelbase.dll") {
        // Locale pointers used by kernelbase locale bootstrap paths.
        const KB_LOCALE_FALLBACK_PTR: u64 = 0x13F938;
        const KB_LOCALE_RUNTIME_PTR: u64 = 0x13F948;
        const KB_LOCALE_TABLE_PTR: u64 = 0x13F950;

        // Some startup paths hit init_locale before this fallback pointer gets
        // initialized by user-mode runtime, which leads to NULL dereference.
        let fallback_va = base.saturating_add(KB_LOCALE_FALLBACK_PTR);
        let runtime_va = base.saturating_add(KB_LOCALE_RUNTIME_PTR);
        let table_va = base.saturating_add(KB_LOCALE_TABLE_PTR);
        if fallback_va >= base
            && fallback_va.saturating_add(8) <= base.saturating_add(size)
            && runtime_va >= base
            && runtime_va.saturating_add(8) <= base.saturating_add(size)
            && table_va >= base
            && table_va.saturating_add(8) <= base.saturating_add(size)
        {
            let fallback = read_mapped_value::<u64>(fallback_va).unwrap_or(0);
            let runtime = read_mapped_value::<u64>(runtime_va).unwrap_or(0);
            let table = read_mapped_value::<u64>(table_va).unwrap_or(0);
            let mut patched = fallback;
            if patched == 0 {
                patched = if runtime != 0 {
                    runtime
                } else if table != 0 {
                    table
                } else {
                    kernelbase_locale_stub_ptr()
                };
                if patched != 0 {
                    let _ = write_mapped_value(fallback_va, patched);
                }
            }
            if runtime == 0 && patched != 0 {
                let _ = write_mapped_value(runtime_va, patched);
            }
            if table == 0 && patched != 0 {
                let _ = write_mapped_value(table_va, patched);
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
        let _ = write_mapped_value(lock_flag_va, 1u32);
    }

    let dbg_flags_va = base.saturating_add(UCRT_DBG_FLAGS_RVA);
    if dbg_flags_va >= base && dbg_flags_va < base.saturating_add(size) {
        let _ = write_mapped_value(dbg_flags_va, 0u8);
    }
}

fn kernelbase_locale_stub_ptr() -> u64 {
    static mut LOCALE_STUB_PTR: u64 = 0;
    unsafe {
        if LOCALE_STUB_PTR != 0 {
            return LOCALE_STUB_PTR;
        }
        let Some(ptr) = crate::alloc::alloc_zeroed(0x40, 16) else {
            return 0;
        };
        // kernelbase!init_locale reads u16 at [stub + 8]
        (ptr.add(8) as *mut u16).write_volatile(0x0c00);
        LOCALE_STUB_PTR = ptr as u64;
        LOCALE_STUB_PTR
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

fn loaded_image_info(base: u64) -> Option<(usize, bool)> {
    let entries = unsafe { &*DLL_RUNTIME.entries.get() };
    for entry in entries.iter() {
        if entry.state == ENTRY_READY && entry.base == base && entry.size != 0 {
            return Some((entry.size as usize, entry.user_backed != 0));
        }
    }
    None
}

fn mapped_range_kind(addr: u64, size: usize) -> Option<bool> {
    let Some(end) = addr.checked_add(size as u64) else {
        return None;
    };
    let entries = unsafe { &*DLL_RUNTIME.entries.get() };
    for entry in entries.iter() {
        if entry.state != ENTRY_READY || entry.base == 0 || entry.size == 0 {
            continue;
        }
        let start = entry.base;
        let limit = start.saturating_add(entry.size as u64);
        if addr >= start && end <= limit {
            return Some(entry.user_backed != 0);
        }
    }
    None
}

fn with_loaded_image_slice<R>(
    base: u64,
    size: usize,
    user_backed: bool,
    f: impl FnOnce(&[u8]) -> R,
) -> Option<R> {
    if user_backed {
        let pid = current_user_pid()?;
        return with_current_process_user_slice(pid, UserVa::new(base), size, VM_ACCESS_READ, f);
    }
    if size == 0 {
        return Some(f(&[]));
    }
    // SAFETY: kernel-backed DLL images use stable kernel memory.
    let bytes = unsafe { core::slice::from_raw_parts(base as *const u8, size) };
    Some(f(bytes))
}

fn read_mapped_value<T: Copy>(addr: u64) -> Option<T> {
    match mapped_range_kind(addr, size_of::<T>())? {
        true => read_current_user_mapped_value(addr as *const T),
        false => {
            // SAFETY: the address range was proven to lie inside a known
            // kernel-backed loaded image.
            Some(unsafe { (addr as *const T).read_volatile() })
        }
    }
}

fn write_mapped_value<T: Copy>(addr: u64, value: T) -> bool {
    match mapped_range_kind(addr, size_of::<T>()) {
        Some(true) => write_current_user_mapped_value(addr as *mut T, value),
        Some(false) => {
            // SAFETY: the address range was proven to lie inside a known
            // kernel-backed loaded image.
            unsafe {
                (addr as *mut T).write_volatile(value);
            }
            true
        }
        None => false,
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

fn try_open_path(path: &str) -> Option<FsFileHandle> {
    fs::open_readonly(path).ok()
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
    let (image_size, user_backed) = loaded_image_info(base)?;
    let (fn_rva_tbl, name_tbl, ord_tbl, num_names, num_funcs, _ord_base, exp_rva, exp_size) =
        with_loaded_image_slice(base, image_size, user_backed, |image| {
            read_export_dir(image)
        })??;
    let target = name.as_bytes();
    with_loaded_image_slice(base, image_size, user_backed, |image| {
        let image = image.as_ptr();
        for i in 0..num_names {
            // SAFETY: `image` points to the validated loaded image slice.
            unsafe {
                let name_rva = pe::ru32(image.add(name_tbl + i * 4)) as usize;
                let export_name = cstr_bytes_in_image(image, image_size, name_rva);
                if export_name == target {
                    let ord = pe::ru16(image.add(ord_tbl + i * 2)) as usize;
                    if ord >= num_funcs {
                        return None;
                    }
                    let fn_rva = pe::ru32(image.add(fn_rva_tbl + ord * 4));
                    if fn_rva == 0 {
                        return None;
                    }
                    return resolve_export_target(
                        image, image_size, base, fn_rva, exp_rva, exp_size, depth,
                    );
                }
            }
        }
        None
    })?
}

fn resolve_export_by_ordinal(base: u64, ordinal: u64, depth: u8) -> Option<u64> {
    let (image_size, user_backed) = loaded_image_info(base)?;
    let (fn_rva_tbl, _name_tbl, _ord_tbl, _num_names, num_funcs, ord_base, exp_rva, exp_size) =
        with_loaded_image_slice(base, image_size, user_backed, |image| {
            read_export_dir(image)
        })??;
    let idx = ordinal.wrapping_sub(ord_base) as usize;
    if idx >= num_funcs {
        return None;
    }
    with_loaded_image_slice(base, image_size, user_backed, |image| {
        let image = image.as_ptr();
        // SAFETY: `image` points to the validated loaded image slice.
        unsafe {
            let fn_rva = pe::ru32(image.add(fn_rva_tbl + idx * 4));
            if fn_rva == 0 {
                return None;
            }
            resolve_export_target(image, image_size, base, fn_rva, exp_rva, exp_size, depth)
        }
    })?
}

fn read_export_dir(image: &[u8]) -> Option<(usize, usize, usize, usize, usize, u64, u32, u32)> {
    let image_len = image.len();
    unsafe {
        let image = image.as_ptr();
        if image_len < 0x80 || pe::ru16(image) != pe::MZ_MAGIC {
            return None;
        }
        let lfanew = pe::ru32(image.add(60)) as usize;
        if lfanew + 24 + 116 > image_len {
            return None;
        }
        if pe::ru32(image.add(lfanew)) != pe::PE_MAGIC {
            return None;
        }

        let oh = image.add(lfanew + 24);
        let exp_rva = pe::ru32(oh.add(112)) as usize;
        let exp_size = pe::ru32(oh.add(116));
        if exp_rva == 0 || exp_size == 0 || exp_rva.checked_add(40)? > image_len {
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

fn resolve_export_target(
    image: *const u8,
    image_len: usize,
    base: u64,
    fn_rva: u32,
    exp_rva: u32,
    exp_size: u32,
    depth: u8,
) -> Option<u64> {
    let fn_rva_u64 = fn_rva as u64;
    let exp_lo = exp_rva as u64;
    let exp_hi = exp_lo.saturating_add(exp_size as u64);
    if fn_rva_u64 < exp_lo || fn_rva_u64 >= exp_hi {
        return Some(base + fn_rva_u64);
    }

    let forward = unsafe { cstr_bytes_in_image(image, image_len, fn_rva_u64 as usize) };
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

unsafe fn cstr_bytes_in_image<'a>(image: *const u8, image_len: usize, offset: usize) -> &'a [u8] {
    if offset >= image_len {
        return &[];
    }
    let mut len = 0usize;
    while offset + len < image_len && *image.add(offset + len) != 0 {
        len += 1;
        if len >= 512 {
            break;
        }
    }
    core::slice::from_raw_parts(image.add(offset), len)
}
