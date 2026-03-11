// PE32+ 加载器 — Guest Kernel 内运行
// 头部解析委托给 winemu_shared::pe，本模块只负责内存分配和加载

use crate::alloc;
use crate::hypercall;
use crate::mm::{UserVa, VM_ACCESS_READ, VM_ACCESS_WRITE, vm_alloc_region_typed, vm_protect_range};
use crate::mm::usercopy::{current_pid as current_user_pid, current_process_user_ptr, translate_user_va};
use crate::mm::VmaType;
use winemu_shared::pe::{self, PeError, PeHeaders};

// ── 错误类型 ─────────────────────────────────────────────────

#[derive(Debug)]
pub enum LdrError {
    Pe(PeError),
    NotArm64,
    AllocFailed,
    BadReloc,
    BadImport,
    ProtectFailed,
    IoError,
}

impl From<PeError> for LdrError {
    fn from(e: PeError) -> Self {
        LdrError::Pe(e)
    }
}

pub type LdrResult<T> = Result<T, LdrError>;

const HEADER_VIEW_SIZE: usize = 4096;
const PAGE_SIZE: u64 = 0x1000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

struct ImageBuffer {
    base: u64,
    ptr: *mut u8,
    size: usize,
    owner_pid: Option<u32>,
}

fn alloc_image_buffer(size: usize, vma_type: VmaType) -> LdrResult<ImageBuffer> {
    if let Some(pid) = current_user_pid() {
        let Some(base) = vm_alloc_region_typed(pid, 0, size as u64, 0x04, vma_type) else {
            return Err(LdrError::AllocFailed);
        };
        let Some(ptr) = current_process_user_ptr(pid, UserVa::new(base), size, VM_ACCESS_WRITE)
        else {
            return Err(LdrError::AllocFailed);
        };
        return Ok(ImageBuffer {
            base,
            ptr,
            size,
            owner_pid: Some(pid),
        });
    }

    let ptr = alloc::alloc_zeroed(size, PAGE_SIZE as usize).ok_or(LdrError::AllocFailed)?;
    Ok(ImageBuffer {
        base: ptr as u64,
        ptr,
        size,
        owner_pid: None,
    })
}

fn read_file_into_image(
    fd: u64,
    image: &ImageBuffer,
    image_off: u64,
    len: usize,
    file_off: u64,
) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = image_off.checked_add(len as u64) else {
        return false;
    };
    if end > image.size as u64 {
        return false;
    }

    if let Some(pid) = image.owner_pid {
        let mut done = 0usize;
        while done < len {
            let Some(cur_va) = UserVa::new(image.base).checked_add(image_off + done as u64) else {
                return false;
            };
            let Some(dst_pa) = translate_user_va(pid, cur_va, VM_ACCESS_WRITE) else {
                return false;
            };
            let page_off = (cur_va.get() as usize) & ((PAGE_SIZE as usize) - 1);
            let chunk = core::cmp::min(len - done, (PAGE_SIZE as usize) - page_off);
            let got = hypercall::host_read_phys(fd, dst_pa, chunk, file_off + done as u64);
            if got != chunk {
                return false;
            }
            done += chunk;
        }
        true
    } else {
        // SAFETY: bounds were checked above and the buffer belongs to this loader.
        let dst = unsafe { image.ptr.add(image_off as usize) };
        hypercall::host_read(fd, dst, len, file_off) == len
    }
}

fn section_nt_prot(chars: u32) -> u32 {
    let exec = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
    let read = (chars & IMAGE_SCN_MEM_READ) != 0;
    let write = (chars & IMAGE_SCN_MEM_WRITE) != 0;
    match (exec, read, write) {
        (true, _, true) => 0x40,
        (true, true, false) => 0x20,
        (true, false, false) => 0x10,
        (false, _, true) => 0x04,
        (false, true, false) => 0x02,
        _ => 0x01,
    }
}

pub fn finalize_loaded_image(image_base: u64) -> LdrResult<()> {
    let Some(pid) = current_user_pid() else {
        return Ok(());
    };
    let Some(ptr) =
        current_process_user_ptr(pid, UserVa::new(image_base), HEADER_VIEW_SIZE, VM_ACCESS_READ)
    else {
        return Err(LdrError::ProtectFailed);
    };
    // SAFETY: the current process mapping was validated above for header access.
    let hdrs = unsafe {
        PeHeaders::from_slice(core::slice::from_raw_parts(ptr as *const u8, HEADER_VIEW_SIZE))?
    };

    if vm_protect_range(pid, image_base, hdrs.size_of_headers as u64, 0x02).is_err() {
        return Err(LdrError::ProtectFailed);
    }

    for sec in hdrs.sections() {
        let sec_size = u64::from(sec.vsize.max(sec.raw_size));
        if sec_size == 0 {
            continue;
        }
        let sec_base = image_base.saturating_add(sec.vaddr as u64);
        if vm_protect_range(pid, sec_base, sec_size, section_nt_prot(sec.chars)).is_err() {
            return Err(LdrError::ProtectFailed);
        }
    }

    Ok(())
}

// ── 已加载镜像描述符 ─────────────────────────────────────────

pub struct LoadedImage {
    pub base: u64,
    pub size: usize,
    pub entry_rva: u32,
}

// ── 导入引用 ─────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub enum ImportRef<'a> {
    Name(&'a str),
    Ordinal(u16),
}

// ── 从 host fd 加载（零拷贝路径）─────────────────────────────

/// 从 host file descriptor 加载 PE。
/// 读取头部 → 解析 → 分配镜像 → 逐 section 读取 → 重定位 → 导入
pub unsafe fn load_from_fd(
    fd: u64,
    file_size: u64,
    vma_type: VmaType,
    resolve_import: impl Fn(&str, ImportRef) -> Option<u64>,
) -> LdrResult<LoadedImage> {
    // 1. 读取 PE 头部（4KB 足够覆盖 DOS + PE + section table）
    let hdr_buf = alloc::alloc_zeroed(HEADER_VIEW_SIZE, 16).ok_or(LdrError::AllocFailed)?;
    let read_len = HEADER_VIEW_SIZE.min(file_size as usize);
    let got = hypercall::host_read(fd, hdr_buf, read_len, 0);
    if got == 0 {
        crate::kerror!("ldr: failed to read PE headers");
        return Err(LdrError::IoError);
    }
    let hdr_slice = core::slice::from_raw_parts(hdr_buf as *const u8, got);

    // 2. 解析 PE 头
    let hdrs = PeHeaders::from_slice(hdr_slice)?;
    crate::kdebug!("ldr: parsed PE headers from fd");

    if hdrs.machine != pe::MACHINE_ARM64 {
        return Err(LdrError::NotArm64);
    }

    // 3. 分配镜像内存
    let image = alloc_image_buffer(hdrs.size_of_image as usize, vma_type)?;
    let buf = image.ptr;
    let load_base = image.base;

    // 4. 复制头部到镜像基址
    let hdr_copy = (hdrs.size_of_headers as usize).min(got);
    // SAFETY: `buf` points to a writable image buffer of at least `hdr_copy` bytes.
    core::ptr::copy_nonoverlapping(hdr_buf as *const u8, buf, hdr_copy);

    // 5. 逐 section 从 fd 读取
    for sec in hdrs.sections() {
        if sec.raw_size > 0 && sec.raw_off > 0 {
            let read_size = (sec.raw_size as usize).min(sec.vsize as usize);
            if !read_file_into_image(fd, &image, sec.vaddr as u64, read_size, sec.raw_off as u64)
            {
                crate::kerror!("ldr: section read failed");
                return Err(LdrError::IoError);
            }
        }
    }

    // 6. 基址重定位
    let delta = load_base.wrapping_sub(hdrs.image_base) as i64;
    if delta != 0 {
        if let Some(dir) = hdrs.data_dir(pe::DIR_BASERELOC) {
            if dir.is_present() {
                apply_relocations(buf, dir.rva as usize, dir.size as usize, delta)?;
            }
        }
    }

    // 7. 导入表
    if let Some(dir) = hdrs.data_dir(pe::DIR_IMPORT) {
        if dir.is_present() {
            apply_imports(buf, dir.rva as usize, &resolve_import)?;
        }
    }

    finalize_loaded_image(load_base)?;

    Ok(LoadedImage {
        base: load_base,
        size: hdrs.size_of_image as usize,
        entry_rva: hdrs.entry_rva,
    })
}

// ── 主加载函数（从内存 slice）───────────────────────────────

pub unsafe fn load(
    image: &[u8],
    vma_type: VmaType,
    resolve_import: impl Fn(&str, ImportRef) -> Option<u64>,
) -> LdrResult<LoadedImage> {
    let hdrs = PeHeaders::from_slice(image)?;
    crate::kdebug!("ldr: parsed PE headers");

    if hdrs.machine != pe::MACHINE_ARM64 {
        return Err(LdrError::NotArm64);
    }

    let image_buf = alloc_image_buffer(hdrs.size_of_image as usize, vma_type)?;
    let buf = image_buf.ptr;
    crate::kdebug!("ldr: alloc ok");
    let load_base = image_buf.base;

    // 先复制 PE headers（导出解析依赖 DOS/NT 头）
    let hdr_copy = (hdrs.size_of_headers as usize).min(image.len());
    if hdr_copy > 0 {
        // SAFETY: `buf` points to a writable image buffer of at least `hdr_copy` bytes.
        core::ptr::copy_nonoverlapping(image.as_ptr(), buf, hdr_copy);
    }

    // 复制各 section
    for sec in hdrs.sections() {
        if sec.raw_size > 0 {
            let src_off = sec.raw_off as usize;
            let dst_off = sec.vaddr as usize;
            let copy_len = (sec.raw_size as usize).min(sec.vsize as usize);
            if src_off + copy_len <= image.len() {
                // SAFETY: source/destination bounds are checked above and both buffers are valid.
                core::ptr::copy_nonoverlapping(
                    image.as_ptr().add(src_off),
                    buf.add(dst_off),
                    copy_len,
                );
            }
        }
    }

    // 基址重定位
    let delta = load_base.wrapping_sub(hdrs.image_base) as i64;
    if delta != 0 {
        if let Some(dir) = hdrs.data_dir(pe::DIR_BASERELOC) {
            if dir.is_present() {
                apply_relocations(buf, dir.rva as usize, dir.size as usize, delta)?;
            }
        }
    }

    // 导入表
    if let Some(dir) = hdrs.data_dir(pe::DIR_IMPORT) {
        if dir.is_present() {
            apply_imports(buf, dir.rva as usize, &resolve_import)?;
        }
    }

    finalize_loaded_image(load_base)?;

    Ok(LoadedImage {
        base: load_base,
        size: hdrs.size_of_image as usize,
        entry_rva: hdrs.entry_rva,
    })
}

/// Load PE image into memory (with relocations) but do not resolve IAT yet.
pub unsafe fn load_from_fd_unlinked(
    fd: u64,
    file_size: u64,
    vma_type: VmaType,
) -> LdrResult<LoadedImage> {
    let hdr_buf = alloc::alloc_zeroed(HEADER_VIEW_SIZE, 16).ok_or(LdrError::AllocFailed)?;
    let read_len = HEADER_VIEW_SIZE.min(file_size as usize);
    let got = hypercall::host_read(fd, hdr_buf, read_len, 0);
    if got == 0 {
        crate::kerror!("ldr: failed to read PE headers");
        return Err(LdrError::IoError);
    }
    let hdr_slice = core::slice::from_raw_parts(hdr_buf as *const u8, got);
    let hdrs = PeHeaders::from_slice(hdr_slice)?;
    crate::kdebug!("ldr: parsed PE headers");

    if hdrs.machine != pe::MACHINE_ARM64 {
        return Err(LdrError::NotArm64);
    }

    let image = alloc_image_buffer(hdrs.size_of_image as usize, vma_type)?;
    let buf = image.ptr;
    crate::kdebug!("ldr: alloc ok");
    let load_base = image.base;

    let hdr_copy = (hdrs.size_of_headers as usize).min(got);
    // SAFETY: `buf` points to a writable image buffer of at least `hdr_copy` bytes.
    core::ptr::copy_nonoverlapping(hdr_buf as *const u8, buf, hdr_copy);

    for sec in hdrs.sections() {
        if sec.raw_size > 0 && sec.raw_off > 0 {
            let read_size = (sec.raw_size as usize).min(sec.vsize as usize);
            if !read_file_into_image(fd, &image, sec.vaddr as u64, read_size, sec.raw_off as u64)
            {
                crate::kerror!("ldr: section read failed");
                return Err(LdrError::IoError);
            }
        }
    }

    let delta = load_base.wrapping_sub(hdrs.image_base) as i64;
    if delta != 0 {
        if let Some(dir) = hdrs.data_dir(pe::DIR_BASERELOC) {
            if dir.is_present() {
                apply_relocations(buf, dir.rva as usize, dir.size as usize, delta)?;
            }
        }
    }

    Ok(LoadedImage {
        base: load_base,
        size: hdrs.size_of_image as usize,
        entry_rva: hdrs.entry_rva,
    })
}

/// Load PE image into memory (with relocations) but do not resolve IAT yet.
pub unsafe fn load_unlinked(image: &[u8], vma_type: VmaType) -> LdrResult<LoadedImage> {
    let hdrs = PeHeaders::from_slice(image)?;
    crate::kdebug!("ldr: parsed PE headers");

    if hdrs.machine != pe::MACHINE_ARM64 {
        return Err(LdrError::NotArm64);
    }

    let image_buf = alloc_image_buffer(hdrs.size_of_image as usize, vma_type)?;
    let buf = image_buf.ptr;
    crate::kdebug!("ldr: alloc ok");
    let load_base = image_buf.base;

    let hdr_copy = (hdrs.size_of_headers as usize).min(image.len());
    if hdr_copy > 0 {
        // SAFETY: `buf` points to a writable image buffer of at least `hdr_copy` bytes.
        core::ptr::copy_nonoverlapping(image.as_ptr(), buf, hdr_copy);
    }

    for sec in hdrs.sections() {
        if sec.raw_size > 0 {
            let src_off = sec.raw_off as usize;
            let dst_off = sec.vaddr as usize;
            let copy_len = (sec.raw_size as usize).min(sec.vsize as usize);
            if src_off + copy_len <= image.len() {
                // SAFETY: source/destination bounds are checked above and both buffers are valid.
                core::ptr::copy_nonoverlapping(
                    image.as_ptr().add(src_off),
                    buf.add(dst_off),
                    copy_len,
                );
            }
        }
    }

    let delta = load_base.wrapping_sub(hdrs.image_base) as i64;
    if delta != 0 {
        if let Some(dir) = hdrs.data_dir(pe::DIR_BASERELOC) {
            if dir.is_present() {
                apply_relocations(buf, dir.rva as usize, dir.size as usize, delta)?;
            }
        }
    }

    Ok(LoadedImage {
        base: load_base,
        size: hdrs.size_of_image as usize,
        entry_rva: hdrs.entry_rva,
    })
}

/// Resolve and patch import table for an already loaded image.
pub unsafe fn link_imports(
    image_base: u64,
    resolve_import: impl Fn(&str, ImportRef) -> Option<u64>,
) -> LdrResult<()> {
    let Some((import_rva, import_size)) = read_import_dir(image_base as *const u8) else {
        return Ok(());
    };
    if import_rva == 0 || import_size == 0 {
        return Ok(());
    }
    apply_imports(image_base as *mut u8, import_rva, &resolve_import)
}

unsafe fn read_import_dir(image: *const u8) -> Option<(usize, usize)> {
    if pe::ru16(image) != pe::MZ_MAGIC {
        return None;
    }
    let lfanew = pe::ru32(image.add(60)) as usize;
    if pe::ru32(image.add(lfanew)) != pe::PE_MAGIC {
        return None;
    }
    let oh = image.add(lfanew + 24);
    let import_rva = pe::ru32(oh.add(112 + pe::DIR_IMPORT * 8)) as usize;
    let import_size = pe::ru32(oh.add(112 + pe::DIR_IMPORT * 8 + 4)) as usize;
    Some((import_rva, import_size))
}

// ── 重定位 ───────────────────────────────────────────────────

unsafe fn apply_relocations(
    base: *mut u8,
    reloc_rva: usize,
    reloc_size: usize,
    delta: i64,
) -> LdrResult<()> {
    let mut off = 0usize;
    while off + 8 <= reloc_size {
        let blk = base.add(reloc_rva + off);
        let page_rva = pe::ru32(blk) as usize;
        let block_size = pe::ru32(blk.add(4)) as usize;
        if block_size < 8 {
            break;
        }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry = pe::ru16(blk.add(8 + i * 2));
            let typ = (entry >> 12) as u8;
            let page_off = (entry & 0x0FFF) as usize;
            match typ {
                pe::REL_ABSOLUTE => {}
                pe::REL_DIR64 => {
                    let target = base.add(page_rva + page_off);
                    let val = pe::ru64(target);
                    pe::wu64(target, (val as i64).wrapping_add(delta) as u64);
                }
                _ => return Err(LdrError::BadReloc),
            }
        }
        off += block_size;
    }
    Ok(())
}

// ── 导入 ─────────────────────────────────────────────────────

unsafe fn apply_imports(
    base: *mut u8,
    imp_rva: usize,
    resolve: &impl Fn(&str, ImportRef) -> Option<u64>,
) -> LdrResult<()> {
    const ID_ORIG_FIRST_THUNK: usize = 0;
    const ID_NAME_RVA: usize = 12;
    const ID_FIRST_THUNK: usize = 16;
    const ID_SIZE: usize = 20;

    let mut desc_off = imp_rva;
    loop {
        let desc = base.add(desc_off);
        let name_rva = pe::ru32(desc.add(ID_NAME_RVA)) as usize;
        if name_rva == 0 {
            break;
        }

        let dll_name = cstr(base.add(name_rva));
        let iat_rva = pe::ru32(desc.add(ID_FIRST_THUNK)) as usize;
        let oft_rva = {
            let v = pe::ru32(desc.add(ID_ORIG_FIRST_THUNK)) as usize;
            if v != 0 {
                v
            } else {
                iat_rva
            }
        };

        let mut slot = 0usize;
        loop {
            let thunk = pe::ru64(base.add(oft_rva + slot * 8));
            if thunk == 0 {
                break;
            }
            let iref = if thunk & (1u64 << 63) != 0 {
                ImportRef::Ordinal((thunk & 0xFFFF) as u16)
            } else {
                let ibn = (thunk & 0x7FFF_FFFF_FFFF_FFFF) as usize;
                ImportRef::Name(cstr(base.add(ibn + 2)))
            };
            let (resolved_dll, resolved_iref, remapped) = match iref {
                ImportRef::Name(fn_name)
                    if dll_name.eq_ignore_ascii_case("kernel32.dll")
                        && should_remap_kernel32_to_ntdll(fn_name) =>
                {
                    ("ntdll.dll", ImportRef::Name(fn_name), true)
                }
                _ => (dll_name, iref, false),
            };
            let Some(addr) = resolve(resolved_dll, resolved_iref) else {
                crate::log::debug_print("ldr: unresolved import ");
                crate::log::debug_print(dll_name);
                crate::log::debug_print("!");
                match iref {
                    ImportRef::Name(fn_name) => {
                        crate::log::debug_print(fn_name);
                    }
                    ImportRef::Ordinal(ord) => {
                        crate::log::debug_print("#");
                        crate::log::debug_u64(ord as u64);
                    }
                }
                if remapped {
                    crate::log::debug_print(" via ");
                    crate::log::debug_print(resolved_dll);
                }
                crate::log::debug_print("\n");
                return Err(LdrError::BadImport);
            };
            if let ImportRef::Name(fn_name) = iref {
                if fn_name == "RtlOpenCrossProcessEmulatorWorkConnection" {
                    crate::log::debug_print("ldr: import ");
                    crate::log::debug_print(dll_name);
                    crate::log::debug_print("!");
                    crate::log::debug_print(fn_name);
                    if remapped {
                        crate::log::debug_print(" => ");
                        crate::log::debug_print(resolved_dll);
                    }
                    crate::log::debug_print(" -> ");
                    crate::log::debug_u64(addr);
                    crate::log::debug_print(" slot=");
                    crate::log::debug_u64(
                        (base as u64).saturating_add(iat_rva as u64 + (slot as u64) * 8),
                    );
                    crate::log::debug_print("\n");
                }
                if dll_name.eq_ignore_ascii_case("kernel32.dll")
                    && (fn_name == "GetProcessHeap"
                        || fn_name == "HeapAlloc"
                        || fn_name == "HeapFree"
                        || fn_name == "HeapReAlloc"
                        || fn_name == "GlobalAlloc"
                        || fn_name == "GlobalReAlloc"
                        || fn_name == "GlobalFree"
                        || fn_name == "GlobalLock"
                        || fn_name == "GlobalUnlock"
                        || fn_name == "GlobalHandle"
                        || fn_name == "GlobalSize"
                        || fn_name == "GlobalFlags"
                        || fn_name == "LocalAlloc"
                        || fn_name == "LocalReAlloc"
                        || fn_name == "LocalFree"
                        || fn_name == "LocalLock"
                        || fn_name == "LocalUnlock"
                        || fn_name == "LocalHandle"
                        || fn_name == "LocalSize"
                        || fn_name == "LocalFlags"
                        || fn_name == "EnterCriticalSection"
                        || fn_name == "LeaveCriticalSection"
                        || fn_name == "RaiseException")
                {
                    crate::log::debug_print("ldr: import ");
                    crate::log::debug_print(dll_name);
                    crate::log::debug_print("!");
                    crate::log::debug_print(fn_name);
                    if remapped {
                        crate::log::debug_print(" => ");
                        crate::log::debug_print(resolved_dll);
                    }
                    crate::log::debug_print(" -> ");
                    crate::log::debug_u64(addr);
                    crate::log::debug_print("\n");
                }
            }
            pe::wu64(base.add(iat_rva + slot * 8), addr);
            slot += 1;
        }
        desc_off += ID_SIZE;
    }
    Ok(())
}

fn should_remap_kernel32_to_ntdll(fn_name: &str) -> bool {
    matches!(
        fn_name,
        "GlobalAlloc"
            | "GlobalReAlloc"
            | "GlobalFree"
            | "GlobalLock"
            | "GlobalUnlock"
            | "GlobalHandle"
            | "GlobalSize"
            | "GlobalFlags"
            | "LocalAlloc"
            | "LocalReAlloc"
            | "LocalFree"
            | "LocalLock"
            | "LocalUnlock"
            | "LocalHandle"
            | "LocalSize"
            | "LocalFlags"
    )
}

unsafe fn cstr<'a>(p: *const u8) -> &'a str {
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    core::str::from_utf8_unchecked(core::slice::from_raw_parts(p, len))
}
