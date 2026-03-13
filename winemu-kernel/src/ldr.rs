// PE32+ 加载器 — Guest Kernel 内运行
// 头部解析委托给 winemu_shared::pe，本模块只负责内存分配和加载

use crate::alloc;
use crate::fs::{self, FsFileHandle};
use crate::mm::usercopy::{
    copy_to_process_user, current_pid as current_user_pid, translate_user_va,
    with_current_process_user_slice, with_current_process_user_slice_mut,
};
use crate::mm::VmaType;
use crate::mm::{vm_alloc_region_typed, vm_protect_range, UserVa, VM_ACCESS_READ, VM_ACCESS_WRITE};
use crate::rust_alloc::vec::Vec;
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

impl ImageBuffer {
    fn copy_from_bytes(&self, image_off: usize, src: &[u8]) -> bool {
        let Some(end) = image_off.checked_add(src.len()) else {
            return false;
        };
        if end > self.size {
            return false;
        }
        if src.is_empty() {
            return true;
        }

        if let Some(pid) = self.owner_pid {
            let Some(dst_va) = UserVa::new(self.base).checked_add(image_off as u64) else {
                return false;
            };
            return copy_to_process_user(pid, dst_va, src.as_ptr(), src.len());
        }

        // SAFETY: bounds were checked above and `ptr` owns the backing buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr.add(image_off), src.len());
        }
        true
    }

    fn with_slice_mut<R>(&self, access: u8, f: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
        if let Some(pid) = self.owner_pid {
            return with_current_process_user_slice_mut(
                pid,
                UserVa::new(self.base),
                self.size,
                access,
                f,
            );
        }

        if self.size == 0 {
            let mut empty = [];
            return Some(f(&mut empty));
        }

        // SAFETY: `ptr` owns a writable buffer of `size` bytes for kernel-backed images.
        let slice = unsafe { core::slice::from_raw_parts_mut(self.ptr, self.size) };
        Some(f(slice))
    }
}

fn alloc_image_buffer(
    size: usize,
    preferred_base: u64,
    allow_relocate: bool,
    vma_type: VmaType,
) -> LdrResult<ImageBuffer> {
    if let Some(pid) = current_user_pid() {
        let exact = if preferred_base != 0 {
            vm_alloc_region_typed(pid, preferred_base, size as u64, 0x04, vma_type)
        } else {
            None
        };
        let base = if allow_relocate {
            exact.or_else(|| vm_alloc_region_typed(pid, 0, size as u64, 0x04, vma_type))
        } else {
            exact
        };
        let Some(base) = base else {
            return Err(LdrError::AllocFailed);
        };
        return Ok(ImageBuffer {
            base,
            ptr: core::ptr::null_mut(),
            size,
            owner_pid: Some(pid),
        });
    }

    if !allow_relocate && preferred_base != 0 {
        crate::kdebug!(
            "ldr: non-reloc image requires preferred base={:#x}",
            preferred_base
        );
        return Err(LdrError::BadReloc);
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
    file: FsFileHandle,
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
            if fs::read_exact_at_phys(file, dst_pa, chunk, file_off + done as u64).is_err() {
                return false;
            }
            done += chunk;
        }
        true
    } else {
        // SAFETY: bounds were checked above and the buffer belongs to this loader.
        let dst = unsafe { image.ptr.add(image_off as usize) };
        fs::read_exact_at(file, dst, len, file_off).is_ok()
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
    let (headers_size, sections) = with_current_process_user_slice(
        pid,
        UserVa::new(image_base),
        HEADER_VIEW_SIZE,
        VM_ACCESS_READ,
        |bytes| -> Result<(u64, Vec<(u64, u64, u32)>), LdrError> {
            let hdrs = PeHeaders::from_slice(bytes)?;
            let mut sections = Vec::new();
            if sections.try_reserve(hdrs.num_sections as usize).is_err() {
                return Err(LdrError::AllocFailed);
            }
            for sec in hdrs.sections() {
                let sec_size = u64::from(sec.vsize.max(sec.raw_size));
                if sec_size == 0 {
                    continue;
                }
                sections.push((
                    image_base.saturating_add(sec.vaddr as u64),
                    sec_size,
                    section_nt_prot(sec.chars),
                ));
            }
            Ok((hdrs.size_of_headers as u64, sections))
        },
    )
    .ok_or(LdrError::ProtectFailed)??;

    if vm_protect_range(pid, image_base, headers_size, 0x02).is_err() {
        return Err(LdrError::ProtectFailed);
    }

    for (sec_base, sec_size, sec_prot) in sections {
        if vm_protect_range(pid, sec_base, sec_size, sec_prot).is_err() {
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

// ── 从 kernel fs file 加载（顺序读取路径）────────────────────

/// 从 kernel fs file 加载 PE。
/// 读取头部 → 解析 → 分配镜像 → 逐 section 读取 → 重定位 → 导入
pub unsafe fn load_from_file(
    file: FsFileHandle,
    file_size: u64,
    vma_type: VmaType,
    resolve_import: impl Fn(&str, ImportRef) -> Option<u64>,
) -> LdrResult<LoadedImage> {
    // 1. 读取 PE 头部（4KB 足够覆盖 DOS + PE + section table）
    let hdr_buf = alloc::alloc_zeroed(HEADER_VIEW_SIZE, 16).ok_or(LdrError::AllocFailed)?;
    let read_len = HEADER_VIEW_SIZE.min(file_size as usize);
    let got = fs::read_at(fs::FsReadRequest {
        file,
        dst: hdr_buf,
        len: read_len,
        offset: 0,
    })
    .map_err(|_| LdrError::IoError)?;
    if got == 0 {
        crate::kerror!("ldr: failed to read PE headers");
        return Err(LdrError::IoError);
    }
    let hdr_slice = core::slice::from_raw_parts(hdr_buf as *const u8, got);

    // 2. 解析 PE 头
    let hdrs = PeHeaders::from_slice(hdr_slice)?;
    crate::ktrace!("ldr: parsed PE headers from fd");

    if hdrs.machine != pe::MACHINE_ARM64 {
        return Err(LdrError::NotArm64);
    }

    let reloc_dir = hdrs
        .data_dir(pe::DIR_BASERELOC)
        .filter(|dir| dir.is_present());

    // 3. 分配镜像内存
    let image = alloc_image_buffer(
        hdrs.size_of_image as usize,
        hdrs.image_base,
        reloc_dir.is_some(),
        vma_type,
    )?;
    let load_base = image.base;

    // 4. 复制头部到镜像基址
    let hdr_copy = (hdrs.size_of_headers as usize).min(got);
    if !image.copy_from_bytes(0, &hdr_slice[..hdr_copy]) {
        return Err(LdrError::AllocFailed);
    }

    // 5. 逐 section 从 fd 读取
    for sec in hdrs.sections() {
        if sec.raw_size > 0 && sec.raw_off > 0 {
            let read_size = (sec.raw_size as usize).min(sec.vsize as usize);
            if !read_file_into_image(
                file,
                &image,
                sec.vaddr as u64,
                read_size,
                sec.raw_off as u64,
            ) {
                crate::kerror!("ldr: section read failed");
                return Err(LdrError::IoError);
            }
        }
    }

    // 6. 基址重定位
    let delta = load_base.wrapping_sub(hdrs.image_base) as i64;
    if delta != 0 {
        let Some(dir) = reloc_dir else {
            crate::kdebug!(
                "ldr: non-reloc image loaded away from preferred base load={:#x} image={:#x}",
                load_base,
                hdrs.image_base
            );
            return Err(LdrError::BadReloc);
        };
        image
            .with_slice_mut(VM_ACCESS_WRITE, |buf| unsafe {
                apply_relocations(buf.as_mut_ptr(), dir.rva as usize, dir.size as usize, delta)
            })
            .ok_or(LdrError::AllocFailed)??;
    }

    // 7. 导入表
    if let Some(dir) = hdrs.data_dir(pe::DIR_IMPORT) {
        if dir.is_present() {
            image
                .with_slice_mut(VM_ACCESS_WRITE, |buf| unsafe {
                    apply_imports(buf.as_mut_ptr(), dir.rva as usize, &resolve_import)
                })
                .ok_or(LdrError::AllocFailed)??;
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
    crate::ktrace!("ldr: parsed PE headers");

    if hdrs.machine != pe::MACHINE_ARM64 {
        return Err(LdrError::NotArm64);
    }

    let reloc_dir = hdrs
        .data_dir(pe::DIR_BASERELOC)
        .filter(|dir| dir.is_present());
    let image_buf = alloc_image_buffer(
        hdrs.size_of_image as usize,
        hdrs.image_base,
        reloc_dir.is_some(),
        vma_type,
    )?;
    crate::ktrace!("ldr: alloc ok");
    let load_base = image_buf.base;

    // 先复制 PE headers（导出解析依赖 DOS/NT 头）
    let hdr_copy = (hdrs.size_of_headers as usize).min(image.len());
    if !image_buf.copy_from_bytes(0, &image[..hdr_copy]) {
        return Err(LdrError::AllocFailed);
    }

    // 复制各 section
    for sec in hdrs.sections() {
        if sec.raw_size > 0 {
            let src_off = sec.raw_off as usize;
            let dst_off = sec.vaddr as usize;
            let copy_len = (sec.raw_size as usize).min(sec.vsize as usize);
            if src_off + copy_len <= image.len() {
                if !image_buf.copy_from_bytes(dst_off, &image[src_off..src_off + copy_len]) {
                    return Err(LdrError::AllocFailed);
                }
            }
        }
    }

    // 基址重定位
    let delta = load_base.wrapping_sub(hdrs.image_base) as i64;
    if delta != 0 {
        let Some(dir) = reloc_dir else {
            crate::kdebug!(
                "ldr: non-reloc image loaded away from preferred base load={:#x} image={:#x}",
                load_base,
                hdrs.image_base
            );
            return Err(LdrError::BadReloc);
        };
        image_buf
            .with_slice_mut(VM_ACCESS_WRITE, |buf| unsafe {
                apply_relocations(buf.as_mut_ptr(), dir.rva as usize, dir.size as usize, delta)
            })
            .ok_or(LdrError::AllocFailed)??;
    }

    // 导入表
    if let Some(dir) = hdrs.data_dir(pe::DIR_IMPORT) {
        if dir.is_present() {
            image_buf
                .with_slice_mut(VM_ACCESS_WRITE, |buf| unsafe {
                    apply_imports(buf.as_mut_ptr(), dir.rva as usize, &resolve_import)
                })
                .ok_or(LdrError::AllocFailed)??;
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
pub unsafe fn load_from_file_unlinked(
    file: FsFileHandle,
    file_size: u64,
    vma_type: VmaType,
) -> LdrResult<LoadedImage> {
    let hdr_buf = alloc::alloc_zeroed(HEADER_VIEW_SIZE, 16).ok_or(LdrError::AllocFailed)?;
    let read_len = HEADER_VIEW_SIZE.min(file_size as usize);
    let got = fs::read_at(fs::FsReadRequest {
        file,
        dst: hdr_buf,
        len: read_len,
        offset: 0,
    })
    .map_err(|_| LdrError::IoError)?;
    if got == 0 {
        crate::kerror!("ldr: failed to read PE headers");
        return Err(LdrError::IoError);
    }
    let hdr_slice = core::slice::from_raw_parts(hdr_buf as *const u8, got);
    let hdrs = PeHeaders::from_slice(hdr_slice)?;
    crate::ktrace!("ldr: parsed PE headers");

    if hdrs.machine != pe::MACHINE_ARM64 {
        return Err(LdrError::NotArm64);
    }

    let reloc_dir = hdrs
        .data_dir(pe::DIR_BASERELOC)
        .filter(|dir| dir.is_present());
    let image = alloc_image_buffer(
        hdrs.size_of_image as usize,
        hdrs.image_base,
        reloc_dir.is_some(),
        vma_type,
    )?;
    crate::ktrace!("ldr: alloc ok");
    let load_base = image.base;

    let hdr_copy = (hdrs.size_of_headers as usize).min(got);
    if !image.copy_from_bytes(0, &hdr_slice[..hdr_copy]) {
        crate::kdebug!(
            "ldr: header copy failed base={:#x} size={:#x} hdr_copy={:#x}",
            load_base,
            hdrs.size_of_image,
            hdr_copy
        );
        return Err(LdrError::AllocFailed);
    }

    for sec in hdrs.sections() {
        if sec.raw_size > 0 && sec.raw_off > 0 {
            let read_size = (sec.raw_size as usize).min(sec.vsize as usize);
            if !read_file_into_image(
                file,
                &image,
                sec.vaddr as u64,
                read_size,
                sec.raw_off as u64,
            ) {
                crate::kerror!(
                    "ldr: section read failed name={:?} vaddr={:#x} raw_off={:#x} raw_size={:#x} vsize={:#x}",
                    sec.name,
                    sec.vaddr,
                    sec.raw_off,
                    sec.raw_size,
                    sec.vsize
                );
                return Err(LdrError::IoError);
            }
        }
    }

    let delta = load_base.wrapping_sub(hdrs.image_base) as i64;
    if delta != 0 {
        let Some(dir) = reloc_dir else {
            crate::kdebug!(
                "ldr: non-reloc image loaded away from preferred base load={:#x} image={:#x}",
                load_base,
                hdrs.image_base
            );
            return Err(LdrError::BadReloc);
        };
        image
            .with_slice_mut(VM_ACCESS_WRITE, |buf| unsafe {
                apply_relocations(buf.as_mut_ptr(), dir.rva as usize, dir.size as usize, delta)
            })
            .ok_or_else(|| {
                crate::kdebug!(
                    "ldr: reloc view failed base={:#x} size={:#x} reloc_rva={:#x} reloc_size={:#x}",
                    load_base,
                    hdrs.size_of_image,
                    dir.rva,
                    dir.size
                );
                LdrError::AllocFailed
            })??;
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
    crate::ktrace!("ldr: parsed PE headers");

    if hdrs.machine != pe::MACHINE_ARM64 {
        return Err(LdrError::NotArm64);
    }

    let reloc_dir = hdrs
        .data_dir(pe::DIR_BASERELOC)
        .filter(|dir| dir.is_present());
    let image_buf = alloc_image_buffer(
        hdrs.size_of_image as usize,
        hdrs.image_base,
        reloc_dir.is_some(),
        vma_type,
    )?;
    crate::ktrace!("ldr: alloc ok");
    let load_base = image_buf.base;

    let hdr_copy = (hdrs.size_of_headers as usize).min(image.len());
    if !image_buf.copy_from_bytes(0, &image[..hdr_copy]) {
        return Err(LdrError::AllocFailed);
    }

    for sec in hdrs.sections() {
        if sec.raw_size > 0 {
            let src_off = sec.raw_off as usize;
            let dst_off = sec.vaddr as usize;
            let copy_len = (sec.raw_size as usize).min(sec.vsize as usize);
            if src_off + copy_len <= image.len() {
                if !image_buf.copy_from_bytes(dst_off, &image[src_off..src_off + copy_len]) {
                    return Err(LdrError::AllocFailed);
                }
            }
        }
    }

    let delta = load_base.wrapping_sub(hdrs.image_base) as i64;
    if delta != 0 {
        let Some(dir) = reloc_dir else {
            crate::kdebug!(
                "ldr: non-reloc image loaded away from preferred base load={:#x} image={:#x}",
                load_base,
                hdrs.image_base
            );
            return Err(LdrError::BadReloc);
        };
        image_buf
            .with_slice_mut(VM_ACCESS_WRITE, |buf| unsafe {
                apply_relocations(buf.as_mut_ptr(), dir.rva as usize, dir.size as usize, delta)
            })
            .ok_or(LdrError::AllocFailed)??;
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
    if let Some(pid) = current_user_pid() {
        let (image_size, import_rva, import_size) = with_current_process_user_slice(
            pid,
            UserVa::new(image_base),
            HEADER_VIEW_SIZE,
            VM_ACCESS_READ,
            |bytes| -> Result<(usize, usize, usize), LdrError> {
                let hdrs = PeHeaders::from_slice(bytes)?;
                let dir = hdrs
                    .data_dir(pe::DIR_IMPORT)
                    .unwrap_or(pe::DataDir { rva: 0, size: 0 });
                Ok((
                    hdrs.size_of_image as usize,
                    dir.rva as usize,
                    dir.size as usize,
                ))
            },
        )
        .ok_or_else(|| {
            crate::kdebug!(
                "ldr: import header view failed pid={} base={:#x}",
                pid,
                image_base
            );
            LdrError::ProtectFailed
        })??;
        if import_rva == 0 || import_size == 0 {
            return Ok(());
        }
        with_current_process_user_slice_mut(
            pid,
            UserVa::new(image_base),
            image_size,
            VM_ACCESS_WRITE,
            |image| unsafe { apply_imports(image.as_mut_ptr(), import_rva, &resolve_import) },
        )
        .ok_or_else(|| {
            crate::kdebug!(
                "ldr: import patch view failed pid={} base={:#x} size={:#x} import_rva={:#x} import_size={:#x}",
                pid,
                image_base,
                image_size,
                import_rva,
                import_size
            );
            LdrError::ProtectFailed
        })??;
        return Ok(());
    }

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
                ImportRef::Name(fn_name) if should_remap_import_to_ntdll(dll_name, fn_name) => {
                    ("ntdll.dll", ImportRef::Name(fn_name), true)
                }
                _ => (dll_name, iref, false),
            };
            let Some(addr) = resolve(resolved_dll, resolved_iref) else {
                match iref {
                    ImportRef::Name(fn_name) => {
                        if remapped {
                            crate::kdebug!(
                                "ldr: unresolved import {}!{} via {}",
                                dll_name,
                                fn_name,
                                resolved_dll
                            );
                        } else {
                            crate::kdebug!("ldr: unresolved import {}!{}", dll_name, fn_name);
                        }
                    }
                    ImportRef::Ordinal(ord) => {
                        if remapped {
                            crate::kdebug!(
                                "ldr: unresolved import {}!#{} via {}",
                                dll_name,
                                ord,
                                resolved_dll
                            );
                        } else {
                            crate::kdebug!("ldr: unresolved import {}!#{}", dll_name, ord);
                        }
                    }
                }
                return Err(LdrError::BadImport);
            };
            if let ImportRef::Name(fn_name) = iref {
                if fn_name == "RtlOpenCrossProcessEmulatorWorkConnection"
                    && crate::log::log_enabled(crate::log::LogLevel::Trace)
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
                    && crate::log::log_enabled(crate::log::LogLevel::Trace)
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

fn should_remap_import_to_ntdll(dll_name: &str, fn_name: &str) -> bool {
    if dll_name.eq_ignore_ascii_case("kernel32.dll") {
        return matches!(
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
                | "MultiByteToWideChar"
                | "WideCharToMultiByte"
        );
    }
    if dll_name.eq_ignore_ascii_case("kernelbase.dll") {
        return matches!(fn_name, "MultiByteToWideChar" | "WideCharToMultiByte");
    }
    false
}

unsafe fn cstr<'a>(p: *const u8) -> &'a str {
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    core::str::from_utf8_unchecked(core::slice::from_raw_parts(p, len))
}
