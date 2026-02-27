// PE32+ 加载器 — Guest Kernel 内运行
// 头部解析委托给 winemu_shared::pe，本模块只负责内存分配和加载

use winemu_shared::pe::{self, PeHeaders, PeError};
use crate::alloc;
use crate::hypercall;

// ── 错误类型 ─────────────────────────────────────────────────

#[derive(Debug)]
pub enum LdrError {
    Pe(PeError),
    NotArm64,
    AllocFailed,
    BadReloc,
    BadImport,
    IoError,
}

impl From<PeError> for LdrError {
    fn from(e: PeError) -> Self { LdrError::Pe(e) }
}

pub type LdrResult<T> = Result<T, LdrError>;

// ── 已加载镜像描述符 ─────────────────────────────────────────

pub struct LoadedImage {
    pub base:      u64,
    pub size:      usize,
    pub entry_rva: u32,
}

// ── 导入引用 ─────────────────────────────────────────────────

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
    resolve_import: impl Fn(&str, ImportRef) -> Option<u64>,
) -> LdrResult<LoadedImage> {
    // 1. 读取 PE 头部（4KB 足够覆盖 DOS + PE + section table）
    const HDR_BUF_SIZE: usize = 4096;
    let hdr_buf = alloc::alloc_zeroed(HDR_BUF_SIZE, 16)
        .ok_or(LdrError::AllocFailed)?;
    let read_len = HDR_BUF_SIZE.min(file_size as usize);
    let got = hypercall::host_read(fd, hdr_buf, read_len, 0);
    if got == 0 {
        hypercall::debug_print("ldr: failed to read PE headers\n");
        return Err(LdrError::IoError);
    }
    let hdr_slice = core::slice::from_raw_parts(hdr_buf as *const u8, got);

    // 2. 解析 PE 头
    let hdrs = PeHeaders::from_slice(hdr_slice)?;
    hypercall::debug_print("ldr: parsed PE headers from fd\n");

    if hdrs.machine != pe::MACHINE_ARM64 {
        return Err(LdrError::NotArm64);
    }

    // 3. 分配镜像内存
    let buf = alloc::alloc_zeroed(hdrs.size_of_image as usize, 4096)
        .ok_or(LdrError::AllocFailed)?;
    let load_base = buf as u64;

    // 4. 复制头部到镜像基址
    let hdr_copy = (hdrs.size_of_headers as usize).min(got);
    core::ptr::copy_nonoverlapping(hdr_buf as *const u8, buf, hdr_copy);

    // 5. 逐 section 从 fd 读取
    for sec in hdrs.sections() {
        if sec.raw_size > 0 && sec.raw_off > 0 {
            let dst = buf.add(sec.vaddr as usize);
            let read_size = (sec.raw_size as usize).min(sec.vsize as usize);
            let n = hypercall::host_read(fd, dst, read_size, sec.raw_off as u64);
            if n == 0 && read_size > 0 {
                hypercall::debug_print("ldr: section read failed\n");
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

    Ok(LoadedImage {
        base:      load_base,
        size:      hdrs.size_of_image as usize,
        entry_rva: hdrs.entry_rva,
    })
}

// ── 主加载函数（从内存 slice）───────────────────────────────

pub unsafe fn load(
    image: &[u8],
    resolve_import: impl Fn(&str, ImportRef) -> Option<u64>,
) -> LdrResult<LoadedImage> {
    let hdrs = PeHeaders::from_slice(image)?;
    crate::hypercall::debug_print("ldr: parsed PE headers\n");

    if hdrs.machine != pe::MACHINE_ARM64 {
        return Err(LdrError::NotArm64);
    }

    let buf = alloc::alloc_zeroed(hdrs.size_of_image as usize, 4096)
        .ok_or(LdrError::AllocFailed)?;
    crate::hypercall::debug_print("ldr: alloc ok\n");
    let load_base = buf as u64;

    // 复制各 section
    for sec in hdrs.sections() {
        if sec.raw_size > 0 {
            let src_off  = sec.raw_off as usize;
            let dst_off  = sec.vaddr as usize;
            let copy_len = (sec.raw_size as usize).min(sec.vsize as usize);
            if src_off + copy_len <= image.len() {
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

    Ok(LoadedImage {
        base:      load_base,
        size:      hdrs.size_of_image as usize,
        entry_rva: hdrs.entry_rva,
    })
}

// ── 重定位 ───────────────────────────────────────────────────

unsafe fn apply_relocations(
    base: *mut u8, reloc_rva: usize, reloc_size: usize, delta: i64,
) -> LdrResult<()> {
    let mut off = 0usize;
    while off + 8 <= reloc_size {
        let blk        = base.add(reloc_rva + off);
        let page_rva   = pe::ru32(blk) as usize;
        let block_size = pe::ru32(blk.add(4)) as usize;
        if block_size < 8 { break; }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry    = pe::ru16(blk.add(8 + i * 2));
            let typ      = (entry >> 12) as u8;
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
    base: *mut u8, imp_rva: usize,
    resolve: &impl Fn(&str, ImportRef) -> Option<u64>,
) -> LdrResult<()> {
    const ID_ORIG_FIRST_THUNK: usize = 0;
    const ID_NAME_RVA:         usize = 12;
    const ID_FIRST_THUNK:      usize = 16;
    const ID_SIZE:             usize = 20;

    let mut desc_off = imp_rva;
    loop {
        let desc     = base.add(desc_off);
        let name_rva = pe::ru32(desc.add(ID_NAME_RVA)) as usize;
        if name_rva == 0 { break; }

        let dll_name = cstr(base.add(name_rva));
        let iat_rva  = pe::ru32(desc.add(ID_FIRST_THUNK)) as usize;
        let oft_rva  = {
            let v = pe::ru32(desc.add(ID_ORIG_FIRST_THUNK)) as usize;
            if v != 0 { v } else { iat_rva }
        };

        let mut slot = 0usize;
        loop {
            let thunk = pe::ru64(base.add(oft_rva + slot * 8));
            if thunk == 0 { break; }
            let iref = if thunk & (1u64 << 63) != 0 {
                ImportRef::Ordinal((thunk & 0xFFFF) as u16)
            } else {
                let ibn = (thunk & 0x7FFF_FFFF_FFFF_FFFF) as usize;
                ImportRef::Name(cstr(base.add(ibn + 2)))
            };
            let addr = resolve(dll_name, iref).ok_or(LdrError::BadImport)?;
            pe::wu64(base.add(iat_rva + slot * 8), addr);
            slot += 1;
        }
        desc_off += ID_SIZE;
    }
    Ok(())
}

unsafe fn cstr<'a>(p: *const u8) -> &'a str {
    let mut len = 0;
    while *p.add(len) != 0 { len += 1; }
    core::str::from_utf8_unchecked(core::slice::from_raw_parts(p, len))
}
