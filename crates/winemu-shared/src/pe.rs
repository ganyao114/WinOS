//! PE32+ 头部解析 — no_std，无内存分配
//! 只做解析，不做加载（加载逻辑在各端自行实现）

// ── 魔数 ─────────────────────────────────────────────────────
pub const MZ_MAGIC: u16 = 0x5A4D;
pub const PE_MAGIC: u32 = 0x0000_4550;
pub const OPT_MAGIC_PE32PLUS: u16 = 0x020B;
pub const MACHINE_ARM64: u16 = 0xAA64;
pub const MACHINE_AMD64: u16 = 0x8664;

// ── 数据目录索引 ─────────────────────────────────────────────
pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_RESOURCE: usize = 2;
pub const DIR_EXCEPTION: usize = 3;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_DEBUG: usize = 6;
pub const DIR_TLS: usize = 9;
pub const DIR_LOAD_CFG: usize = 10;
pub const DIR_IAT: usize = 12;

// ── 重定位类型 ───────────────────────────────────────────────
pub const REL_ABSOLUTE: u8 = 0;
pub const REL_DIR64: u8 = 10;

// ── 原始内存读取（无对齐要求，小端）────────────────────────
#[inline(always)]
pub unsafe fn ru16(p: *const u8) -> u16 {
    let mut v = 0u16;
    core::ptr::copy_nonoverlapping(p, &mut v as *mut u16 as *mut u8, 2);
    u16::from_le(v)
}

#[inline(always)]
pub unsafe fn ru32(p: *const u8) -> u32 {
    let mut v = 0u32;
    core::ptr::copy_nonoverlapping(p, &mut v as *mut u32 as *mut u8, 4);
    u32::from_le(v)
}

#[inline(always)]
pub unsafe fn ru64(p: *const u8) -> u64 {
    let mut v = 0u64;
    core::ptr::copy_nonoverlapping(p, &mut v as *mut u64 as *mut u8, 8);
    u64::from_le(v)
}

#[inline(always)]
pub unsafe fn wu64(p: *mut u8, v: u64) {
    let v = v.to_le();
    core::ptr::copy_nonoverlapping(&v as *const u64 as *const u8, p, 8);
}

// ── 解析错误 ─────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeError {
    TooSmall,
    InvalidMz,
    InvalidPe,
    NotPe32Plus,
    UnsupportedMachine,
    BadDirectory,
}

// ── 数据目录条目 ─────────────────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct DataDir {
    pub rva: u32,
    pub size: u32,
}

impl DataDir {
    pub fn is_present(self) -> bool {
        self.rva != 0 && self.size != 0
    }
}

// ── 节头 ─────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub vsize: u32,
    pub vaddr: u32,
    pub raw_size: u32,
    pub raw_off: u32,
    pub chars: u32,
}

// ── 已解析的 PE 头 ───────────────────────────────────────────
pub struct PeHeaders {
    /// 文件/内存起始指针
    base: *const u8,
    /// 文件/内存总长度
    pub len: usize,
    /// OptionalHeader 偏移（相对 base）
    oh_off: usize,
    /// 第一个 SectionHeader 偏移（相对 base）
    sec_off: usize,

    pub machine: u16,
    pub num_sections: u16,
    pub entry_rva: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub stack_reserve: u64,
    pub stack_commit: u64,
    pub num_dirs: u32,
}

impl PeHeaders {
    /// 从原始字节解析 PE 头（不做内存分配）
    pub unsafe fn parse(data: *const u8, len: usize) -> Result<Self, PeError> {
        if len < 64 {
            return Err(PeError::TooSmall);
        }
        if ru16(data) != MZ_MAGIC {
            return Err(PeError::InvalidMz);
        }
        let lfanew = ru32(data.add(60)) as usize;
        if lfanew + 24 > len {
            return Err(PeError::InvalidPe);
        }
        if ru32(data.add(lfanew)) != PE_MAGIC {
            return Err(PeError::InvalidPe);
        }

        let fh_off = lfanew + 4;
        let fh = data.add(fh_off);
        let machine = ru16(fh);
        let num_sections = ru16(fh.add(2));
        let opt_size = ru16(fh.add(16)) as usize;

        let oh_off = fh_off + 20;
        let oh = data.add(oh_off);
        if oh_off + 2 > len {
            return Err(PeError::InvalidPe);
        }
        if ru16(oh) != OPT_MAGIC_PE32PLUS {
            return Err(PeError::NotPe32Plus);
        }
        // PE32+ OptionalHeader:
        //   NumberOfRvaAndSizes @ +108
        //   DataDirectory[0]     @ +112
        if oh_off + 112 > len {
            return Err(PeError::TooSmall);
        }

        let entry_rva = ru32(oh.add(16));
        let image_base = ru64(oh.add(24));
        let size_of_image = ru32(oh.add(56));
        let size_of_headers = ru32(oh.add(60));
        let stack_reserve = ru64(oh.add(72));
        let stack_commit = ru64(oh.add(80));
        let num_dirs = ru32(oh.add(108));

        let sec_off = oh_off + opt_size;

        Ok(Self {
            base: data,
            len,
            oh_off,
            sec_off,
            machine,
            num_sections,
            entry_rva,
            image_base,
            size_of_image,
            size_of_headers,
            stack_reserve,
            stack_commit,
            num_dirs,
        })
    }

    /// 从 slice 解析（安全包装）
    pub fn from_slice(data: &[u8]) -> Result<Self, PeError> {
        unsafe { Self::parse(data.as_ptr(), data.len()) }
    }

    /// 读取数据目录条目
    pub fn data_dir(&self, idx: usize) -> Option<DataDir> {
        if idx >= self.num_dirs as usize {
            return None;
        }
        let off = self.oh_off + 112 + idx * 8;
        if off + 8 > self.len {
            return None;
        }
        unsafe {
            let p = self.base.add(off);
            Some(DataDir {
                rva: ru32(p),
                size: ru32(p.add(4)),
            })
        }
    }

    /// 读取第 i 个节头
    pub fn section(&self, i: usize) -> Option<SectionHeader> {
        if i >= self.num_sections as usize {
            return None;
        }
        let off = self.sec_off + i * 40;
        if off + 40 > self.len {
            return None;
        }
        unsafe {
            let s = self.base.add(off);
            let mut name = [0u8; 8];
            core::ptr::copy_nonoverlapping(s, name.as_mut_ptr(), 8);
            Some(SectionHeader {
                name,
                vsize: ru32(s.add(8)),
                vaddr: ru32(s.add(12)),
                raw_size: ru32(s.add(16)),
                raw_off: ru32(s.add(20)),
                chars: ru32(s.add(36)),
            })
        }
    }

    /// 迭代所有节头
    pub fn sections(&self) -> SectionIter<'_> {
        SectionIter {
            headers: self,
            idx: 0,
        }
    }

    /// 原始指针（用于加载器内部）
    pub fn base_ptr(&self) -> *const u8 {
        self.base
    }
}

pub struct SectionIter<'a> {
    headers: &'a PeHeaders,
    idx: usize,
}

impl<'a> Iterator for SectionIter<'a> {
    type Item = SectionHeader;
    fn next(&mut self) -> Option<Self::Item> {
        let s = self.headers.section(self.idx)?;
        self.idx += 1;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe32plus_data_dir_offsets_are_correct() {
        let mut image = [0u8; 0x240];

        // DOS header
        image[0..2].copy_from_slice(&MZ_MAGIC.to_le_bytes());
        image[60..64].copy_from_slice(&(0x80u32).to_le_bytes()); // e_lfanew

        // NT headers
        let nt = 0x80usize;
        image[nt..nt + 4].copy_from_slice(&PE_MAGIC.to_le_bytes());
        let fh = nt + 4;
        image[fh..fh + 2].copy_from_slice(&MACHINE_ARM64.to_le_bytes());
        image[fh + 2..fh + 4].copy_from_slice(&(1u16).to_le_bytes()); // NumberOfSections
        image[fh + 16..fh + 18].copy_from_slice(&(240u16).to_le_bytes()); // SizeOfOptionalHeader

        let oh = fh + 20;
        image[oh..oh + 2].copy_from_slice(&OPT_MAGIC_PE32PLUS.to_le_bytes());
        image[oh + 16..oh + 20].copy_from_slice(&(0x1000u32).to_le_bytes()); // Entry
        image[oh + 24..oh + 32].copy_from_slice(&(0x1400_0000_0u64).to_le_bytes()); // ImageBase
        image[oh + 56..oh + 60].copy_from_slice(&(0x5000u32).to_le_bytes()); // SizeOfImage
        image[oh + 60..oh + 64].copy_from_slice(&(0x400u32).to_le_bytes()); // SizeOfHeaders
        image[oh + 72..oh + 80].copy_from_slice(&(0x10_0000u64).to_le_bytes()); // StackReserve
        image[oh + 80..oh + 88].copy_from_slice(&(0x1000u64).to_le_bytes()); // StackCommit
        image[oh + 108..oh + 112].copy_from_slice(&(16u32).to_le_bytes()); // NumberOfRvaAndSizes

        // Import directory entry (index 1): RVA 0x20A0, Size 0x28.
        let import_dir = oh + 112 + DIR_IMPORT * 8;
        image[import_dir..import_dir + 4].copy_from_slice(&(0x20A0u32).to_le_bytes());
        image[import_dir + 4..import_dir + 8].copy_from_slice(&(0x28u32).to_le_bytes());

        let hdrs = PeHeaders::from_slice(&image).expect("parse should succeed");
        assert_eq!(hdrs.num_dirs, 16);
        let dir = hdrs.data_dir(DIR_IMPORT).expect("import dir should exist");
        assert_eq!(dir.rva, 0x20A0);
        assert_eq!(dir.size, 0x28);
        assert!(dir.is_present());
    }
}
