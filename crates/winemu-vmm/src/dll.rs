// DLL 加载器 — host 侧
// 从 host 文件系统读取 PE32+ DLL，解析头部，分配 guest VA，
// 复制 section，应用重定位，返回 guest 加载基址。
//
// 导入表解析留给 guest kernel ldr.rs（Phase 3 改为 VMM 侧递归加载）。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use winemu_shared::pe::{self, PeHeaders, PeError};
use crate::memory::GuestMemory;
use crate::vaspace::VaSpace;

// ── 错误 ─────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DllError {
    NotFound(String),
    Pe(PeError),
    NoMemory,
    Io(std::io::Error),
}

impl From<PeError> for DllError {
    fn from(e: PeError) -> Self { DllError::Pe(e) }
}
impl From<std::io::Error> for DllError {
    fn from(e: std::io::Error) -> Self { DllError::Io(e) }
}

// ── 已加载 DLL 描述符 ─────────────────────────────────────────

#[derive(Clone)]
pub struct LoadedDll {
    pub name:      String,
    pub guest_base: u64,
    pub size:      usize,
    pub entry_rva: u32,
}

// ── DLL 加载器 ────────────────────────────────────────────────

pub struct DllLoader {
    /// DLL 搜索路径列表（按顺序查找）
    search_paths: Vec<PathBuf>,
    /// 已加载 DLL 缓存（name → descriptor）
    loaded: Mutex<HashMap<String, LoadedDll>>,
}

impl DllLoader {
    pub fn new(search_paths: Vec<PathBuf>) -> Self {
        Self {
            search_paths,
            loaded: Mutex::new(HashMap::new()),
        }
    }

    /// 从已加载 DLL 的 export 表查找函数 VA。
    /// `name` 可以是符号名，也可以是 "#NNN" 格式的序号字符串。
    pub fn get_proc(
        &self,
        guest_base: u64,
        name: &str,
        memory: &Arc<RwLock<GuestMemory>>,
    ) -> Option<u64> {
        use winemu_shared::pe;

        let mem = memory.read().unwrap();
        let mem_base = mem.base_gpa().0;

        // 读 PE 头，找 export directory
        let dos_sig = read_u16(&mem, mem_base + guest_base);
        if dos_sig != pe::MZ_MAGIC { return None; }
        let lfanew = read_u32(&mem, mem_base + guest_base + 60) as u64;
        if read_u32(&mem, mem_base + guest_base + lfanew) != pe::PE_MAGIC { return None; }

        let oh = guest_base + lfanew + 24;
        let exp_rva  = read_u32(&mem, mem_base + oh + 96) as u64;
        let exp_size = read_u32(&mem, mem_base + oh + 100);
        if exp_rva == 0 || exp_size == 0 { return None; }

        let exp = guest_base + exp_rva;
        let exp_base   = read_u32(&mem, mem_base + exp + 16) as u64; // OrdinalBase
        let num_funcs  = read_u32(&mem, mem_base + exp + 20) as u64;
        let num_names  = read_u32(&mem, mem_base + exp + 24) as u64;
        let fn_rva_tbl = guest_base + read_u32(&mem, mem_base + exp + 28) as u64;
        let name_tbl   = guest_base + read_u32(&mem, mem_base + exp + 32) as u64;
        let ord_tbl    = guest_base + read_u32(&mem, mem_base + exp + 36) as u64;

        // Ordinal lookup: "#NNN" or pure numeric string
        let ordinal_req: Option<u64> = if let Some(rest) = name.strip_prefix('#') {
            rest.parse::<u64>().ok()
        } else {
            None
        };

        if let Some(ordinal) = ordinal_req {
            // ordinal is the raw export ordinal; index = ordinal - OrdinalBase
            let idx = ordinal.wrapping_sub(exp_base);
            if idx < num_funcs {
                let fn_rva = read_u32(&mem, mem_base + fn_rva_tbl + idx * 4) as u64;
                if fn_rva != 0 {
                    return Some(guest_base + fn_rva);
                }
            }
            return None;
        }

        // Name-based lookup
        for i in 0..num_names {
            let name_rva = read_u32(&mem, mem_base + name_tbl + i * 4) as u64;
            let export_name = read_cstr(&mem, mem_base + guest_base + name_rva);
            if export_name == name {
                let ord = read_u16(&mem, mem_base + ord_tbl + i * 2) as u64;
                if ord < num_funcs {
                    let fn_rva = read_u32(&mem, mem_base + fn_rva_tbl + ord * 4) as u64;
                    return Some(guest_base + fn_rva);
                }
            }
        }
        None
    }

    /// Ordinal-based lookup (called from IAT patching for `ImportRef::Ordinal`).
    pub fn get_proc_by_ordinal(
        &self,
        guest_base: u64,
        ordinal: u16,
        memory: &Arc<RwLock<GuestMemory>>,
    ) -> Option<u64> {
        let name = format!("#{}", ordinal);
        self.get_proc(guest_base, &name, memory)
    }

    /// 查找已加载的 DLL（大小写不敏感）
    pub fn get(&self, name: &str) -> Option<LoadedDll> {
        let key = name.to_ascii_lowercase();
        self.loaded.lock().unwrap().get(&key).cloned()
    }

    /// 加载 DLL（若已加载则直接返回缓存）
    pub fn load(
        &self,
        name: &str,
        memory: &Arc<RwLock<GuestMemory>>,
        vaspace: &Mutex<VaSpace>,
    ) -> Result<LoadedDll, DllError> {
        let key = name.to_ascii_lowercase();

        // 缓存命中
        if let Some(dll) = self.loaded.lock().unwrap().get(&key).cloned() {
            return Ok(dll);
        }

        // 在搜索路径中定位文件
        let path = self.find(name)
            .ok_or_else(|| DllError::NotFound(name.to_string()))?;

        log::info!("DllLoader: loading {} from {}", name, path.display());

        let data = std::fs::read(&path)?;
        let dll = self.load_bytes(name, &data, memory, vaspace)?;

        self.loaded.lock().unwrap().insert(key, dll.clone());
        Ok(dll)
    }

    /// 从字节数组加载（不缓存，供内部使用）
    fn load_bytes(
        &self,
        name: &str,
        data: &[u8],
        memory: &Arc<RwLock<GuestMemory>>,
        vaspace: &Mutex<VaSpace>,
    ) -> Result<LoadedDll, DllError> {
        let hdrs = PeHeaders::from_slice(data)?;

        let img_size = hdrs.size_of_image as usize;

        // 在 guest VA 空间分配
        let guest_base = {
            let mut va = vaspace.lock().unwrap();
            // 优先使用 PE 首选基址
            let hint = hdrs.image_base;
            va.alloc(hint, img_size as u64, 0x20) // PAGE_EXECUTE_READ
                .ok_or(DllError::NoMemory)?
        };

        // 写入 guest 内存
        {
            let mut mem = memory.write().unwrap();
            let base_gpa = mem.base_gpa();

            // 复制 PE 头
            let hdr_size = hdrs.size_of_headers as usize;
            let hdr_size = hdr_size.min(data.len());
            write_guest(&mut mem, base_gpa.0 + guest_base, &data[..hdr_size]);

            // 复制各 section
            for sec in hdrs.sections() {
                if sec.raw_size == 0 { continue; }
                let src_off  = sec.raw_off as usize;
                let dst_va   = guest_base + sec.vaddr as u64;
                let copy_len = (sec.raw_size as usize).min(sec.vsize as usize);
                if src_off + copy_len > data.len() { continue; }
                write_guest(&mut mem, base_gpa.0 + dst_va, &data[src_off..src_off + copy_len]);
            }

            // 基址重定位
            let delta = guest_base.wrapping_sub(hdrs.image_base) as i64;
            if delta != 0 {
                if let Some(dir) = hdrs.data_dir(pe::DIR_BASERELOC) {
                    if dir.is_present() {
                        apply_relocs(
                            &mut mem, base_gpa.0, guest_base,
                            dir.rva as usize, dir.size as usize, delta,
                        );
                    }
                }
            }
        }

        log::info!("DllLoader: {} loaded at guest_base={:#x} size={:#x}",
            name, guest_base, img_size);

        Ok(LoadedDll {
            name:       name.to_string(),
            guest_base,
            size:       img_size,
            entry_rva:  hdrs.entry_rva,
        })
    }

    fn find(&self, name: &str) -> Option<PathBuf> {
        for dir in &self.search_paths {
            let p = dir.join(name);
            if p.exists() { return Some(p); }
            let lower = dir.join(name.to_ascii_lowercase());
            if lower.exists() { return Some(lower); }
        }
        None
    }
}

// ── guest 内存写入辅助 ────────────────────────────────────────

fn write_guest(mem: &mut GuestMemory, gpa: u64, data: &[u8]) {
    use winemu_core::addr::Gpa;
    let mem_base = mem.base_gpa().0;
    let mem_size = mem.size() as u64;
    let offset = gpa.saturating_sub(mem_base);
    if offset >= mem_size { return; }
    let avail = (mem_size - offset) as usize;
    let len = data.len().min(avail);
    mem.write_bytes(Gpa(gpa), &data[..len]);
}

// ── 基址重定位 ────────────────────────────────────────────────

fn apply_relocs(
    mem: &mut GuestMemory,
    mem_base_gpa: u64,
    image_base: u64,
    reloc_rva: usize,
    reloc_size: usize,
    delta: i64,
) {
    use winemu_core::addr::Gpa;

    let mut off = 0usize;
    while off + 8 <= reloc_size {
        let blk_gpa = mem_base_gpa + image_base + reloc_rva as u64 + off as u64;
        let page_rva   = read_u32(mem, blk_gpa) as usize;
        let block_size = read_u32(mem, blk_gpa + 4) as usize;
        if block_size < 8 { break; }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry_gpa = blk_gpa + 8 + i as u64 * 2;
            let entry = read_u16(mem, entry_gpa);
            let typ      = (entry >> 12) as u8;
            let page_off = (entry & 0x0FFF) as u64;
            if typ == pe::REL_DIR64 {
                let target_gpa = mem_base_gpa + image_base + page_rva as u64 + page_off;
                let val = read_u64(mem, target_gpa);
                let new_val = (val as i64).wrapping_add(delta) as u64;
                mem.write_bytes(Gpa(target_gpa), &new_val.to_le_bytes());
            }
        }
        off += block_size;
    }
}

fn read_u16(mem: &GuestMemory, gpa: u64) -> u16 {
    use winemu_core::addr::Gpa;
    let b = mem.read_bytes(Gpa(gpa), 2);
    u16::from_le_bytes([b[0], b[1]])
}

fn read_u32(mem: &GuestMemory, gpa: u64) -> u32 {
    use winemu_core::addr::Gpa;
    let b = mem.read_bytes(Gpa(gpa), 4);
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn read_u64(mem: &GuestMemory, gpa: u64) -> u64 {
    use winemu_core::addr::Gpa;
    let b = mem.read_bytes(Gpa(gpa), 8);
    u64::from_le_bytes(b.try_into().unwrap_or([0;8]))
}

fn read_cstr(mem: &GuestMemory, gpa: u64) -> String {
    use winemu_core::addr::Gpa;
    let mut result = Vec::new();
    let mut off = 0u64;
    loop {
        let b = mem.read_bytes(Gpa(gpa + off), 1);
        if b.is_empty() || b[0] == 0 { break; }
        result.push(b[0]);
        off += 1;
        if off > 512 { break; }
    }
    String::from_utf8_lossy(&result).into_owned()
}
