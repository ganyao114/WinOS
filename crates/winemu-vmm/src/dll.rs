// DLL 加载器 — host 侧
// 从 host 文件系统读取 PE32+ DLL，解析头部，分配 guest VA，
// 复制 section，应用重定位，返回 guest 加载基址。
//
// 导入表解析留给 guest kernel ldr.rs（Phase 3 改为 VMM 侧递归加载）。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use crate::memory::GuestMemory;
use crate::vaspace::VaSpace;
use winemu_shared::pe::{self, PeError, PeHeaders};

// ── 错误 ─────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DllError {
    NotFound(String),
    Pe(PeError),
    NoMemory,
    Io(std::io::Error),
}

impl From<PeError> for DllError {
    fn from(e: PeError) -> Self {
        DllError::Pe(e)
    }
}
impl From<std::io::Error> for DllError {
    fn from(e: std::io::Error) -> Self {
        DllError::Io(e)
    }
}

// ── 已加载 DLL 描述符 ─────────────────────────────────────────

#[derive(Clone)]
pub struct LoadedDll {
    pub name: String,
    pub guest_base: u64,
    pub size: usize,
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

        // 读 PE 头，找 export directory
        // guest_base is already a GPA; read_u16/read_u32 take raw GPAs
        let dos_sig = read_u16(&mem, guest_base);
        if dos_sig != pe::MZ_MAGIC {
            return None;
        }
        let lfanew = read_u32(&mem, guest_base + 60) as u64;
        if read_u32(&mem, guest_base + lfanew) != pe::PE_MAGIC {
            return None;
        }

        let oh = guest_base + lfanew + 24;
        // PE32+ OptionalHeader: DataDirectory starts at +112.
        let exp_rva = read_u32(&mem, oh + 112) as u64;
        let exp_size = read_u32(&mem, oh + 116);
        if exp_rva == 0 || exp_size == 0 {
            return None;
        }

        let exp = guest_base + exp_rva;
        let exp_base = read_u32(&mem, exp + 16) as u64; // OrdinalBase
        let num_funcs = read_u32(&mem, exp + 20) as u64;
        let num_names = read_u32(&mem, exp + 24) as u64;
        let fn_rva_tbl = guest_base + read_u32(&mem, exp + 28) as u64;
        let name_tbl = guest_base + read_u32(&mem, exp + 32) as u64;
        let ord_tbl = guest_base + read_u32(&mem, exp + 36) as u64;

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
                let fn_rva = read_u32(&mem, fn_rva_tbl + idx * 4) as u64;
                if fn_rva != 0 {
                    return Some(guest_base + fn_rva);
                }
            }
            return None;
        }

        // Name-based lookup
        for i in 0..num_names {
            let name_rva = read_u32(&mem, name_tbl + i * 4) as u64;
            let export_name = read_cstr(&mem, guest_base + name_rva);
            if export_name == name {
                let ord = read_u16(&mem, ord_tbl + i * 2) as u64;
                if ord < num_funcs {
                    let fn_rva = read_u32(&mem, fn_rva_tbl + ord * 4) as u64;
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
        let path = self
            .find(name)
            .ok_or_else(|| DllError::NotFound(name.to_string()))?;

        log::info!("DllLoader: loading {} from {}", name, path.display());

        let data = std::fs::read(&path)?;
        let hdrs = PeHeaders::from_slice(&data).map_err(DllError::Pe)?;

        // 收集导入的 DLL 名称（在分配 guest 内存前，避免持锁递归）
        let import_dll_names = collect_import_dll_names(&hdrs, &data);

        let img_size = hdrs.size_of_image as usize;
        let image_base = hdrs.image_base;
        let entry_rva = hdrs.entry_rva;
        let reloc_dir = hdrs.data_dir(pe::DIR_BASERELOC);
        let import_dir = hdrs.data_dir(pe::DIR_IMPORT);

        let (mem_base, mem_end) = {
            let mem = memory.read().unwrap();
            (mem.base_gpa().0, mem.base_gpa().0 + mem.size() as u64)
        };
        let alloc_end = mem_end.min(crate::phys::PHYS_POOL_BASE);

        let fits_guest_window = |base: u64| -> bool {
            if base < mem_base {
                return false;
            }
            let Some(end) = base.checked_add(img_size as u64) else {
                return false;
            };
            end <= alloc_end
        };

        // 在 guest VA 空间分配
        let guest_base = {
            let mut va = vaspace.lock().unwrap();
            let mut chosen = None;

            if fits_guest_window(image_base) {
                chosen = va.alloc(image_base, img_size as u64, 0x20);
            }

            if chosen.is_none() {
                for hint in [
                    0x5800_0000u64,
                    0x5400_0000u64,
                    0x5000_0000u64,
                    mem_base + 0x0800_0000,
                    mem_base + 0x0400_0000,
                ] {
                    if !fits_guest_window(hint) {
                        continue;
                    }
                    if let Some(base) = va.alloc(hint, img_size as u64, 0x20) {
                        chosen = Some(base);
                        break;
                    }
                }
            }

            chosen.ok_or(DllError::NoMemory)?
        };

        // 写入 guest 内存（sections + 重定位）
        {
            let mut mem = memory.write().unwrap();

            let hdr_size = (hdrs.size_of_headers as usize).min(data.len());
            write_guest(&mut mem, guest_base, &data[..hdr_size]);

            for sec in hdrs.sections() {
                if sec.raw_size == 0 {
                    continue;
                }
                let src_off = sec.raw_off as usize;
                let dst_gpa = guest_base + sec.vaddr as u64;
                let copy_len = (sec.raw_size as usize).min(sec.vsize as usize);
                if src_off + copy_len > data.len() {
                    continue;
                }
                write_guest(
                    &mut mem,
                    dst_gpa,
                    &data[src_off..src_off + copy_len],
                );
            }

            let delta = guest_base.wrapping_sub(image_base) as i64;
            if delta != 0 {
                if let Some(dir) = reloc_dir {
                    if dir.is_present() {
                        apply_relocs(
                            &mut mem,
                            guest_base,
                            dir.rva as usize,
                            dir.size as usize,
                            delta,
                        );
                    }
                }
            }
        }

        let dll = LoadedDll {
            name: name.to_string(),
            guest_base,
            size: img_size,
            entry_rva,
        };

        // 插入缓存（在递归加载依赖前，防止循环依赖）
        self.loaded.lock().unwrap().insert(key, dll.clone());

        // 递归加载依赖 DLL，然后填充 IAT
        if let Some(imp_dir) = import_dir {
            if imp_dir.is_present() {
                // 先递归加载所有依赖（不持有 memory 锁）
                for dep in &import_dll_names {
                    if let Err(e) = self.load(dep, memory, vaspace) {
                        log::warn!(
                            "DllLoader: failed to load dep {} for {}: {:?}",
                            dep,
                            name,
                            e
                        );
                    }
                }
                // 填充 IAT：先快照 cache，再持有 memory 写锁
                let cache_snapshot: HashMap<String, LoadedDll> =
                    self.loaded.lock().unwrap().clone();
                let mut mem = memory.write().unwrap();
                apply_imports_guest(
                    &mut mem,
                    guest_base,
                    imp_dir.rva as usize,
                    &cache_snapshot,
                );
            }
        }

        log::info!(
            "DllLoader: {} loaded at guest_base={:#x} size={:#x}",
            name,
            guest_base,
            img_size
        );
        Ok(dll)
    }

    fn find(&self, name: &str) -> Option<PathBuf> {
        for dir in &self.search_paths {
            let p = dir.join(name);
            if p.exists() {
                return Some(p);
            }
            let lower = dir.join(name.to_ascii_lowercase());
            if lower.exists() {
                return Some(lower);
            }
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
    if offset >= mem_size {
        return;
    }
    let avail = (mem_size - offset) as usize;
    let len = data.len().min(avail);
    mem.write_bytes(Gpa(gpa), &data[..len]);
}

// ── 基址重定位 ────────────────────────────────────────────────

fn apply_relocs(
    mem: &mut GuestMemory,
    image_base: u64,
    reloc_rva: usize,
    reloc_size: usize,
    delta: i64,
) {
    use winemu_core::addr::Gpa;

    let mut off = 0usize;
    while off + 8 <= reloc_size {
        let blk_gpa = image_base + reloc_rva as u64 + off as u64;
        let page_rva = read_u32(mem, blk_gpa) as usize;
        let block_size = read_u32(mem, blk_gpa + 4) as usize;
        if block_size < 8 {
            break;
        }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry_gpa = blk_gpa + 8 + i as u64 * 2;
            let entry = read_u16(mem, entry_gpa);
            let typ = (entry >> 12) as u8;
            let page_off = (entry & 0x0FFF) as u64;
            if typ == pe::REL_DIR64 {
                let target_gpa = image_base + page_rva as u64 + page_off;
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
    if b.len() < 2 {
        return 0;
    }
    u16::from_le_bytes([b[0], b[1]])
}

fn read_u32(mem: &GuestMemory, gpa: u64) -> u32 {
    use winemu_core::addr::Gpa;
    let b = mem.read_bytes(Gpa(gpa), 4);
    if b.len() < 4 {
        return 0;
    }
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn read_u64(mem: &GuestMemory, gpa: u64) -> u64 {
    use winemu_core::addr::Gpa;
    let b = mem.read_bytes(Gpa(gpa), 8);
    if b.len() < 8 {
        return 0;
    }
    u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
}

fn read_cstr(mem: &GuestMemory, gpa: u64) -> String {
    use winemu_core::addr::Gpa;
    let mut result = Vec::new();
    let mut off = 0u64;
    loop {
        let b = mem.read_bytes(Gpa(gpa + off), 1);
        if b.is_empty() || b[0] == 0 {
            break;
        }
        result.push(b[0]);
        off += 1;
        if off > 512 {
            break;
        }
    }
    String::from_utf8_lossy(&result).into_owned()
}

/// 从 PE 原始字节中收集 Import Directory 里的 DLL 名称（不需要 guest 内存）
fn collect_import_dll_names(hdrs: &PeHeaders, data: &[u8]) -> Vec<String> {
    let dir = match hdrs.data_dir(pe::DIR_IMPORT) {
        Some(d) if d.is_present() => d,
        _ => return Vec::new(),
    };
    let mut names = Vec::new();
    let mut off = dir.rva as usize;
    loop {
        if off + 20 > data.len() {
            break;
        }
        let name_rva =
            u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap_or([0; 4])) as usize;
        if name_rva == 0 {
            break;
        }
        if name_rva < data.len() {
            let end = data[name_rva..].iter().position(|&b| b == 0).unwrap_or(0);
            if let Ok(s) = std::str::from_utf8(&data[name_rva..name_rva + end]) {
                names.push(s.to_string());
            }
        }
        off += 20;
    }
    names
}

/// 填充已加载到 guest 内存中的 DLL 的 IAT。
/// `cache` 是已加载 DLL 的映射（lowercase name → LoadedDll）。
fn apply_imports_guest(
    mem: &mut GuestMemory,
    image_base: u64,
    imp_rva: usize,
    cache: &HashMap<String, LoadedDll>,
) {
    use winemu_core::addr::Gpa;

    let mut desc_off = imp_rva;
    loop {
        let desc_gpa = image_base + desc_off as u64;
        let name_rva = read_u32(mem, desc_gpa + 12) as usize;
        if name_rva == 0 {
            break;
        }

        let dll_name = read_cstr(mem, image_base + name_rva as u64).to_ascii_lowercase();
        let dep_base = match cache.get(&dll_name) {
            Some(d) => d.guest_base,
            None => {
                desc_off += 20;
                continue;
            }
        };

        let iat_rva = read_u32(mem, desc_gpa + 16) as u64;
        let oft_rva = {
            let v = read_u32(mem, desc_gpa) as u64;
            if v != 0 {
                v
            } else {
                iat_rva
            }
        };

        let mut slot = 0u64;
        loop {
            let thunk_gpa = image_base + oft_rva + slot * 8;
            let thunk = read_u64(mem, thunk_gpa);
            if thunk == 0 {
                break;
            }

            let fn_va = if thunk & (1u64 << 63) != 0 {
                // Import by ordinal
                let ordinal = (thunk & 0xFFFF) as u64;
                resolve_export_by_ordinal(mem, dep_base, ordinal)
            } else {
                // Import by name (skip 2-byte hint)
                let ibn_rva = (thunk & 0x7FFF_FFFF_FFFF_FFFF) as u64;
                let fn_name = read_cstr(mem, image_base + ibn_rva + 2);
                resolve_export_by_name(mem, dep_base, &fn_name)
            };

            if fn_va != 0 {
                let iat_slot_gpa = image_base + iat_rva + slot * 8;
                mem.write_bytes(Gpa(iat_slot_gpa), &fn_va.to_le_bytes());
            } else {
                log::warn!(
                    "apply_imports_guest: unresolved import from {} slot={}",
                    dll_name,
                    slot
                );
            }
            slot += 1;
        }
        desc_off += 20;
    }
}

fn resolve_export_by_name(mem: &GuestMemory, dll_base: u64, name: &str) -> u64 {
    let (fn_rva_tbl, name_tbl, ord_tbl, num_names, num_funcs, _exp_base) =
        read_export_dir(mem, dll_base);
    for i in 0..num_names {
        let name_rva = read_u32(mem, name_tbl + i * 4) as u64;
        let export_name = read_cstr(mem, dll_base + name_rva);
        if export_name == name {
            let ord = read_u16(mem, ord_tbl + i * 2) as u64;
            if ord < num_funcs {
                let fn_rva = read_u32(mem, fn_rva_tbl + ord * 4) as u64;
                if fn_rva != 0 {
                    return dll_base + fn_rva;
                }
            }
        }
    }
    0
}

fn resolve_export_by_ordinal(mem: &GuestMemory, dll_base: u64, ordinal: u64) -> u64 {
    let (fn_rva_tbl, _, _, _, num_funcs, exp_base) = read_export_dir(mem, dll_base);
    let idx = ordinal.wrapping_sub(exp_base);
    if idx < num_funcs {
        let fn_rva = read_u32(mem, fn_rva_tbl + idx * 4) as u64;
        if fn_rva != 0 {
            return dll_base + fn_rva;
        }
    }
    0
}

/// Returns (fn_rva_tbl, name_tbl, ord_tbl, num_names, num_funcs, ordinal_base)
fn read_export_dir(
    mem: &GuestMemory,
    dll_base: u64,
) -> (u64, u64, u64, u64, u64, u64) {
    let dos_sig = read_u16(mem, dll_base);
    if dos_sig != pe::MZ_MAGIC {
        return (0, 0, 0, 0, 0, 0);
    }
    let lfanew = read_u32(mem, dll_base + 60) as u64;
    let oh = dll_base + lfanew + 24;
    let exp_rva = read_u32(mem, oh + 112) as u64;
    let exp_size = read_u32(mem, oh + 116);
    if exp_rva == 0 || exp_size == 0 {
        return (0, 0, 0, 0, 0, 0);
    }
    let exp = dll_base + exp_rva;
    let exp_base = read_u32(mem, exp + 16) as u64;
    let num_funcs = read_u32(mem, exp + 20) as u64;
    let num_names = read_u32(mem, exp + 24) as u64;
    let fn_rva_tbl = dll_base + read_u32(mem, exp + 28) as u64;
    let name_tbl = dll_base + read_u32(mem, exp + 32) as u64;
    let ord_tbl = dll_base + read_u32(mem, exp + 36) as u64;
    (
        fn_rva_tbl, name_tbl, ord_tbl, num_names, num_funcs, exp_base,
    )
}
