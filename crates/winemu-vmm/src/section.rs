// NT Section 对象 — NtCreateSection / NtMapViewOfSection / NtUnmapViewOfSection

use std::collections::HashMap;
use std::sync::Mutex;

use winemu_core::addr::Gpa;
use crate::memory::GuestMemory;
use crate::vaspace::VaSpace;
use crate::file_io::FileTable;

// NT 状态码
pub const STATUS_SUCCESS:           u64 = 0x0000_0000;
pub const STATUS_INVALID_HANDLE:    u64 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
pub const STATUS_NO_MEMORY:         u64 = 0xC000_0017;

/// Section 的后端数据来源
enum SectionBacking {
    /// 匿名 pagefile-backed section：内容全零，按需分配
    Anonymous { size: u64 },
    /// 文件 backed section：从 FileTable 读取内容快照
    File { data: Vec<u8> },
}

struct Section {
    backing: SectionBacking,
    /// PAGE_* 保护标志（来自 NtCreateSection 的 flProtect）
    prot: u32,
}

pub struct SectionTable {
    sections: Mutex<HashMap<u64, Section>>,
    next_handle: Mutex<u64>,
}

impl SectionTable {
    pub fn new() -> Self {
        Self {
            sections: Mutex::new(HashMap::new()),
            next_handle: Mutex::new(0x8000_0001), // 高位区分 section handle
        }
    }

    fn alloc_handle(&self) -> u64 {
        let mut n = self.next_handle.lock().unwrap();
        let h = *n;
        *n += 1;
        h
    }

    /// NtCreateSection
    /// file_handle == 0  → anonymous (pagefile-backed)
    /// file_handle != 0  → file-backed (snapshot read from FileTable)
    pub fn create(
        &self,
        file_handle: u64,
        size: u64,
        prot: u32,
        files: &FileTable,
    ) -> (u64, u64) {
        let backing = if file_handle == 0 {
            if size == 0 {
                return (STATUS_INVALID_PARAMETER, 0);
            }
            SectionBacking::Anonymous { size }
        } else {
            // Read entire file into a snapshot buffer
            let (st, file_size) = files.query_size(file_handle);
            if st != STATUS_SUCCESS {
                return (STATUS_INVALID_HANDLE, 0);
            }
            let read_size = if size == 0 { file_size } else { size.min(file_size) } as usize;
            let mut data = vec![0u8; read_size];
            let (st2, _) = files.read(file_handle, &mut data, Some(0));
            if st2 != STATUS_SUCCESS && st2 != 0xC000_011B {
                // allow STATUS_END_OF_FILE on short read
                return (STATUS_INVALID_HANDLE, 0);
            }
            SectionBacking::File { data }
        };

        let h = self.alloc_handle();
        self.sections.lock().unwrap().insert(h, Section { backing, prot });
        log::debug!("NT_CREATE_SECTION: handle={:#x} prot={:#x}", h, prot);
        (STATUS_SUCCESS, h)
    }

    /// NtMapViewOfSection
    /// Maps the section into guest VA space and copies data into guest memory.
    /// Returns mapped VA (0 on failure).
    pub fn map_view(
        &self,
        section_handle: u64,
        base_hint: u64,
        map_size: u64,
        offset: u64,
        _prot: u32,
        vaspace: &mut VaSpace,
        mem: &mut GuestMemory,
    ) -> (u64, u64) {
        let sections = self.sections.lock().unwrap();
        let sec = match sections.get(&section_handle) {
            Some(s) => s,
            None => return (STATUS_INVALID_HANDLE, 0),
        };

        let (data_slice, section_size): (&[u8], u64) = match &sec.backing {
            SectionBacking::Anonymous { size } => (&[], *size),
            SectionBacking::File { data } => (data.as_slice(), data.len() as u64),
        };

        // Determine actual mapping size
        let avail = section_size.saturating_sub(offset);
        let actual_size = if map_size == 0 { avail } else { map_size.min(avail) };
        if actual_size == 0 {
            return (STATUS_INVALID_PARAMETER, 0);
        }

        // Allocate VA
        let va = match vaspace.alloc(base_hint, actual_size, sec.prot) {
            Some(v) => v,
            None => return (STATUS_NO_MEMORY, 0),
        };

        // Zero the region first (anonymous sections are zero-filled)
        let zero = vec![0u8; actual_size as usize];
        mem.write_bytes(Gpa(va), &zero);

        // Copy file data if file-backed
        if !data_slice.is_empty() {
            let src_start = offset as usize;
            let src_end   = (src_start + actual_size as usize).min(data_slice.len());
            if src_start < data_slice.len() {
                mem.write_bytes(Gpa(va), &data_slice[src_start..src_end]);
            }
        }

        log::debug!("NT_MAP_VIEW: section={:#x} va={:#x} size={:#x} offset={:#x}",
            section_handle, va, actual_size, offset);
        (STATUS_SUCCESS, va)
    }

    /// NtUnmapViewOfSection — free the VA region
    pub fn unmap_view(&self, base_va: u64, vaspace: &mut VaSpace) -> u64 {
        if vaspace.free(base_va) {
            log::debug!("NT_UNMAP_VIEW: va={:#x}", base_va);
            STATUS_SUCCESS
        } else {
            STATUS_INVALID_PARAMETER
        }
    }

    /// Close a section handle
    pub fn close(&self, handle: u64) -> bool {
        self.sections.lock().unwrap().remove(&handle).is_some()
    }
}
