use memmap2::MmapMut;
use winemu_core::{addr::Gpa, Result, WinemuError};

pub struct GuestMemory {
    mmap: MmapMut,
    base_gpa: Gpa,
    size: usize,
}

impl GuestMemory {
    pub fn new(size: usize) -> Result<Self> {
        let mmap = MmapMut::map_anon(size)
            .map_err(|e| WinemuError::Memory(format!("mmap failed: {}", e)))?;
        Ok(Self {
            mmap,
            base_gpa: Gpa(0x40000000),
            size,
        })
    }

    pub fn base_gpa(&self) -> Gpa {
        self.base_gpa
    }
    pub fn size(&self) -> usize {
        self.size
    }

    pub fn hva(&self) -> *mut u8 {
        self.mmap.as_ptr() as *mut u8
    }

    pub fn write_bytes(&mut self, gpa: Gpa, data: &[u8]) {
        let Some(offset) = self.offset_for_range(gpa, data.len()) else {
            return;
        };
        self.mmap[offset..offset + data.len()].copy_from_slice(data);
    }

    pub fn write_bytes_for_execution(&mut self, gpa: Gpa, data: &[u8]) -> Result<()> {
        let offset = self.offset_for_range(gpa, data.len()).ok_or_else(|| {
            WinemuError::Memory(format!(
                "guest physical exec write out of range gpa={:#x} len={:#x}",
                gpa.0,
                data.len()
            ))
        })?;
        self.mmap[offset..offset + data.len()].copy_from_slice(data);
        self.invalidate_icache(offset, data.len());
        Ok(())
    }

    pub fn read_bytes(&self, gpa: Gpa, len: usize) -> &[u8] {
        let Some(offset) = self.offset_for_range(gpa, len) else {
            return &[];
        };
        &self.mmap[offset..offset + len]
    }

    fn offset_for_range(&self, gpa: Gpa, len: usize) -> Option<usize> {
        if gpa.0 < self.base_gpa.0 {
            return None;
        }
        let offset = (gpa.0 - self.base_gpa.0) as usize;
        let end = offset.checked_add(len)?;
        if end > self.size {
            return None;
        }
        Some(offset)
    }

    #[cfg(target_os = "macos")]
    fn invalidate_icache(&mut self, offset: usize, len: usize) {
        if len == 0 {
            return;
        }
        // SAFETY: `offset_for_range` bounds-checks the written range, so this
        // pointer and length describe a valid slice inside the mmap.
        unsafe {
            let ptr = self.mmap.as_mut_ptr().add(offset).cast();
            sys_dcache_flush(ptr, len);
            sys_icache_invalidate(ptr, len);
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn invalidate_icache(&mut self, _offset: usize, _len: usize) {}
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn sys_icache_invalidate(start: *mut core::ffi::c_void, len: usize);
    fn sys_dcache_flush(start: *mut core::ffi::c_void, len: usize);
}
