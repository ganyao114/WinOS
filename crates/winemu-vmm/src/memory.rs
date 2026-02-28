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
        if gpa.0 < self.base_gpa.0 {
            return;
        }
        let offset = (gpa.0 - self.base_gpa.0) as usize;
        if offset + data.len() > self.size {
            return;
        }
        self.mmap[offset..offset + data.len()].copy_from_slice(data);
    }

    pub fn read_bytes(&self, gpa: Gpa, len: usize) -> &[u8] {
        if gpa.0 < self.base_gpa.0 {
            return &[];
        }
        let offset = (gpa.0 - self.base_gpa.0) as usize;
        if offset + len > self.size {
            return &[];
        }
        &self.mmap[offset..offset + len]
    }
}
