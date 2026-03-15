use crate::memory::GuestMemory;
use std::sync::{Arc, RwLock};
use winemu_core::{addr::Gpa, Result, WinemuError};

pub struct GuestMemoryAccess {
    memory: Arc<RwLock<GuestMemory>>,
}

impl GuestMemoryAccess {
    pub fn new(memory: Arc<RwLock<GuestMemory>>) -> Self {
        Self { memory }
    }

    pub fn read_phys(&self, gpa: u64, len: usize) -> Result<Vec<u8>> {
        let memory = self.memory.read().unwrap();
        let bytes = memory.read_bytes(Gpa(gpa), len);
        if bytes.len() != len {
            return Err(WinemuError::Memory(format!(
                "guest physical read out of range gpa={:#x} len={:#x}",
                gpa, len
            )));
        }
        Ok(bytes.to_vec())
    }

    pub fn read_phys_u64(&self, gpa: u64) -> Result<u64> {
        let bytes = self.read_phys(gpa, core::mem::size_of::<u64>())?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&bytes);
        Ok(u64::from_le_bytes(raw))
    }

    pub fn write_phys(&self, gpa: u64, bytes: &[u8]) -> Result<()> {
        let mut memory = self.memory.write().unwrap();
        let base = memory.base_gpa().0;
        if gpa < base {
            return Err(WinemuError::Memory(format!(
                "guest physical write out of range gpa={:#x} len={:#x}",
                gpa,
                bytes.len()
            )));
        }
        let offset = (gpa - base) as usize;
        let end = offset.checked_add(bytes.len()).ok_or_else(|| {
            WinemuError::Memory(format!(
                "guest physical write overflow gpa={:#x} len={:#x}",
                gpa,
                bytes.len()
            ))
        })?;
        if end > memory.size() {
            return Err(WinemuError::Memory(format!(
                "guest physical write out of range gpa={:#x} len={:#x}",
                gpa,
                bytes.len()
            )));
        }
        memory.write_bytes_for_execution(Gpa(gpa), bytes)
    }
}
