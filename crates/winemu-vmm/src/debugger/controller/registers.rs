use super::DebugController;
use crate::debugger::types::VcpuSnapshot;
use winemu_core::{Result, WinemuError};

impl DebugController {
    pub fn set_gdb_register(&self, vcpu_id: u32, index: usize, raw: &[u8]) -> Result<()> {
        self.with_snapshot_mut(vcpu_id, |snapshot| {
            set_snapshot_register_from_gdb(snapshot, index, raw)
        })
    }

    pub fn replace_gdb_register_file(&self, vcpu_id: u32, raw: &[u8]) -> Result<()> {
        self.with_snapshot_mut(vcpu_id, |snapshot| {
            let mut offset = 0usize;
            for index in 0..gdb_register_count() {
                let Some(size) = gdb_register_size(index) else {
                    break;
                };
                let end = offset
                    .checked_add(size)
                    .ok_or_else(|| WinemuError::Memory("gdb register file overflow".to_string()))?;
                if end > raw.len() {
                    return Err(WinemuError::Memory(
                        "short gdb register file payload".to_string(),
                    ));
                }
                set_snapshot_register_from_gdb(snapshot, index, &raw[offset..end])?;
                offset = end;
            }
            if offset != raw.len() {
                return Err(WinemuError::Memory(
                    "unexpected trailing gdb register bytes".to_string(),
                ));
            }
            Ok(())
        })
    }
}

fn gdb_register_count() -> usize {
    34
}

fn gdb_register_size(index: usize) -> Option<usize> {
    match index {
        0..=32 => Some(core::mem::size_of::<u64>()),
        33 => Some(core::mem::size_of::<u32>()),
        _ => None,
    }
}

fn set_snapshot_register_from_gdb(
    snapshot: &mut VcpuSnapshot,
    index: usize,
    raw: &[u8],
) -> Result<()> {
    #[cfg(target_arch = "aarch64")]
    {
        match index {
            0..=30 => snapshot.regs.x[index] = decode_u64(raw)?,
            31 => snapshot.regs.sp = decode_u64(raw)?,
            32 => snapshot.regs.pc = decode_u64(raw)?,
            33 => snapshot.regs.pstate = decode_u32(raw)? as u64,
            _ => {
                return Err(WinemuError::Memory(format!(
                    "unsupported gdb register index {}",
                    index
                )));
            }
        }
        Ok(())
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = snapshot;
        let _ = index;
        let _ = raw;
        Err(WinemuError::Memory(
            "gdb register writes are only implemented for aarch64".to_string(),
        ))
    }
}

fn decode_u64(raw: &[u8]) -> Result<u64> {
    if raw.len() != core::mem::size_of::<u64>() {
        return Err(WinemuError::Memory(format!(
            "invalid 64-bit register payload size {}",
            raw.len()
        )));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(raw);
    Ok(u64::from_le_bytes(bytes))
}

fn decode_u32(raw: &[u8]) -> Result<u32> {
    if raw.len() != core::mem::size_of::<u32>() {
        return Err(WinemuError::Memory(format!(
            "invalid 32-bit register payload size {}",
            raw.len()
        )));
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(raw);
    Ok(u32::from_le_bytes(bytes))
}
