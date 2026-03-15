use super::memory::GuestMemoryAccess;
use super::types::VcpuSnapshot;
use winemu_core::{Result, WinemuError};

const DESC_TYPE_MASK: u64 = 0b11;
const DESC_INVALID: u64 = 0b00;
const DESC_BLOCK: u64 = 0b01;
const DESC_TABLE_OR_PAGE: u64 = 0b11;
const TABLE_ADDR_MASK: u64 = !0xFFF;
const DESC_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
const L1_BLOCK_SIZE: u64 = 1024 * 1024 * 1024;
const L2_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
const PAGE_SIZE_4K: u64 = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TranslationRoot {
    Ttbr0,
    Ttbr1,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TranslationSpace {
    pub root: TranslationRoot,
    pub root_base: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct TranslationTrace {
    pub l0e: u64,
    pub l1e: u64,
    pub l2e: u64,
    pub l3e: u64,
    pub gpa: u64,
}

pub fn translation_space_for_va(snapshot: &VcpuSnapshot, va: u64) -> Result<TranslationSpace> {
    let sys = snapshot.aarch64_system_regs().ok_or_else(|| {
        WinemuError::Memory("virtual translation is only implemented for aarch64 snapshots".into())
    })?;
    let granule = (sys.tcr_el1 >> 14) & 0b11;
    if granule != 0 {
        return Err(WinemuError::Memory(format!(
            "unsupported TG0 in TCR_EL1: {:#x}",
            granule
        )));
    }
    let (root, root_base) = translation_root_base(&sys, va)?;
    Ok(TranslationSpace { root, root_base })
}

pub fn translate_va_in_space(
    memory: &GuestMemoryAccess,
    space: TranslationSpace,
    va: u64,
) -> Result<u64> {
    Ok(translate_va_in_space_trace(memory, space, va)?.gpa)
}

pub fn translate_va_in_space_trace(
    memory: &GuestMemoryAccess,
    space: TranslationSpace,
    va: u64,
) -> Result<TranslationTrace> {
    let l0_base = space.root_base;
    let l0e = memory.read_phys_u64(table_entry_addr(l0_base, l0_index(va)))?;
    if desc_kind(l0e) != DESC_TABLE_OR_PAGE {
        return invalid_translation::<TranslationTrace>(va, 0, l0e);
    }

    let l1_base = table_base(l0e);
    let l1e = memory.read_phys_u64(table_entry_addr(l1_base, l1_index(va)))?;
    match desc_kind(l1e) {
        DESC_INVALID => return invalid_translation::<TranslationTrace>(va, 1, l1e),
        DESC_BLOCK => {
            return Ok(TranslationTrace {
                l0e,
                l1e,
                l2e: 0,
                l3e: 0,
                gpa: block_base(l1e, L1_BLOCK_SIZE) | (va & (L1_BLOCK_SIZE - 1)),
            });
        }
        DESC_TABLE_OR_PAGE => {}
        other => {
            return Err(WinemuError::Memory(format!(
                "unsupported l1 descriptor kind={} va={:#x} desc={:#x}",
                other, va, l1e
            )));
        }
    }

    let l2_base = table_base(l1e);
    let l2e = memory.read_phys_u64(table_entry_addr(l2_base, l2_index(va)))?;
    match desc_kind(l2e) {
        DESC_INVALID => return invalid_translation::<TranslationTrace>(va, 2, l2e),
        DESC_BLOCK => {
            return Ok(TranslationTrace {
                l0e,
                l1e,
                l2e,
                l3e: 0,
                gpa: block_base(l2e, L2_BLOCK_SIZE) | (va & (L2_BLOCK_SIZE - 1)),
            });
        }
        DESC_TABLE_OR_PAGE => {}
        other => {
            return Err(WinemuError::Memory(format!(
                "unsupported l2 descriptor kind={} va={:#x} desc={:#x}",
                other, va, l2e
            )));
        }
    }

    let l3_base = table_base(l2e);
    let l3e = memory.read_phys_u64(table_entry_addr(l3_base, l3_index(va)))?;
    if desc_kind(l3e) != DESC_TABLE_OR_PAGE {
        return invalid_translation::<TranslationTrace>(va, 3, l3e);
    }
    Ok(TranslationTrace {
        l0e,
        l1e,
        l2e,
        l3e,
        gpa: block_base(l3e, PAGE_SIZE_4K) | (va & (PAGE_SIZE_4K - 1)),
    })
}

fn invalid_translation<T>(va: u64, level: u8, desc: u64) -> Result<T> {
    Err(WinemuError::Memory(format!(
        "virtual translation failed va={:#x} level={} desc={:#x}",
        va, level, desc
    )))
}

fn desc_kind(desc: u64) -> u64 {
    desc & DESC_TYPE_MASK
}

fn table_base(desc: u64) -> u64 {
    desc & TABLE_ADDR_MASK
}

fn block_base(desc: u64, span: u64) -> u64 {
    (desc & DESC_ADDR_MASK) & !(span - 1)
}

fn table_entry_addr(base: u64, index: usize) -> u64 {
    base + (index as u64) * 8
}

fn translation_root_base(
    sys: &super::types::Aarch64SystemRegs,
    va: u64,
) -> Result<(TranslationRoot, u64)> {
    let lower_bits = input_addr_bits((sys.tcr_el1 & 0x3f) as u8)?;
    let upper_bits = input_addr_bits(((sys.tcr_el1 >> 16) & 0x3f) as u8)?;
    let lower_limit = region_size(lower_bits)?;
    let upper_start = upper_region_start(upper_bits)?;

    if va < lower_limit {
        return Ok((TranslationRoot::Ttbr0, sys.ttbr0_el1 & TABLE_ADDR_MASK));
    }
    if va >= upper_start {
        return Ok((TranslationRoot::Ttbr1, sys.ttbr1_el1 & TABLE_ADDR_MASK));
    }
    Err(WinemuError::Memory(format!(
        "virtual address {:#x} is outside TTBR0/TTBR1 ranges (TCR_EL1={:#x})",
        va, sys.tcr_el1
    )))
}

fn input_addr_bits(tsz: u8) -> Result<u8> {
    if tsz > 63 {
        return Err(WinemuError::Memory(format!(
            "invalid TCR_EL1 TxSZ value {}",
            tsz
        )));
    }
    Ok(64 - tsz)
}

fn region_size(bits: u8) -> Result<u64> {
    match bits {
        0 => Err(WinemuError::Memory(
            "invalid zero-sized translation region".to_string(),
        )),
        64 => Ok(u64::MAX),
        _ => Ok(1u64 << bits),
    }
}

fn upper_region_start(bits: u8) -> Result<u64> {
    match bits {
        0 => Err(WinemuError::Memory(
            "invalid zero-sized upper translation region".to_string(),
        )),
        64 => Ok(0),
        _ => Ok(!((1u64 << bits) - 1)),
    }
}

fn l0_index(va: u64) -> usize {
    ((va >> 39) & 0x1ff) as usize
}

fn l1_index(va: u64) -> usize {
    ((va >> 30) & 0x1ff) as usize
}

fn l2_index(va: u64) -> usize {
    ((va >> 21) & 0x1ff) as usize
}

fn l3_index(va: u64) -> usize {
    ((va >> 12) & 0x1ff) as usize
}
