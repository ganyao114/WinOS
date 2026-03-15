use super::translate::TranslationSpace;
use winemu_core::{Result, WinemuError};

pub const ESR_EC_BRK64: u64 = 0x3c;
pub const SOFTWARE_BREAKPOINT_KIND: usize = 4;
pub const AARCH64_BRK_0: [u8; SOFTWARE_BREAKPOINT_KIND] = [0x00, 0x00, 0x20, 0xd4];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BreakpointKey {
    pub space: TranslationSpace,
    pub addr: u64,
}

#[derive(Clone, Debug)]
pub struct SoftwareBreakpoint {
    pub key: BreakpointKey,
    pub kind: usize,
    pub original: [u8; SOFTWARE_BREAKPOINT_KIND],
    pub refs: usize,
}

pub fn validate_software_breakpoint_kind(kind: usize) -> Result<()> {
    if kind != SOFTWARE_BREAKPOINT_KIND {
        return Err(WinemuError::Memory(format!(
            "unsupported software breakpoint kind {}",
            kind
        )));
    }
    Ok(())
}

pub fn is_software_breakpoint_encoding(bytes: &[u8]) -> bool {
    bytes == AARCH64_BRK_0
}
