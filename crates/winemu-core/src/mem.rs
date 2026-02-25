use bitflags::bitflags;

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemProt: u32 {
        const NONE  = 0x00;
        const READ  = 0x01;
        const WRITE = 0x02;
        const EXEC  = 0x04;
        const RW    = Self::READ.bits() | Self::WRITE.bits();
        const RX    = Self::READ.bits() | Self::EXEC.bits();
        const RWX   = Self::READ.bits() | Self::WRITE.bits() | Self::EXEC.bits();
    }
}

impl MemProt {
    pub fn from_win32(protect: u32) -> Self {
        match protect {
            0x01 => Self::NONE,  // PAGE_NOACCESS
            0x02 => Self::READ,  // PAGE_READONLY
            0x04 => Self::RX,    // PAGE_EXECUTE_READ
            0x40 => Self::RWX,   // PAGE_EXECUTE_READWRITE
            _ => Self::RW,       // PAGE_READWRITE (default)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_win32() {
        assert_eq!(MemProt::from_win32(0x01), MemProt::NONE);
        assert_eq!(MemProt::from_win32(0x02), MemProt::READ);
        assert_eq!(MemProt::from_win32(0x04), MemProt::RX);
        assert_eq!(MemProt::from_win32(0x40), MemProt::RWX);
        assert_eq!(MemProt::from_win32(0x04 | 0x40), MemProt::RW);
    }
}
