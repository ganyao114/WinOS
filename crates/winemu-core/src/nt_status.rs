#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtStatus {
    Success = 0x00000000,
    Pending = 0x00000103,
    ObjectNameExists = 0x40000000,
    BufferOverflow = 0x80000005,
    AccessViolation = 0xC0000005,
    InvalidHandle = 0xC0000008,
    InvalidParameter = 0xC000000D,
    NoSuchFile = 0xC000000F,
    AccessDenied = 0xC0000022,
    ObjectNameNotFound = 0xC0000034,
    ObjectNameCollision = 0xC0000035,
    InsufficientResources = 0xC000009A,
    NotImplemented = 0xC0000002,
}

impl From<NtStatus> for u32 {
    fn from(s: NtStatus) -> u32 {
        s as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_status_values() {
        assert_eq!(u32::from(NtStatus::Success), 0x00000000);
        assert_eq!(u32::from(NtStatus::AccessViolation), 0xC0000005);
        assert_eq!(u32::from(NtStatus::NotImplemented), 0xC0000002);
    }
}
