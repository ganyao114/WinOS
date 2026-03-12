use crate::mm::PhysAddr;

use super::backing;
use super::types::{FsBackingHandle, FsError};

pub(crate) fn read_into_phys(
    backing: FsBackingHandle,
    file_off: u64,
    dst: PhysAddr,
    len: usize,
) -> Result<usize, FsError> {
    backing::pager_read_into_phys(backing, file_off, dst, len)
}
