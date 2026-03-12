use super::file;
use super::types::{FsError, FsFileHandle, FsStdHandle};

const FILE_DEVICE_DISK: u32 = 0x0000_0007;
const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x0000_0001;
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;
const DEFAULT_BYTES_PER_SECTOR: u32 = 4096;
const DEFAULT_SECTORS_PER_ALLOC: u32 = 1;
const DEFAULT_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const FS_NAME: &str = "WinEmuFS";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsVolumeTarget {
    Std(FsStdHandle),
    File(FsFileHandle),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsVolumeDeviceInfo {
    device_type: u32,
    characteristics: u32,
}

impl FsVolumeDeviceInfo {
    #[inline]
    pub fn device_type(self) -> u32 {
        self.device_type
    }

    #[inline]
    pub fn characteristics(self) -> u32 {
        self.characteristics
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsVolumeAttributeInfo {
    attributes: u32,
    max_component_name_len: u32,
    fs_name: &'static str,
}

impl FsVolumeAttributeInfo {
    #[inline]
    pub fn attributes(self) -> u32 {
        self.attributes
    }

    #[inline]
    pub fn max_component_name_len(self) -> u32 {
        self.max_component_name_len
    }

    #[inline]
    pub fn fs_name(self) -> &'static str {
        self.fs_name
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsVolumeSizeInfo {
    total_units: u64,
    avail_units: u64,
    sectors_per_alloc: u32,
    bytes_per_sector: u32,
}

impl FsVolumeSizeInfo {
    #[inline]
    pub fn total_units(self) -> u64 {
        self.total_units
    }

    #[inline]
    pub fn avail_units(self) -> u64 {
        self.avail_units
    }

    #[inline]
    pub fn sectors_per_alloc(self) -> u32 {
        self.sectors_per_alloc
    }

    #[inline]
    pub fn bytes_per_sector(self) -> u32 {
        self.bytes_per_sector
    }
}

fn validate_target(target: FsVolumeTarget) -> Result<(), FsError> {
    match target {
        FsVolumeTarget::Std(_) => Ok(()),
        FsVolumeTarget::File(file_handle) => {
            let _ = file::query_info(file_handle)?;
            Ok(())
        }
    }
}

pub fn query_volume_device_info(target: FsVolumeTarget) -> Result<FsVolumeDeviceInfo, FsError> {
    validate_target(target)?;
    Ok(FsVolumeDeviceInfo {
        device_type: FILE_DEVICE_DISK,
        characteristics: 0,
    })
}

pub fn query_volume_attribute_info(
    target: FsVolumeTarget,
) -> Result<FsVolumeAttributeInfo, FsError> {
    validate_target(target)?;
    Ok(FsVolumeAttributeInfo {
        attributes: FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK,
        max_component_name_len: 255,
        fs_name: FS_NAME,
    })
}

pub fn query_volume_size_info(target: FsVolumeTarget) -> Result<FsVolumeSizeInfo, FsError> {
    let file_bytes = match target {
        FsVolumeTarget::Std(_) => 0,
        FsVolumeTarget::File(file_handle) => file::file_size(file_handle)?,
    };
    let total_bytes = core::cmp::max(file_bytes, DEFAULT_TOTAL_BYTES);
    let total_units = core::cmp::max(total_bytes / DEFAULT_BYTES_PER_SECTOR as u64, 1);
    Ok(FsVolumeSizeInfo {
        total_units,
        avail_units: total_units / 2,
        sectors_per_alloc: DEFAULT_SECTORS_PER_ALLOC,
        bytes_per_sector: DEFAULT_BYTES_PER_SECTOR,
    })
}
