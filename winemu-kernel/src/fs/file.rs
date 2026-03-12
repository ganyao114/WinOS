use crate::mm::PhysAddr;

use super::devfs;
use super::hostfs;
use super::namespace;
use super::object::{self, FsBackendKind};
use super::types::{
    FsError, FsFileHandle, FsFileInfo, FsFileKind, FsOpenMode, FsOpenRequest, FsPathInfo,
    FsReadPhysRequest, FsReadRequest, FsStandardInfo, FsStdHandle, FsWritePhysRequest,
};

pub fn open(req: &FsOpenRequest<'_>) -> Result<FsFileHandle, FsError> {
    namespace::open(req)
}

pub fn open_readonly(path: &str) -> Result<FsFileHandle, FsError> {
    open(&FsOpenRequest {
        path,
        mode: FsOpenMode::Read,
    })
}

pub fn close(file: FsFileHandle) {
    let Some(record) = object::file_record(file) else {
        return;
    };
    if !object::free_file(file) {
        return;
    }
    match record.backend {
        FsBackendKind::HostFs => hostfs::close(record.backend_idx),
        FsBackendKind::WinEmuHost => {}
    }
}

pub(crate) fn retain_file(file: FsFileHandle) -> bool {
    object::retain_file(file)
}

pub(crate) fn file_ref_count(file: FsFileHandle) -> u32 {
    object::file_ref_count(file)
}

pub fn file_kind(file: FsFileHandle) -> Result<FsFileKind, FsError> {
    let record = object::file_record(file).ok_or(FsError::InvalidHandle)?;
    match record.backend {
        FsBackendKind::HostFs => Ok(FsFileKind::Regular),
        FsBackendKind::WinEmuHost => Ok(FsFileKind::Device),
    }
}

pub fn query_info(file: FsFileHandle) -> Result<FsFileInfo, FsError> {
    let record = object::file_record(file).ok_or(FsError::InvalidHandle)?;
    match record.backend {
        FsBackendKind::HostFs => hostfs::query_info(record.backend_idx),
        FsBackendKind::WinEmuHost => Ok(devfs::query_winemu_host_info()),
    }
}

pub(crate) fn file_name_utf16(file: FsFileHandle) -> Option<crate::rust_alloc::vec::Vec<u16>> {
    object::file_name_utf16(file)
}

#[inline]
pub fn file_size(file: FsFileHandle) -> Result<u64, FsError> {
    Ok(query_info(file)?.size)
}

pub fn query_standard_info(file: FsFileHandle) -> Result<FsStandardInfo, FsError> {
    Ok(FsStandardInfo::new_regular(file_size(file)?))
}

pub fn query_std_standard_info(_std: FsStdHandle) -> FsStandardInfo {
    FsStandardInfo::new_regular(0)
}

pub fn query_path_info(path: &str) -> Result<FsPathInfo, FsError> {
    let file = open_readonly(path)?;
    let size = file_size(file);
    close(file);
    Ok(FsPathInfo::new_regular(size?))
}

pub fn read_at(req: FsReadRequest) -> Result<usize, FsError> {
    let record = object::file_record(req.file).ok_or(FsError::InvalidHandle)?;
    match record.backend {
        FsBackendKind::HostFs => hostfs::read_at(record.backend_idx, req.dst, req.len, req.offset),
        FsBackendKind::WinEmuHost => Err(FsError::Unsupported),
    }
}

pub fn read_exact_at(
    file: FsFileHandle,
    dst: *mut u8,
    len: usize,
    offset: u64,
) -> Result<(), FsError> {
    let got = read_at(FsReadRequest {
        file,
        dst,
        len,
        offset,
    })?;
    if got == len {
        Ok(())
    } else {
        Err(FsError::IoError)
    }
}

pub fn read_at_phys(req: FsReadPhysRequest) -> Result<usize, FsError> {
    let record = object::file_record(req.file).ok_or(FsError::InvalidHandle)?;
    match record.backend {
        FsBackendKind::HostFs => {
            hostfs::read_at_phys(record.backend_idx, req.dst, req.len, req.offset)
        }
        FsBackendKind::WinEmuHost => Err(FsError::Unsupported),
    }
}

pub fn read_exact_at_phys(
    file: FsFileHandle,
    dst: PhysAddr,
    len: usize,
    offset: u64,
) -> Result<(), FsError> {
    let got = read_at_phys(FsReadPhysRequest {
        file,
        dst,
        len,
        offset,
    })?;
    if got == len {
        Ok(())
    } else {
        Err(FsError::IoError)
    }
}

pub fn write_at_phys(req: FsWritePhysRequest) -> Result<usize, FsError> {
    let record = object::file_record(req.file).ok_or(FsError::InvalidHandle)?;
    match record.backend {
        FsBackendKind::HostFs => {
            hostfs::write_at_phys(record.backend_idx, req.src, req.len, req.offset)
        }
        FsBackendKind::WinEmuHost => Err(FsError::Unsupported),
    }
}

pub fn read_std_at_phys(
    std: FsStdHandle,
    dst: PhysAddr,
    len: usize,
    offset: u64,
) -> Result<usize, FsError> {
    hostfs::read_std_at_phys(std, dst, len, offset)
}

pub fn write_std_at_phys(
    std: FsStdHandle,
    src: PhysAddr,
    len: usize,
    offset: u64,
) -> Result<usize, FsError> {
    hostfs::write_std_at_phys(std, src, len, offset)
}

pub(crate) fn import_host_file(fd: u64, size_hint: u64) -> Result<FsFileHandle, FsError> {
    let backend_idx = hostfs::import_existing(fd, size_hint)?;
    match object::alloc_file(FsBackendKind::HostFs, backend_idx, &[]) {
        Ok(file) => Ok(file),
        Err(err) => {
            hostfs::close(backend_idx);
            Err(err)
        }
    }
}
