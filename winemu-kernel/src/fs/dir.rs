use super::hostfs;
use super::object::{self, FsBackendKind};
use super::types::{FsDirEntry, FsError, FsFileHandle, FsStdHandle};

pub fn readdir(file: FsFileHandle, restart: bool) -> Result<Option<FsDirEntry>, FsError> {
    let record = object::file_record(file).ok_or(FsError::InvalidHandle)?;
    match record.backend {
        FsBackendKind::HostFs => hostfs::readdir(record.backend_idx, restart),
        FsBackendKind::WinEmuHost => Err(FsError::Unsupported),
    }
}

pub fn readdir_std(std: FsStdHandle, restart: bool) -> Result<Option<FsDirEntry>, FsError> {
    hostfs::readdir_std(std, restart)
}
