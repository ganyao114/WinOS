use super::devfs;
use super::hostfs;
use super::object::{self, FsBackendKind};
use super::path;
use super::types::{FsError, FsFileHandle, FsOpenRequest};

pub(crate) fn open(req: &FsOpenRequest<'_>) -> Result<FsFileHandle, FsError> {
    let mut normalized_buf = [0u8; 512];
    let path = path::normalize_path_str(req.path, &mut normalized_buf).unwrap_or(req.path);

    if devfs::is_winemu_host_path(path) {
        return object::alloc_file(FsBackendKind::WinEmuHost, 0, path.as_bytes());
    }

    let backend_idx = hostfs::open(&FsOpenRequest {
        path,
        mode: req.mode,
    })?;
    match object::alloc_file(FsBackendKind::HostFs, backend_idx, path.as_bytes()) {
        Ok(file) => Ok(file),
        Err(err) => {
            hostfs::close(backend_idx);
            Err(err)
        }
    }
}
