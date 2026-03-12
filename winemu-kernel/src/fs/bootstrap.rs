use super::types::{FsError, FsFileHandle};

pub struct InitialExe {
    pub file: FsFileHandle,
    pub size: u64,
}

pub fn open_initial_exe() -> Result<InitialExe, FsError> {
    let (fd, size) = crate::hypercall::query_exe_info();
    if fd == u64::MAX || size == 0 {
        return Err(FsError::NotFound);
    }
    let file = super::import_host_file(fd, size)?;
    Ok(InitialExe { file, size })
}
