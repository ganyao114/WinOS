use super::async_io;
use super::hostfs;
use super::object::{self, FsBackendKind};
use super::types::{FsAsyncSubmit, FsError, FsFileHandle, FsNotifyRecord};

pub fn notify_dir(
    file: FsFileHandle,
    watch_tree: bool,
    completion_filter: u32,
) -> Result<Option<FsNotifyRecord>, FsError> {
    let record = object::file_record(file).ok_or(FsError::InvalidHandle)?;
    match record.backend {
        FsBackendKind::HostFs => {
            hostfs::notify_dir(record.backend_idx, watch_tree, completion_filter)
        }
        FsBackendKind::WinEmuHost => Err(FsError::Unsupported),
    }
}

pub(crate) fn notify_dir_async(
    file: FsFileHandle,
    owner_pid: u32,
    waiter_tid: u32,
    watch_tree: bool,
    completion_filter: u32,
) -> Result<FsAsyncSubmit<FsNotifyRecord>, FsError> {
    async_io::submit_async_notify_dir(file, owner_pid, waiter_tid, watch_tree, completion_filter)
}
