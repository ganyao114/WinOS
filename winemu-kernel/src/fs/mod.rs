mod async_io;
mod backing;
pub mod bootstrap;
mod devfs;
pub mod device;
mod dir;
mod file;
mod hostfs;
mod namespace;
mod notify;
mod object;
mod pager;
pub(crate) mod path;
pub mod types;
mod volume;

pub(crate) use async_io::FsAsyncCompletion;
#[allow(unused_imports)]
pub use device::{
    FsDeviceIoctlRequest, FsDeviceIoctlSubmit, FsIoctlOutput, IOCTL_WINEMU_HOST_PING,
    IOCTL_WINEMU_HOSTCALL_SYNC, WinEmuHostcallRequest, WinEmuHostcallResponse,
};
#[allow(unused_imports)]
pub use dir::{readdir, readdir_std};
pub(crate) use file::file_name_utf16;
pub(crate) use file::file_ref_count;
pub(crate) use file::retain_file;
#[allow(unused_imports)]
pub use file::{
    close, create_dir, file_kind, file_size, open, open_readonly, query_info, query_path_info,
    query_standard_info, query_std_standard_info, read_at, read_at_phys, read_exact_at,
    read_exact_at_phys, read_std_at_phys, seek, set_len, write_at_phys, write_std_at_phys,
};
#[allow(unused_imports)]
pub use notify::notify_dir;
pub(crate) use types::FsBackingHandle;
#[allow(unused_imports)]
pub use types::{
    FsAsyncSubmit, FsDirEntry, FsError, FsFileHandle, FsFileInfo, FsFileKind, FsNotifyRecord,
    FsOpenMode, FsOpenRequest, FsPathInfo, FsReadPhysRequest, FsReadRequest, FsStandardInfo,
    FsStdHandle, FsWritePhysRequest,
};
#[allow(unused_imports)]
pub use volume::{
    FsVolumeAttributeInfo, FsVolumeDeviceInfo, FsVolumeSizeInfo, FsVolumeTarget,
    query_volume_attribute_info, query_volume_device_info, query_volume_size_info,
};

pub fn device_io_control(req: FsDeviceIoctlRequest) -> Result<FsDeviceIoctlSubmit, FsError> {
    let submit = device::device_io_control(req)?;
    if let FsDeviceIoctlSubmit::Pending { request_id } = submit {
        if let Err(err) = async_io::register_pending_device_io_control(request_id) {
            let _ = device::cancel_async_device_io_control(request_id);
            return Err(err);
        }
    }
    Ok(submit)
}

pub(crate) fn create_backing_from_file(
    file: FsFileHandle,
    file_offset: u64,
    size: u64,
    is_image: bool,
) -> Result<FsBackingHandle, FsError> {
    backing::create_from_file(file, file_offset, size, is_image)
}

pub(crate) fn retain_backing(backing: FsBackingHandle) -> bool {
    backing::retain(backing)
}

pub(crate) fn release_backing(backing: FsBackingHandle) {
    backing::release(backing);
}

pub(crate) fn pager_read_into_phys(
    backing: FsBackingHandle,
    file_off: u64,
    dst: crate::mm::PhysAddr,
    len: usize,
) -> Result<usize, FsError> {
    pager::read_into_phys(backing, file_off, dst, len)
}

pub(crate) fn pager_write_from_phys(
    backing: FsBackingHandle,
    file_off: u64,
    src: crate::mm::PhysAddr,
    len: usize,
) -> Result<usize, FsError> {
    pager::write_from_phys(backing, file_off, src, len)
}

fn complete_async_device_io_control(cpl: crate::hypercall::HostCallCompletion) -> FsIoctlOutput {
    device::complete_async_device_io_control(cpl)
}

pub(crate) fn cancel_async_request(request_id: u64) -> Result<(), FsError> {
    if request_id == 0 {
        return Ok(());
    }
    let _ = async_io::cancel_request(request_id);
    let _ = crate::hypercall::hostcall_cancel(request_id);
    let _ = crate::hostcall::unregister_pending_request(request_id);
    Ok(())
}

pub(crate) fn dispatch_async_completion(
    cpl: crate::hypercall::HostCallCompletion,
) -> Option<FsAsyncCompletion> {
    async_io::dispatch_async_completion(cpl)
}

pub(crate) fn read_at_phys_async(
    req: FsReadPhysRequest,
    owner_pid: u32,
    waiter_tid: u32,
) -> Result<FsAsyncSubmit<usize>, FsError> {
    async_io::submit_async_read(req, owner_pid, waiter_tid)
}

pub(crate) fn write_at_phys_async(
    req: FsWritePhysRequest,
    owner_pid: u32,
    waiter_tid: u32,
) -> Result<FsAsyncSubmit<usize>, FsError> {
    async_io::submit_async_write(req, owner_pid, waiter_tid)
}

pub(crate) fn notify_dir_async(
    file: FsFileHandle,
    owner_pid: u32,
    waiter_tid: u32,
    watch_tree: bool,
    completion_filter: u32,
) -> Result<FsAsyncSubmit<FsNotifyRecord>, FsError> {
    notify::notify_dir_async(file, owner_pid, waiter_tid, watch_tree, completion_filter)
}

pub(crate) fn import_host_file(fd: u64, size_hint: u64) -> Result<FsFileHandle, FsError> {
    file::import_host_file(fd, size_hint)
}
