use winemu_shared::hostcall as hc;
use winemu_shared::status;

use crate::hostcall;
use crate::hypercall;
use crate::hypercall::HostCallCompletion;

use super::super::device::{
    FsDeviceIoctlRequest, FsDeviceIoctlSubmit, FsIoctlOutput, IOCTL_WINEMU_HOST_PING,
    IOCTL_WINEMU_HOSTCALL_SYNC, WINEMU_HOSTCALL_PACKET_VERSION, WinEmuHostcallRequest,
    WinEmuHostcallResponse,
};
use super::super::types::{FsError, FsFileInfo};

pub(crate) const WINEMU_HOST_DEVICE_PATH: &str = "\\Device\\WinEmuHost";
pub(crate) const WINEMU_HOST_DEVICE_PATH_NORMALIZED: &str = "Device/WinEmuHost";

fn status_to_fs_error(st: u32) -> FsError {
    match st {
        status::NO_MEMORY => FsError::NoMemory,
        status::INVALID_HANDLE => FsError::InvalidHandle,
        _ => FsError::IoError,
    }
}

fn submit_hostcall(
    owner_pid: u32,
    waiter_tid: u32,
    req: WinEmuHostcallRequest,
) -> Result<FsDeviceIoctlSubmit, FsError> {
    if req.version != WINEMU_HOSTCALL_PACKET_VERSION {
        return Err(FsError::IoError);
    }

    let submit = hostcall::submit_tracked(
        owner_pid,
        waiter_tid,
        hostcall::SubmitArgs {
            opcode: req.opcode,
            flags: req.flags,
            arg0: req.arg0,
            arg1: req.arg1,
            arg2: req.arg2,
            arg3: req.arg3,
            user_tag: req.user_tag,
        },
    )
    .map_err(status_to_fs_error)?;

    Ok(match submit {
        hostcall::SubmitOutcome::Completed(done) => FsDeviceIoctlSubmit::Completed(
            FsIoctlOutput::from_hostcall_response(WinEmuHostcallResponse {
                host_result: done.host_result,
                aux: done.value0,
                request_id: 0,
            }),
        ),
        hostcall::SubmitOutcome::Pending { request_id } => {
            FsDeviceIoctlSubmit::Pending { request_id }
        }
    })
}

pub(crate) fn is_winemu_host_path(path: &str) -> bool {
    super::super::path::eq_ascii_ci(path, WINEMU_HOST_DEVICE_PATH)
        || super::super::path::eq_ascii_ci(path, WINEMU_HOST_DEVICE_PATH_NORMALIZED)
}

pub(crate) fn query_winemu_host_info() -> FsFileInfo {
    FsFileInfo { size: 0 }
}

pub(crate) fn device_io_control(req: FsDeviceIoctlRequest) -> Result<FsDeviceIoctlSubmit, FsError> {
    match req.code {
        IOCTL_WINEMU_HOST_PING => Ok(FsDeviceIoctlSubmit::Completed(
            FsIoctlOutput::from_ping_magic(),
        )),
        IOCTL_WINEMU_HOSTCALL_SYNC => submit_hostcall(
            req.owner_pid,
            req.waiter_tid,
            req.hostcall_request.ok_or(FsError::IoError)?,
        ),
        _ => Err(FsError::Unsupported),
    }
}

pub(crate) fn complete_async_device_io_control(cpl: HostCallCompletion) -> FsIoctlOutput {
    let host_result = if cpl.host_result < 0 {
        hc::HC_INVALID
    } else {
        cpl.host_result as u64
    };
    FsIoctlOutput::from_hostcall_response(WinEmuHostcallResponse {
        host_result,
        aux: cpl.value0,
        request_id: cpl.request_id,
    })
}

pub(crate) fn cancel_async_device_io_control(request_id: u64) -> Result<(), FsError> {
    if request_id == 0 {
        return Ok(());
    }
    let _ = hypercall::hostcall_cancel(request_id);
    let _ = hostcall::unregister_pending_request(request_id);
    Ok(())
}
