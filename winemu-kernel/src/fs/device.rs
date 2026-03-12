use core::mem::size_of;

use crate::hypercall::HostCallCompletion;

use super::object::{self, FsBackendKind};
use super::types::{FsError, FsFileHandle};

pub const WINEMU_HOST_PING_MAGIC: u32 = 0x5745_4D55;
pub const IOCTL_WINEMU_HOST_PING: u32 = 0x0022_A000;
pub const IOCTL_WINEMU_HOSTCALL_SYNC: u32 = 0x0022_A004;
pub const WINEMU_HOSTCALL_PACKET_VERSION: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WinEmuHostcallRequest {
    pub version: u32,
    pub _reserved: u32,
    pub opcode: u64,
    pub flags: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub user_tag: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WinEmuHostcallResponse {
    pub host_result: u64,
    pub aux: u64,
    pub request_id: u64,
}

const FS_IOCTL_OUTPUT_CAP: usize = size_of::<WinEmuHostcallResponse>();

#[derive(Clone, Copy)]
pub struct FsIoctlOutput {
    len: usize,
    bytes: [u8; FS_IOCTL_OUTPUT_CAP],
}

impl FsIoctlOutput {
    pub fn len(self) -> usize {
        self.len
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, FsError> {
        if bytes.len() > FS_IOCTL_OUTPUT_CAP {
            return Err(FsError::Unsupported);
        }
        let mut out = [0u8; FS_IOCTL_OUTPUT_CAP];
        out[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            len: bytes.len(),
            bytes: out,
        })
    }

    pub(crate) fn from_ping_magic() -> Self {
        let mut out = [0u8; FS_IOCTL_OUTPUT_CAP];
        out[..size_of::<u32>()].copy_from_slice(&WINEMU_HOST_PING_MAGIC.to_le_bytes());
        Self {
            len: size_of::<u32>(),
            bytes: out,
        }
    }

    pub(crate) fn from_hostcall_response(resp: WinEmuHostcallResponse) -> Self {
        let mut out = [0u8; FS_IOCTL_OUTPUT_CAP];
        out[0..8].copy_from_slice(&resp.host_result.to_le_bytes());
        out[8..16].copy_from_slice(&resp.aux.to_le_bytes());
        out[16..24].copy_from_slice(&resp.request_id.to_le_bytes());
        Self {
            len: size_of::<WinEmuHostcallResponse>(),
            bytes: out,
        }
    }
}

#[derive(Clone, Copy)]
pub struct FsDeviceIoctlRequest {
    pub file: FsFileHandle,
    pub code: u32,
    pub owner_pid: u32,
    pub waiter_tid: u32,
    pub hostcall_request: Option<WinEmuHostcallRequest>,
}

#[derive(Clone, Copy)]
pub enum FsDeviceIoctlSubmit {
    Completed(FsIoctlOutput),
    Pending { request_id: u64 },
}

pub fn device_io_control(req: FsDeviceIoctlRequest) -> Result<FsDeviceIoctlSubmit, FsError> {
    let record = object::file_record(req.file).ok_or(FsError::InvalidHandle)?;
    match record.backend {
        FsBackendKind::WinEmuHost => super::devfs::device_io_control(req),
        FsBackendKind::HostFs => Err(FsError::Unsupported),
    }
}

pub(crate) fn complete_async_device_io_control(cpl: HostCallCompletion) -> FsIoctlOutput {
    super::devfs::complete_async_device_io_control(cpl)
}

pub(crate) fn cancel_async_device_io_control(request_id: u64) -> Result<(), FsError> {
    super::devfs::cancel_async_device_io_control(request_id)
}
