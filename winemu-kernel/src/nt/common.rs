use crate::process::{with_process_mut, KObjectKind};

use super::state::file_host_fd;
use crate::mm::usercopy::{
    copy_to_process_user, current_pid, ensure_user_range_access, write_user_value,
};
use crate::mm::UserVa;
use crate::mm::VM_ACCESS_WRITE;

pub(crate) const STD_INPUT_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFF6;
pub(crate) const STD_OUTPUT_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFF5;
pub(crate) const STD_ERROR_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFF4;

pub(crate) const FILE_OPEN: u32 = 1;

pub(crate) const HOST_OPEN_READ: u64 = 0;
pub(crate) const HOST_OPEN_WRITE: u64 = 1;
pub(crate) const HOST_OPEN_RW: u64 = 2;
pub(crate) const HOST_OPEN_CREATE: u64 = 3;
pub(crate) const HOST_PSEUDO_FD_WINEMU_HOST: u64 = u64::MAX - 1;
pub(crate) const WINEMU_HOST_DEVICE_PATH: &str = "\\Device\\WinEmuHost";
pub(crate) const WINEMU_HOST_DEVICE_PATH_NORMALIZED: &str = "Device/WinEmuHost";

pub(crate) const MEM_COMMIT: u32 = 0x1000;
pub(crate) const MEM_RESERVE: u32 = 0x2000;
pub(crate) const MEM_DECOMMIT: u32 = 0x4000;
pub(crate) const MEM_RELEASE: u32 = 0x8000;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct IoStatusBlock {
    pub(crate) status: u64,
    pub(crate) info: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct IoStatusBlockPtr(*mut IoStatusBlock);

#[inline(always)]
pub(crate) fn align_up_4k(v: u64) -> u64 {
    (v + 0xFFF) & !0xFFF
}

impl IoStatusBlockPtr {
    #[inline]
    pub(crate) fn from_raw(ptr: *mut IoStatusBlock) -> Self {
        Self(ptr)
    }

    #[inline]
    pub(crate) fn as_raw(self) -> *mut IoStatusBlock {
        self.0
    }

    #[inline]
    pub(crate) fn write_current(self, st: u32, info: u64) {
        let Some(pid) = current_pid() else {
            return;
        };
        let _ = self.write_for_pid(pid, st, info);
    }

    #[inline]
    pub(crate) fn write_for_pid(self, pid: u32, st: u32, info: u64) -> bool {
        if !self.0.is_null() {
            return write_user_value(
                pid,
                self.0,
                IoStatusBlock {
                    status: st as u64,
                    info,
                },
            );
        }
        true
    }
}

pub(crate) fn write_iosb(iosb_ptr: *mut IoStatusBlock, st: u32, info: u64) {
    IoStatusBlockPtr::from_raw(iosb_ptr).write_current(st, info);
}

pub(crate) fn write_iosb_for_pid(
    pid: u32,
    iosb_ptr: *mut IoStatusBlock,
    st: u32,
    info: u64,
) -> bool {
    IoStatusBlockPtr::from_raw(iosb_ptr).write_for_pid(pid, st, info)
}

pub(crate) fn map_open_flags(access: u32, disposition: u32) -> u64 {
    let can_read = (access & (0x8000_0000 | 0x0001)) != 0;
    let can_write = (access & (0x4000_0000 | 0x0002)) != 0;
    if disposition != FILE_OPEN {
        return HOST_OPEN_CREATE;
    }
    match (can_read, can_write) {
        (true, true) => HOST_OPEN_RW,
        (false, true) => HOST_OPEN_WRITE,
        _ => HOST_OPEN_READ,
    }
}

pub(crate) fn file_handle_to_host_fd(file_handle: u64) -> Option<u64> {
    file_handle_to_host_fd_for_pid(crate::process::current_pid(), file_handle)
}

pub(crate) fn file_handle_to_host_fd_for_pid(owner_pid: u32, file_handle: u64) -> Option<u64> {
    match file_handle {
        STD_INPUT_HANDLE => Some(0),
        STD_OUTPUT_HANDLE => Some(1),
        STD_ERROR_HANDLE => Some(2),
        _ => {
            let obj =
                with_process_mut(owner_pid, |p| p.handle_table.get(file_handle as u32)).flatten();
            match obj {
                Some(o) if o.kind == KObjectKind::File => file_host_fd(o.obj_idx),
                _ => None,
            }
        }
    }
}

// ── GuestWriter ───────────────────────────────────────────────────────────────
//
// Writes a flat struct into guest memory at `buf`, advancing an internal
// offset. Validates buffer length up front via `GuestWriter::new`.
//
// Usage:
//   let mut w = GuestWriter::new(buf, len, 24)?;  // None if buf null or len < 24
//   w.u64(0);          // BaseAddress
//   w.u32(attrs);      // AllocationAttributes
//   w.u32(0);          // padding
//   w.u64(size);       // MaximumSize

pub(crate) struct GuestWriter {
    pid: u32,
    base: UserVa,
    offset: usize,
}

impl GuestWriter {
    /// Returns None if `buf` is null or `len < required`.
    #[inline]
    pub(crate) fn new(buf: *mut u8, len: usize, required: usize) -> Option<Self> {
        let pid = current_pid()?;
        Self::for_pid(pid, buf, len, required)
    }

    #[inline]
    pub(crate) fn for_pid(pid: u32, buf: *mut u8, len: usize, required: usize) -> Option<Self> {
        let base = UserVa::new(buf as u64);
        if buf.is_null()
            || len < required
            || !ensure_user_range_access(pid, base, required, VM_ACCESS_WRITE)
        {
            None
        } else {
            Some(Self {
                pid,
                base,
                offset: 0,
            })
        }
    }

    #[inline]
    fn write_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        let Some(dst_va) = self.base.checked_add(self.offset as u64) else {
            debug_assert!(false, "guest writer address overflow");
            return self;
        };
        let ok = copy_to_process_user(self.pid, dst_va, bytes.as_ptr(), bytes.len());
        debug_assert!(ok);
        self.offset += bytes.len();
        self
    }

    #[inline]
    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.write_bytes(&[v])
    }

    #[inline]
    pub(crate) fn u16(&mut self, v: u16) -> &mut Self {
        self.write_bytes(&v.to_le_bytes())
    }

    #[inline]
    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.write_bytes(&v.to_le_bytes())
    }

    #[inline]
    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.write_bytes(&v.to_le_bytes())
    }

    #[inline]
    pub(crate) fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.write_bytes(bytes)
    }

    /// Zero-fill `n` bytes.
    #[inline]
    pub(crate) fn zeros(&mut self, n: usize) -> &mut Self {
        const ZERO_CHUNK: [u8; 32] = [0; 32];
        let mut remain = n;
        while remain != 0 {
            let chunk = core::cmp::min(remain, ZERO_CHUNK.len());
            let _ = self.write_bytes(&ZERO_CHUNK[..chunk]);
            remain -= chunk;
        }
        self
    }

    #[inline]
    pub(crate) fn bytes_written(&self) -> usize {
        self.offset
    }

    /// Write a `repr(C)` struct directly into guest memory.
    /// Caller must ensure `T` is `Copy` and has no padding surprises.
    #[inline]
    pub(crate) fn write_struct<T: Copy>(&mut self, v: T) -> &mut Self {
        let size = core::mem::size_of::<T>();
        let Some(dst_va) = self.base.checked_add(self.offset as u64) else {
            debug_assert!(false, "guest writer address overflow");
            return self;
        };
        let ok = copy_to_process_user(self.pid, dst_va, (&v as *const T).cast::<u8>(), size);
        debug_assert!(ok);
        self.offset += size;
        self
    }
}
