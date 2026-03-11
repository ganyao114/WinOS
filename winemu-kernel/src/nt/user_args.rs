use super::SvcFrame;
use crate::mm::usercopy::{
    read_current_user_value, read_user_value, write_current_user_value, write_user_value,
};

#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct UserInPtr<T>(*const T);

#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct UserOutPtr<T>(*mut T);

#[derive(Clone, Copy)]
pub(crate) struct SyscallArgs<'a> {
    frame: &'a SvcFrame,
}

impl<T> UserInPtr<T> {
    #[inline]
    pub(crate) fn from_raw(ptr: *const T) -> Self {
        Self(ptr)
    }

    #[inline]
    pub(crate) fn as_raw(self) -> *const T {
        self.0
    }

    #[inline]
    pub(crate) fn is_null(self) -> bool {
        self.0.is_null()
    }
}

impl<T: Copy> UserInPtr<T> {
    #[inline]
    pub(crate) fn read_current(self) -> Option<T> {
        if self.0.is_null() {
            None
        } else {
            read_current_user_value(self.0)
        }
    }

    #[inline]
    pub(crate) fn read_for_pid(self, pid: u32) -> Option<T> {
        if self.0.is_null() {
            None
        } else {
            read_user_value(pid, self.0)
        }
    }
}

impl<T> UserOutPtr<T> {
    #[inline]
    pub(crate) fn from_raw(ptr: *mut T) -> Self {
        Self(ptr)
    }

    #[inline]
    pub(crate) fn as_raw(self) -> *mut T {
        self.0
    }

    #[inline]
    pub(crate) fn is_null(self) -> bool {
        self.0.is_null()
    }
}

impl<T: Copy> UserOutPtr<T> {
    #[inline]
    pub(crate) fn read_current(self) -> Option<T> {
        if self.0.is_null() {
            None
        } else {
            read_current_user_value(self.0 as *const T)
        }
    }

    #[inline]
    pub(crate) fn read_for_pid(self, pid: u32) -> Option<T> {
        if self.0.is_null() {
            None
        } else {
            read_user_value(pid, self.0 as *const T)
        }
    }

    #[inline]
    pub(crate) fn write_current(self, value: T) -> bool {
        !self.0.is_null() && write_current_user_value(self.0, value)
    }

    #[inline]
    pub(crate) fn write_current_if_present(self, value: T) -> bool {
        self.0.is_null() || write_current_user_value(self.0, value)
    }

    #[inline]
    pub(crate) fn write_for_pid(self, pid: u32, value: T) -> bool {
        !self.0.is_null() && write_user_value(pid, self.0, value)
    }

    #[inline]
    pub(crate) fn write_for_pid_if_present(self, pid: u32, value: T) -> bool {
        self.0.is_null() || write_user_value(pid, self.0, value)
    }
}

impl<'a> SyscallArgs<'a> {
    #[inline]
    pub(crate) fn new(frame: &'a SvcFrame) -> Self {
        Self { frame }
    }

    #[inline]
    pub(crate) fn spill_u64(self, index: usize) -> Option<u64> {
        let offset = (index as u64).checked_mul(core::mem::size_of::<u64>() as u64)?;
        let spill_va = self.frame.user_sp().checked_add(offset)?;
        read_current_user_value(spill_va as *const u64)
    }

    #[inline]
    pub(crate) fn spill_bool(self, index: usize) -> Option<bool> {
        self.spill_u64(index).map(|value| value != 0)
    }
}

#[inline]
pub(crate) fn syscall_spill_u64(frame: &SvcFrame, index: usize) -> Option<u64> {
    SyscallArgs::new(frame).spill_u64(index)
}

#[inline]
pub(crate) fn syscall_spill_bool(frame: &SvcFrame, index: usize) -> Option<bool> {
    SyscallArgs::new(frame).spill_bool(index)
}
