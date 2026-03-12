use crate::mm::PhysAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsError {
    NotFound,
    InvalidHandle,
    IoError,
    NoMemory,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsFileKind {
    Regular,
    Device,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsOpenMode {
    Read,
    Write,
    ReadWrite,
    Create,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsStdHandle {
    Input,
    Output,
    Error,
}

#[derive(Clone, Copy)]
pub struct FsOpenRequest<'a> {
    pub path: &'a str,
    pub mode: FsOpenMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsFileInfo {
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsStandardInfo {
    allocation_size: u64,
    end_of_file: u64,
    number_of_links: u32,
    delete_pending: bool,
    directory: bool,
}

impl FsStandardInfo {
    #[inline]
    pub fn allocation_size(self) -> u64 {
        self.allocation_size
    }

    #[inline]
    pub fn end_of_file(self) -> u64 {
        self.end_of_file
    }

    #[inline]
    pub fn number_of_links(self) -> u32 {
        self.number_of_links
    }

    #[inline]
    pub fn delete_pending(self) -> bool {
        self.delete_pending
    }

    #[inline]
    pub fn directory(self) -> bool {
        self.directory
    }

    pub(crate) fn new_regular(size: u64) -> Self {
        Self {
            allocation_size: size,
            end_of_file: size,
            number_of_links: 1,
            delete_pending: false,
            directory: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsPathInfo {
    size: u64,
    directory: bool,
}

impl FsPathInfo {
    #[inline]
    pub fn size(self) -> u64 {
        self.size
    }

    #[inline]
    pub fn directory(self) -> bool {
        self.directory
    }

    pub(crate) fn new_regular(size: u64) -> Self {
        Self {
            size,
            directory: false,
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsFileHandle(pub(crate) u32);

impl FsFileHandle {
    #[inline]
    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    #[inline]
    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FsBackingHandle(pub(crate) u32);

impl FsBackingHandle {
    #[inline]
    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    #[inline]
    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsReadRequest {
    pub file: FsFileHandle,
    pub dst: *mut u8,
    pub len: usize,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsReadPhysRequest {
    pub file: FsFileHandle,
    pub dst: PhysAddr,
    pub len: usize,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsWritePhysRequest {
    pub file: FsFileHandle,
    pub src: PhysAddr,
    pub len: usize,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsAsyncSubmit<T> {
    Completed(T),
    Pending { request_id: u64 },
}

#[derive(Clone, Copy)]
pub struct FsDirEntry {
    is_dir: bool,
    name_len: u16,
    name: [u8; 512],
}

impl FsDirEntry {
    pub(crate) fn new(name: &[u8], is_dir: bool) -> Result<Self, FsError> {
        if name.is_empty() || name.len() > 512 {
            return Err(FsError::IoError);
        }
        let mut out = [0u8; 512];
        out[..name.len()].copy_from_slice(name);
        Ok(Self {
            is_dir,
            name_len: name.len() as u16,
            name: out,
        })
    }

    #[inline]
    pub fn is_dir(self) -> bool {
        self.is_dir
    }

    #[inline]
    pub fn name_len(self) -> usize {
        self.name_len as usize
    }

    #[inline]
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

#[derive(Clone, Copy)]
pub struct FsNotifyRecord {
    action: u32,
    name_len: u16,
    name: [u8; 512],
}

impl FsNotifyRecord {
    pub(crate) fn new(action: u32, name: &[u8]) -> Result<Self, FsError> {
        if action == 0 || name.is_empty() || name.len() > 512 {
            return Err(FsError::IoError);
        }
        let mut out = [0u8; 512];
        out[..name.len()].copy_from_slice(name);
        Ok(Self {
            action,
            name_len: name.len() as u16,
            name: out,
        })
    }

    #[inline]
    pub fn action(self) -> u32 {
        self.action
    }

    #[inline]
    pub fn name_len(self) -> usize {
        self.name_len as usize
    }

    #[inline]
    pub fn name(&self) -> &[u8] {
        let len = self.name_len as usize;
        &self.name[..len]
    }
}
