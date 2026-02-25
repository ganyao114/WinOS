// NT 文件 I/O 后端 — 将 Guest NT 文件操作映射到 host 文件系统

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;

// NT 访问掩码
const GENERIC_READ:    u32 = 0x8000_0000;
const GENERIC_WRITE:   u32 = 0x4000_0000;
const FILE_READ_DATA:  u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;

// NT 创建处置
const FILE_SUPERSEDE:    u32 = 0;
const FILE_OPEN:         u32 = 1;
const FILE_CREATE:       u32 = 2;
const FILE_OPEN_IF:      u32 = 3;
const FILE_OVERWRITE:    u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

// NT 状态码
pub const STATUS_SUCCESS:           u64 = 0x0000_0000;
pub const STATUS_OBJECT_NOT_FOUND:  u64 = 0xC000_0034;
pub const STATUS_ACCESS_DENIED:     u64 = 0xC000_0022;
pub const STATUS_INVALID_HANDLE:    u64 = 0xC000_0008;
pub const STATUS_END_OF_FILE:       u64 = 0xC000_011B;
pub const STATUS_OBJECT_NAME_COLLISION: u64 = 0xC000_0035;

struct FileHandle {
    file: File,
    #[allow(dead_code)]
    path: PathBuf,
    can_read:  bool,
    can_write: bool,
}

pub struct FileTable {
    handles: Mutex<HashMap<u64, FileHandle>>,
    next_handle: Mutex<u64>,
    root: PathBuf,
}

impl FileTable {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            handles: Mutex::new(HashMap::new()),
            next_handle: Mutex::new(1),
            root: root.into(),
        }
    }

    fn alloc_handle(&self) -> u64 {
        let mut n = self.next_handle.lock().unwrap();
        let h = *n;
        *n += 1;
        h
    }

    /// NT 路径 → host 路径（简单映射：去掉 \??\C:\ 前缀）
    fn resolve(&self, nt_path: &str) -> PathBuf {
        // Strip common NT prefixes
        let stripped = nt_path
            .trim_start_matches("\\??\\")
            .trim_start_matches("\\\\?\\")
            .trim_start_matches("\\\\.\\");
        // Strip drive letter (e.g. "C:\foo" → "foo")
        let no_drive = if stripped.len() >= 3 && stripped.as_bytes()[1] == b':' {
            &stripped[3..]
        } else {
            stripped
        };
        // Convert backslashes
        let rel: String = no_drive.chars().map(|c| if c == '\\' { '/' } else { c }).collect();
        self.root.join(rel)
    }

    /// NtCreateFile
    /// Returns (status, handle)
    pub fn create(
        &self,
        nt_path: &str,
        access: u32,
        disposition: u32,
    ) -> (u64, u64) {
        let path = self.resolve(nt_path);
        let can_read  = access & (GENERIC_READ  | FILE_READ_DATA)  != 0;
        let can_write = access & (GENERIC_WRITE | FILE_WRITE_DATA) != 0;

        let result = match disposition {
            FILE_OPEN => OpenOptions::new()
                .read(can_read).write(can_write).open(&path),
            FILE_CREATE => OpenOptions::new()
                .read(can_read).write(can_write).create_new(true).open(&path),
            FILE_OPEN_IF => OpenOptions::new()
                .read(can_read).write(can_write).create(true).open(&path),
            FILE_OVERWRITE | FILE_OVERWRITE_IF | FILE_SUPERSEDE => OpenOptions::new()
                .read(can_read).write(true).create(true).truncate(true).open(&path),
            _ => OpenOptions::new()
                .read(can_read).write(can_write).create(true).open(&path),
        };

        match result {
            Ok(file) => {
                let h = self.alloc_handle();
                self.handles.lock().unwrap().insert(h, FileHandle {
                    file, path, can_read, can_write,
                });
                (STATUS_SUCCESS, h)
            }
            Err(e) => {
                let status = match e.kind() {
                    std::io::ErrorKind::NotFound       => STATUS_OBJECT_NOT_FOUND,
                    std::io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
                    std::io::ErrorKind::AlreadyExists  => STATUS_OBJECT_NAME_COLLISION,
                    _ => STATUS_ACCESS_DENIED,
                };
                (status, 0)
            }
        }
    }

    /// NtReadFile — returns (status, bytes_read)
    pub fn read(&self, handle: u64, buf: &mut [u8], offset: Option<u64>) -> (u64, usize) {
        let mut handles = self.handles.lock().unwrap();
        let fh = match handles.get_mut(&handle) {
            Some(h) => h,
            None => return (STATUS_INVALID_HANDLE, 0),
        };
        if !fh.can_read { return (STATUS_ACCESS_DENIED, 0); }
        if let Some(off) = offset {
            if fh.file.seek(SeekFrom::Start(off)).is_err() {
                return (STATUS_ACCESS_DENIED, 0);
            }
        }
        match fh.file.read(buf) {
            Ok(0)  => (STATUS_END_OF_FILE, 0),
            Ok(n)  => (STATUS_SUCCESS, n),
            Err(_) => (STATUS_ACCESS_DENIED, 0),
        }
    }

    /// NtWriteFile — returns (status, bytes_written)
    pub fn write(&self, handle: u64, buf: &[u8], offset: Option<u64>) -> (u64, usize) {
        // Windows console handles: 0x14=stdout, 0x18=stderr (from TEB)
        if handle == 0x14 || handle == 0x18 {
            use std::io::Write;
            let _ = std::io::stdout().write_all(buf);
            return (STATUS_SUCCESS, buf.len());
        }
        let mut handles = self.handles.lock().unwrap();
        let fh = match handles.get_mut(&handle) {
            Some(h) => h,
            None => return (STATUS_INVALID_HANDLE, 0),
        };
        if !fh.can_write { return (STATUS_ACCESS_DENIED, 0); }
        if let Some(off) = offset {
            if fh.file.seek(SeekFrom::Start(off)).is_err() {
                return (STATUS_ACCESS_DENIED, 0);
            }
        }
        match fh.file.write(buf) {
            Ok(n)  => (STATUS_SUCCESS, n),
            Err(_) => (STATUS_ACCESS_DENIED, 0),
        }
    }

    /// NtClose
    pub fn close(&self, handle: u64) -> u64 {
        if self.handles.lock().unwrap().remove(&handle).is_some() {
            STATUS_SUCCESS
        } else {
            STATUS_INVALID_HANDLE
        }
    }

    /// NtQueryInformationFile — returns file size
    pub fn query_size(&self, handle: u64) -> (u64, u64) {
        let handles = self.handles.lock().unwrap();
        let fh = match handles.get(&handle) {
            Some(h) => h,
            None => return (STATUS_INVALID_HANDLE, 0),
        };
        match fh.file.metadata() {
            Ok(m)  => (STATUS_SUCCESS, m.len()),
            Err(_) => (STATUS_ACCESS_DENIED, 0),
        }
    }
}
