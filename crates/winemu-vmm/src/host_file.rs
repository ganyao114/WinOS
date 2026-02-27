// Host file table — low-level file operations for the guest kernel.
// Separate from NT FileTable (file_io.rs) which handles NT syscall semantics.
// These are used by the kernel's PE loader, DLL loader, etc.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::Mutex;

/// Host file open flags (matches winemu-shared nr module docs)
const FLAG_READ:   u64 = 0;
const FLAG_WRITE:  u64 = 1;
const FLAG_RW:     u64 = 2;
const FLAG_CREATE: u64 = 3;

struct HostFile {
    file: File,
    #[allow(dead_code)]
    path: PathBuf,
}

pub struct HostFileTable {
    files: Mutex<HashMap<u64, HostFile>>,
    next_fd: Mutex<u64>,
    root: PathBuf,
}

impl HostFileTable {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            files: Mutex::new(HashMap::new()),
            next_fd: Mutex::new(1),
            root: root.into(),
        }
    }

    fn alloc_fd(&self) -> u64 {
        let mut n = self.next_fd.lock().unwrap();
        let fd = *n;
        *n += 1;
        fd
    }

    /// Resolve a guest path to a host path.
    /// Guest kernel passes UTF-8 paths relative to the filesystem root.
    fn resolve(&self, path: &str) -> PathBuf {
        // Strip leading slashes/backslashes
        let stripped = path
            .trim_start_matches('/')
            .trim_start_matches('\\');
        // Convert backslashes
        let rel: String = stripped.chars().map(|c| if c == '\\' { '/' } else { c }).collect();
        self.root.join(rel)
    }

    /// Open a host file by absolute path (bypasses root resolution).
    /// Returns fd (u64::MAX on failure).
    pub fn open_absolute(&self, path: &std::path::Path, flags: u64) -> u64 {
        let result = match flags {
            FLAG_READ => OpenOptions::new().read(true).open(path),
            FLAG_WRITE => OpenOptions::new().write(true).open(path),
            FLAG_RW => OpenOptions::new().read(true).write(true).open(path),
            FLAG_CREATE => OpenOptions::new()
                .read(true).write(true).create(true).open(path),
            _ => OpenOptions::new().read(true).open(path),
        };
        match result {
            Ok(file) => {
                let fd = self.alloc_fd();
                self.files.lock().unwrap().insert(fd, HostFile {
                    file,
                    path: path.to_path_buf(),
                });
                fd
            }
            Err(e) => {
                log::warn!("host_open_absolute({:?}): {}", path, e);
                u64::MAX
            }
        }
    }

    /// Open a host file. Returns fd (u64::MAX on failure).
    pub fn open(&self, path: &str, flags: u64) -> u64 {
        let host_path = self.resolve(path);
        let result = match flags {
            FLAG_READ => OpenOptions::new().read(true).open(&host_path),
            FLAG_WRITE => OpenOptions::new().write(true).open(&host_path),
            FLAG_RW => OpenOptions::new().read(true).write(true).open(&host_path),
            FLAG_CREATE => OpenOptions::new()
                .read(true).write(true).create(true).open(&host_path),
            _ => OpenOptions::new().read(true).open(&host_path),
        };
        match result {
            Ok(file) => {
                let fd = self.alloc_fd();
                self.files.lock().unwrap().insert(fd, HostFile {
                    file,
                    path: host_path,
                });
                fd
            }
            Err(e) => {
                log::warn!("host_open({:?}): {}", host_path, e);
                u64::MAX
            }
        }
    }

    /// Read from file into a buffer. Returns bytes read.
    pub fn read(&self, fd: u64, buf: &mut [u8], offset: u64) -> usize {
        let mut files = self.files.lock().unwrap();
        let hf = match files.get_mut(&fd) {
            Some(f) => f,
            None => return 0,
        };
        if offset != u64::MAX {
            if hf.file.seek(SeekFrom::Start(offset)).is_err() {
                return 0;
            }
        }
        hf.file.read(buf).unwrap_or(0)
    }

    /// Write buffer to file. Returns bytes written.
    pub fn write(&self, fd: u64, buf: &[u8], offset: u64) -> usize {
        let mut files = self.files.lock().unwrap();
        let hf = match files.get_mut(&fd) {
            Some(f) => f,
            None => return 0,
        };
        if offset != u64::MAX {
            if hf.file.seek(SeekFrom::Start(offset)).is_err() {
                return 0;
            }
        }
        hf.file.write(buf).unwrap_or(0)
    }

    /// Close a file.
    pub fn close(&self, fd: u64) {
        self.files.lock().unwrap().remove(&fd);
    }

    /// Query file size. Returns size (0 on error).
    pub fn stat(&self, fd: u64) -> u64 {
        let files = self.files.lock().unwrap();
        match files.get(&fd) {
            Some(hf) => hf.file.metadata().map(|m| m.len()).unwrap_or(0),
            None => 0,
        }
    }

    /// Get the raw fd for mmap. Returns None if not found.
    pub fn raw_fd(&self, fd: u64) -> Option<i32> {
        let files = self.files.lock().unwrap();
        files.get(&fd).map(|hf| hf.file.as_raw_fd())
    }
}
