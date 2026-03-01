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
const FLAG_READ: u64 = 0;
const FLAG_WRITE: u64 = 1;
const FLAG_RW: u64 = 2;
const FLAG_CREATE: u64 = 3;

struct HostFile {
    file: File,
    #[allow(dead_code)]
    path: PathBuf,
    dir_cursor: usize,
    dir_notify_snapshot: Vec<String>,
    dir_notify_init: bool,
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
            // Reserve 0/1/2 for stdin/stdout/stderr.
            next_fd: Mutex::new(3),
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
        let stripped = path.trim_start_matches('/').trim_start_matches('\\');
        // Convert backslashes
        let rel: String = stripped
            .chars()
            .map(|c| if c == '\\' { '/' } else { c })
            .collect();
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
                .read(true)
                .write(true)
                .create(true)
                .open(path),
            _ => OpenOptions::new().read(true).open(path),
        };
        match result {
            Ok(file) => {
                let fd = self.alloc_fd();
                self.files.lock().unwrap().insert(
                    fd,
                    HostFile {
                        file,
                        path: path.to_path_buf(),
                        dir_cursor: 0,
                        dir_notify_snapshot: Vec::new(),
                        dir_notify_init: false,
                    },
                );
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
                .read(true)
                .write(true)
                .create(true)
                .open(&host_path),
            _ => OpenOptions::new().read(true).open(&host_path),
        };
        match result {
            Ok(file) => {
                let fd = self.alloc_fd();
                self.files.lock().unwrap().insert(
                    fd,
                    HostFile {
                        file,
                        path: host_path,
                        dir_cursor: 0,
                        dir_notify_snapshot: Vec::new(),
                        dir_notify_init: false,
                    },
                );
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
        if fd == 0 {
            use std::io::Read;
            return std::io::stdin().read(buf).unwrap_or(0);
        }
        if fd == 1 || fd == 2 {
            return 0;
        }
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
        if fd == 1 {
            use std::io::Write;
            let mut out = std::io::stdout();
            if out.write_all(buf).is_ok() {
                let _ = out.flush();
                return buf.len();
            }
            return 0;
        }
        if fd == 2 {
            use std::io::Write;
            let mut err = std::io::stderr();
            if err.write_all(buf).is_ok() {
                let _ = err.flush();
                return buf.len();
            }
            return 0;
        }
        if fd == 0 {
            return 0;
        }
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
        if fd <= 2 {
            return;
        }
        self.files.lock().unwrap().remove(&fd);
    }

    /// Query file size. Returns size (0 on error).
    pub fn stat(&self, fd: u64) -> u64 {
        if fd <= 2 {
            return 0;
        }
        let files = self.files.lock().unwrap();
        match files.get(&fd) {
            Some(hf) => hf.file.metadata().map(|m| m.len()).unwrap_or(0),
            None => 0,
        }
    }

    /// Read next directory entry name.
    ///
    /// Return value:
    /// - 0: no more files
    /// - u64::MAX: invalid fd / not a directory / error
    /// - otherwise: bit63=is_dir, low32=name_len(bytes copied to `buf`)
    pub fn readdir(&self, fd: u64, buf: &mut [u8], restart: bool) -> u64 {
        const FLAG_IS_DIR: u64 = 1u64 << 63;

        if fd <= 2 || buf.is_empty() {
            return u64::MAX;
        }

        let mut files = self.files.lock().unwrap();
        let hf = match files.get_mut(&fd) {
            Some(v) => v,
            None => return u64::MAX,
        };

        match hf.file.metadata() {
            Ok(meta) if meta.is_dir() => {}
            _ => return u64::MAX,
        }

        if restart {
            hf.dir_cursor = 0;
        }

        let mut entries: Vec<(String, bool)> = Vec::new();
        let iter = match std::fs::read_dir(&hf.path) {
            Ok(v) => v,
            Err(_) => return u64::MAX,
        };
        for item in iter {
            let Ok(entry) = item else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.is_empty() {
                continue;
            }
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            entries.push((name, is_dir));
        }
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        if hf.dir_cursor >= entries.len() {
            return 0;
        }

        let (name, is_dir) = &entries[hf.dir_cursor];
        hf.dir_cursor += 1;

        let name_bytes = name.as_bytes();
        let copied = name_bytes.len().min(buf.len());
        buf[..copied].copy_from_slice(&name_bytes[..copied]);

        let mut ret = copied as u64;
        if *is_dir {
            ret |= FLAG_IS_DIR;
        }
        ret
    }

    fn read_dir_snapshot(path: &std::path::Path, watch_tree: bool) -> Option<Vec<String>> {
        let mut out = Vec::new();
        let iter = std::fs::read_dir(path).ok()?;
        for item in iter {
            let Ok(entry) = item else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.is_empty() {
                continue;
            }
            out.push(name.clone());
            if watch_tree && entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let sub = path.join(&name);
                if let Some(children) = Self::read_dir_snapshot(&sub, true) {
                    for child in children {
                        out.push(format!("{}/{}", name, child));
                    }
                }
            }
        }
        out.sort_unstable();
        Some(out)
    }

    /// Query one pending directory change and return changed name.
    ///
    /// Return value:
    /// - 0: no change
    /// - u64::MAX: invalid fd / not a directory / error
    /// - otherwise: bits[39:32]=action, low32=name_len
    pub fn notify_dir_change(
        &self,
        fd: u64,
        buf: &mut [u8],
        watch_tree: bool,
        _completion_filter: u32,
    ) -> u64 {
        if fd <= 2 || buf.is_empty() {
            return u64::MAX;
        }

        let mut files = self.files.lock().unwrap();
        let hf = match files.get_mut(&fd) {
            Some(v) => v,
            None => return u64::MAX,
        };

        match hf.file.metadata() {
            Ok(meta) if meta.is_dir() => {}
            _ => return u64::MAX,
        }

        let Some(current) = Self::read_dir_snapshot(&hf.path, watch_tree) else {
            return u64::MAX;
        };

        if !hf.dir_notify_init {
            hf.dir_notify_snapshot = current;
            hf.dir_notify_init = true;
            return 0;
        }

        let old = &hf.dir_notify_snapshot;
        if *old == current {
            return 0;
        }

        let mut action: u8 = 3; // FILE_ACTION_MODIFIED
        let mut changed_name = String::from(".");

        let mut oi = 0usize;
        let mut ci = 0usize;
        while oi < old.len() && ci < current.len() {
            if old[oi] == current[ci] {
                oi += 1;
                ci += 1;
                continue;
            }
            if old[oi] > current[ci] {
                action = 1; // FILE_ACTION_ADDED
                changed_name = current[ci].clone();
                break;
            }
            action = 2; // FILE_ACTION_REMOVED
            changed_name = old[oi].clone();
            break;
        }
        if oi >= old.len() && ci < current.len() {
            action = 1;
            changed_name = current[ci].clone();
        } else if ci >= current.len() && oi < old.len() {
            action = 2;
            changed_name = old[oi].clone();
        }

        hf.dir_notify_snapshot = current;

        let bytes = changed_name.as_bytes();
        let copied = bytes.len().min(buf.len());
        buf[..copied].copy_from_slice(&bytes[..copied]);
        ((action as u64) << 32) | (copied as u64)
    }

    /// Get the raw fd for mmap. Returns None if not found.
    pub fn raw_fd(&self, fd: u64) -> Option<i32> {
        let files = self.files.lock().unwrap();
        files.get(&fd).map(|hf| hf.file.as_raw_fd())
    }
}
