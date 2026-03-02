use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl LogLevel {
    #[inline(always)]
    fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }

    #[inline(always)]
    fn from_u8(raw: u8) -> Self {
        match raw {
            1 => Self::Error,
            2 => Self::Warn,
            3 => Self::Info,
            5 => Self::Trace,
            _ => Self::Debug,
        }
    }
}

static LOG_LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Debug as u8);

const LOG_LINE_MAX: usize = 512;

struct LogLineBuffer {
    buf: [u8; LOG_LINE_MAX],
    len: usize,
    truncated: bool,
}

impl LogLineBuffer {
    fn new() -> Self {
        Self {
            buf: [0; LOG_LINE_MAX],
            len: 0,
            truncated: false,
        }
    }

    fn push_str_lossy(&mut self, s: &str) {
        if s.is_empty() || self.len >= self.buf.len() {
            if !s.is_empty() {
                self.truncated = true;
            }
            return;
        }
        let src = s.as_bytes();
        let rem = self.buf.len() - self.len;
        let take = core::cmp::min(rem, src.len());
        self.buf[self.len..self.len + take].copy_from_slice(&src[..take]);
        self.len += take;
        if take < src.len() {
            self.truncated = true;
        }
    }

    fn ends_with_newline(&self) -> bool {
        self.len != 0 && self.buf[self.len - 1] == b'\n'
    }

    fn finalize(&mut self) {
        if self.truncated {
            self.push_str_lossy(" [truncated]");
        }
        if !self.ends_with_newline() {
            if self.len < self.buf.len() {
                self.buf[self.len] = b'\n';
                self.len += 1;
            } else if self.len != 0 {
                self.buf[self.len - 1] = b'\n';
            }
        }
    }

    fn as_str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl Write for LogLineBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_str_lossy(s);
        Ok(())
    }
}

#[inline(always)]
pub fn set_log_level(level: LogLevel) {
    LOG_LEVEL.store(level as u8, Ordering::Relaxed);
}

#[inline(always)]
pub fn set_log_level_raw(level: u8) {
    set_log_level(LogLevel::from_u8(level));
}

#[inline(always)]
pub fn log_level() -> LogLevel {
    LogLevel::from_u8(LOG_LEVEL.load(Ordering::Relaxed))
}

#[inline(always)]
pub fn log_enabled(level: LogLevel) -> bool {
    (level as u8) <= LOG_LEVEL.load(Ordering::Relaxed)
}

pub fn logf(level: LogLevel, args: fmt::Arguments<'_>) {
    if !log_enabled(level) {
        return;
    }

    let mut line = LogLineBuffer::new();
    let _ = write!(&mut line, "[{}] ", level.as_str());
    let _ = line.write_fmt(args);
    line.finalize();
    crate::hypercall::debug_print(line.as_str());
}

pub fn log(level: LogLevel, msg: &str) {
    logf(level, format_args!("{}", msg));
}

/// Compatibility shim for legacy incremental debug logging call sites.
/// Emits only when `Debug` level is enabled.
pub fn debug_print(msg: &str) {
    if log_enabled(LogLevel::Debug) {
        crate::hypercall::debug_print(msg);
    }
}

/// Compatibility shim for legacy incremental debug logging call sites.
/// Emits a single `0x...` token only when `Debug` level is enabled.
pub fn debug_u64(val: u64) {
    if !log_enabled(LogLevel::Debug) {
        return;
    }
    let hex = b"0123456789abcdef";
    let mut buf = [0u8; 18]; // "0x" + 16 hex digits
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16usize {
        let shift = (15 - i) * 4;
        buf[2 + i] = hex[((val >> shift) & 0xF) as usize];
    }
    let s = unsafe { core::str::from_utf8_unchecked(&buf) };
    crate::hypercall::debug_print(s);
}

#[macro_export]
macro_rules! klog {
    ($level:expr, $($arg:tt)*) => {{
        $crate::hypercall::logf($level, core::format_args!($($arg)*))
    }};
}

#[macro_export]
macro_rules! ktrace {
    ($($arg:tt)*) => {{
        $crate::klog!($crate::hypercall::LogLevel::Trace, $($arg)*)
    }};
}

#[macro_export]
macro_rules! kdebug {
    ($($arg:tt)*) => {{
        $crate::klog!($crate::hypercall::LogLevel::Debug, $($arg)*)
    }};
}

#[macro_export]
macro_rules! kinfo {
    ($($arg:tt)*) => {{
        $crate::klog!($crate::hypercall::LogLevel::Info, $($arg)*)
    }};
}

#[macro_export]
macro_rules! kwarn {
    ($($arg:tt)*) => {{
        $crate::klog!($crate::hypercall::LogLevel::Warn, $($arg)*)
    }};
}

#[macro_export]
macro_rules! kerror {
    ($($arg:tt)*) => {{
        $crate::klog!($crate::hypercall::LogLevel::Error, $($arg)*)
    }};
}
