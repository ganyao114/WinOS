use crate::rust_alloc::string::String;

use super::user_args::UserInPtr;
use crate::mm::usercopy::read_current_user_bytes;

const OA_ROOT_DIRECTORY_OFFSET: u64 = 0x08;
const OA_OBJECT_NAME_OFFSET: u64 = 0x10;
const OA_ATTRIBUTES_OFFSET: u64 = 0x18;
const US_LENGTH_OFFSET: u64 = 0x00;
const US_BUFFER_OFFSET: u64 = 0x08;

#[derive(Clone, Copy)]
pub(crate) struct UnicodeStringView {
    ptr: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct ObjectAttributesView {
    ptr: u64,
}

#[inline(always)]
fn shift_left(path: &mut [u8], len: usize, count: usize) -> usize {
    if count == 0 {
        return len;
    }
    if count >= len {
        return 0;
    }
    for i in count..len {
        path[i - count] = path[i];
    }
    len - count
}

#[inline(always)]
fn lower_ascii(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

fn starts_with_case_insensitive(path: &[u8], prefix: &[u8]) -> bool {
    if path.len() < prefix.len() {
        return false;
    }
    for i in 0..prefix.len() {
        if lower_ascii(path[i]) != prefix[i] {
            return false;
        }
    }
    true
}

fn normalize_separators(path: &mut [u8], len: usize) -> usize {
    let mut out = 0usize;
    let mut prev_sep = false;
    for i in 0..len {
        let mut b = path[i];
        if b == b'\\' {
            b = b'/';
        }
        if b == b'/' {
            if prev_sep {
                continue;
            }
            prev_sep = true;
        } else {
            prev_sep = false;
        }
        path[out] = b;
        out += 1;
    }
    out
}

fn read_unicode_ascii_internal(
    us: UnicodeStringView,
    out: &mut [u8],
    normalize_path: bool,
) -> usize {
    if out.is_empty() {
        return 0;
    }
    let byte_len = us.byte_len();
    let buf_ptr = us.buffer_ptr();
    if byte_len == 0 || buf_ptr == 0 {
        return 0;
    }
    let copy_len = core::cmp::min(byte_len, out.len().saturating_mul(2));
    let Some(bytes) = read_current_user_bytes(buf_ptr as *const u8, copy_len) else {
        return 0;
    };
    let count = bytes.len() / 2;
    for i in 0..count {
        let wc = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
        out[i] = if wc < 0x80 { wc as u8 } else { b'?' };
    }
    if normalize_path {
        normalize_separators(out, count)
    } else {
        count
    }
}

impl UnicodeStringView {
    #[inline]
    pub(crate) fn from_ptr(ptr: u64) -> Option<Self> {
        if ptr == 0 {
            None
        } else {
            Some(Self { ptr })
        }
    }

    #[inline]
    pub(crate) fn byte_len(self) -> usize {
        UserInPtr::from_raw((self.ptr + US_LENGTH_OFFSET) as *const u16)
            .read_current()
            .unwrap_or(0) as usize
    }

    #[inline]
    pub(crate) fn buffer_ptr(self) -> u64 {
        UserInPtr::from_raw((self.ptr + US_BUFFER_OFFSET) as *const u64)
            .read_current()
            .unwrap_or(0)
    }

    #[inline]
    pub(crate) fn read_ascii(self, out: &mut [u8]) -> usize {
        read_unicode_ascii_internal(self, out, false)
    }

    #[inline]
    pub(crate) fn read_path(self, out: &mut [u8]) -> usize {
        let len = read_unicode_ascii_internal(self, out, true);
        normalize_nt_path(out, len)
    }
}

impl ObjectAttributesView {
    #[inline]
    pub(crate) fn from_ptr(ptr: u64) -> Option<Self> {
        if ptr == 0 {
            None
        } else {
            Some(Self { ptr })
        }
    }

    #[inline]
    pub(crate) fn root_directory(self) -> u64 {
        UserInPtr::from_raw((self.ptr + OA_ROOT_DIRECTORY_OFFSET) as *const u64)
            .read_current()
            .unwrap_or(0)
    }

    #[inline]
    pub(crate) fn name_ptr(self) -> u64 {
        UserInPtr::from_raw((self.ptr + OA_OBJECT_NAME_OFFSET) as *const u64)
            .read_current()
            .unwrap_or(0)
    }

    #[inline]
    pub(crate) fn attributes(self) -> u32 {
        UserInPtr::from_raw((self.ptr + OA_ATTRIBUTES_OFFSET) as *const u32)
            .read_current()
            .unwrap_or(0)
    }

    #[inline]
    pub(crate) fn name(self) -> Option<UnicodeStringView> {
        UnicodeStringView::from_ptr(self.name_ptr())
    }

    #[inline]
    pub(crate) fn read_name_ascii(self, out: &mut [u8]) -> usize {
        self.name().map_or(0, |us| us.read_ascii(out))
    }

    #[inline]
    pub(crate) fn read_path(self, out: &mut [u8]) -> usize {
        self.name().map_or(0, |us| us.read_path(out))
    }
}

pub(crate) fn normalize_nt_path(path: &mut [u8], len: usize) -> usize {
    crate::fs::path::normalize_nt_path(path, len)
}

pub(crate) fn normalize_registry_path(path: &mut [u8], len: usize) -> (usize, bool) {
    let mut len = normalize_separators(path, len);
    len = normalize_nt_path(path, len);

    let prefixes: [&[u8]; 5] = [
        b"registry/machine/",
        b"registry/user/",
        b"hkey_local_machine/",
        b"hklm/",
        b"registry/",
    ];

    for prefix in prefixes {
        if !starts_with_case_insensitive(&path[..len], prefix) {
            continue;
        }
        let new_len = shift_left(path, len, prefix.len());
        return (new_len, true);
    }

    (len, false)
}

pub(crate) fn bytes_path_to_registry(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut prev_sep = false;
    for b in bytes {
        let ch = if *b == b'/' || *b == b'\\' {
            '\\'
        } else {
            *b as char
        };
        if ch == '\\' {
            if prev_sep {
                continue;
            }
            prev_sep = true;
            out.push('\\');
        } else {
            prev_sep = false;
            out.push(ch);
        }
    }
    while out.ends_with('\\') {
        out.pop();
    }
    out
}
