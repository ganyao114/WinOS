use crate::rust_alloc::string::String;

use crate::mm::usercopy::read_current_user_value;

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

fn read_unicode_ascii_internal(us_ptr: u64, out: &mut [u8], normalize_path: bool) -> usize {
    if us_ptr == 0 || out.is_empty() {
        return 0;
    }
    let byte_len = read_current_user_value(us_ptr as *const u16).unwrap_or(0) as usize;
    let buf_ptr = read_current_user_value((us_ptr + 8) as *const u64).unwrap_or(0);
    if byte_len == 0 || buf_ptr == 0 {
        return 0;
    }
    let count = core::cmp::min(byte_len / 2, out.len());
    for i in 0..count {
        let wc = read_current_user_value((buf_ptr + (i as u64 * 2)) as *const u16).unwrap_or(0);
        out[i] = if wc < 0x80 { wc as u8 } else { b'?' };
    }
    if normalize_path {
        normalize_separators(out, count)
    } else {
        count
    }
}

pub(crate) fn read_unicode_direct(us_ptr: u64, out: &mut [u8]) -> usize {
    read_unicode_ascii_internal(us_ptr, out, false)
}

pub(crate) fn normalize_nt_path(path: &mut [u8], len: usize) -> usize {
    let mut len = normalize_separators(path, len);
    if len == 0 {
        return 0;
    }

    let mut start = 0usize;
    if len >= 4
        && ((path[0] == b'/' && path[1] == b'?' && path[2] == b'?' && path[3] == b'/')
            || (path[0] == b'/' && path[1] == b'/' && path[2] == b'?' && path[3] == b'/')
            || (path[0] == b'/' && path[1] == b'/' && path[2] == b'.' && path[3] == b'/'))
    {
        start = 4;
    }

    while start < len && path[start] == b'/' {
        start += 1;
    }

    if start + 1 < len && path[start + 1] == b':' {
        start += 2;
        while start < len && path[start] == b'/' {
            start += 1;
        }
    }

    len = shift_left(path, len, start);
    while len > 0 && path[len - 1] == b'/' {
        len -= 1;
    }
    len
}

pub(crate) fn read_oa_path(oa_ptr: u64, out: &mut [u8]) -> usize {
    if oa_ptr == 0 || out.is_empty() {
        return 0;
    }
    let us_ptr = read_current_user_value((oa_ptr + 0x10) as *const u64).unwrap_or(0);
    let len = read_unicode_ascii_internal(us_ptr, out, true);
    normalize_nt_path(out, len)
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
