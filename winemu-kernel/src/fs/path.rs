#[inline(always)]
pub(crate) fn lower_ascii(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b + 32
    } else {
        b
    }
}

pub(crate) fn eq_ascii_ci(a: &str, b: &str) -> bool {
    let aa = a.as_bytes();
    let bb = b.as_bytes();
    if aa.len() != bb.len() {
        return false;
    }
    let mut i = 0usize;
    while i < aa.len() {
        if lower_ascii(aa[i]) != lower_ascii(bb[i]) {
            return false;
        }
        i += 1;
    }
    true
}

#[inline(always)]
fn shift_left(path: &mut [u8], len: usize, count: usize) -> usize {
    if count == 0 {
        return len;
    }
    if count >= len {
        return 0;
    }
    let mut i = count;
    while i < len {
        path[i - count] = path[i];
        i += 1;
    }
    len - count
}

fn normalize_separators(path: &mut [u8], len: usize) -> usize {
    let mut out = 0usize;
    let mut prev_sep = false;
    let mut i = 0usize;
    while i < len {
        let mut b = path[i];
        if b == b'\\' {
            b = b'/';
        }
        if b == b'/' {
            if prev_sep {
                i += 1;
                continue;
            }
            prev_sep = true;
        } else {
            prev_sep = false;
        }
        path[out] = b;
        out += 1;
        i += 1;
    }
    out
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

pub(crate) fn normalize_path_str<'a>(path: &str, scratch: &'a mut [u8]) -> Option<&'a str> {
    let bytes = path.as_bytes();
    if bytes.len() > scratch.len() {
        return None;
    }
    scratch[..bytes.len()].copy_from_slice(bytes);
    let len = normalize_nt_path(scratch, bytes.len());
    core::str::from_utf8(&scratch[..len]).ok()
}
