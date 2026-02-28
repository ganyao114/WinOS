use crate::rust_alloc::{string::{String, ToString}, vec::Vec};
use crate::sched::sync::{self, make_handle, HANDLE_TYPE_KEY};
use winemu_shared::status;
use winereg::{
    KeyNode, RegistryKey, RegistryValue, RegistryValueData, REG_BINARY, REG_DWORD, REG_EXPAND_SZ,
    REG_MULTI_SZ, REG_QWORD, REG_SZ,
};

use super::common::{read_oa_path, read_unicode_direct};
use super::SvcFrame;

const MAX_KEY_HANDLES: usize = 1024;
const MAX_PATH: usize = 256;
const MAX_NAME_BYTES: usize = 256;
const MAX_VALUE_NAME_UTF16: usize = 256;

struct RegistryState {
    root: KeyNode,
    handles: [Option<KeyNode>; MAX_KEY_HANDLES],
}

static mut REG_STATE: Option<RegistryState> = None;

fn ensure_state() -> &'static mut RegistryState {
    unsafe {
        if REG_STATE.is_none() {
            REG_STATE = Some(RegistryState {
                root: RegistryKey::create_root(),
                handles: [const { None }; MAX_KEY_HANDLES],
            });
        }
        REG_STATE.as_mut().unwrap()
    }
}

fn lower_ascii(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

fn normalize_registry_path(path: &mut [u8], mut len: usize) -> (usize, bool) {
    for b in path.iter_mut().take(len) {
        if *b == b'\\' {
            *b = b'/';
        }
    }

    let mut start = 0usize;
    while start < len && path[start] == b'/' {
        start += 1;
    }
    if start != 0 {
        for i in start..len {
            path[i - start] = path[i];
        }
        len -= start;
    }

    let prefixes: [&[u8]; 5] = [
        b"registry/machine/",
        b"registry/user/",
        b"hkey_local_machine/",
        b"hklm/",
        b"registry/",
    ];

    for prefix in prefixes {
        if len < prefix.len() {
            continue;
        }
        let mut matches = true;
        for i in 0..prefix.len() {
            if lower_ascii(path[i]) != prefix[i] {
                matches = false;
                break;
            }
        }
        if !matches {
            continue;
        }

        for i in prefix.len()..len {
            path[i - prefix.len()] = path[i];
        }
        len -= prefix.len();
        while len > 0 && path[0] == b'/' {
            for i in 1..len {
                path[i - 1] = path[i];
            }
            len -= 1;
        }
        return (len, true);
    }

    (len, false)
}

fn bytes_path_to_registry(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut prev_sep = false;
    for b in bytes {
        let ch = if *b == b'/' || *b == b'\\' { '\\' } else { *b as char };
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

fn read_value_name(us_ptr: u64) -> String {
    let mut raw = [0u8; MAX_NAME_BYTES];
    let len = read_unicode_direct(us_ptr, &mut raw);
    let mut out = String::new();
    for &b in raw.iter().take(len) {
        out.push(b as char);
    }
    out
}

fn alloc_key_handle(state: &mut RegistryState, node: KeyNode) -> Option<u32> {
    for i in 1..MAX_KEY_HANDLES {
        if state.handles[i].is_none() {
            state.handles[i] = Some(node);
            return Some(i as u32);
        }
    }
    None
}

fn key_node_from_handle(state: &RegistryState, handle: u64) -> Option<KeyNode> {
    if sync::handle_type(handle) != HANDLE_TYPE_KEY {
        return None;
    }
    let idx = sync::handle_idx(handle) as usize;
    if idx == 0 || idx >= MAX_KEY_HANDLES {
        return None;
    }
    state.handles[idx].clone()
}

fn join_registry_path(base: &str, rel: &str) -> String {
    if base.is_empty() {
        return rel.to_string();
    }
    if rel.is_empty() {
        return base.to_string();
    }
    let mut s = String::with_capacity(base.len() + 1 + rel.len());
    s.push_str(base);
    s.push('\\');
    s.push_str(rel);
    s
}

fn oa_full_path(oa_ptr: u64, state: &RegistryState) -> Option<String> {
    if oa_ptr == 0 {
        return Some(String::new());
    }

    let root_handle = unsafe { ((oa_ptr + 0x8) as *const u64).read_volatile() };
    let mut rel = [0u8; MAX_PATH];
    let rel_len_raw = read_oa_path(oa_ptr, &mut rel);
    let (rel_len, abs) = normalize_registry_path(&mut rel, rel_len_raw);
    let rel_path = bytes_path_to_registry(&rel[..rel_len]);

    if abs {
        return Some(rel_path);
    }

    let Some(root) = key_node_from_handle(state, root_handle) else {
        return Some(rel_path);
    };

    let base = RegistryKey::get_full_path(&root);
    Some(join_registry_path(&base, &rel_path))
}

fn parse_utf16le_string(data: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let ch = u16::from_le_bytes([data[i], data[i + 1]]);
        i += 2;
        if ch == 0 {
            break;
        }
        out.push(core::char::from_u32(ch as u32).unwrap_or('?'));
    }
    out
}

fn parse_utf16le_multisz(data: &[u8]) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = Vec::<u16>::new();
    let mut i = 0usize;

    while i + 1 < data.len() {
        let ch = u16::from_le_bytes([data[i], data[i + 1]]);
        i += 2;

        if ch == 0 {
            if cur.is_empty() {
                break;
            }
            let s: String = cur
                .iter()
                .map(|u| core::char::from_u32(*u as u32).unwrap_or('?'))
                .collect();
            parts.push(s);
            cur.clear();
            continue;
        }

        cur.push(ch);
    }

    parts
}

fn decode_registry_value(name: &str, ty: u32, data: &[u8]) -> RegistryValue {
    let parsed = match ty {
        REG_SZ => RegistryValueData::String(parse_utf16le_string(data)),
        REG_EXPAND_SZ => RegistryValueData::ExpandString(parse_utf16le_string(data)),
        REG_MULTI_SZ => RegistryValueData::MultiString(parse_utf16le_multisz(data)),
        REG_DWORD if data.len() >= 4 => {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&data[..4]);
            RegistryValueData::Dword(u32::from_le_bytes(arr))
        }
        REG_QWORD if data.len() >= 8 => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&data[..8]);
            RegistryValueData::Qword(u64::from_le_bytes(arr))
        }
        _ => RegistryValueData::Binary(data.to_vec(), if ty == 0 { REG_BINARY } else { ty }),
    };
    RegistryValue::new(name.to_string(), parsed)
}

fn encode_utf16_bytes(s: &str, out: &mut [u8]) -> usize {
    let mut w = 0usize;
    for ch in s.encode_utf16() {
        if w + 2 > out.len() {
            break;
        }
        let b = ch.to_le_bytes();
        out[w] = b[0];
        out[w + 1] = b[1];
        w += 2;
    }
    w
}

fn write_ret_len(ptr: u64, len: usize) {
    if ptr != 0 {
        unsafe { (ptr as *mut u32).write_volatile(len as u32) };
    }
}

fn gc_key_handles(state: &mut RegistryState) {
    for slot in state.handles.iter_mut().skip(1) {
        let Some(node) = slot.as_ref() else {
            continue;
        };
        let path = RegistryKey::get_full_path(node);
        if path.is_empty() {
            continue;
        }
        if RegistryKey::find_key(&state.root, &path).is_none() {
            *slot = None;
        }
    }
}

pub(crate) fn close_key_handle(handle: u64) -> bool {
    let state = ensure_state();
    if sync::handle_type(handle) != HANDLE_TYPE_KEY {
        return false;
    }
    let idx = sync::handle_idx(handle) as usize;
    if idx == 0 || idx >= MAX_KEY_HANDLES {
        return false;
    }
    if state.handles[idx].is_none() {
        return false;
    }
    state.handles[idx] = None;
    true
}

pub(crate) fn handle_open_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let out_ptr = frame.x[0] as *mut u64;
    let oa_ptr = frame.x[2];

    let Some(path) = oa_full_path(oa_ptr, state) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };

    let Some(node) = RegistryKey::find_key(&state.root, &path) else {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    };

    let Some(handle_idx) = alloc_key_handle(state, node) else {
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };

    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(make_handle(HANDLE_TYPE_KEY, handle_idx)) };
    }
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_create_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let out_ptr = frame.x[0] as *mut u64;
    let oa_ptr = frame.x[2];
    let disp_ptr = frame.x[6] as *mut u32;

    let Some(path) = oa_full_path(oa_ptr, state) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };

    let existing = RegistryKey::find_key(&state.root, &path);
    let (node, disp) = if let Some(node) = existing {
        (node, 2u32)
    } else {
        (RegistryKey::create_key_recursive(&state.root, &path), 1u32)
    };

    let Some(handle_idx) = alloc_key_handle(state, node) else {
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };

    if !disp_ptr.is_null() {
        unsafe { disp_ptr.write_volatile(disp) };
    }
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(make_handle(HANDLE_TYPE_KEY, handle_idx)) };
    }
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_delete_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let path = RegistryKey::get_full_path(&node);
    if path.is_empty() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let (parent_path, name) = match path.rsplit_once('\\') {
        Some((p, n)) => (p, n),
        None => ("", path.as_str()),
    };

    let parent = if parent_path.is_empty() {
        Some(state.root.clone())
    } else {
        RegistryKey::find_key(&state.root, parent_path)
    };

    let Some(parent) = parent else {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    };

    if !RegistryKey::delete_subkey(&parent, name, true) {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }

    gc_key_handles(state);
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_set_value_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];
    let value_name_us = frame.x[1];
    let value_type = frame.x[3] as u32;
    let data_ptr = frame.x[4] as *const u8;
    let data_len = frame.x[5] as usize;

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    if data_len != 0 && data_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let value_name = read_value_name(value_name_us);
    let raw_data = if data_len == 0 {
        Vec::new()
    } else {
        unsafe { core::slice::from_raw_parts(data_ptr, data_len) }.to_vec()
    };

    let value = decode_registry_value(&value_name, value_type, &raw_data);
    node.borrow_mut().set_value(value_name, value);
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_query_value_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];
    let value_name_us = frame.x[1];
    let info_class = frame.x[2] as u32;
    let out_ptr = frame.x[3] as *mut u8;
    let out_len = frame.x[4] as usize;
    let ret_len_ptr = frame.x[5];

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let value_name = read_value_name(value_name_us);
    let guard = node.borrow();
    let Some(value) = guard.get_value(&value_name).cloned() else {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    };

    let mut value_name_w = [0u8; MAX_VALUE_NAME_UTF16 * 2];
    let value_name_wlen = encode_utf16_bytes(&value.name, &mut value_name_w);
    let value_data = value.raw_bytes();
    let value_ty = value.reg_type();
    let value_data_len = value_data.len();

    unsafe {
        match info_class {
            0 => {
                let need = 12 + value_name_wlen;
                write_ret_len(ret_len_ptr, need);
                if out_ptr.is_null() || out_len < need {
                    frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(0);
                (out_ptr.add(4) as *mut u32).write_volatile(value_ty);
                (out_ptr.add(8) as *mut u32).write_volatile(value_name_wlen as u32);
                core::ptr::copy_nonoverlapping(value_name_w.as_ptr(), out_ptr.add(12), value_name_wlen);
                frame.x[0] = status::SUCCESS as u64;
            }
            1 => {
                let need = 20 + value_name_wlen + value_data_len;
                write_ret_len(ret_len_ptr, need);
                if out_ptr.is_null() || out_len < need {
                    frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(0);
                (out_ptr.add(4) as *mut u32).write_volatile(value_ty);
                (out_ptr.add(8) as *mut u32).write_volatile((20 + value_name_wlen) as u32);
                (out_ptr.add(12) as *mut u32).write_volatile(value_data_len as u32);
                (out_ptr.add(16) as *mut u32).write_volatile(value_name_wlen as u32);
                core::ptr::copy_nonoverlapping(value_name_w.as_ptr(), out_ptr.add(20), value_name_wlen);
                if value_data_len != 0 {
                    core::ptr::copy_nonoverlapping(
                        value_data.as_ptr(),
                        out_ptr.add(20 + value_name_wlen),
                        value_data_len,
                    );
                }
                frame.x[0] = status::SUCCESS as u64;
            }
            2 => {
                let need = 12 + value_data_len;
                write_ret_len(ret_len_ptr, need);
                if out_ptr.is_null() || out_len < need {
                    frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(0);
                (out_ptr.add(4) as *mut u32).write_volatile(value_ty);
                (out_ptr.add(8) as *mut u32).write_volatile(value_data_len as u32);
                if value_data_len != 0 {
                    core::ptr::copy_nonoverlapping(value_data.as_ptr(), out_ptr.add(12), value_data_len);
                }
                frame.x[0] = status::SUCCESS as u64;
            }
            _ => {
                frame.x[0] = status::INVALID_PARAMETER as u64;
            }
        }
    }
}

pub(crate) fn handle_enumerate_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];
    let index = frame.x[1] as usize;
    let info_class = frame.x[2] as u32;
    let out_ptr = frame.x[3] as *mut u8;
    let out_len = frame.x[4] as usize;
    let ret_len_ptr = frame.x[5];

    if info_class != 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let child = {
        let guard = node.borrow();
        guard.subkeys().values().nth(index).cloned()
    };
    let Some(child) = child else {
        frame.x[0] = status::NO_MORE_ENTRIES as u64;
        return;
    };

    let child_name = child.borrow().name.clone();
    let mut child_name_w = [0u8; MAX_VALUE_NAME_UTF16 * 2];
    let child_name_wlen = encode_utf16_bytes(&child_name, &mut child_name_w);

    let need = 16 + child_name_wlen;
    write_ret_len(ret_len_ptr, need);
    if out_ptr.is_null() || out_len < need {
        frame.x[0] = status::BUFFER_TOO_SMALL as u64;
        return;
    }

    unsafe {
        (out_ptr as *mut u64).write_volatile(0);
        (out_ptr.add(8) as *mut u32).write_volatile(0);
        (out_ptr.add(12) as *mut u32).write_volatile(child_name_wlen as u32);
        core::ptr::copy_nonoverlapping(child_name_w.as_ptr(), out_ptr.add(16), child_name_wlen);
    }

    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_enumerate_value_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];
    let index = frame.x[1] as usize;
    let info_class = frame.x[2] as u32;
    let out_ptr = frame.x[3] as *mut u8;
    let out_len = frame.x[4] as usize;
    let ret_len_ptr = frame.x[5];

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let value = {
        let guard = node.borrow();
        guard.values().values().nth(index).cloned()
    };
    let Some(value) = value else {
        frame.x[0] = status::NO_MORE_ENTRIES as u64;
        return;
    };

    let mut value_name_w = [0u8; MAX_VALUE_NAME_UTF16 * 2];
    let value_name_wlen = encode_utf16_bytes(&value.name, &mut value_name_w);
    let value_data = value.raw_bytes();
    let value_ty = value.reg_type();
    let value_data_len = value_data.len();

    unsafe {
        match info_class {
            0 => {
                let need = 12 + value_name_wlen;
                write_ret_len(ret_len_ptr, need);
                if out_ptr.is_null() || out_len < need {
                    frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(0);
                (out_ptr.add(4) as *mut u32).write_volatile(value_ty);
                (out_ptr.add(8) as *mut u32).write_volatile(value_name_wlen as u32);
                core::ptr::copy_nonoverlapping(value_name_w.as_ptr(), out_ptr.add(12), value_name_wlen);
                frame.x[0] = status::SUCCESS as u64;
            }
            1 => {
                let need = 20 + value_name_wlen + value_data_len;
                write_ret_len(ret_len_ptr, need);
                if out_ptr.is_null() || out_len < need {
                    frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(0);
                (out_ptr.add(4) as *mut u32).write_volatile(value_ty);
                (out_ptr.add(8) as *mut u32).write_volatile((20 + value_name_wlen) as u32);
                (out_ptr.add(12) as *mut u32).write_volatile(value_data_len as u32);
                (out_ptr.add(16) as *mut u32).write_volatile(value_name_wlen as u32);
                core::ptr::copy_nonoverlapping(value_name_w.as_ptr(), out_ptr.add(20), value_name_wlen);
                if value_data_len != 0 {
                    core::ptr::copy_nonoverlapping(
                        value_data.as_ptr(),
                        out_ptr.add(20 + value_name_wlen),
                        value_data_len,
                    );
                }
                frame.x[0] = status::SUCCESS as u64;
            }
            2 => {
                let need = 12 + value_data_len;
                write_ret_len(ret_len_ptr, need);
                if out_ptr.is_null() || out_len < need {
                    frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(0);
                (out_ptr.add(4) as *mut u32).write_volatile(value_ty);
                (out_ptr.add(8) as *mut u32).write_volatile(value_data_len as u32);
                if value_data_len != 0 {
                    core::ptr::copy_nonoverlapping(value_data.as_ptr(), out_ptr.add(12), value_data_len);
                }
                frame.x[0] = status::SUCCESS as u64;
            }
            _ => {
                frame.x[0] = status::INVALID_PARAMETER as u64;
            }
        }
    }
}

pub(crate) fn handle_delete_value_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];
    let value_name_us = frame.x[1];

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let value_name = read_value_name(value_name_us);
    if node.borrow_mut().delete_value(&value_name) {
        frame.x[0] = status::SUCCESS as u64;
    } else {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
    }
}
