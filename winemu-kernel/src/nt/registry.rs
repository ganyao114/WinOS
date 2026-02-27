use crate::sched::sync::{self, make_handle, HANDLE_TYPE_KEY};
use winemu_shared::status;

use super::common::read_unicode_direct;
use super::common::read_oa_path;
use super::SvcFrame;

const MAX_KEYS: usize = 256;
const MAX_KEY_HANDLES: usize = 1024;
const MAX_VALUES: usize = 1024;
const MAX_NAME: usize = 96;
const MAX_VALUE_DATA: usize = 512;
const MAX_PATH: usize = 256;
const ROOT_KEY_IDX: u16 = 1;

#[derive(Clone, Copy)]
struct RegKey {
    in_use: bool,
    parent: u16,
    name_len: u8,
    name: [u8; MAX_NAME],
}

impl RegKey {
    const fn empty() -> Self {
        Self {
            in_use: false,
            parent: 0,
            name_len: 0,
            name: [0; MAX_NAME],
        }
    }
}

#[derive(Clone, Copy)]
struct RegValue {
    in_use: bool,
    key_idx: u16,
    ty: u32,
    name_len: u8,
    name: [u8; MAX_NAME],
    data_len: u16,
    data: [u8; MAX_VALUE_DATA],
}

impl RegValue {
    const fn empty() -> Self {
        Self {
            in_use: false,
            key_idx: 0,
            ty: 0,
            name_len: 0,
            name: [0; MAX_NAME],
            data_len: 0,
            data: [0; MAX_VALUE_DATA],
        }
    }
}

#[derive(Clone, Copy)]
struct KeyHandle {
    in_use: bool,
    key_idx: u16,
}

impl KeyHandle {
    const fn empty() -> Self {
        Self {
            in_use: false,
            key_idx: 0,
        }
    }
}

static mut REG_INIT: bool = false;
static mut KEYS: [RegKey; MAX_KEYS] = [const { RegKey::empty() }; MAX_KEYS];
static mut KEY_HANDLES: [KeyHandle; MAX_KEY_HANDLES] =
    [const { KeyHandle::empty() }; MAX_KEY_HANDLES];
static mut VALUES: [RegValue; MAX_VALUES] = [const { RegValue::empty() }; MAX_VALUES];

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

    for p in prefixes {
        if len >= p.len() {
            let mut ok = true;
            for i in 0..p.len() {
                if lower_ascii(path[i]) != p[i] {
                    ok = false;
                    break;
                }
            }
            if ok {
                for i in p.len()..len {
                    path[i - p.len()] = path[i];
                }
                len -= p.len();
                while len > 0 && path[0] == b'/' {
                    for i in 1..len {
                        path[i - 1] = path[i];
                    }
                    len -= 1;
                }
                return (len, true);
            }
        }
    }

    (len, false)
}

fn eq_name(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if lower_ascii(a[i]) != lower_ascii(b[i]) {
            return false;
        }
    }
    true
}

fn ensure_init() {
    unsafe {
        if REG_INIT {
            return;
        }
        KEYS[ROOT_KEY_IDX as usize].in_use = true;
        KEYS[ROOT_KEY_IDX as usize].parent = 0;
        KEYS[ROOT_KEY_IDX as usize].name_len = 0;
        REG_INIT = true;
    }
}

fn find_child(parent: u16, seg: &[u8]) -> Option<u16> {
    unsafe {
        for i in 1..MAX_KEYS {
            let k = KEYS[i];
            if !k.in_use || k.parent != parent {
                continue;
            }
            let nlen = k.name_len as usize;
            if eq_name(&k.name[..nlen], seg) {
                return Some(i as u16);
            }
        }
    }
    None
}

fn alloc_key(parent: u16, seg: &[u8]) -> Option<u16> {
    unsafe {
        for i in 1..MAX_KEYS {
            if !KEYS[i].in_use {
                KEYS[i].in_use = true;
                KEYS[i].parent = parent;
                let nlen = core::cmp::min(seg.len(), MAX_NAME);
                KEYS[i].name_len = nlen as u8;
                for j in 0..nlen {
                    KEYS[i].name[j] = lower_ascii(seg[j]);
                }
                return Some(i as u16);
            }
        }
    }
    None
}

fn path_walk(path: &[u8], create_missing: bool) -> Option<u16> {
    ensure_init();
    let mut cur = ROOT_KEY_IDX;
    let mut i = 0usize;
    while i < path.len() {
        while i < path.len() && path[i] == b'/' {
            i += 1;
        }
        if i >= path.len() {
            break;
        }
        let start = i;
        while i < path.len() && path[i] != b'/' {
            i += 1;
        }
        let seg = &path[start..i];
        if seg.is_empty() {
            continue;
        }
        if let Some(next) = find_child(cur, seg) {
            cur = next;
        } else if create_missing {
            cur = alloc_key(cur, seg)?;
        } else {
            return None;
        }
    }
    Some(cur)
}

fn build_key_path(idx: u16, out: &mut [u8]) -> usize {
    let mut chain = [0u16; 32];
    let mut n = 0usize;
    let mut cur = idx;
    unsafe {
        while cur != ROOT_KEY_IDX && cur != 0 && n < chain.len() {
            chain[n] = cur;
            n += 1;
            cur = KEYS[cur as usize].parent;
        }
    }
    let mut w = 0usize;
    unsafe {
        for ci in (0..n).rev() {
            let k = KEYS[chain[ci] as usize];
            let name_len = k.name_len as usize;
            if name_len == 0 {
                continue;
            }
            if w != 0 && w < out.len() {
                out[w] = b'/';
                w += 1;
            }
            let copy = core::cmp::min(name_len, out.len().saturating_sub(w));
            for j in 0..copy {
                out[w + j] = k.name[j];
            }
            w += copy;
            if w >= out.len() {
                break;
            }
        }
    }
    core::cmp::min(w, out.len())
}

fn key_idx_from_handle(handle: u64) -> Option<u16> {
    if sync::handle_type(handle) != HANDLE_TYPE_KEY {
        return None;
    }
    let hidx = sync::handle_idx(handle) as usize;
    unsafe {
        if hidx >= MAX_KEY_HANDLES || !KEY_HANDLES[hidx].in_use {
            None
        } else {
            let idx = KEY_HANDLES[hidx].key_idx as usize;
            if idx == 0 || idx >= MAX_KEYS || !KEYS[idx].in_use {
                None
            } else {
                Some(idx as u16)
            }
        }
    }
}

fn alloc_key_handle(key_idx: u16) -> Option<u16> {
    unsafe {
        for i in 1..MAX_KEY_HANDLES {
            if !KEY_HANDLES[i].in_use {
                KEY_HANDLES[i].in_use = true;
                KEY_HANDLES[i].key_idx = key_idx;
                return Some(i as u16);
            }
        }
    }
    None
}

fn gc_key_handles() {
    unsafe {
        for i in 1..MAX_KEY_HANDLES {
            if !KEY_HANDLES[i].in_use {
                continue;
            }
            let idx = KEY_HANDLES[i].key_idx as usize;
            if idx == 0 || idx >= MAX_KEYS || !KEYS[idx].in_use {
                KEY_HANDLES[i].in_use = false;
                KEY_HANDLES[i].key_idx = 0;
            }
        }
    }
}

fn delete_key_tree(idx: u16) {
    unsafe {
        for i in 1..MAX_KEYS {
            if KEYS[i].in_use && KEYS[i].parent == idx {
                delete_key_tree(i as u16);
            }
        }
        for i in 1..MAX_VALUES {
            if VALUES[i].in_use && VALUES[i].key_idx == idx {
                VALUES[i].in_use = false;
            }
        }
        if idx != ROOT_KEY_IDX {
            KEYS[idx as usize].in_use = false;
            KEYS[idx as usize].name_len = 0;
        }
    }
}

fn find_value(key_idx: u16, name: &[u8]) -> Option<usize> {
    unsafe {
        for i in 1..MAX_VALUES {
            let v = VALUES[i];
            if !v.in_use || v.key_idx != key_idx {
                continue;
            }
            let nlen = v.name_len as usize;
            if eq_name(&v.name[..nlen], name) {
                return Some(i);
            }
        }
    }
    None
}

fn alloc_value_slot(key_idx: u16, name: &[u8]) -> Option<usize> {
    unsafe {
        for i in 1..MAX_VALUES {
            if !VALUES[i].in_use {
                VALUES[i].in_use = true;
                VALUES[i].key_idx = key_idx;
                let nlen = core::cmp::min(name.len(), MAX_NAME);
                VALUES[i].name_len = nlen as u8;
                for j in 0..nlen {
                    VALUES[i].name[j] = lower_ascii(name[j]);
                }
                VALUES[i].data_len = 0;
                VALUES[i].ty = 0;
                return Some(i);
            }
        }
    }
    None
}

fn copy_utf16_ascii(name: &[u8], out: &mut [u8]) -> usize {
    let mut w = 0usize;
    for ch in name {
        if w + 2 > out.len() {
            break;
        }
        out[w] = *ch;
        out[w + 1] = 0;
        w += 2;
    }
    w
}

fn write_ret_len(ptr: u64, len: usize) {
    if ptr != 0 {
        unsafe { (ptr as *mut u32).write_volatile(len as u32) };
    }
}

fn oa_full_path(oa_ptr: u64, out: &mut [u8]) -> Option<usize> {
    if oa_ptr == 0 {
        return Some(0);
    }
    let root_handle = unsafe { ((oa_ptr + 0x8) as *const u64).read_volatile() };
    let mut rel = [0u8; MAX_PATH];
    let rel_len_raw = read_oa_path(oa_ptr, &mut rel);
    let (rel_len, abs) = normalize_registry_path(&mut rel, rel_len_raw);

    let root_idx = key_idx_from_handle(root_handle);
    if abs || root_idx.is_none() {
        let copy = core::cmp::min(rel_len, out.len());
        for i in 0..copy {
            out[i] = rel[i];
        }
        return Some(copy);
    }

    let base_idx = root_idx?;
    let mut w = build_key_path(base_idx, out);
    if rel_len != 0 {
        if w < out.len() {
            out[w] = b'/';
            w += 1;
        }
        let copy = core::cmp::min(rel_len, out.len().saturating_sub(w));
        for i in 0..copy {
            out[w + i] = rel[i];
        }
        w += copy;
    }
    Some(core::cmp::min(w, out.len()))
}

pub(crate) fn close_key_handle(handle: u64) -> bool {
    if sync::handle_type(handle) != HANDLE_TYPE_KEY {
        return false;
    }
    let hidx = sync::handle_idx(handle) as usize;
    unsafe {
        if hidx == 0 || hidx >= MAX_KEY_HANDLES || !KEY_HANDLES[hidx].in_use {
            return false;
        }
        KEY_HANDLES[hidx].in_use = false;
        KEY_HANDLES[hidx].key_idx = 0;
    }
    true
}

pub(crate) fn handle_open_key(frame: &mut SvcFrame) {
    ensure_init();
    let out_ptr = frame.x[0] as *mut u64;
    let oa_ptr = frame.x[2];

    let mut path = [0u8; MAX_PATH];
    let len = match oa_full_path(oa_ptr, &mut path) {
        Some(v) => v,
        None => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
    };

    let idx = match path_walk(&path[..len], false) {
        Some(v) => v,
        None => {
            frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
            return;
        }
    };

    let handle_idx = match alloc_key_handle(idx) {
        Some(v) => v,
        None => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };

    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(make_handle(HANDLE_TYPE_KEY, handle_idx)) };
    }
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_create_key(frame: &mut SvcFrame) {
    ensure_init();
    let out_ptr = frame.x[0] as *mut u64;
    let oa_ptr = frame.x[2];
    let disp_ptr = frame.x[6] as *mut u32;

    let mut path = [0u8; MAX_PATH];
    let len = match oa_full_path(oa_ptr, &mut path) {
        Some(v) => v,
        None => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        }
    };

    let existing = path_walk(&path[..len], false);
    let (idx, disp) = if let Some(v) = existing {
        (v, 2u32)
    } else {
        match path_walk(&path[..len], true) {
            Some(v) => (v, 1u32),
            None => {
                frame.x[0] = status::NO_MEMORY as u64;
                return;
            }
        }
    };

    let handle_idx = match alloc_key_handle(idx) {
        Some(v) => v,
        None => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
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
    ensure_init();
    let handle = frame.x[0];
    let idx = match key_idx_from_handle(handle) {
        Some(v) => v,
        None => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };
    delete_key_tree(idx);
    gc_key_handles();
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_set_value_key(frame: &mut SvcFrame) {
    ensure_init();
    let handle = frame.x[0];
    let val_name_us = frame.x[1];
    let val_type = frame.x[3] as u32;
    let data_ptr = frame.x[4] as *const u8;
    let data_len = frame.x[5] as usize;

    let key_idx = match key_idx_from_handle(handle) {
        Some(v) => v,
        None => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    if data_len > MAX_VALUE_DATA {
        frame.x[0] = status::BUFFER_TOO_SMALL as u64;
        return;
    }
    if data_len != 0 && data_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let mut name = [0u8; MAX_NAME];
    let name_len = read_unicode_direct(val_name_us, &mut name);
    for b in name.iter_mut().take(name_len) {
        *b = lower_ascii(*b);
    }

    let slot = find_value(key_idx, &name[..name_len]).or_else(|| alloc_value_slot(key_idx, &name[..name_len]));
    let i = match slot {
        Some(v) => v,
        None => {
            frame.x[0] = status::NO_MEMORY as u64;
            return;
        }
    };

    unsafe {
        VALUES[i].ty = val_type;
        VALUES[i].data_len = data_len as u16;
        if data_len != 0 {
            core::ptr::copy_nonoverlapping(data_ptr, VALUES[i].data.as_mut_ptr(), data_len);
        }
    }

    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_query_value_key(frame: &mut SvcFrame) {
    ensure_init();
    let handle = frame.x[0];
    let val_name_us = frame.x[1];
    let info_class = frame.x[2] as u32;
    let out_ptr = frame.x[3] as *mut u8;
    let out_len = frame.x[4] as usize;
    let ret_len_ptr = frame.x[5];

    let key_idx = match key_idx_from_handle(handle) {
        Some(v) => v,
        None => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let mut name = [0u8; MAX_NAME];
    let name_len = read_unicode_direct(val_name_us, &mut name);
    for b in name.iter_mut().take(name_len) {
        *b = lower_ascii(*b);
    }

    let vi = match find_value(key_idx, &name[..name_len]) {
        Some(v) => v,
        None => {
            frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
            return;
        }
    };

    unsafe {
        let v = VALUES[vi];
        let mut name_w = [0u8; MAX_NAME * 2];
        let name_wlen = copy_utf16_ascii(&v.name[..v.name_len as usize], &mut name_w);
        let data_len = v.data_len as usize;

        match info_class {
            0 => {
                let need = 12 + name_wlen;
                write_ret_len(ret_len_ptr, need);
                if out_ptr.is_null() || out_len < need {
                    frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(0);
                (out_ptr.add(4) as *mut u32).write_volatile(v.ty);
                (out_ptr.add(8) as *mut u32).write_volatile(name_wlen as u32);
                core::ptr::copy_nonoverlapping(name_w.as_ptr(), out_ptr.add(12), name_wlen);
                frame.x[0] = status::SUCCESS as u64;
            }
            1 => {
                let need = 20 + name_wlen + data_len;
                write_ret_len(ret_len_ptr, need);
                if out_ptr.is_null() || out_len < need {
                    frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(0);
                (out_ptr.add(4) as *mut u32).write_volatile(v.ty);
                (out_ptr.add(8) as *mut u32).write_volatile((20 + name_wlen) as u32);
                (out_ptr.add(12) as *mut u32).write_volatile(data_len as u32);
                (out_ptr.add(16) as *mut u32).write_volatile(name_wlen as u32);
                core::ptr::copy_nonoverlapping(name_w.as_ptr(), out_ptr.add(20), name_wlen);
                if data_len != 0 {
                    core::ptr::copy_nonoverlapping(v.data.as_ptr(), out_ptr.add(20 + name_wlen), data_len);
                }
                frame.x[0] = status::SUCCESS as u64;
            }
            2 => {
                let need = 12 + data_len;
                write_ret_len(ret_len_ptr, need);
                if out_ptr.is_null() || out_len < need {
                    frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(0);
                (out_ptr.add(4) as *mut u32).write_volatile(v.ty);
                (out_ptr.add(8) as *mut u32).write_volatile(data_len as u32);
                if data_len != 0 {
                    core::ptr::copy_nonoverlapping(v.data.as_ptr(), out_ptr.add(12), data_len);
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
    ensure_init();
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

    let key_idx = match key_idx_from_handle(handle) {
        Some(v) => v,
        None => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let mut found = 0usize;
    let mut child_idx = None;
    unsafe {
        for i in 1..MAX_KEYS {
            if KEYS[i].in_use && KEYS[i].parent == key_idx {
                if found == index {
                    child_idx = Some(i as u16);
                    break;
                }
                found += 1;
            }
        }
    }
    let ci = match child_idx {
        Some(v) => v,
        None => {
            frame.x[0] = status::NO_MORE_ENTRIES as u64;
            return;
        }
    };

    unsafe {
        let k = KEYS[ci as usize];
        let mut name_w = [0u8; MAX_NAME * 2];
        let name_wlen = copy_utf16_ascii(&k.name[..k.name_len as usize], &mut name_w);
        let need = 16 + name_wlen;
        write_ret_len(ret_len_ptr, need);
        if out_ptr.is_null() || out_len < need {
            frame.x[0] = status::BUFFER_TOO_SMALL as u64;
            return;
        }
        (out_ptr as *mut u64).write_volatile(0);
        (out_ptr.add(8) as *mut u32).write_volatile(0);
        (out_ptr.add(12) as *mut u32).write_volatile(name_wlen as u32);
        core::ptr::copy_nonoverlapping(name_w.as_ptr(), out_ptr.add(16), name_wlen);
    }

    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_enumerate_value_key(frame: &mut SvcFrame) {
    ensure_init();
    let handle = frame.x[0];
    let index = frame.x[1] as usize;
    let info_class = frame.x[2] as u32;
    let out_ptr = frame.x[3] as *mut u8;
    let out_len = frame.x[4] as usize;
    let ret_len_ptr = frame.x[5];

    let key_idx = match key_idx_from_handle(handle) {
        Some(v) => v,
        None => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let mut found = 0usize;
    let mut vi = None;
    unsafe {
        for i in 1..MAX_VALUES {
            if VALUES[i].in_use && VALUES[i].key_idx == key_idx {
                if found == index {
                    vi = Some(i);
                    break;
                }
                found += 1;
            }
        }
    }
    let i = match vi {
        Some(v) => v,
        None => {
            frame.x[0] = status::NO_MORE_ENTRIES as u64;
            return;
        }
    };

    unsafe {
        let v = VALUES[i];
        let mut name_w = [0u8; MAX_NAME * 2];
        let name_wlen = copy_utf16_ascii(&v.name[..v.name_len as usize], &mut name_w);
        let data_len = v.data_len as usize;

        match info_class {
            0 => {
                let need = 12 + name_wlen;
                write_ret_len(ret_len_ptr, need);
                if out_ptr.is_null() || out_len < need {
                    frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(0);
                (out_ptr.add(4) as *mut u32).write_volatile(v.ty);
                (out_ptr.add(8) as *mut u32).write_volatile(name_wlen as u32);
                core::ptr::copy_nonoverlapping(name_w.as_ptr(), out_ptr.add(12), name_wlen);
                frame.x[0] = status::SUCCESS as u64;
            }
            1 => {
                let need = 20 + name_wlen + data_len;
                write_ret_len(ret_len_ptr, need);
                if out_ptr.is_null() || out_len < need {
                    frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(0);
                (out_ptr.add(4) as *mut u32).write_volatile(v.ty);
                (out_ptr.add(8) as *mut u32).write_volatile((20 + name_wlen) as u32);
                (out_ptr.add(12) as *mut u32).write_volatile(data_len as u32);
                (out_ptr.add(16) as *mut u32).write_volatile(name_wlen as u32);
                core::ptr::copy_nonoverlapping(name_w.as_ptr(), out_ptr.add(20), name_wlen);
                if data_len != 0 {
                    core::ptr::copy_nonoverlapping(v.data.as_ptr(), out_ptr.add(20 + name_wlen), data_len);
                }
                frame.x[0] = status::SUCCESS as u64;
            }
            2 => {
                let need = 12 + data_len;
                write_ret_len(ret_len_ptr, need);
                if out_ptr.is_null() || out_len < need {
                    frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                    return;
                }
                (out_ptr as *mut u32).write_volatile(0);
                (out_ptr.add(4) as *mut u32).write_volatile(v.ty);
                (out_ptr.add(8) as *mut u32).write_volatile(data_len as u32);
                if data_len != 0 {
                    core::ptr::copy_nonoverlapping(v.data.as_ptr(), out_ptr.add(12), data_len);
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
    ensure_init();
    let handle = frame.x[0];
    let val_name_us = frame.x[1];

    let key_idx = match key_idx_from_handle(handle) {
        Some(v) => v,
        None => {
            frame.x[0] = status::INVALID_HANDLE as u64;
            return;
        }
    };

    let mut name = [0u8; MAX_NAME];
    let name_len = read_unicode_direct(val_name_us, &mut name);
    for b in name.iter_mut().take(name_len) {
        *b = lower_ascii(*b);
    }

    if let Some(i) = find_value(key_idx, &name[..name_len]) {
        unsafe { VALUES[i].in_use = false; }
    }

    frame.x[0] = status::SUCCESS as u64;
}
