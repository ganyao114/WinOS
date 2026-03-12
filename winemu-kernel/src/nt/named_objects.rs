// nt/named_objects.rs — Global named-object table for NT sync primitives.
//
// Supports named Event, Mutex, Semaphore objects.
// Name normalization: strips Local\, Global\, \BaseNamedObjects\,
// \Sessions\N\BaseNamedObjects\ prefixes, then lowercases.
//
// Thread-safety: all access is under the scheduler lock (same as sync objects).

use core::cell::UnsafeCell;

use crate::process::KObjectKind;

const MAX_NAMED: usize = 256;
const MAX_NAME_BYTES: usize = 128;

#[derive(Clone, Copy)]
pub(crate) struct NamedEntry {
    pub(crate) kind: KObjectKind,
    pub(crate) obj_idx: u32,
    pub(crate) name_len: u8,
    pub(crate) name: [u8; MAX_NAME_BYTES],
}

struct NameTable {
    entries: [Option<NamedEntry>; MAX_NAMED],
    count: usize,
}

impl NameTable {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_NAMED],
            count: 0,
        }
    }
}

struct NameTableCell(UnsafeCell<NameTable>);

unsafe impl Sync for NameTableCell {}

static NAME_TABLE: NameTableCell = NameTableCell(UnsafeCell::new(NameTable::new()));

fn table() -> &'static mut NameTable {
    // SAFETY: Named object lookup/insert/remove are serialized by the scheduler
    // lock; the UnsafeCell only replaces `static mut` storage.
    unsafe { &mut *NAME_TABLE.0.get() }
}

// ── Name normalization ────────────────────────────────────────────────────────

fn lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

fn skip_prefix(name: &[u8], prefix: &[u8]) -> Option<usize> {
    if name.len() < prefix.len() {
        return None;
    }
    for (i, &p) in prefix.iter().enumerate() {
        if lower(name[i]) != p {
            return None;
        }
    }
    Some(prefix.len())
}

/// Normalize a raw object name (ASCII bytes, already extracted from UNICODE_STRING)
/// into a canonical lowercase bare name. Returns the normalized length written to `out`.
pub(crate) fn normalize_name(raw: &[u8], out: &mut [u8; MAX_NAME_BYTES]) -> usize {
    let mut src = raw;

    // Strip leading backslash
    if src.first() == Some(&b'\\') {
        src = &src[1..];
    }

    // \BaseNamedObjects\<name>
    if let Some(off) = skip_prefix(src, b"basenamedobjects\\") {
        src = &src[off..];
    }
    // \Sessions\N\BaseNamedObjects\<name>  — skip "sessions\N\"
    else if let Some(off) = skip_prefix(src, b"sessions\\") {
        // skip digits + backslash
        let mut i = off;
        while i < src.len() && src[i].is_ascii_digit() {
            i += 1;
        }
        if i < src.len() && src[i] == b'\\' {
            i += 1;
        }
        let rest = &src[i..];
        if let Some(off2) = skip_prefix(rest, b"basenamedobjects\\") {
            src = &rest[off2..];
        } else {
            src = rest;
        }
    }
    // Local\<name>
    else if let Some(off) = skip_prefix(src, b"local\\") {
        src = &src[off..];
    }
    // Global\<name>
    else if let Some(off) = skip_prefix(src, b"global\\") {
        src = &src[off..];
    }

    let len = core::cmp::min(src.len(), MAX_NAME_BYTES);
    for i in 0..len {
        out[i] = lower(src[i]);
    }
    len
}

// ── Table operations ──────────────────────────────────────────────────────────

/// Look up a named object. Returns obj_idx if found.
pub(crate) fn lookup(
    kind: KObjectKind,
    name: &[u8; MAX_NAME_BYTES],
    name_len: usize,
) -> Option<u32> {
    let t = table();
    for slot in t.entries.iter().flatten() {
        if slot.kind == kind
            && slot.name_len as usize == name_len
            && slot.name[..name_len] == name[..name_len]
        {
            return Some(slot.obj_idx);
        }
    }
    None
}

/// Insert a named object. Returns false if table is full.
pub(crate) fn insert(
    kind: KObjectKind,
    obj_idx: u32,
    name: &[u8; MAX_NAME_BYTES],
    name_len: usize,
) -> bool {
    let t = table();
    if t.count >= MAX_NAMED {
        return false;
    }
    for slot in t.entries.iter_mut() {
        if slot.is_none() {
            let mut entry = NamedEntry {
                kind,
                obj_idx,
                name_len: name_len as u8,
                name: [0u8; MAX_NAME_BYTES],
            };
            entry.name[..name_len].copy_from_slice(&name[..name_len]);
            *slot = Some(entry);
            t.count += 1;
            return true;
        }
    }
    false
}

/// Remove a named object by obj_idx + kind (called on close).
pub(crate) fn remove(kind: KObjectKind, obj_idx: u32) {
    let t = table();
    for slot in t.entries.iter_mut() {
        if let Some(e) = slot {
            if e.kind == kind && e.obj_idx == obj_idx {
                *slot = None;
                t.count = t.count.saturating_sub(1);
                return;
            }
        }
    }
}
