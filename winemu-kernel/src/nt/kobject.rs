use crate::rust_alloc::vec::Vec;
use crate::process::{KObjectKind, KObjectRef, with_process_mut};
use winemu_shared::status;

use super::{file, registry, section};

// ── Object type metadata ──────────────────────────────────────────────────────

pub(crate) struct KObjectOps {
    pub(crate) type_name_utf16:       &'static [u16],
    pub(crate) close_last_ref:        fn(u32) -> u32,
    pub(crate) query_name_utf16:      fn(u32) -> Option<Vec<u16>>,
    pub(crate) valid_access_mask:     u32,
    pub(crate) security_required:     bool,
    pub(crate) maintain_handle_count: bool,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct KObjectTypeStats {
    pub(crate) object_count: u32,
    pub(crate) handle_count: u32,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct KObjectTypeMeta {
    pub(crate) valid_access_mask:     u32,
    pub(crate) security_required:     bool,
    pub(crate) maintain_handle_count: bool,
}

const PROCESS_NAME:   &[u16] = &[80,114,111,99,101,115,115];
const THREAD_NAME:    &[u16] = &[84,104,114,101,97,100];
const EVENT_NAME:     &[u16] = &[69,118,101,110,116];
const MUTANT_NAME:    &[u16] = &[77,117,116,97,110,116];
const SEMAPHORE_NAME: &[u16] = &[83,101,109,97,112,104,111,114,101];
const FILE_NAME:      &[u16] = &[70,105,108,101];
const SECTION_NAME:   &[u16] = &[83,101,99,116,105,111,110];
const KEY_NAME:       &[u16] = &[75,101,121];
const TOKEN_NAME:     &[u16] = &[84,111,107,101,110];

const ACCESS_MASK_EVENT:     u32 = 0x001F_0003;
const ACCESS_MASK_MUTEX:     u32 = 0x001F_0001;
const ACCESS_MASK_SEMAPHORE: u32 = 0x001F_0003;
const ACCESS_MASK_PROCESS:   u32 = 0x001F_FFFF;
const ACCESS_MASK_THREAD:    u32 = 0x001F_FFFF;
const ACCESS_MASK_FILE:      u32 = 0x001F_01FF;
const ACCESS_MASK_SECTION:   u32 = 0x001F_001F;
const ACCESS_MASK_KEY:       u32 = 0x000F_003F;
const ACCESS_MASK_TOKEN:     u32 = 0x000F_01FF;

fn query_name_none(_: u32) -> Option<Vec<u16>> { None }
fn query_name_key(idx: u32)     -> Option<Vec<u16>> { registry::key_name_utf16(idx) }
fn query_name_section(idx: u32) -> Option<Vec<u16>> { section::section_name_utf16(idx) }
fn query_name_file(idx: u32)    -> Option<Vec<u16>> { file::file_name_utf16(idx) }

fn close_event(idx: u32)     -> u32 {
    crate::sched::sync::sync_free_idx(idx);
    status::SUCCESS
}
fn close_mutant(idx: u32)    -> u32 { crate::sched::sync::sync_free_idx(idx); status::SUCCESS }
fn close_semaphore(idx: u32) -> u32 { crate::sched::sync::sync_free_idx(idx); status::SUCCESS }
fn close_thread(_tid: u32)   -> u32 { status::SUCCESS }
fn close_process(pid: u32)   -> u32 {
    crate::process::last_handle_closed(pid);
    status::SUCCESS
}
fn close_token(_idx: u32)    -> u32 { status::SUCCESS }
fn close_file(idx: u32)      -> u32 { file::close_file_idx(idx); status::SUCCESS }
fn close_section(idx: u32)   -> u32 { section::close_section_idx(idx); status::SUCCESS }
fn close_key(idx: u32)       -> u32 {
    if registry::close_key_idx(idx) { status::SUCCESS } else { status::INVALID_HANDLE }
}

pub(crate) fn ops_for_kind(kind: KObjectKind) -> &'static KObjectOps {
    ops_for(kind)
}

fn ops_for(kind: KObjectKind) -> &'static KObjectOps {
    match kind {
        KObjectKind::Event     => &KObjectOps { type_name_utf16: EVENT_NAME,     close_last_ref: close_event,     query_name_utf16: query_name_none, valid_access_mask: ACCESS_MASK_EVENT,     security_required: false, maintain_handle_count: false },
        KObjectKind::Mutex     => &KObjectOps { type_name_utf16: MUTANT_NAME,    close_last_ref: close_mutant,    query_name_utf16: query_name_none, valid_access_mask: ACCESS_MASK_MUTEX,     security_required: false, maintain_handle_count: false },
        KObjectKind::Semaphore => &KObjectOps { type_name_utf16: SEMAPHORE_NAME, close_last_ref: close_semaphore, query_name_utf16: query_name_none, valid_access_mask: ACCESS_MASK_SEMAPHORE, security_required: false, maintain_handle_count: false },
        KObjectKind::Thread    => &KObjectOps { type_name_utf16: THREAD_NAME,    close_last_ref: close_thread,    query_name_utf16: query_name_none, valid_access_mask: ACCESS_MASK_THREAD,    security_required: false, maintain_handle_count: true  },
        KObjectKind::Process   => &KObjectOps { type_name_utf16: PROCESS_NAME,   close_last_ref: close_process,   query_name_utf16: query_name_none, valid_access_mask: ACCESS_MASK_PROCESS,   security_required: false, maintain_handle_count: true  },
        KObjectKind::File      => &KObjectOps { type_name_utf16: FILE_NAME,      close_last_ref: close_file,      query_name_utf16: query_name_file,  valid_access_mask: ACCESS_MASK_FILE,      security_required: false, maintain_handle_count: false },
        KObjectKind::Section   => &KObjectOps { type_name_utf16: SECTION_NAME,   close_last_ref: close_section,   query_name_utf16: query_name_section, valid_access_mask: ACCESS_MASK_SECTION, security_required: false, maintain_handle_count: false },
        KObjectKind::Key       => &KObjectOps { type_name_utf16: KEY_NAME,       close_last_ref: close_key,       query_name_utf16: query_name_key,   valid_access_mask: ACCESS_MASK_KEY,      security_required: false, maintain_handle_count: false },
        KObjectKind::Token     => &KObjectOps { type_name_utf16: TOKEN_NAME,     close_last_ref: close_token,     query_name_utf16: query_name_none, valid_access_mask: ACCESS_MASK_TOKEN,    security_required: false, maintain_handle_count: false },
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Add an object to the current process's handle table.
/// Returns the opaque handle value (u32 cast to u64 for NT compat).
pub(crate) fn add_handle_for_pid(pid: u32, obj: KObjectRef) -> Option<u64> {
    with_process_mut(pid, |p| p.handle_table.add(obj))
        .flatten()
        .map(|h| h as u64)
}

/// Resolve a handle to (KObjectKind, obj_idx) for the current process.
pub(crate) fn resolve_handle_target(handle: u64) -> Option<(KObjectKind, u32)> {
    let pid = crate::process::current_pid();
    resolve_handle_target_for_pid(pid, handle)
}

/// Resolve a handle to (KObjectKind, obj_idx) for a specific process.
pub(crate) fn resolve_handle_target_for_pid(pid: u32, handle: u64) -> Option<(KObjectKind, u32)> {
    with_process_mut(pid, |p| p.handle_table.get(handle as u32))
        .flatten()
        .map(|obj| (obj.kind, obj.obj_idx))
}

/// Close a handle in the current process's table. Calls close_last_ref on the object.
pub(crate) fn close_handle_for_current(handle: u64) -> u32 {
    let pid = crate::process::current_pid();
    close_handle_for_pid(pid, handle)
}

/// Close a handle in a specific process's table.
pub(crate) fn close_handle_for_pid(pid: u32, handle: u64) -> u32 {
    let obj = with_process_mut(pid, |p| p.handle_table.remove(handle as u32)).flatten();
    match obj {
        Some(o) => (ops_for(o.kind).close_last_ref)(o.obj_idx),
        None    => status::INVALID_HANDLE,
    }
}

/// Drain all handles for a process (on exit). Calls close_last_ref for each.
pub(crate) fn drain_handles_for_pid(pid: u32) {
    with_process_mut(pid, |p| {
        p.handle_table.drain(|obj| {
            (ops_for(obj.kind).close_last_ref)(obj.obj_idx);
        });
    });
}

/// Duplicate a handle from source_pid to target_pid.
pub(crate) fn duplicate_handle(
    source_pid: u32,
    source_handle: u64,
    target_pid: u32,
) -> Option<u64> {
    let obj = with_process_mut(source_pid, |p| p.handle_table.get(source_handle as u32))
        .flatten()?;
    add_handle_for_pid(target_pid, obj)
}

/// Get the thread ID from a thread handle in the current process.
pub(crate) fn handle_to_tid(handle: u64) -> Option<u32> {
    let (kind, idx) = resolve_handle_target(handle)?;
    if kind == KObjectKind::Thread { Some(idx) } else { None }
}

/// Create a thread handle in the current process's table.
pub(crate) fn make_thread_handle(tid: u32) -> u64 {
    let pid = crate::process::current_pid();
    add_handle_for_pid(pid, KObjectRef::thread(tid)).unwrap_or(0)
}

/// Get the type name (UTF-16) for a kind.
pub(crate) fn object_type_name_for_kind(kind: KObjectKind) -> &'static [u16] {
    ops_for(kind).type_name_utf16
}

pub(crate) fn object_name_utf16_for_kind(kind: KObjectKind, obj_idx: u32) -> Option<Vec<u16>> {
    (ops_for(kind).query_name_utf16)(obj_idx)
}

pub(crate) fn object_type_meta_for_kind(kind: KObjectKind) -> KObjectTypeMeta {
    let ops = ops_for(kind);
    KObjectTypeMeta {
        valid_access_mask:     ops.valid_access_mask,
        security_required:     ops.security_required,
        maintain_handle_count: ops.maintain_handle_count,
    }
}

/// Legacy shim: accepts old htype u64 constants, maps to KObjectKind.
pub(crate) fn object_type_name(htype: u64) -> Option<&'static [u16]> {
    htype_to_kind(htype).map(|k| ops_for(k).type_name_utf16)
}

pub(crate) fn object_name_utf16(htype: u64, obj_idx: u32) -> Option<Vec<u16>> {
    let kind = htype_to_kind(htype)?;
    (ops_for(kind).query_name_utf16)(obj_idx)
}

pub(crate) fn close_last_ref(htype: u64, obj_idx: u32) -> u32 {
    match htype_to_kind(htype) {
        Some(k) => (ops_for(k).close_last_ref)(obj_idx),
        None    => status::INVALID_HANDLE,
    }
}

pub(crate) fn object_ref_count(_htype: u64, _obj_idx: u32) -> u32 { 1 }

pub(crate) fn object_type_stats(_htype: u64) -> KObjectTypeStats {
    KObjectTypeStats::default()
}

pub(crate) fn object_type_meta(htype: u64) -> Option<KObjectTypeMeta> {
    let kind = htype_to_kind(htype)?;
    Some(object_type_meta_for_kind(kind))
}

// ── htype legacy constants → KObjectKind ─────────────────────────────────────

pub(crate) fn htype_to_kind(htype: u64) -> Option<KObjectKind> {
    use crate::sched::sync::{
        HANDLE_TYPE_EVENT, HANDLE_TYPE_MUTEX, HANDLE_TYPE_SEMAPHORE,
        HANDLE_TYPE_THREAD, HANDLE_TYPE_PROCESS, HANDLE_TYPE_FILE,
        HANDLE_TYPE_SECTION, HANDLE_TYPE_KEY, HANDLE_TYPE_TOKEN,
    };
    match htype {
        HANDLE_TYPE_EVENT     => Some(KObjectKind::Event),
        HANDLE_TYPE_MUTEX     => Some(KObjectKind::Mutex),
        HANDLE_TYPE_SEMAPHORE => Some(KObjectKind::Semaphore),
        HANDLE_TYPE_THREAD    => Some(KObjectKind::Thread),
        HANDLE_TYPE_PROCESS   => Some(KObjectKind::Process),
        HANDLE_TYPE_FILE      => Some(KObjectKind::File),
        HANDLE_TYPE_SECTION   => Some(KObjectKind::Section),
        HANDLE_TYPE_KEY       => Some(KObjectKind::Key),
        HANDLE_TYPE_TOKEN     => Some(KObjectKind::Token),
        _                     => None,
    }
}
