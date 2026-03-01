use crate::sched::sync::{
    self, HANDLE_TYPE_EVENT, HANDLE_TYPE_FILE, HANDLE_TYPE_KEY, HANDLE_TYPE_MUTEX,
    HANDLE_TYPE_PROCESS, HANDLE_TYPE_SECTION, HANDLE_TYPE_SEMAPHORE, HANDLE_TYPE_THREAD,
    HANDLE_TYPE_TOKEN,
};
use winemu_shared::status;

use super::{file, registry, section};

pub(crate) struct KObjectOps {
    pub(crate) type_name_utf16: &'static [u16],
    pub(crate) close_last_ref: fn(u32) -> u32,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct KObjectTypeStats {
    pub(crate) object_count: u32,
    pub(crate) handle_count: u32,
}

const PROCESS_NAME: &[u16] = &[80, 114, 111, 99, 101, 115, 115];
const THREAD_NAME: &[u16] = &[84, 104, 114, 101, 97, 100];
const EVENT_NAME: &[u16] = &[69, 118, 101, 110, 116];
const MUTANT_NAME: &[u16] = &[77, 117, 116, 97, 110, 116];
const SEMAPHORE_NAME: &[u16] = &[83, 101, 109, 97, 112, 104, 111, 114, 101];
const FILE_NAME: &[u16] = &[70, 105, 108, 101];
const SECTION_NAME: &[u16] = &[83, 101, 99, 116, 105, 111, 110];
const KEY_NAME: &[u16] = &[75, 101, 121];
const TOKEN_NAME: &[u16] = &[84, 111, 107, 101, 110];

const PROCESS_OPS: KObjectOps = KObjectOps {
    type_name_utf16: PROCESS_NAME,
    close_last_ref: close_process,
};
const THREAD_OPS: KObjectOps = KObjectOps {
    type_name_utf16: THREAD_NAME,
    close_last_ref: close_thread,
};
const EVENT_OPS: KObjectOps = KObjectOps {
    type_name_utf16: EVENT_NAME,
    close_last_ref: close_event,
};
const MUTANT_OPS: KObjectOps = KObjectOps {
    type_name_utf16: MUTANT_NAME,
    close_last_ref: close_mutant,
};
const SEMAPHORE_OPS: KObjectOps = KObjectOps {
    type_name_utf16: SEMAPHORE_NAME,
    close_last_ref: close_semaphore,
};
const FILE_OPS: KObjectOps = KObjectOps {
    type_name_utf16: FILE_NAME,
    close_last_ref: close_file,
};
const SECTION_OPS: KObjectOps = KObjectOps {
    type_name_utf16: SECTION_NAME,
    close_last_ref: close_section,
};
const KEY_OPS: KObjectOps = KObjectOps {
    type_name_utf16: KEY_NAME,
    close_last_ref: close_key,
};
const TOKEN_OPS: KObjectOps = KObjectOps {
    type_name_utf16: TOKEN_NAME,
    close_last_ref: close_token,
};

#[inline(always)]
fn close_event(idx: u32) -> u32 {
    sync::destroy_object_by_type(HANDLE_TYPE_EVENT, idx)
}

#[inline(always)]
fn close_mutant(idx: u32) -> u32 {
    sync::destroy_object_by_type(HANDLE_TYPE_MUTEX, idx)
}

#[inline(always)]
fn close_semaphore(idx: u32) -> u32 {
    sync::destroy_object_by_type(HANDLE_TYPE_SEMAPHORE, idx)
}

#[inline(always)]
fn close_thread(idx: u32) -> u32 {
    sync::destroy_object_by_type(HANDLE_TYPE_THREAD, idx)
}

#[inline(always)]
fn close_process(idx: u32) -> u32 {
    sync::destroy_object_by_type(HANDLE_TYPE_PROCESS, idx)
}

#[inline(always)]
fn close_token(idx: u32) -> u32 {
    sync::destroy_object_by_type(HANDLE_TYPE_TOKEN, idx)
}

#[inline(always)]
fn close_file(idx: u32) -> u32 {
    file::close_file_idx(idx);
    status::SUCCESS
}

#[inline(always)]
fn close_section(idx: u32) -> u32 {
    section::close_section_idx(idx);
    status::SUCCESS
}

#[inline(always)]
fn close_key(idx: u32) -> u32 {
    if registry::close_key_idx(idx) {
        status::SUCCESS
    } else {
        status::INVALID_HANDLE
    }
}

pub(crate) fn ops_for_type(htype: u64) -> Option<&'static KObjectOps> {
    match htype {
        HANDLE_TYPE_PROCESS => Some(&PROCESS_OPS),
        HANDLE_TYPE_THREAD => Some(&THREAD_OPS),
        HANDLE_TYPE_EVENT => Some(&EVENT_OPS),
        HANDLE_TYPE_MUTEX => Some(&MUTANT_OPS),
        HANDLE_TYPE_SEMAPHORE => Some(&SEMAPHORE_OPS),
        HANDLE_TYPE_FILE => Some(&FILE_OPS),
        HANDLE_TYPE_SECTION => Some(&SECTION_OPS),
        HANDLE_TYPE_KEY => Some(&KEY_OPS),
        HANDLE_TYPE_TOKEN => Some(&TOKEN_OPS),
        _ => None,
    }
}

pub(crate) fn object_type_name(htype: u64) -> Option<&'static [u16]> {
    Some(ops_for_type(htype)?.type_name_utf16)
}

pub(crate) fn close_last_ref(htype: u64, obj_idx: u32) -> u32 {
    let Some(ops) = ops_for_type(htype) else {
        return status::INVALID_HANDLE;
    };
    (ops.close_last_ref)(obj_idx)
}

pub(crate) fn resolve_handle_target(handle: u64) -> Option<(u64, u32)> {
    if let Some(pid) = crate::process::resolve_process_handle(handle) {
        return Some((HANDLE_TYPE_PROCESS, pid));
    }
    let htype = sync::handle_type(handle);
    if htype == 0 {
        return None;
    }
    let idx = sync::handle_idx(handle);
    if idx == 0 {
        return None;
    }
    Some((htype, idx))
}

pub(crate) fn object_ref_count(htype: u64, obj_idx: u32) -> u32 {
    sync::object_ref_count(htype, obj_idx)
}

pub(crate) fn object_type_stats(htype: u64) -> KObjectTypeStats {
    let stats = sync::object_type_stats(htype);
    KObjectTypeStats {
        object_count: stats.object_count,
        handle_count: stats.handle_count,
    }
}
