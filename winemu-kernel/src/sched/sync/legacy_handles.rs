// sched/sync/legacy_handles.rs — Typed handle table (legacy NT handle API)
//
// Handles are u64 values encoding (type << 32 | obj_idx).
// A global handle table maps handle values to (owner_pid, type, obj_idx).

use crate::kobj::ObjectStore;

// ── Handle type constants ─────────────────────────────────────────────────────

pub const HANDLE_TYPE_NONE:      u64 = 0;
pub const HANDLE_TYPE_EVENT:     u64 = 1;
pub const HANDLE_TYPE_MUTEX:     u64 = 2;
pub const HANDLE_TYPE_SEMAPHORE: u64 = 3;
pub const HANDLE_TYPE_THREAD:    u64 = 4;
pub const HANDLE_TYPE_PROCESS:   u64 = 5;
pub const HANDLE_TYPE_FILE:      u64 = 6;
pub const HANDLE_TYPE_SECTION:   u64 = 7;
pub const HANDLE_TYPE_KEY:       u64 = 8;
pub const HANDLE_TYPE_TOKEN:     u64 = 9;

// ── Handle encoding ───────────────────────────────────────────────────────────

#[inline]
pub fn encode_handle(htype: u64, idx: u32) -> u64 {
    (htype << 32) | (idx as u64)
}

#[inline]
pub fn handle_type(handle: u64) -> u64 {
    handle >> 32
}

#[inline]
pub fn handle_idx(handle: u64) -> u32 {
    handle as u32
}

// ── Handle entry ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct HandleEntry {
    owner_pid:  u32,
    htype:      u64,
    obj_idx:    u32,
    ref_count:  u32,
    handle_val: u64,
    next:       u32,
}

// ── Global handle table ───────────────────────────────────────────────────────

const BUCKET_COUNT: usize = 256;

struct HandleTable {
    entries:       ObjectStore<HandleEntry>,
    buckets:       [u32; BUCKET_COUNT],
    obj_counts:    [u32; 16],
    handle_counts: [u32; 16],
}

impl HandleTable {
    fn new() -> Self {
        Self {
            entries:       ObjectStore::new(),
            buckets:       [0u32; BUCKET_COUNT],
            obj_counts:    [0u32; 16],
            handle_counts: [0u32; 16],
        }
    }
}

static mut HANDLE_TABLE: Option<HandleTable> = None;

fn table() -> &'static HandleTable {
    unsafe {
        if HANDLE_TABLE.is_none() {
            HANDLE_TABLE = Some(HandleTable::new());
        }
        HANDLE_TABLE.as_ref().unwrap()
    }
}

fn table_mut() -> &'static mut HandleTable {
    unsafe {
        if HANDLE_TABLE.is_none() {
            HANDLE_TABLE = Some(HandleTable::new());
        }
        HANDLE_TABLE.as_mut().unwrap()
    }
}

#[inline]
fn bucket(handle_val: u64) -> usize {
    ((handle_val ^ (handle_val >> 16)).wrapping_mul(0x9E37_79B1u64) as usize) % BUCKET_COUNT
}

// ── CloseHandleInfo ───────────────────────────────────────────────────────────

pub struct CloseHandleInfo {
    pub htype:          u64,
    pub obj_idx:        u32,
    pub destroy_object: bool,
}

// ── ObjectTypeStats ───────────────────────────────────────────────────────────

pub struct ObjectTypeStats {
    pub object_count: u32,
    pub handle_count: u32,
}

// ── Core operations ───────────────────────────────────────────────────────────

pub fn make_new_handle(htype: u64, obj_idx: u32) -> Option<u64> {
    let pid = crate::process::current_pid();
    make_new_handle_for_pid(htype, obj_idx, pid)
}

pub fn make_new_handle_for_pid(htype: u64, obj_idx: u32, owner_pid: u32) -> Option<u64> {
    let handle_val = encode_handle(htype, obj_idx);
    let t = table_mut();
    let bkt = bucket(handle_val);
    let head = t.buckets[bkt];
    let id = t.entries.alloc_with(|_| HandleEntry {
        owner_pid, htype, obj_idx, ref_count: 1, handle_val, next: head,
    })?;
    t.buckets[bkt] = id;
    let ht = htype as usize;
    if ht < 16 {
        t.obj_counts[ht] = t.obj_counts[ht].saturating_add(1);
        t.handle_counts[ht] = t.handle_counts[ht].saturating_add(1);
    }
    Some(handle_val)
}

fn find_entry(handle_val: u64, owner_pid: u32) -> Option<u32> {
    let t = table();
    let bkt = bucket(handle_val);
    let mut cur = t.buckets[bkt];
    while cur != 0 {
        let ptr = t.entries.get_ptr(cur);
        if ptr.is_null() { break; }
        let e = unsafe { &*ptr };
        if e.handle_val == handle_val && (owner_pid == 0 || e.owner_pid == owner_pid) {
            return Some(cur);
        }
        cur = e.next;
    }
    None
}

fn remove_entry(id: u32) -> Option<HandleEntry> {
    let ptr = table().entries.get_ptr(id);
    if ptr.is_null() { return None; }
    let e = unsafe { *ptr };
    let bkt = bucket(e.handle_val);
    let mut prev = 0u32;
    let mut cur = table().buckets[bkt];
    while cur != 0 {
        let cptr = table().entries.get_ptr(cur);
        if cptr.is_null() { break; }
        let ce = unsafe { &*cptr };
        if cur == id {
            let next = ce.next;
            if prev == 0 {
                table_mut().buckets[bkt] = next;
            } else {
                let pptr = table_mut().entries.get_ptr(prev);
                if !pptr.is_null() { unsafe { (*pptr).next = next }; }
            }
            break;
        }
        prev = cur;
        cur = ce.next;
    }
    table_mut().entries.free(id);
    let ht = e.htype as usize;
    if ht < 16 {
        table_mut().handle_counts[ht] = table_mut().handle_counts[ht].saturating_sub(1);
    }
    Some(e)
}

pub fn handle_type_by_owner(handle: u64, owner_pid: u32) -> u64 {
    find_entry(handle, owner_pid).map(|id| {
        let ptr = table().entries.get_ptr(id);
        if ptr.is_null() { 0 } else { unsafe { (*ptr).htype } }
    }).unwrap_or(0)
}

pub fn handle_idx_by_owner(handle: u64, owner_pid: u32) -> u32 {
    find_entry(handle, owner_pid).map(|id| {
        let ptr = table().entries.get_ptr(id);
        if ptr.is_null() { 0 } else { unsafe { (*ptr).obj_idx } }
    }).unwrap_or(0)
}

pub fn close_handle_info(handle: u64) -> Option<CloseHandleInfo> {
    let pid = crate::process::current_pid();
    close_handle_info_for_pid(pid, handle)
}

pub fn close_handle_info_for_pid(owner_pid: u32, handle: u64) -> Option<CloseHandleInfo> {
    let id = find_entry(handle, owner_pid)?;
    let ptr = table_mut().entries.get_ptr(id);
    if ptr.is_null() { return None; }
    let rc = unsafe {
        (*ptr).ref_count = (*ptr).ref_count.saturating_sub(1);
        (*ptr).ref_count
    };
    let e = unsafe { *ptr };
    if rc == 0 {
        remove_entry(id);
        let ht = e.htype as usize;
        if ht < 16 {
            table_mut().obj_counts[ht] = table_mut().obj_counts[ht].saturating_sub(1);
        }
        Some(CloseHandleInfo { htype: e.htype, obj_idx: e.obj_idx, destroy_object: true })
    } else {
        Some(CloseHandleInfo { htype: e.htype, obj_idx: e.obj_idx, destroy_object: false })
    }
}

pub fn duplicate_handle_between(source_pid: u32, handle: u64, target_pid: u32) -> Result<u64, u32> {
    let id = find_entry(handle, source_pid)
        .ok_or(winemu_shared::status::INVALID_HANDLE)?;
    let ptr = table_mut().entries.get_ptr(id);
    if ptr.is_null() { return Err(winemu_shared::status::INVALID_HANDLE); }
    let e = unsafe { *ptr };
    unsafe { (*ptr).ref_count += 1 };
    make_new_handle_for_pid(e.htype, e.obj_idx, target_pid)
        .ok_or(winemu_shared::status::NO_MEMORY)
}

pub fn close_all_handles_for_pid(pid: u32) -> usize {
    let mut to_remove = [0u32; 256];
    let mut count = 0usize;
    for bkt in 0..BUCKET_COUNT {
        let mut cur = table().buckets[bkt];
        while cur != 0 {
            let ptr = table().entries.get_ptr(cur);
            if ptr.is_null() { break; }
            let e = unsafe { &*ptr };
            if e.owner_pid == pid && count < to_remove.len() {
                to_remove[count] = cur;
                count += 1;
            }
            cur = e.next;
        }
    }
    for i in 0..count { remove_entry(to_remove[i]); }
    count
}

pub fn destroy_object_by_type(htype: u64, obj_idx: u32) -> u32 {
    let handle_val = encode_handle(htype, obj_idx);
    let mut to_remove = [0u32; 64];
    let mut count = 0usize;
    let bkt = bucket(handle_val);
    let mut cur = table().buckets[bkt];
    while cur != 0 {
        let ptr = table().entries.get_ptr(cur);
        if ptr.is_null() { break; }
        let e = unsafe { &*ptr };
        if e.htype == htype && e.obj_idx == obj_idx && count < to_remove.len() {
            to_remove[count] = cur;
            count += 1;
        }
        cur = e.next;
    }
    for i in 0..count { remove_entry(to_remove[i]); }
    let ht = htype as usize;
    if ht < 16 {
        table_mut().obj_counts[ht] = table_mut().obj_counts[ht].saturating_sub(1);
    }
    winemu_shared::status::SUCCESS
}

pub fn object_ref_count(htype: u64, obj_idx: u32) -> u32 {
    let handle_val = encode_handle(htype, obj_idx);
    let bkt = bucket(handle_val);
    let mut cur = table().buckets[bkt];
    while cur != 0 {
        let ptr = table().entries.get_ptr(cur);
        if ptr.is_null() { break; }
        let e = unsafe { &*ptr };
        if e.htype == htype && e.obj_idx == obj_idx {
            return e.ref_count;
        }
        cur = e.next;
    }
    0
}

pub fn object_type_stats(htype: u64) -> ObjectTypeStats {
    let ht = htype as usize;
    if ht < 16 {
        ObjectTypeStats {
            object_count: table().obj_counts[ht],
            handle_count: table().handle_counts[ht],
        }
    } else {
        ObjectTypeStats { object_count: 0, handle_count: 0 }
    }
}

pub fn thread_notify_terminated(_tid: u32) {}
pub fn process_notify_terminated(_pid: u32) {}
