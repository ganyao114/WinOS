// ── HandleTable ───────────────────────────────────────────────
// Handle encoding: bits[31:28] = type, bits[27:0] = handle slot id
// 保持在低 32 bit，兼容用户态把 HANDLE 临时存到 u32 的场景。

pub const HANDLE_TYPE_EVENT: u64 = 1;
pub const HANDLE_TYPE_MUTEX: u64 = 2;
pub const HANDLE_TYPE_SEMAPHORE: u64 = 3;
pub const HANDLE_TYPE_THREAD: u64 = 4;
pub const HANDLE_TYPE_FILE: u64 = 5;
pub const HANDLE_TYPE_SECTION: u64 = 6;
pub const HANDLE_TYPE_KEY: u64 = 7;
pub const HANDLE_TYPE_PROCESS: u64 = 8;
pub const HANDLE_TYPE_TOKEN: u64 = 9;

#[derive(Clone, Copy)]
struct HandleEntry {
    key: u32,
    owner_pid: u32,
}

#[derive(Clone, Copy)]
struct ObjectRef {
    key: u32,
    refs: u32,
}

#[derive(Clone, Copy, Default)]
pub struct ObjectTypeStats {
    pub object_count: u32,
    pub handle_count: u32,
}

#[derive(Clone, Copy)]
pub struct HandleCloseInfo {
    pub htype: u64,
    pub obj_idx: u32,
    pub destroy_object: bool,
}

pub fn make_handle(htype: u64, idx: u32) -> u64 {
    ((htype & HANDLE_TYPE_MASK) << HANDLE_SLOT_BITS) | ((idx as u64) & HANDLE_SLOT_MASK)
}

#[inline]
fn key_type(key: u32) -> u64 {
    ((key as u64) >> HANDLE_SLOT_BITS) & HANDLE_TYPE_MASK
}

#[inline]
fn key_idx(key: u32) -> u32 {
    key & (HANDLE_SLOT_MASK as u32)
}

fn handles_store_mut() -> &'static mut ObjectStore<HandleEntry> {
    unsafe {
        let slot = &mut *SYNC_STATE.handles.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn refs_mut() -> &'static mut Vec<ObjectRef> {
    unsafe {
        let slot = &mut *SYNC_STATE.refs.get();
        if slot.is_none() {
            *slot = Some(Vec::new());
        }
        slot.as_mut().unwrap()
    }
}

fn ref_inc(key: u32) -> bool {
    let refs = refs_mut();
    let mut i = 0usize;
    while i < refs.len() {
        if refs[i].key == key {
            refs[i].refs = refs[i].refs.saturating_add(1);
            return true;
        }
        i += 1;
    }
    if refs.try_reserve(1).is_err() {
        return false;
    }
    refs.push(ObjectRef { key, refs: 1 });
    true
}

fn ref_dec_is_last(key: u32) -> bool {
    let refs = refs_mut();
    let mut i = 0usize;
    while i < refs.len() {
        if refs[i].key == key {
            if refs[i].refs > 1 {
                refs[i].refs -= 1;
                return false;
            }
            refs.swap_remove(i);
            return true;
        }
        i += 1;
    }
    true
}

fn current_handle_owner_pid() -> u32 {
    let pid = crate::process::current_pid();
    if pid != 0 {
        pid
    } else {
        crate::process::boot_pid()
    }
}

fn alloc_handle_instance_for_key(key: u32, owner_pid: u32) -> Option<u64> {
    if owner_pid == 0 {
        return None;
    }
    if key_type(key) == 0 || key_idx(key) == 0 {
        return None;
    }
    if !ref_inc(key) {
        return None;
    }
    let id = match handles_store_mut().alloc_with(|_| HandleEntry { key, owner_pid }) {
        Some(v) => v,
        None => {
            let _ = ref_dec_is_last(key);
            return None;
        }
    };
    Some(make_handle(key_type(key), id))
}

fn resolve_user_handle_for_pid(h: u64, owner_pid: u32) -> Option<(u32, u64, u32, u32)> {
    if owner_pid == 0 {
        return None;
    }
    let htype = (h >> HANDLE_SLOT_BITS) & HANDLE_TYPE_MASK;
    if htype == 0 {
        return None;
    }
    let hid = (h & HANDLE_SLOT_MASK) as u32;
    let ptr = handles_store_mut().get_ptr(hid);
    if ptr.is_null() {
        return None;
    }
    let entry = unsafe { *ptr };
    if entry.owner_pid != owner_pid {
        return None;
    }
    if key_type(entry.key) != htype {
        return None;
    }
    Some((hid, htype, key_idx(entry.key), entry.key))
}

fn resolve_user_handle(h: u64) -> Option<(u32, u64, u32, u32)> {
    resolve_user_handle_for_pid(h, current_handle_owner_pid())
}

fn decode_object_key(h: u64) -> Option<u32> {
    let key = h as u32;
    if key_type(key) == 0 || key_idx(key) == 0 {
        return None;
    }
    Some(key)
}

fn resolve_handle_key_for_pid(h: u64, owner_pid: u32) -> Option<u32> {
    resolve_user_handle_for_pid(h, owner_pid).map(|(_hid, _htype, _idx, key)| key)
}

fn resolve_handle_key_for_pid_or_object_key(h: u64, owner_pid: u32) -> Option<u32> {
    resolve_handle_key_for_pid(h, owner_pid).or_else(|| decode_object_key(h))
}

fn handles_same_object_for_pid(a: u64, b: u64, owner_pid: u32) -> bool {
    match (
        resolve_handle_key_for_pid(a, owner_pid),
        resolve_handle_key_for_pid_or_object_key(b, owner_pid),
    ) {
        (Some(ka), Some(kb)) => ka == kb,
        _ => false,
    }
}

fn handle_type_for_pid(h: u64, owner_pid: u32) -> u64 {
    if let Some((_hid, htype, _idx, _key)) = resolve_user_handle_for_pid(h, owner_pid) {
        htype
    } else {
        0
    }
}

fn handle_idx_for_pid(h: u64, owner_pid: u32) -> u32 {
    if let Some((_hid, _htype, idx, _key)) = resolve_user_handle_for_pid(h, owner_pid) {
        idx
    } else {
        0
    }
}

pub fn handle_type(h: u64) -> u64 {
    if let Some((_hid, htype, _idx, _key)) = resolve_user_handle(h) {
        htype
    } else {
        0
    }
}

pub fn handle_idx(h: u64) -> u32 {
    if let Some((_hid, _htype, idx, _key)) = resolve_user_handle(h) {
        idx
    } else {
        0
    }
}

pub fn handle_type_by_owner(h: u64, owner_pid: u32) -> u64 {
    handle_type_for_pid(h, owner_pid)
}

pub fn handle_idx_by_owner(h: u64, owner_pid: u32) -> u32 {
    handle_idx_for_pid(h, owner_pid)
}

fn resolve_handle_idx_by_type(h: u64, expected_type: u64) -> Option<u32> {
    if handle_type(h) != expected_type {
        return None;
    }
    let idx = handle_idx(h);
    if idx == 0 {
        return None;
    }
    Some(idx)
}

fn resolve_handle_idx_by_type_for_pid(h: u64, owner_pid: u32, expected_type: u64) -> Option<u32> {
    if handle_type_for_pid(h, owner_pid) != expected_type {
        return None;
    }
    let idx = handle_idx_for_pid(h, owner_pid);
    if idx == 0 {
        return None;
    }
    Some(idx)
}

pub fn make_new_handle(htype: u64, obj_idx: u32) -> Option<u64> {
    make_new_handle_for_pid(current_handle_owner_pid(), htype, obj_idx)
}

pub fn make_new_handle_for_pid(owner_pid: u32, htype: u64, obj_idx: u32) -> Option<u64> {
    alloc_handle_instance_for_key(make_handle(htype, obj_idx) as u32, owner_pid)
}

pub fn duplicate_handle(h: u64) -> Option<u64> {
    let owner_pid = current_handle_owner_pid();
    duplicate_handle_between(owner_pid, h, owner_pid).ok()
}

pub fn duplicate_handle_between(
    source_pid: u32,
    source_handle: u64,
    target_pid: u32,
) -> Result<u64, u32> {
    let (_hid, _htype, _idx, key) =
        resolve_user_handle_for_pid(source_handle, source_pid).ok_or(STATUS_INVALID_HANDLE)?;
    alloc_handle_instance_for_key(key, target_pid).ok_or(status::NO_MEMORY)
}

fn close_handle_slot_for_pid(hid: u32, owner_pid: u32) -> Option<HandleCloseInfo> {
    let ptr = handles_store_mut().get_ptr(hid);
    if ptr.is_null() {
        return None;
    }
    let entry = unsafe { *ptr };
    if entry.owner_pid != owner_pid {
        return None;
    }
    let htype = key_type(entry.key);
    let obj_idx = key_idx(entry.key);
    if htype == 0 || obj_idx == 0 {
        return None;
    }
    if !handles_store_mut().free(hid) {
        return None;
    }
    let destroy_object = ref_dec_is_last(entry.key);
    Some(HandleCloseInfo {
        htype,
        obj_idx,
        destroy_object,
    })
}

pub fn close_handle_info(h: u64) -> Option<HandleCloseInfo> {
    let (hid, _htype, _obj_idx, _key) = resolve_user_handle(h)?;
    close_handle_slot_for_pid(hid, current_handle_owner_pid())
}

pub fn close_handle_info_for_pid(owner_pid: u32, h: u64) -> Option<HandleCloseInfo> {
    let (hid, _htype, _obj_idx, _key) = resolve_user_handle_for_pid(h, owner_pid)?;
    close_handle_slot_for_pid(hid, owner_pid)
}

pub fn close_all_handles_for_pid(owner_pid: u32) -> usize {
    if owner_pid == 0 {
        return 0;
    }

    let mut handle_ids = Vec::new();
    handles_store_mut().for_each_live_ptr(|hid, ptr| unsafe {
        if (*ptr).owner_pid == owner_pid {
            let _ = handle_ids.try_reserve(1);
            handle_ids.push(hid);
        }
    });

    let mut closed = 0usize;
    for hid in handle_ids {
        let Some(info) = close_handle_slot_for_pid(hid, owner_pid) else {
            continue;
        };
        closed += 1;
        if info.destroy_object {
            let _ = destroy_object_by_type(info.htype, info.obj_idx);
        }
    }
    closed
}

pub fn object_ref_count(htype: u64, obj_idx: u32) -> u32 {
    if htype == 0 || obj_idx == 0 {
        return 0;
    }
    let key = make_handle(htype, obj_idx) as u32;
    let refs = refs_mut();
    let mut i = 0usize;
    while i < refs.len() {
        if refs[i].key == key {
            return refs[i].refs;
        }
        i += 1;
    }
    0
}

pub fn object_type_stats(htype: u64) -> ObjectTypeStats {
    if htype == 0 {
        return ObjectTypeStats::default();
    }
    let refs = refs_mut();
    let mut stats = ObjectTypeStats::default();
    let mut i = 0usize;
    while i < refs.len() {
        let entry = refs[i];
        if key_type(entry.key) == htype {
            stats.object_count = stats.object_count.saturating_add(1);
            stats.handle_count = stats.handle_count.saturating_add(entry.refs);
        }
        i += 1;
    }
    let live_objects = backing_object_count(htype);
    if live_objects > stats.object_count {
        stats.object_count = live_objects;
    }
    stats
}

fn backing_store_live_count<T>(slot: &UnsafeCell<Option<ObjectStore<T>>>) -> u32 {
    unsafe {
        let Some(store) = (&*slot.get()).as_ref() else {
            return 0;
        };
        let mut count = 0u32;
        store.for_each_live_id(|_| {
            count = count.saturating_add(1);
        });
        count
    }
}

fn backing_object_count(htype: u64) -> u32 {
    match htype {
        HANDLE_TYPE_EVENT => backing_store_live_count(&SYNC_STATE.events),
        HANDLE_TYPE_MUTEX => backing_store_live_count(&SYNC_STATE.mutexes),
        HANDLE_TYPE_SEMAPHORE => backing_store_live_count(&SYNC_STATE.semaphores),
        HANDLE_TYPE_THREAD => thread_count(),
        HANDLE_TYPE_PROCESS => crate::process::process_count(),
        _ => 0,
    }
}

fn recompute_owned_mutex_priority_locked(owner_tid: u32) {
    if owner_tid == 0 || !thread_exists(owner_tid) {
        return;
    }
    let mut target = with_thread(owner_tid, |t| t.base_priority);
    mutexes_store_mut().for_each_live_ptr(|_id, ptr| unsafe {
        if (*ptr).owner_tid != owner_tid {
            return;
        }
        if let Some(waiter_prio) = (*ptr).waiters.highest_waiting_priority() {
            if waiter_prio > target {
                target = waiter_prio;
            }
        }
    });
    set_thread_priority_locked(owner_tid, target);
}

