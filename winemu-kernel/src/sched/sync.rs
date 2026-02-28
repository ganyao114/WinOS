// Guest kernel 同步原语 — EL1
// KEvent, KMutex, KSemaphore, Thread waiters, HandleTable
// 所有状态机在 guest 内完成，不走 HVC。

use crate::kobj::ObjectStore;
use crate::nt::constants::{
    HANDLE_SLOT_BITS, HANDLE_SLOT_MASK, HANDLE_TYPE_MASK, NTSTATUS_ERROR_BIT,
};
use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use winemu_shared::status;

use super::{
    boost_thread_priority_locked, clear_wait_deadline_locked, current_tid, sched_lock_acquire,
    sched_lock_release, set_thread_priority_locked, set_thread_state_locked,
    set_wait_deadline_locked, thread_exists, wake, with_thread, with_thread_mut, ThreadState,
    MAX_WAIT_HANDLES, WAIT_KIND_DELAY, WAIT_KIND_MULTI_ALL, WAIT_KIND_MULTI_ANY, WAIT_KIND_NONE,
    WAIT_KIND_SINGLE,
};

// ── NTSTATUS 常量 ─────────────────────────────────────────────

pub const STATUS_SUCCESS: u32 = status::SUCCESS;
pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_TIMEOUT: u32 = status::TIMEOUT;
pub const STATUS_ABANDONED: u32 = status::ABANDONED_WAIT_0;
pub const STATUS_INVALID_HANDLE: u32 = status::INVALID_HANDLE;
pub const STATUS_INVALID_PARAMETER: u32 = status::INVALID_PARAMETER;
pub const STATUS_MUTANT_NOT_OWNED: u32 = status::MUTANT_NOT_OWNED;
pub const STATUS_SEMAPHORE_LIMIT_EXCEEDED: u32 = status::SEMAPHORE_LIMIT_EXCEEDED;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WaitDeadline {
    Infinite,
    Immediate,
    DeadlineTicks(u64),
}

// ── 等待队列（动态，按优先级排序）─────────────────────────────

pub struct WaitQueue {
    tids: Vec<u32>,
}

impl WaitQueue {
    pub fn new() -> Self {
        Self { tids: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.tids.len()
    }

    pub fn enqueue(&mut self, tid: u32) {
        if tid == 0 {
            return;
        }
        for i in 0..self.tids.len() {
            if self.tids[i] == tid {
                return;
            }
        }

        let prio = with_thread(tid, |t| t.priority);
        let mut pos = self.tids.len();
        for i in 0..self.tids.len() {
            let cur_tid = self.tids[i];
            let cur_prio = with_thread(cur_tid, |t| t.priority);
            if prio > cur_prio {
                pos = i;
                break;
            }
        }

        if self.tids.try_reserve(1).is_err() {
            return;
        }
        self.tids.insert(pos, tid);
    }

    pub fn dequeue_waiting(&mut self) -> u32 {
        while !self.tids.is_empty() {
            let tid = self.tids.remove(0);
            if tid != 0
                && thread_exists(tid)
                && with_thread(tid, |t| t.state == ThreadState::Waiting)
            {
                return tid;
            }
        }
        0
    }

    pub fn remove(&mut self, tid: u32) {
        if tid == 0 || self.tids.is_empty() {
            return;
        }
        for i in 0..self.tids.len() {
            if self.tids[i] == tid {
                self.tids.remove(i);
                return;
            }
        }
    }

    pub fn highest_waiting_priority(&self) -> Option<u8> {
        let mut best: Option<u8> = None;
        for i in 0..self.tids.len() {
            let tid = self.tids[i];
            if tid == 0 || !thread_exists(tid) {
                continue;
            }
            let prio = with_thread(tid, |t| {
                if t.state == ThreadState::Waiting {
                    Some(t.priority)
                } else {
                    None
                }
            });
            if let Some(p) = prio {
                best = match best {
                    Some(cur) if cur >= p => Some(cur),
                    _ => Some(p),
                };
            }
        }
        best
    }
}

// ── KEvent ────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    NotificationEvent = 0,    // manual-reset
    SynchronizationEvent = 1, // auto-reset
}

pub struct KEvent {
    pub signaled: bool,
    pub ev_type: EventType,
    pub waiters: WaitQueue,
}

impl KEvent {
    fn new(ev_type: EventType, signaled: bool) -> Self {
        Self {
            signaled,
            ev_type,
            waiters: WaitQueue::new(),
        }
    }

    fn set_locked(&mut self, idx: u32) {
        let h = make_handle(HANDLE_TYPE_EVENT, idx);
        if self.ev_type == EventType::SynchronizationEvent {
            self.signaled = true;
            if wake_queue_one_for_handle_locked(&mut self.waiters, h) {
                self.signaled = false;
            }
            return;
        }
        self.signaled = true;
        let _ = wake_queue_all_for_handle_locked(&mut self.waiters, h);
    }

    fn reset(&mut self) {
        self.signaled = false;
    }
}

// ── KMutex ────────────────────────────────────────────────────

pub struct KMutex {
    pub owner_tid: u32, // 0 = unowned
    pub recursion: u32,
    pub waiters: WaitQueue,
}

impl KMutex {
    fn new(initial_owner: bool) -> Self {
        let owner_tid = if initial_owner { current_tid() } else { 0 };
        let recursion = if initial_owner { 1 } else { 0 };
        Self {
            owner_tid,
            recursion,
            waiters: WaitQueue::new(),
        }
    }

    fn release_locked(&mut self, idx: u32, current_tid: u32) -> u32 {
        if self.owner_tid != current_tid {
            return STATUS_MUTANT_NOT_OWNED;
        }

        if self.recursion > 0 {
            self.recursion -= 1;
        }
        if self.recursion > 0 {
            return STATUS_SUCCESS;
        }

        self.owner_tid = 0;
        let h = make_handle(HANDLE_TYPE_MUTEX, idx);
        let _ = wake_queue_one_for_handle_locked(&mut self.waiters, h);

        recompute_owned_mutex_priority_locked(current_tid);
        if self.owner_tid != 0 {
            recompute_owned_mutex_priority_locked(self.owner_tid);
        }
        STATUS_SUCCESS
    }
}

// ── KSemaphore ────────────────────────────────────────────────

pub struct KSemaphore {
    pub count: i32,
    pub maximum: i32,
    pub waiters: WaitQueue,
}

impl KSemaphore {
    fn new(initial: i32, maximum: i32) -> Self {
        Self {
            count: initial,
            maximum,
            waiters: WaitQueue::new(),
        }
    }

    fn release_locked(&mut self, idx: u32, count: i32) -> Result<u32, u32> {
        if count <= 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let prev = self.count;
        let new_count = self.count.saturating_add(count);
        if new_count > self.maximum {
            return Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED);
        }
        self.count = new_count;

        let h = make_handle(HANDLE_TYPE_SEMAPHORE, idx);
        let mut rounds = self.waiters.len();
        while rounds > 0 && self.count > 0 {
            if !wake_queue_one_for_handle_locked(&mut self.waiters, h) {
                break;
            }
            rounds -= 1;
        }
        Ok(prev as u32)
    }
}

struct SyncState {
    events: UnsafeCell<Option<ObjectStore<KEvent>>>,
    mutexes: UnsafeCell<Option<ObjectStore<KMutex>>>,
    semaphores: UnsafeCell<Option<ObjectStore<KSemaphore>>>,
    handles: UnsafeCell<Option<ObjectStore<HandleEntry>>>,
    refs: UnsafeCell<Option<Vec<ObjectRef>>>,
    thread_waiters: UnsafeCell<Option<Vec<WaitQueue>>>,
    process_waiters: UnsafeCell<Option<Vec<WaitQueue>>>,
}

unsafe impl Sync for SyncState {}

static SYNC_STATE: SyncState = SyncState {
    events: UnsafeCell::new(None),
    mutexes: UnsafeCell::new(None),
    semaphores: UnsafeCell::new(None),
    handles: UnsafeCell::new(None),
    refs: UnsafeCell::new(None),
    thread_waiters: UnsafeCell::new(None),
    process_waiters: UnsafeCell::new(None),
};

fn events_store_mut() -> &'static mut ObjectStore<KEvent> {
    unsafe {
        let slot = &mut *SYNC_STATE.events.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn mutexes_store_mut() -> &'static mut ObjectStore<KMutex> {
    unsafe {
        let slot = &mut *SYNC_STATE.mutexes.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn semaphores_store_mut() -> &'static mut ObjectStore<KSemaphore> {
    unsafe {
        let slot = &mut *SYNC_STATE.semaphores.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn thread_waiters_mut() -> &'static mut Vec<WaitQueue> {
    unsafe {
        let slot = &mut *SYNC_STATE.thread_waiters.get();
        if slot.is_none() {
            let mut v = Vec::new();
            let _ = v.try_reserve(1);
            v.push(WaitQueue::new()); // index 0 unused
            *slot = Some(v);
        }
        slot.as_mut().unwrap()
    }
}

fn ensure_thread_waiters_slot(tid: u32) -> bool {
    let idx = tid as usize;
    let waiters = thread_waiters_mut();
    if idx < waiters.len() {
        return true;
    }
    let need = idx + 1 - waiters.len();
    if waiters.try_reserve(need).is_err() {
        return false;
    }
    while waiters.len() <= idx {
        waiters.push(WaitQueue::new());
    }
    true
}

fn thread_waiters_ptr(tid: u32) -> *mut WaitQueue {
    let idx = tid as usize;
    unsafe {
        let Some(waiters) = (&mut *SYNC_STATE.thread_waiters.get()).as_mut() else {
            return null_mut();
        };
        if idx >= waiters.len() {
            return null_mut();
        }
        &mut waiters[idx] as *mut WaitQueue
    }
}

fn process_waiters_mut() -> &'static mut Vec<WaitQueue> {
    unsafe {
        let slot = &mut *SYNC_STATE.process_waiters.get();
        if slot.is_none() {
            let mut v = Vec::new();
            let _ = v.try_reserve(1);
            v.push(WaitQueue::new()); // index 0 unused
            *slot = Some(v);
        }
        slot.as_mut().unwrap()
    }
}

fn ensure_process_waiters_slot(pid: u32) -> bool {
    let idx = pid as usize;
    let waiters = process_waiters_mut();
    if idx < waiters.len() {
        return true;
    }
    let need = idx + 1 - waiters.len();
    if waiters.try_reserve(need).is_err() {
        return false;
    }
    while waiters.len() <= idx {
        waiters.push(WaitQueue::new());
    }
    true
}

fn process_waiters_ptr(pid: u32) -> *mut WaitQueue {
    let idx = pid as usize;
    unsafe {
        let Some(waiters) = (&mut *SYNC_STATE.process_waiters.get()).as_mut() else {
            return null_mut();
        };
        if idx >= waiters.len() {
            return null_mut();
        }
        &mut waiters[idx] as *mut WaitQueue
    }
}

fn event_ptr(idx: u32) -> *mut KEvent {
    events_store_mut().get_ptr(idx)
}

fn mutex_ptr(idx: u32) -> *mut KMutex {
    mutexes_store_mut().get_ptr(idx)
}

fn semaphore_ptr(idx: u32) -> *mut KSemaphore {
    semaphores_store_mut().get_ptr(idx)
}

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

// ── 内部辅助 ──────────────────────────────────────────────────

fn deadline_ticks(timeout: WaitDeadline) -> u64 {
    match timeout {
        WaitDeadline::Infinite | WaitDeadline::Immediate => 0,
        WaitDeadline::DeadlineTicks(t) => t,
    }
}

fn set_wait_metadata(tid: u32, kind: u8, handles: &[u64], timeout: WaitDeadline) {
    let count = if handles.len() > MAX_WAIT_HANDLES {
        MAX_WAIT_HANDLES
    } else {
        handles.len()
    };
    let deadline = deadline_ticks(timeout);
    set_thread_state_locked(tid, ThreadState::Waiting);
    with_thread_mut(tid, |t| {
        t.wait_result = STATUS_PENDING;
        t.wait_kind = kind;
        t.wait_count = count as u8;
        t.wait_signaled = 0;
        t.wait_handles.fill(0);
        let mut i = 0usize;
        while i < count {
            t.wait_handles[i] = handles[i];
            i += 1;
        }
    });
    set_wait_deadline_locked(tid, deadline);
}

fn clear_wait_metadata(tid: u32) {
    clear_wait_deadline_locked(tid);
    with_thread_mut(tid, |t| {
        t.wait_kind = WAIT_KIND_NONE;
        t.wait_count = 0;
        t.wait_signaled = 0;
        t.wait_handles.fill(0);
    });
}

fn validate_thread_target_tid(target_tid: u32) -> bool {
    if target_tid == 0 || !thread_exists(target_tid) {
        return false;
    }
    let state = with_thread(target_tid, |t| t.state);
    state != ThreadState::Free
}

fn waiter_owner_pid(waiter_tid: u32) -> u32 {
    if waiter_tid != 0 {
        if let Some(pid) = crate::sched::thread_pid(waiter_tid) {
            if pid != 0 {
                return pid;
            }
        }
    }
    current_handle_owner_pid()
}

fn validate_waitable_handle_locked(h: u64) -> u32 {
    let owner_pid = waiter_owner_pid(current_tid());
    let htype = handle_type_for_pid(h, owner_pid);
    let idx = handle_idx_for_pid(h, owner_pid);
    match htype {
        HANDLE_TYPE_EVENT => {
            if idx == 0 || event_ptr(idx).is_null() {
                STATUS_INVALID_HANDLE
            } else {
                STATUS_SUCCESS
            }
        }
        HANDLE_TYPE_MUTEX => {
            if idx == 0 || mutex_ptr(idx).is_null() {
                STATUS_INVALID_HANDLE
            } else {
                STATUS_SUCCESS
            }
        }
        HANDLE_TYPE_SEMAPHORE => {
            if idx == 0 || semaphore_ptr(idx).is_null() {
                STATUS_INVALID_HANDLE
            } else {
                STATUS_SUCCESS
            }
        }
        HANDLE_TYPE_THREAD => {
            if validate_thread_target_tid(idx) {
                STATUS_SUCCESS
            } else {
                STATUS_INVALID_HANDLE
            }
        }
        HANDLE_TYPE_PROCESS => {
            if idx != 0 && crate::process::process_exists(idx) {
                STATUS_SUCCESS
            } else {
                STATUS_INVALID_HANDLE
            }
        }
        _ => STATUS_INVALID_HANDLE,
    }
}

fn is_handle_signaled_locked(waiter_tid: u32, h: u64) -> bool {
    let owner_pid = waiter_owner_pid(waiter_tid);
    let htype = handle_type_for_pid(h, owner_pid);
    let idx = handle_idx_for_pid(h, owner_pid);
    match htype {
        HANDLE_TYPE_EVENT => {
            let ev = event_ptr(idx);
            if ev.is_null() {
                return false;
            }
            unsafe { (*ev).signaled }
        }
        HANDLE_TYPE_MUTEX => {
            let m = mutex_ptr(idx);
            if m.is_null() {
                return false;
            }
            unsafe { (*m).owner_tid == 0 || (*m).owner_tid == waiter_tid }
        }
        HANDLE_TYPE_SEMAPHORE => {
            let s = semaphore_ptr(idx);
            if s.is_null() {
                return false;
            }
            unsafe { (*s).count > 0 }
        }
        HANDLE_TYPE_THREAD => {
            let tid = idx;
            if tid == 0 || !thread_exists(tid) {
                false
            } else {
                let state = with_thread(tid, |t| t.state);
                state == ThreadState::Terminated || state == ThreadState::Free
            }
        }
        HANDLE_TYPE_PROCESS => idx != 0 && crate::process::process_signaled(idx),
        _ => false,
    }
}

fn consume_handle_signal_locked(waiter_tid: u32, h: u64) -> bool {
    let owner_pid = waiter_owner_pid(waiter_tid);
    let htype = handle_type_for_pid(h, owner_pid);
    let idx = handle_idx_for_pid(h, owner_pid);
    match htype {
        HANDLE_TYPE_EVENT => {
            let ev = event_ptr(idx);
            if ev.is_null() {
                return false;
            }
            unsafe {
                if !(*ev).signaled {
                    return false;
                }
                if (*ev).ev_type == EventType::SynchronizationEvent {
                    (*ev).signaled = false;
                }
            }
            true
        }
        HANDLE_TYPE_MUTEX => {
            let m = mutex_ptr(idx);
            if m.is_null() {
                return false;
            }
            unsafe {
                if (*m).owner_tid == 0 {
                    (*m).owner_tid = waiter_tid;
                    (*m).recursion = 1;
                    recompute_owned_mutex_priority_locked(waiter_tid);
                    return true;
                }
                if (*m).owner_tid == waiter_tid {
                    (*m).recursion = (*m).recursion.saturating_add(1);
                    recompute_owned_mutex_priority_locked(waiter_tid);
                    return true;
                }
            }
            false
        }
        HANDLE_TYPE_SEMAPHORE => {
            let s = semaphore_ptr(idx);
            if s.is_null() {
                return false;
            }
            unsafe {
                if (*s).count <= 0 {
                    return false;
                }
                (*s).count -= 1;
            }
            true
        }
        HANDLE_TYPE_THREAD => is_handle_signaled_locked(waiter_tid, h),
        HANDLE_TYPE_PROCESS => is_handle_signaled_locked(waiter_tid, h),
        _ => false,
    }
}

fn copy_wait_handles_for_thread(tid: u32) -> ([u64; MAX_WAIT_HANDLES], usize) {
    let mut local = [0u64; MAX_WAIT_HANDLES];
    let mut count = 0usize;
    with_thread(tid, |t| {
        count = t.wait_count as usize;
        let mut i = 0usize;
        while i < count && i < MAX_WAIT_HANDLES {
            local[i] = t.wait_handles[i];
            i += 1;
        }
    });
    (local, count)
}

fn wait_all_handles_signaled_locked(tid: u32, handles: &[u64]) -> bool {
    let mut i = 0usize;
    while i < handles.len() {
        if !is_handle_signaled_locked(tid, handles[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn consume_wait_all_locked(tid: u32, handles: &[u64]) -> bool {
    if !wait_all_handles_signaled_locked(tid, handles) {
        return false;
    }
    let mut i = 0usize;
    while i < handles.len() {
        if !consume_handle_signal_locked(tid, handles[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn register_waiter_on_handle_locked(h: u64, tid: u32) {
    let owner_pid = waiter_owner_pid(tid);
    let htype = handle_type_for_pid(h, owner_pid);
    let idx = handle_idx_for_pid(h, owner_pid);
    match htype {
        HANDLE_TYPE_EVENT => {
            let ev = event_ptr(idx);
            if !ev.is_null() {
                unsafe { (*ev).waiters.enqueue(tid) };
            }
        }
        HANDLE_TYPE_MUTEX => {
            let m = mutex_ptr(idx);
            if !m.is_null() {
                unsafe {
                    (*m).waiters.enqueue(tid);
                    let owner_tid = (*m).owner_tid;
                    if owner_tid != 0 && owner_tid != tid {
                        let waiter_prio = with_thread(tid, |t| t.priority);
                        boost_thread_priority_locked(owner_tid, waiter_prio);
                    }
                }
            }
        }
        HANDLE_TYPE_SEMAPHORE => {
            let s = semaphore_ptr(idx);
            if !s.is_null() {
                unsafe { (*s).waiters.enqueue(tid) };
            }
        }
        HANDLE_TYPE_THREAD => {
            if validate_thread_target_tid(idx) && ensure_thread_waiters_slot(idx) {
                let q = thread_waiters_ptr(idx);
                if !q.is_null() {
                    unsafe { (*q).enqueue(tid) };
                }
            }
        }
        HANDLE_TYPE_PROCESS => {
            if idx != 0 && crate::process::process_exists(idx) && ensure_process_waiters_slot(idx) {
                let q = process_waiters_ptr(idx);
                if !q.is_null() {
                    unsafe { (*q).enqueue(tid) };
                }
            }
        }
        _ => {}
    }
}

fn remove_waiter_from_handle_locked(h: u64, tid: u32) {
    let owner_pid = waiter_owner_pid(tid);
    let htype = handle_type_for_pid(h, owner_pid);
    let idx = handle_idx_for_pid(h, owner_pid);
    match htype {
        HANDLE_TYPE_EVENT => {
            let ev = event_ptr(idx);
            if !ev.is_null() {
                unsafe { (*ev).waiters.remove(tid) };
            }
        }
        HANDLE_TYPE_MUTEX => {
            let m = mutex_ptr(idx);
            if !m.is_null() {
                unsafe { (*m).waiters.remove(tid) };
            }
        }
        HANDLE_TYPE_SEMAPHORE => {
            let s = semaphore_ptr(idx);
            if !s.is_null() {
                unsafe { (*s).waiters.remove(tid) };
            }
        }
        HANDLE_TYPE_THREAD => {
            let q = thread_waiters_ptr(idx);
            if !q.is_null() {
                unsafe { (*q).remove(tid) };
            }
        }
        HANDLE_TYPE_PROCESS => {
            let q = process_waiters_ptr(idx);
            if !q.is_null() {
                unsafe { (*q).remove(tid) };
            }
        }
        _ => {}
    }
}

fn cleanup_wait_registration_locked(tid: u32) {
    let (handles, count) = copy_wait_handles_for_thread(tid);
    let mut i = 0usize;
    while i < count {
        remove_waiter_from_handle_locked(handles[i], tid);
        i += 1;
    }
}

fn wait_index_for_handle_locked(tid: u32, h: u64) -> Option<usize> {
    let owner_pid = waiter_owner_pid(tid);
    with_thread(tid, |t| {
        let count = t.wait_count as usize;
        let mut i = 0usize;
        while i < count && i < MAX_WAIT_HANDLES {
            if handles_same_object_for_pid(t.wait_handles[i], h, owner_pid) {
                return Some(i);
            }
            i += 1;
        }
        None
    })
}

fn complete_wait_locked(tid: u32, result: u32) {
    cleanup_wait_registration_locked(tid);
    clear_wait_metadata(tid);
    wake(tid, result);
}

fn try_complete_waiter_for_handle_locked(tid: u32, signaled_handle: u64) -> bool {
    let (state, kind) = with_thread(tid, |t| (t.state, t.wait_kind));
    if state != ThreadState::Waiting {
        return false;
    }

    match kind {
        WAIT_KIND_SINGLE => {
            let expected = with_thread(tid, |t| t.wait_handles[0]);
            let owner_pid = waiter_owner_pid(tid);
            if !handles_same_object_for_pid(expected, signaled_handle, owner_pid) {
                return false;
            }
            if !consume_handle_signal_locked(tid, expected) {
                return false;
            }
            complete_wait_locked(tid, STATUS_SUCCESS);
            true
        }
        WAIT_KIND_MULTI_ANY => {
            let Some(index) = wait_index_for_handle_locked(tid, signaled_handle) else {
                return false;
            };
            let expected = with_thread(tid, |t| t.wait_handles[index]);
            if !consume_handle_signal_locked(tid, expected) {
                return false;
            }
            complete_wait_locked(tid, STATUS_SUCCESS + index as u32);
            true
        }
        WAIT_KIND_MULTI_ALL => {
            if let Some(index) = wait_index_for_handle_locked(tid, signaled_handle) {
                with_thread_mut(tid, |t| t.wait_signaled |= 1u64 << (index as u64));
            }
            let (handles, count) = copy_wait_handles_for_thread(tid);
            let handles = &handles[..count];
            if !wait_all_handles_signaled_locked(tid, handles) {
                return false;
            }
            if !consume_wait_all_locked(tid, handles) {
                return false;
            }
            complete_wait_locked(tid, STATUS_SUCCESS);
            true
        }
        _ => false,
    }
}

fn wake_queue_one_for_handle_locked(queue: &mut WaitQueue, signaled_handle: u64) -> bool {
    let attempts = queue.len();
    let mut i = 0usize;
    while i < attempts {
        let tid = queue.dequeue_waiting();
        if tid == 0 {
            return false;
        }
        if try_complete_waiter_for_handle_locked(tid, signaled_handle) {
            return true;
        }
        if thread_exists(tid) && with_thread(tid, |t| t.state == ThreadState::Waiting) {
            queue.enqueue(tid);
        }
        i += 1;
    }
    false
}

fn wake_queue_all_for_handle_locked(queue: &mut WaitQueue, signaled_handle: u64) -> usize {
    let attempts = queue.len();
    let mut i = 0usize;
    let mut woke = 0usize;
    while i < attempts {
        let tid = queue.dequeue_waiting();
        if tid == 0 {
            break;
        }
        if try_complete_waiter_for_handle_locked(tid, signaled_handle) {
            woke += 1;
        } else if thread_exists(tid) && with_thread(tid, |t| t.state == ThreadState::Waiting) {
            queue.enqueue(tid);
        }
        i += 1;
    }
    woke
}

fn wait_common_locked(handles: &[u64], wait_all: bool, timeout: WaitDeadline) -> u32 {
    if handles.is_empty() || handles.len() > MAX_WAIT_HANDLES {
        return STATUS_INVALID_PARAMETER;
    }

    let mut i = 0usize;
    while i < handles.len() {
        let st = validate_waitable_handle_locked(handles[i]);
        if st != STATUS_SUCCESS {
            return st;
        }
        i += 1;
    }

    if wait_all {
        let owner_pid = waiter_owner_pid(current_tid());
        let mut i = 0usize;
        while i < handles.len() {
            let mut j = i + 1;
            while j < handles.len() {
                if handles_same_object_for_pid(handles[i], handles[j], owner_pid) {
                    return STATUS_INVALID_PARAMETER;
                }
                j += 1;
            }
            i += 1;
        }
    }

    let cur = current_tid();

    if wait_all {
        if consume_wait_all_locked(cur, handles) {
            return STATUS_SUCCESS;
        }
    } else {
        let mut idx = 0usize;
        while idx < handles.len() {
            let h = handles[idx];
            if is_handle_signaled_locked(cur, h) && consume_handle_signal_locked(cur, h) {
                return STATUS_SUCCESS + idx as u32;
            }
            idx += 1;
        }
    }

    if timeout == WaitDeadline::Immediate {
        return STATUS_TIMEOUT;
    }

    let kind = if handles.len() == 1 {
        WAIT_KIND_SINGLE
    } else if wait_all {
        WAIT_KIND_MULTI_ALL
    } else {
        WAIT_KIND_MULTI_ANY
    };
    set_wait_metadata(cur, kind, handles, timeout);

    let mut i = 0usize;
    while i < handles.len() {
        register_waiter_on_handle_locked(handles[i], cur);
        i += 1;
    }

    STATUS_PENDING
}

// ── 对外接口：等待/清理/线程终止通知 ─────────────────────────

/// Wait on a single handle. Returns NTSTATUS.
pub fn wait_handle(h: u64, timeout: WaitDeadline) -> u32 {
    sched_lock_acquire();
    let st = wait_common_locked(core::slice::from_ref(&h), false, timeout);
    sched_lock_release();
    st
}

/// Wait on multiple handles. wait_all=false => WaitAny, true => WaitAll.
pub fn wait_multiple(handles: &[u64], wait_all: bool, timeout: WaitDeadline) -> u32 {
    sched_lock_acquire();
    let st = wait_common_locked(handles, wait_all, timeout);
    sched_lock_release();
    st
}

/// Delay current thread for specified timeout semantics.
/// Return STATUS_PENDING if the thread is blocked; scheduler timeout path
/// will resume it with STATUS_SUCCESS.
pub fn delay_current_thread(timeout: WaitDeadline) -> u32 {
    if timeout == WaitDeadline::Immediate {
        return STATUS_SUCCESS;
    }

    sched_lock_acquire();
    let cur = current_tid();
    if cur == 0 || !thread_exists(cur) {
        sched_lock_release();
        return STATUS_INVALID_PARAMETER;
    }

    set_wait_metadata(cur, WAIT_KIND_DELAY, &[], timeout);
    set_thread_state_locked(cur, ThreadState::Waiting);
    sched_lock_release();
    STATUS_PENDING
}

/// Remove a waiting thread from all object wait queues.
/// Called on timeout/cancel/wake cleanup paths.
pub fn cleanup_wait_registration(tid: u32) {
    if tid == 0 {
        return;
    }
    sched_lock_acquire();
    cleanup_wait_registration_locked(tid);
    sched_lock_release();
}

/// Notify synchronization subsystem that a thread became terminated.
/// Wakes waiters blocked on this thread handle.
pub fn thread_notify_terminated(target_tid: u32) {
    if target_tid == 0 {
        return;
    }
    sched_lock_acquire();
    let h = make_handle(HANDLE_TYPE_THREAD, target_tid);
    let q = thread_waiters_ptr(target_tid);
    if !q.is_null() {
        unsafe {
            wake_queue_all_for_handle_locked(&mut *q, h);
        }
    }
    sched_lock_release();
}

/// Notify synchronization subsystem that a process became terminated.
/// Wakes waiters blocked on this process handle.
pub fn process_notify_terminated(target_pid: u32) {
    if target_pid == 0 {
        return;
    }
    sched_lock_acquire();
    let h = make_handle(HANDLE_TYPE_PROCESS, target_pid);
    let q = process_waiters_ptr(target_pid);
    if !q.is_null() {
        unsafe {
            wake_queue_all_for_handle_locked(&mut *q, h);
        }
    }
    sched_lock_release();
}

// ── Event API ────────────────────────────────────────────────

pub fn create_event_handle(ev_type: EventType, initial_state: bool) -> Result<u64, u32> {
    let Some(idx) = event_alloc(ev_type, initial_state) else {
        return Err(status::NO_MEMORY);
    };
    let Some(h) = make_new_handle(HANDLE_TYPE_EVENT, idx) else {
        event_free(idx);
        return Err(status::NO_MEMORY);
    };
    Ok(h)
}

pub fn event_alloc(ev_type: EventType, initial_state: bool) -> Option<u32> {
    events_store_mut().alloc_with(|_| KEvent::new(ev_type, initial_state))
}

pub fn event_set(idx: u32) -> u32 {
    if idx == 0 {
        return STATUS_INVALID_HANDLE;
    }
    let ev_ptr = event_ptr(idx);
    if ev_ptr.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    sched_lock_acquire();
    unsafe { (*ev_ptr).set_locked(idx) };
    sched_lock_release();

    STATUS_SUCCESS
}

pub fn event_reset(idx: u32) -> u32 {
    if idx == 0 {
        return STATUS_INVALID_HANDLE;
    }
    let ev = event_ptr(idx);
    if ev.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    sched_lock_acquire();
    unsafe { (*ev).reset() };
    sched_lock_release();
    STATUS_SUCCESS
}

pub fn event_set_by_handle(h: u64) -> u32 {
    let Some(idx) = resolve_handle_idx_by_type(h, HANDLE_TYPE_EVENT) else {
        return STATUS_INVALID_HANDLE;
    };
    event_set(idx)
}

pub fn event_reset_by_handle(h: u64) -> u32 {
    let Some(idx) = resolve_handle_idx_by_type(h, HANDLE_TYPE_EVENT) else {
        return STATUS_INVALID_HANDLE;
    };
    event_reset(idx)
}

pub fn event_free(idx: u32) {
    if idx == 0 {
        return;
    }
    let _ = events_store_mut().free(idx);
}

// ── Mutex API ────────────────────────────────────────────────

pub fn create_mutex_handle(initial_owner: bool) -> Result<u64, u32> {
    let Some(idx) = mutex_alloc(initial_owner) else {
        return Err(status::NO_MEMORY);
    };
    let Some(h) = make_new_handle(HANDLE_TYPE_MUTEX, idx) else {
        mutex_free(idx);
        return Err(status::NO_MEMORY);
    };
    Ok(h)
}

pub fn mutex_alloc(initial_owner: bool) -> Option<u32> {
    mutexes_store_mut().alloc_with(|_| KMutex::new(initial_owner))
}

pub fn mutex_release(idx: u32) -> u32 {
    if idx == 0 {
        return STATUS_INVALID_HANDLE;
    }
    let m_ptr = mutex_ptr(idx);
    if m_ptr.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    sched_lock_acquire();
    let st = unsafe { (*m_ptr).release_locked(idx, current_tid()) };
    sched_lock_release();
    st
}

pub fn mutex_free(idx: u32) {
    if idx == 0 {
        return;
    }
    let _ = mutexes_store_mut().free(idx);
}

pub fn mutex_release_by_handle(h: u64) -> u32 {
    let Some(idx) = resolve_handle_idx_by_type(h, HANDLE_TYPE_MUTEX) else {
        return STATUS_INVALID_HANDLE;
    };
    mutex_release(idx)
}

// ── Semaphore API ────────────────────────────────────────────

pub fn create_semaphore_handle(initial: i32, maximum: i32) -> Result<u64, u32> {
    if maximum <= 0 || initial < 0 || initial > maximum {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let Some(idx) = semaphore_alloc(initial, maximum) else {
        return Err(status::NO_MEMORY);
    };
    let Some(h) = make_new_handle(HANDLE_TYPE_SEMAPHORE, idx) else {
        semaphore_free(idx);
        return Err(status::NO_MEMORY);
    };
    Ok(h)
}

pub fn semaphore_alloc(initial: i32, maximum: i32) -> Option<u32> {
    if maximum <= 0 || initial < 0 || initial > maximum {
        return None;
    }
    semaphores_store_mut().alloc_with(|_| KSemaphore::new(initial, maximum))
}

/// Returns previous count, or STATUS_SEMAPHORE_LIMIT_EXCEEDED.
pub fn semaphore_release(idx: u32, count: i32) -> u32 {
    if idx == 0 {
        return STATUS_INVALID_HANDLE;
    }

    let s_ptr = semaphore_ptr(idx);
    if s_ptr.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    sched_lock_acquire();
    let st = unsafe {
        match (*s_ptr).release_locked(idx, count) {
            Ok(prev) => prev,
            Err(err) => err,
        }
    };
    sched_lock_release();
    st
}

pub fn semaphore_free(idx: u32) {
    if idx == 0 {
        return;
    }
    let _ = semaphores_store_mut().free(idx);
}

pub fn semaphore_release_by_handle(h: u64, count: i32) -> Result<u32, u32> {
    let Some(idx) = resolve_handle_idx_by_type(h, HANDLE_TYPE_SEMAPHORE) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    let prev_or_status = semaphore_release(idx, count);
    if (prev_or_status & NTSTATUS_ERROR_BIT) != 0 {
        Err(prev_or_status)
    } else {
        Ok(prev_or_status)
    }
}

// ── Handle wait / close ─────────────────────────────────────

pub fn close_handle(h: u64) -> u32 {
    let Some(info) = close_handle_info(h) else {
        return STATUS_INVALID_HANDLE;
    };
    if !info.destroy_object {
        return STATUS_SUCCESS;
    }
    destroy_object_by_type(info.htype, info.obj_idx)
}

pub fn destroy_object_by_type(htype: u64, obj_idx: u32) -> u32 {
    match htype {
        HANDLE_TYPE_EVENT => {
            event_free(obj_idx);
            STATUS_SUCCESS
        }
        HANDLE_TYPE_MUTEX => {
            mutex_free(obj_idx);
            STATUS_SUCCESS
        }
        HANDLE_TYPE_SEMAPHORE => {
            semaphore_free(obj_idx);
            STATUS_SUCCESS
        }
        HANDLE_TYPE_THREAD => STATUS_SUCCESS,
        HANDLE_TYPE_PROCESS => {
            crate::process::last_handle_closed(obj_idx);
            STATUS_SUCCESS
        }
        _ => STATUS_INVALID_HANDLE,
    }
}
