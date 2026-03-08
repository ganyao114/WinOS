// sched/sync/state.rs — Per-process sync object handle table
//
// Stores KEvent / KMutex / KSemaphore objects keyed by NT handle (u64).
// All access requires the scheduler lock to be held.

use crate::sched::sync::primitives_api::{KEvent, KMutex, KSemaphore};
use crate::kobj::ObjectStore;
use winemu_shared::status;

// ── SyncObject enum ───────────────────────────────────────────────────────────

pub enum SyncObject {
    Event(KEvent),
    Mutex(KMutex),
    Semaphore(KSemaphore),
}

impl SyncObject {
    pub fn as_event(&self) -> Option<&KEvent> {
        if let SyncObject::Event(e) = self { Some(e) } else { None }
    }
    pub fn as_event_mut(&mut self) -> Option<&mut KEvent> {
        if let SyncObject::Event(e) = self { Some(e) } else { None }
    }
    pub fn as_mutex(&self) -> Option<&KMutex> {
        if let SyncObject::Mutex(m) = self { Some(m) } else { None }
    }
    pub fn as_mutex_mut(&mut self) -> Option<&mut KMutex> {
        if let SyncObject::Mutex(m) = self { Some(m) } else { None }
    }
    pub fn as_semaphore(&self) -> Option<&KSemaphore> {
        if let SyncObject::Semaphore(s) = self { Some(s) } else { None }
    }
    pub fn as_semaphore_mut(&mut self) -> Option<&mut KSemaphore> {
        if let SyncObject::Semaphore(s) = self { Some(s) } else { None }
    }

    pub fn is_signaled(&self) -> bool {
        match self {
            SyncObject::Event(e)     => e.is_signaled(),
            SyncObject::Mutex(m)     => m.owner_tid == 0,
            SyncObject::Semaphore(s) => s.count > 0,
        }
    }
}

// ── SyncHandleTable ───────────────────────────────────────────────────────────

/// Per-process handle table for sync objects.
/// Handle values are u32 indices into the ObjectStore.
pub struct SyncHandleTable {
    store: ObjectStore<SyncObject>,
}

impl SyncHandleTable {
    pub fn new() -> Self {
        Self { store: ObjectStore::new() }
    }

    /// Allocate a new sync object. Returns the handle (u32 cast to u64).
    pub fn alloc(&mut self, obj: SyncObject) -> Option<u64> {
        self.store.alloc_with(|_id| obj).map(|id| id as u64)
    }

    /// Get an immutable reference to the object for `handle`.
    pub fn get(&self, handle: u64) -> Option<&SyncObject> {
        let ptr = self.store.get_ptr(handle as u32);
        if ptr.is_null() { None } else { Some(unsafe { &*ptr }) }
    }

    /// Get a mutable reference to the object for `handle`.
    pub fn get_mut(&mut self, handle: u64) -> Option<&mut SyncObject> {
        let ptr = self.store.get_ptr(handle as u32);
        if ptr.is_null() { None } else { Some(unsafe { &mut *ptr }) }
    }

    /// Free a handle.
    pub fn free(&mut self, handle: u64) -> bool {
        self.store.free(handle as u32)
    }

    pub fn contains(&self, handle: u64) -> bool {
        self.store.contains(handle as u32)
    }
}

unsafe impl Send for SyncHandleTable {}
unsafe impl Sync for SyncHandleTable {}

// ── Global sync handle table ──────────────────────────────────────────────────
// For now a single global table (single-process model).
// In a multi-process model this would be per-KProcess.

use core::cell::UnsafeCell;

pub struct GlobalSyncState {
    table: UnsafeCell<Option<SyncHandleTable>>,
}

unsafe impl Sync for GlobalSyncState {}
unsafe impl Send for GlobalSyncState {}

impl GlobalSyncState {
    const fn new() -> Self {
        Self { table: UnsafeCell::new(None) }
    }

    pub fn init(&self) {
        unsafe { *self.table.get() = Some(SyncHandleTable::new()) };
    }

    #[inline]
    pub unsafe fn table(&self) -> &SyncHandleTable {
        (*self.table.get()).as_ref().expect("sync state not initialized")
    }

    #[inline]
    pub unsafe fn table_mut(&self) -> &mut SyncHandleTable {
        (*self.table.get()).as_mut().expect("sync state not initialized")
    }
}

pub static SYNC_STATE: GlobalSyncState = GlobalSyncState::new();

pub fn init_sync_state() {
    SYNC_STATE.init();
}

// ── Free-function helpers (require scheduler lock) ────────────────────────────

pub fn sync_alloc(obj: SyncObject) -> Option<u64> {
    unsafe { SYNC_STATE.table_mut() }.alloc(obj)
}

pub fn sync_get(handle: u64) -> Option<&'static SyncObject> {
    unsafe { SYNC_STATE.table() }.get(handle)
}

pub fn sync_get_mut(handle: u64) -> Option<&'static mut SyncObject> {
    unsafe { SYNC_STATE.table_mut() }.get_mut(handle)
}

pub fn sync_free(handle: u64) -> bool {
    unsafe { SYNC_STATE.table_mut() }.free(handle)
}

/// Get by raw obj_idx (not handle). Used after resolving via KHandleTable.
pub fn sync_get_by_idx(idx: u32) -> Option<&'static SyncObject> {
    let ptr = unsafe { SYNC_STATE.table() }.store.get_ptr(idx);
    if ptr.is_null() { None } else { Some(unsafe { &*ptr }) }
}

/// Get mutable by raw obj_idx.
pub fn sync_get_mut_by_idx(idx: u32) -> Option<&'static mut SyncObject> {
    let ptr = unsafe { SYNC_STATE.table_mut() }.store.get_ptr(idx);
    if ptr.is_null() { None } else { Some(unsafe { &mut *ptr }) }
}

/// Free by raw obj_idx. Called from kobject close_last_ref.
pub fn sync_free_idx(idx: u32) -> bool {
    let table = unsafe { SYNC_STATE.table_mut() };
    let ptr = table.store.get_ptr(idx);
    if ptr.is_null() {
        return false;
    }

    unsafe {
        match &mut *ptr {
            SyncObject::Event(e) => {
                e.waiters.wake_all_with_status(status::INVALID_HANDLE);
            }
            SyncObject::Mutex(m) => {
                m.owner_tid = 0;
                m.recursion = 0;
                m.waiters.wake_all_with_status(status::INVALID_HANDLE);
            }
            SyncObject::Semaphore(s) => {
                s.waiters.wake_all_with_status(status::INVALID_HANDLE);
            }
        }
    }

    table.store.free(idx)
}
