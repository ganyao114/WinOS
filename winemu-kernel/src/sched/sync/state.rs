// sched/sync/state.rs — Global sync object store
//
// Stores KEvent / KMutex / KSemaphore objects keyed by object index.
// The public NT handles are managed by process::KHandleTable and carry obj_idx.
// All access here requires the scheduler lock to be held.

use crate::kobj::ObjectStore;
use crate::sched::sync::primitives_api::{KEvent, KMutex, KSemaphore};
use winemu_shared::status;

// ── SyncObject enum ───────────────────────────────────────────────────────────

pub enum SyncObject {
    Event(KEvent),
    Mutex(KMutex),
    Semaphore(KSemaphore),
}

impl SyncObject {
    pub fn as_event(&self) -> Option<&KEvent> {
        if let SyncObject::Event(e) = self {
            Some(e)
        } else {
            None
        }
    }
    pub fn as_event_mut(&mut self) -> Option<&mut KEvent> {
        if let SyncObject::Event(e) = self {
            Some(e)
        } else {
            None
        }
    }
    pub fn as_mutex(&self) -> Option<&KMutex> {
        if let SyncObject::Mutex(m) = self {
            Some(m)
        } else {
            None
        }
    }
    pub fn as_mutex_mut(&mut self) -> Option<&mut KMutex> {
        if let SyncObject::Mutex(m) = self {
            Some(m)
        } else {
            None
        }
    }
    pub fn as_semaphore(&self) -> Option<&KSemaphore> {
        if let SyncObject::Semaphore(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_semaphore_mut(&mut self) -> Option<&mut KSemaphore> {
        if let SyncObject::Semaphore(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn is_signaled(&self) -> bool {
        match self {
            SyncObject::Event(e) => e.is_signaled(),
            SyncObject::Mutex(m) => m.owner_tid == 0,
            SyncObject::Semaphore(s) => s.count > 0,
        }
    }
}

// ── SyncObjectStore ───────────────────────────────────────────────────────────

/// Backing store for sync objects.
/// Object IDs (u32) are used as obj_idx in process::KHandleTable entries.
pub struct SyncObjectStore {
    store: ObjectStore<SyncObject>,
}

impl SyncObjectStore {
    pub fn new() -> Self {
        Self {
            store: ObjectStore::new(),
        }
    }

    /// Allocate a new sync object. Returns object index (u32 cast to u64).
    pub fn alloc(&mut self, obj: SyncObject) -> Option<u64> {
        self.store.alloc_with(|_id| obj).map(|id| id as u64)
    }

    /// Get an immutable reference to the object for `handle`.
    pub fn get(&self, handle: u64) -> Option<&SyncObject> {
        let ptr = self.store.get_ptr(handle as u32);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*ptr })
        }
    }

    /// Get a mutable reference to the object for `handle`.
    pub fn get_mut(&mut self, handle: u64) -> Option<&mut SyncObject> {
        let ptr = self.store.get_ptr(handle as u32);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &mut *ptr })
        }
    }

    /// Free a handle.
    pub fn free(&mut self, handle: u64) -> bool {
        self.store.free(handle as u32)
    }
}

unsafe impl Send for SyncObjectStore {}
unsafe impl Sync for SyncObjectStore {}

// ── Global sync object store ──────────────────────────────────────────────────

use core::cell::UnsafeCell;

pub struct GlobalSyncState {
    store: UnsafeCell<Option<SyncObjectStore>>,
}

unsafe impl Sync for GlobalSyncState {}
unsafe impl Send for GlobalSyncState {}

impl GlobalSyncState {
    const fn new() -> Self {
        Self {
            store: UnsafeCell::new(None),
        }
    }

    pub fn init(&self) {
        unsafe { *self.store.get() = Some(SyncObjectStore::new()) };
    }

    #[inline]
    pub unsafe fn store(&self) -> &SyncObjectStore {
        (*self.store.get())
            .as_ref()
            .expect("sync state not initialized")
    }

    #[inline]
    pub unsafe fn store_mut(&self) -> &mut SyncObjectStore {
        (*self.store.get())
            .as_mut()
            .expect("sync state not initialized")
    }
}

pub static SYNC_STATE: GlobalSyncState = GlobalSyncState::new();

pub fn init_sync_state() {
    SYNC_STATE.init();
}

// ── Free-function helpers (require scheduler lock) ────────────────────────────

pub fn sync_alloc(obj: SyncObject) -> Option<u64> {
    unsafe { SYNC_STATE.store_mut() }.alloc(obj)
}

/// Get by raw obj_idx (not handle). Used after resolving via KHandleTable.
pub fn sync_get_by_idx(idx: u32) -> Option<&'static SyncObject> {
    let ptr = unsafe { SYNC_STATE.store() }.store.get_ptr(idx);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

/// Get mutable by raw obj_idx.
pub fn sync_get_mut_by_idx(idx: u32) -> Option<&'static mut SyncObject> {
    let ptr = unsafe { SYNC_STATE.store_mut() }.store.get_ptr(idx);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &mut *ptr })
    }
}

/// Free by raw obj_idx. Called from kobject close_last_ref.
pub fn sync_free_idx(idx: u32) -> bool {
    let store = unsafe { SYNC_STATE.store_mut() };
    let ptr = store.store.get_ptr(idx);
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

    store.store.free(idx)
}
