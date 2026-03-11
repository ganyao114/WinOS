// sched/thread_store.rs — Thin wrapper around ObjectStore<KThread>
// Free-functions (with_thread, thread_exists) live in global.rs to avoid
// circular dependency.

use crate::kobj::ObjectStore;
use crate::sched::types::KThread;

pub struct ThreadStore(ObjectStore<KThread>);

impl ThreadStore {
    pub fn new() -> Self {
        Self(ObjectStore::new())
    }

    /// Allocate a new KThread slot, calling `f(tid)` to construct it.
    pub fn alloc(&mut self, f: impl FnOnce(u32) -> KThread) -> Option<u32> {
        self.0.alloc_with(f)
    }

    /// Free a thread slot (drops the KThread).
    pub fn free(&mut self, tid: u32) -> bool {
        self.0.free(tid)
    }

    pub fn contains(&self, tid: u32) -> bool {
        self.0.contains(tid)
    }

    /// Immutable borrow — None if tid not found.
    pub fn get(&self, tid: u32) -> Option<&KThread> {
        let ptr = self.0.get_ptr(tid);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*ptr })
        }
    }

    /// Mutable borrow — None if tid not found.
    pub fn get_mut(&mut self, tid: u32) -> Option<&mut KThread> {
        let ptr = self.0.get_ptr(tid);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &mut *ptr })
        }
    }

    /// Return a raw mutable pointer to the thread, or null if not found.
    pub fn get_ptr(&self, tid: u32) -> Option<*mut KThread> {
        let ptr = self.0.get_ptr(tid);
        if ptr.is_null() {
            None
        } else {
            Some(ptr)
        }
    }

    /// Iterate over all live thread IDs.
    pub fn for_each_id(&self, mut f: impl FnMut(u32)) {
        self.0.for_each_live_id(|id| f(id));
    }

    /// Iterate over all live threads (immutable).
    pub fn for_each(&self, mut f: impl FnMut(u32, &KThread)) {
        self.0.for_each_live_ptr(|id, ptr| {
            if !ptr.is_null() {
                f(id, unsafe { &*ptr });
            }
        });
    }
}

// SAFETY: ThreadStore is only accessed under the scheduler spinlock.
unsafe impl Send for ThreadStore {}
unsafe impl Sync for ThreadStore {}
