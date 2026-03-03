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
    wait_queue_pool: UnsafeCell<Option<SlabPool<WaitQueueNode>>>,
}

unsafe impl Sync for SyncState {}

static SYNC_STATE: SyncState = SyncState {
    events: UnsafeCell::new(None),
    mutexes: UnsafeCell::new(None),
    semaphores: UnsafeCell::new(None),
    handles: UnsafeCell::new(None),
    refs: UnsafeCell::new(None),
    wait_queue_pool: UnsafeCell::new(None),
};

fn wait_queue_pool_mut() -> &'static mut Option<SlabPool<WaitQueueNode>> {
    unsafe { &mut *SYNC_STATE.wait_queue_pool.get() }
}

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

fn thread_waiters_ptr(tid: u32) -> *mut WaitQueue {
    if tid == 0 || !thread_exists(tid) {
        return null_mut();
    }
    let mut ptr = null_mut();
    with_thread_mut(tid, |t| {
        ptr = &mut t.waiters as *mut WaitQueue;
    });
    ptr
}

fn process_waiters_ptr(pid: u32) -> *mut WaitQueue {
    if pid == 0 || !crate::process::process_exists(pid) {
        return null_mut();
    }
    let mut ptr = null_mut();
    let _ = crate::process::with_process_mut(pid, |p| {
        ptr = &mut p.waiters as *mut WaitQueue;
    });
    ptr
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
