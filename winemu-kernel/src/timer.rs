use crate::kobj::ObjectStore;
use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;

pub use crate::arch::timer::{
    idle_wait_until_deadline_100ns, schedule_running_slice_100ns, DEFAULT_TIMESLICE_100NS,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum TimerTaskKind {
    ThreadTimeout = 1,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TimerTaskHandle {
    pub id: u32,
    pub generation: u32,
}

impl TimerTaskHandle {
    #[inline(always)]
    pub const fn invalid() -> Self {
        Self {
            id: 0,
            generation: 0,
        }
    }

    #[inline(always)]
    pub const fn is_valid(self) -> bool {
        self.id != 0 && self.generation != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FiredTimerTask {
    pub kind: TimerTaskKind,
    pub target_id: u32,
    pub deadline_100ns: u64,
    pub handle: TimerTaskHandle,
}

#[derive(Clone, Copy)]
struct TimerTaskRecord {
    kind: TimerTaskKind,
    target_id: u32,
    deadline_100ns: u64,
    generation: u32,
}

#[derive(Clone, Copy, Default)]
struct TimerHeapEntry {
    deadline_100ns: u64,
    task_id: u32,
    generation: u32,
}

struct TimerHeap {
    data: Vec<TimerHeapEntry>,
}

impl TimerHeap {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    #[inline(always)]
    fn clear(&mut self) {
        self.data.clear();
    }

    fn push(&mut self, ent: TimerHeapEntry) -> bool {
        if self.data.try_reserve(1).is_err() {
            return false;
        }
        self.data.push(ent);
        let mut idx = self.data.len() - 1;
        while idx > 0 {
            let parent = (idx - 1) / 2;
            if self.data[parent].deadline_100ns <= self.data[idx].deadline_100ns {
                break;
            }
            self.data.swap(parent, idx);
            idx = parent;
        }
        true
    }

    #[inline(always)]
    fn peek(&self) -> Option<TimerHeapEntry> {
        self.data.first().copied()
    }

    fn pop(&mut self) -> Option<TimerHeapEntry> {
        if self.data.is_empty() {
            return None;
        }
        let top = self.data[0];
        let tail = self.data.pop().unwrap();
        if !self.data.is_empty() {
            self.data[0] = tail;
            let mut idx = 0usize;
            loop {
                let left = idx * 2 + 1;
                let right = left + 1;
                if left >= self.data.len() {
                    break;
                }
                let mut smallest = left;
                if right < self.data.len()
                    && self.data[right].deadline_100ns < self.data[left].deadline_100ns
                {
                    smallest = right;
                }
                if self.data[idx].deadline_100ns <= self.data[smallest].deadline_100ns {
                    break;
                }
                self.data.swap(idx, smallest);
                idx = smallest;
            }
        }
        Some(top)
    }
}

struct TimerTaskState {
    tasks: Option<ObjectStore<TimerTaskRecord>>,
    heap: TimerHeap,
    rebuild_needed: bool,
    next_generation: u32,
}

impl TimerTaskState {
    fn new() -> Self {
        Self {
            tasks: None,
            heap: TimerHeap::new(),
            rebuild_needed: false,
            next_generation: 0,
        }
    }
}

struct TimerTaskRegistry {
    state: UnsafeCell<Option<TimerTaskState>>,
}

unsafe impl Sync for TimerTaskRegistry {}

static TIMER_TASKS: TimerTaskRegistry = TimerTaskRegistry {
    state: UnsafeCell::new(None),
};

fn state_mut() -> &'static mut TimerTaskState {
    unsafe {
        let slot = &mut *TIMER_TASKS.state.get();
        if slot.is_none() {
            *slot = Some(TimerTaskState::new());
        }
        slot.as_mut().unwrap()
    }
}

fn tasks_store_mut(state: &mut TimerTaskState) -> &mut ObjectStore<TimerTaskRecord> {
    if state.tasks.is_none() {
        state.tasks = Some(ObjectStore::new());
    }
    state.tasks.as_mut().unwrap()
}

#[inline(always)]
fn next_generation(state: &mut TimerTaskState) -> u32 {
    let mut generation = state.next_generation.wrapping_add(1);
    if generation == 0 {
        generation = 1;
    }
    state.next_generation = generation;
    generation
}

fn heap_entry_is_live(state: &mut TimerTaskState, entry: TimerHeapEntry) -> bool {
    let ptr = tasks_store_mut(state).get_ptr(entry.task_id);
    if ptr.is_null() {
        return false;
    }
    unsafe {
        (*ptr).generation == entry.generation
            && (*ptr).deadline_100ns == entry.deadline_100ns
            && (*ptr).deadline_100ns != 0
    }
}

fn prune_heap_locked(state: &mut TimerTaskState) {
    while let Some(head) = state.heap.peek() {
        if heap_entry_is_live(state, head) {
            break;
        }
        let _ = state.heap.pop();
    }
}

fn rebuild_heap_locked(state: &mut TimerTaskState) {
    if !state.rebuild_needed {
        return;
    }
    state.rebuild_needed = false;
    state.heap.clear();
    if state.tasks.is_none() {
        return;
    }
    let mut overflow = false;
    let store = state.tasks.as_ref().unwrap();
    store.for_each_live_ptr(|task_id, ptr| unsafe {
        let rec = *ptr;
        if rec.deadline_100ns == 0 {
            return;
        }
        let ok = state.heap.push(TimerHeapEntry {
            deadline_100ns: rec.deadline_100ns,
            task_id,
            generation: rec.generation,
        });
        if !ok {
            overflow = true;
        }
    });
    if overflow {
        state.rebuild_needed = true;
    }
}

pub fn register_task(
    kind: TimerTaskKind,
    target_id: u32,
    deadline_100ns: u64,
) -> Option<TimerTaskHandle> {
    if target_id == 0 || deadline_100ns == 0 {
        return None;
    }
    let state = state_mut();
    let generation = next_generation(state);
    let task_id = tasks_store_mut(state).alloc_with(|_| TimerTaskRecord {
        kind,
        target_id,
        deadline_100ns,
        generation,
    })?;
    let handle = TimerTaskHandle { id: task_id, generation };
    let ok = state.heap.push(TimerHeapEntry {
        deadline_100ns,
        task_id,
        generation,
    });
    if !ok {
        state.rebuild_needed = true;
    }
    Some(handle)
}

pub fn rearm_task(handle: TimerTaskHandle, deadline_100ns: u64) -> Option<TimerTaskHandle> {
    if !handle.is_valid() {
        return None;
    }
    if deadline_100ns == 0 {
        let _ = cancel_task(handle);
        return None;
    }
    let state = state_mut();
    let generation = next_generation(state);

    {
        let ptr = tasks_store_mut(state).get_ptr(handle.id);
        if ptr.is_null() {
            return None;
        }
        unsafe {
            if (*ptr).generation != handle.generation {
                return None;
            }
            (*ptr).deadline_100ns = deadline_100ns;
            (*ptr).generation = generation;
        }
    }

    let new_handle = TimerTaskHandle {
        id: handle.id,
        generation,
    };
    let ok = state.heap.push(TimerHeapEntry {
        deadline_100ns,
        task_id: handle.id,
        generation,
    });
    if !ok {
        state.rebuild_needed = true;
    }

    Some(new_handle)
}

pub fn cancel_task(handle: TimerTaskHandle) -> bool {
    if !handle.is_valid() {
        return false;
    }
    let state = state_mut();
    let store = tasks_store_mut(state);
    let ptr = store.get_ptr(handle.id);
    if ptr.is_null() {
        return false;
    }
    unsafe {
        if (*ptr).generation != handle.generation {
            return false;
        }
    }
    store.free(handle.id)
}

pub fn next_deadline_locked() -> u64 {
    let state = state_mut();
    rebuild_heap_locked(state);
    prune_heap_locked(state);
    state.heap.peek().map_or(0, |e| e.deadline_100ns)
}

pub fn pop_expired_task_locked(now_100ns: u64) -> Option<FiredTimerTask> {
    let state = state_mut();
    rebuild_heap_locked(state);
    loop {
        prune_heap_locked(state);
        let head = state.heap.peek()?;
        if head.deadline_100ns > now_100ns {
            return None;
        }
        let _ = state.heap.pop();

        let ptr = tasks_store_mut(state).get_ptr(head.task_id);
        if ptr.is_null() {
            continue;
        }
        let rec = unsafe { *ptr };
        if rec.generation != head.generation || rec.deadline_100ns != head.deadline_100ns {
            continue;
        }

        let fired = FiredTimerTask {
            kind: rec.kind,
            target_id: rec.target_id,
            deadline_100ns: rec.deadline_100ns,
            handle: TimerTaskHandle {
                id: head.task_id,
                generation: rec.generation,
            },
        };
        let _ = tasks_store_mut(state).free(head.task_id);
        return Some(fired);
    }
}
