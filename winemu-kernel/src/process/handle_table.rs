// process/handle_table.rs — Per-process NT handle table
//
// Handle encoding (u32, Windows convention: low 2 bits = 0):
//   bits  [1: 0] = 0           (always zero, Windows compat)
//   bits [11: 2] = index       (10 bits, 0..1023)
//   bits [26:12] = linear_id   (15 bits, 1..32767, ABA guard)
//   bits [31:27] = 0           (reserved)
//
// Storage: inline 16-slot array on first use, grows via kmalloc:
//   16 → 64 → 256 → 1024 (max)
//
// All operations are O(1). Caller must hold the scheduler lock or
// process lock before calling any mutating method.

// ── Object reference ─────────────────────────────────────────────────────────

/// A typed reference to a kernel object stored in the handle table.
/// The inner u32 is the object's index in its respective store
/// (obj_idx for sync objects, tid for threads, pid for processes, etc.).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum KObjectKind {
    Event     = 1,
    Mutex     = 2,
    Semaphore = 3,
    Thread    = 4,
    Process   = 5,
    File      = 6,
    Section   = 7,
    Key       = 8,
    Token     = 9,
}

#[derive(Clone, Copy, Debug)]
pub struct KObjectRef {
    pub kind:    KObjectKind,
    pub obj_idx: u32,
}

impl KObjectRef {
    #[inline] pub fn event(idx: u32)     -> Self { Self { kind: KObjectKind::Event,     obj_idx: idx } }
    #[inline] pub fn mutex(idx: u32)     -> Self { Self { kind: KObjectKind::Mutex,     obj_idx: idx } }
    #[inline] pub fn semaphore(idx: u32) -> Self { Self { kind: KObjectKind::Semaphore, obj_idx: idx } }
    #[inline] pub fn thread(tid: u32)    -> Self { Self { kind: KObjectKind::Thread,    obj_idx: tid } }
    #[inline] pub fn process(pid: u32)   -> Self { Self { kind: KObjectKind::Process,   obj_idx: pid } }
    #[inline] pub fn file(idx: u32)      -> Self { Self { kind: KObjectKind::File,      obj_idx: idx } }
    #[inline] pub fn section(idx: u32)   -> Self { Self { kind: KObjectKind::Section,   obj_idx: idx } }
    #[inline] pub fn key(idx: u32)       -> Self { Self { kind: KObjectKind::Key,       obj_idx: idx } }
    #[inline] pub fn token(idx: u32)     -> Self { Self { kind: KObjectKind::Token,     obj_idx: idx } }
}

// ── Handle encoding ───────────────────────────────────────────────────────────

#[inline]
pub fn encode_handle(index: u16, linear_id: u16) -> u32 {
    ((index as u32) << 2) | ((linear_id as u32) << 12)
}

#[inline]
pub fn decode_handle(handle: u32) -> Option<(usize, u16)> {
    if handle == 0 { return None; }
    let index = ((handle >> 2) & 0x3FF) as usize;
    let lid   = ((handle >> 12) & 0x7FFF) as u16;
    if lid == 0 { return None; }
    Some((index, lid))
}

// ── Slot info (union: linear_id when occupied, next_free when free) ───────────

#[derive(Clone, Copy)]
union SlotInfo {
    linear_id: u16,
    next_free: i16,
}

// ── KHandleTable ─────────────────────────────────────────────────────────────

const INLINE_CAP: usize = 16;
const MAX_CAP:    usize = 1024;

pub struct KHandleTable {
    // Heap arrays used after inline capacity is exhausted.
    heap_objects: *mut Option<KObjectRef>,
    heap_slots:   *mut SlotInfo,
    capacity: u16,
    free_head: i16,   // -1 = full
    count:    u16,
    next_lid: u16,    // next linear_id to assign (wraps 1..=32767)
    is_heap:  bool,

    // Inline storage — avoids first alloc for small processes
    inline_objects: [Option<KObjectRef>; INLINE_CAP],
    inline_slots:   [SlotInfo; INLINE_CAP],
}

unsafe impl Send for KHandleTable {}
unsafe impl Sync for KHandleTable {}

impl KHandleTable {
    pub fn new() -> Self {
        let mut t = Self {
            heap_objects: core::ptr::null_mut(),
            heap_slots:   core::ptr::null_mut(),
            capacity: INLINE_CAP as u16,
            free_head: 0,
            count:    0,
            next_lid: 1,
            is_heap:  false,
            inline_objects: [None; INLINE_CAP],
            inline_slots:   [SlotInfo { next_free: -1 }; INLINE_CAP],
        };
        // Build inline freelist: 0 → 1 → ... → 15 → -1
        for i in 0..INLINE_CAP {
            t.inline_slots[i] = SlotInfo {
                next_free: if i + 1 < INLINE_CAP { i as i16 + 1 } else { -1 },
            };
        }
        t
    }

    #[inline]
    fn objects_ptr(&self) -> *const Option<KObjectRef> {
        if self.is_heap {
            self.heap_objects as *const Option<KObjectRef>
        } else {
            self.inline_objects.as_ptr()
        }
    }

    #[inline]
    fn objects_mut_ptr(&mut self) -> *mut Option<KObjectRef> {
        if self.is_heap {
            self.heap_objects
        } else {
            self.inline_objects.as_mut_ptr()
        }
    }

    #[inline]
    fn slots_ptr(&self) -> *const SlotInfo {
        if self.is_heap {
            self.heap_slots as *const SlotInfo
        } else {
            self.inline_slots.as_ptr()
        }
    }

    #[inline]
    fn slots_mut_ptr(&mut self) -> *mut SlotInfo {
        if self.is_heap {
            self.heap_slots
        } else {
            self.inline_slots.as_mut_ptr()
        }
    }

    #[inline]
    fn alloc_lid(&mut self) -> u16 {
        let id = self.next_lid;
        self.next_lid = if self.next_lid >= 32767 { 1 } else { self.next_lid + 1 };
        id
    }

    /// Grow capacity: 16→64→256→1024. Returns false on OOM.
    fn grow(&mut self) -> bool {
        let new_cap: usize = match self.capacity as usize {
            16  => 64,
            64  => 256,
            256 => 1024,
            _   => return false,
        };
        crate::log::debug_u64(
            0xC1C0_0000_0000_0000 | ((self.capacity as u64) << 16) | (new_cap as u64),
        );
        let obj_bytes = new_cap * core::mem::size_of::<Option<KObjectRef>>();
        let slt_bytes = new_cap * core::mem::size_of::<SlotInfo>();
        let new_obj = crate::mm::kmalloc::alloc(obj_bytes, 8) as *mut Option<KObjectRef>;
        let new_slt = crate::mm::kmalloc::alloc(slt_bytes, 2) as *mut SlotInfo;
        if new_obj.is_null() || new_slt.is_null() {
            if !new_obj.is_null() { crate::mm::kmalloc::dealloc(new_obj as *mut u8); }
            if !new_slt.is_null() { crate::mm::kmalloc::dealloc(new_slt as *mut u8); }
            crate::log::debug_u64(0xC1C1_FFFF_FFFF_FFFF);
            return false;
        }
        let old_cap = self.capacity as usize;
        unsafe {
            // Copy existing entries
            core::ptr::copy_nonoverlapping(self.objects_ptr(), new_obj, old_cap);
            core::ptr::copy_nonoverlapping(self.slots_ptr(), new_slt, old_cap);
            // Init new slots as freelist: old_cap → old_cap+1 → ... → new_cap-1 → old free_head
            for i in old_cap..new_cap {
                (*new_obj.add(i)) = None;
                (*new_slt.add(i)) = SlotInfo {
                    next_free: if i + 1 < new_cap { i as i16 + 1 } else { self.free_head },
                };
            }
        }
        if self.is_heap {
            crate::mm::kmalloc::dealloc(self.heap_objects as *mut u8);
            crate::mm::kmalloc::dealloc(self.heap_slots as *mut u8);
        }
        self.heap_objects = new_obj;
        self.heap_slots = new_slt;
        self.free_head = old_cap as i16;
        self.capacity  = new_cap as u16;
        self.is_heap   = true;
        crate::log::debug_u64(0xC1C1_0000_0000_0000 | (new_cap as u64));
        true
    }

    /// Add an object, returns the opaque handle value or None on OOM/full.
    pub fn add(&mut self, obj: KObjectRef) -> Option<u32> {
        if self.free_head < 0 {
            if !self.grow() { return None; }
        }
        let idx = self.free_head as usize;
        let lid = self.alloc_lid();
        unsafe {
            let slots = self.slots_mut_ptr();
            let objects = self.objects_mut_ptr();
            self.free_head = (*slots.add(idx)).next_free;
            (*objects.add(idx)) = Some(obj);
            (*slots.add(idx)) = SlotInfo { linear_id: lid };
        }
        self.count += 1;
        Some(encode_handle(idx as u16, lid))
    }

    /// Look up an object by handle. O(1).
    pub fn get(&self, handle: u32) -> Option<KObjectRef> {
        let (idx, lid) = decode_handle(handle)?;
        if idx >= self.capacity as usize { return None; }
        unsafe {
            let slots = self.slots_ptr();
            let objects = self.objects_ptr();
            if (*slots.add(idx)).linear_id != lid { return None; }
            *objects.add(idx)
        }
    }

    /// Remove and return an object by handle. O(1).
    pub fn remove(&mut self, handle: u32) -> Option<KObjectRef> {
        let (idx, lid) = decode_handle(handle)?;
        if idx >= self.capacity as usize { return None; }
        unsafe {
            let slots = self.slots_mut_ptr();
            let objects = self.objects_mut_ptr();
            if (*slots.add(idx)).linear_id != lid { return None; }
            let obj = (*objects.add(idx)).take()?;
            (*slots.add(idx)) = SlotInfo { next_free: self.free_head };
            self.free_head = idx as i16;
            self.count -= 1;
            Some(obj)
        }
    }

    /// Drain all entries, calling f for each. Used on process exit.
    pub fn drain(&mut self, mut f: impl FnMut(KObjectRef)) {
        let objects = self.objects_mut_ptr();
        let slots = self.slots_mut_ptr();
        for i in 0..self.capacity as usize {
            unsafe {
                if let Some(obj) = (*objects.add(i)).take() {
                    (*slots.add(i)) = SlotInfo { next_free: self.free_head };
                    self.free_head = i as i16;
                    self.count -= 1;
                    f(obj);
                }
            }
        }
    }

    /// Count of live handles.
    #[inline] pub fn count(&self) -> u16 { self.count }

    /// Iterate all live entries (handle, obj). Used for stats/query.
    pub fn for_each(&self, mut f: impl FnMut(u32, KObjectRef)) {
        let objects = self.objects_ptr();
        let slots = self.slots_ptr();
        for i in 0..self.capacity as usize {
            unsafe {
                if let Some(obj) = *objects.add(i) {
                    let lid = (*slots.add(i)).linear_id;
                    if lid != 0 {
                        f(encode_handle(i as u16, lid), obj);
                    }
                }
            }
        }
    }
}

impl Drop for KHandleTable {
    fn drop(&mut self) {
        if self.is_heap {
            crate::mm::kmalloc::dealloc(self.heap_objects as *mut u8);
            crate::mm::kmalloc::dealloc(self.heap_slots as *mut u8);
        }
    }
}
