use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const DEFAULT_SLAB_BYTES: usize = 16 * 1024;
const SLAB_SHRINK_HIGH_WATERMARK: usize = 3;
const SLAB_SHRINK_KEEP_LOW_WATERMARK: usize = 1;
// 2-byte ABA tag: this makes ABA very unlikely in practice, but not impossible
// once the tag wraps (every 65,536 successful head updates).
const FREE_HEAD_TAG_BITS: usize = 16;
const FREE_HEAD_PTR_BITS: usize = usize::BITS as usize - FREE_HEAD_TAG_BITS;
const FREE_HEAD_TAG_SHIFT: usize = FREE_HEAD_PTR_BITS;
const FREE_HEAD_PTR_MASK: usize = (1usize << FREE_HEAD_TAG_SHIFT) - 1;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("SlabPool tagged free-list requires 64-bit pointers");

#[repr(C)]
struct FreeNode {
    next: *mut FreeNode,
    slab_idx: u32,
}

struct SlabMeta {
    base: *mut u8,
    live: AtomicUsize,
}

impl SlabMeta {
    #[inline(always)]
    fn empty() -> Self {
        Self {
            base: null_mut(),
            live: AtomicUsize::new(0),
        }
    }
}

fn align_up(v: usize, align: usize) -> usize {
    (v + align - 1) & !(align - 1)
}

pub struct SlabPool<T> {
    // Packed head: [63:48]=tag, [47:0]=ptr(canonical/48-bit).
    // We currently accept 16-bit tag wraparound risk.
    free_head: AtomicUsize,
    slabs: UnsafeCell<Vec<SlabMeta>>,
    stride: usize,
    align: usize,
    slab_bytes: usize,
    maintenance: AtomicBool,
    fast_ops: AtomicUsize,
    shrink_probe: AtomicUsize,
    _marker: PhantomData<T>,
}

unsafe impl<T> Sync for SlabPool<T> {}

struct FastPathGuard<'a, T> {
    pool: &'a SlabPool<T>,
}

impl<'a, T> Drop for FastPathGuard<'a, T> {
    fn drop(&mut self) {
        self.pool.fast_ops.fetch_sub(1, Ordering::Release);
    }
}

struct MaintenanceGuard<'a, T> {
    pool: &'a SlabPool<T>,
}

impl<'a, T> Drop for MaintenanceGuard<'a, T> {
    fn drop(&mut self) {
        self.pool.maintenance.store(false, Ordering::Release);
    }
}

impl<T> SlabPool<T> {
    pub fn new() -> Self {
        let align = align_of::<T>().max(align_of::<FreeNode>());
        let stride = align_up(size_of::<T>().max(size_of::<FreeNode>()), align);
        Self {
            free_head: AtomicUsize::new(0),
            slabs: UnsafeCell::new(Vec::new()),
            stride,
            align,
            slab_bytes: DEFAULT_SLAB_BYTES.max(stride),
            maintenance: AtomicBool::new(false),
            fast_ops: AtomicUsize::new(0),
            shrink_probe: AtomicUsize::new(0),
            _marker: PhantomData,
        }
    }

    #[inline]
    fn slabs(&self) -> &Vec<SlabMeta> {
        unsafe { &*self.slabs.get() }
    }

    #[inline]
    fn slabs_mut(&self) -> &mut Vec<SlabMeta> {
        unsafe { &mut *self.slabs.get() }
    }

    #[inline(always)]
    fn enter_fast_path(&self) -> FastPathGuard<'_, T> {
        loop {
            while self.maintenance.load(Ordering::Acquire) {
                spin_loop();
            }
            self.fast_ops.fetch_add(1, Ordering::AcqRel);
            if !self.maintenance.load(Ordering::Acquire) {
                return FastPathGuard { pool: self };
            }
            self.fast_ops.fetch_sub(1, Ordering::Release);
            spin_loop();
        }
    }

    #[inline(always)]
    fn try_begin_maintenance(&self) -> Option<MaintenanceGuard<'_, T>> {
        if self
            .maintenance
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        while self.fast_ops.load(Ordering::Acquire) != 0 {
            spin_loop();
        }
        Some(MaintenanceGuard { pool: self })
    }

    #[inline(always)]
    fn begin_maintenance(&self) -> MaintenanceGuard<'_, T> {
        loop {
            if let Some(g) = self.try_begin_maintenance() {
                return g;
            }
            spin_loop();
        }
    }

    #[inline(always)]
    fn decode_head_ptr(packed: usize) -> *mut FreeNode {
        let raw = packed & FREE_HEAD_PTR_MASK;
        let sign = 1usize << (FREE_HEAD_TAG_SHIFT - 1);
        let canonical = if (raw & sign) != 0 {
            raw | (!FREE_HEAD_PTR_MASK)
        } else {
            raw
        };
        canonical as *mut FreeNode
    }

    #[inline(always)]
    fn decode_head_tag(packed: usize) -> u16 {
        (packed >> FREE_HEAD_TAG_SHIFT) as u16
    }

    #[inline(always)]
    fn encode_head(ptr: *mut FreeNode, tag: u16) -> usize {
        let addr = ptr as usize;
        debug_assert_eq!(
            Self::decode_head_ptr(addr & FREE_HEAD_PTR_MASK) as usize,
            addr
        );
        ((tag as usize) << FREE_HEAD_TAG_SHIFT) | (addr & FREE_HEAD_PTR_MASK)
    }

    #[inline(always)]
    fn bump_head_tag(packed: usize) -> u16 {
        Self::decode_head_tag(packed).wrapping_add(1)
    }

    #[inline(always)]
    fn load_head_ptr(&self, order: Ordering) -> *mut FreeNode {
        Self::decode_head_ptr(self.free_head.load(order))
    }

    #[inline(always)]
    fn store_head_ptr_with_bumped_tag(&self, ptr: *mut FreeNode, order: Ordering) {
        let cur = self.free_head.load(Ordering::Relaxed);
        let next = Self::encode_head(ptr, Self::bump_head_tag(cur));
        self.free_head.store(next, order);
    }

    #[inline(always)]
    fn pop_free_node(&self) -> *mut FreeNode {
        let mut cur = self.free_head.load(Ordering::Acquire);
        loop {
            let head = Self::decode_head_ptr(cur);
            if head.is_null() {
                return null_mut();
            }
            let next = unsafe { (*head).next };
            let want = Self::encode_head(next, Self::bump_head_tag(cur));
            match self.free_head.compare_exchange_weak(
                cur,
                want,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return head,
                Err(actual) => cur = actual,
            }
        }
    }

    #[inline(always)]
    fn push_free_node(&self, node: *mut FreeNode) {
        let mut cur = self.free_head.load(Ordering::Acquire);
        loop {
            let head = Self::decode_head_ptr(cur);
            unsafe {
                (*node).next = head;
            }
            let want = Self::encode_head(node, Self::bump_head_tag(cur));
            match self.free_head.compare_exchange_weak(
                cur,
                want,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    #[inline(always)]
    fn objs_per_slab(&self) -> usize {
        (self.slab_bytes / self.stride).max(1)
    }

    #[inline(always)]
    fn slab_range_in(&self, slabs: &[SlabMeta], idx: usize) -> Option<(usize, usize)> {
        if idx >= slabs.len() {
            return None;
        }
        let meta = &slabs[idx];
        if meta.base.is_null() {
            return None;
        }
        let lo = meta.base as usize;
        let hi = lo.checked_add(self.objs_per_slab().checked_mul(self.stride)?)?;
        Some((lo, hi))
    }

    #[inline(always)]
    fn slab_contains_addr_in(&self, slabs: &[SlabMeta], idx: usize, addr: usize) -> bool {
        let Some((lo, hi)) = self.slab_range_in(slabs, idx) else {
            return false;
        };
        addr >= lo && addr < hi
    }

    fn find_slab_index_in(&self, slabs: &[SlabMeta], ptr: *mut u8) -> Option<usize> {
        let addr = ptr as usize;
        let mut i = 0usize;
        while i < slabs.len() {
            if let Some((lo, hi)) = self.slab_range_in(slabs, i) {
                if addr >= lo && addr < hi {
                    return Some(i);
                }
            }
            i += 1;
        }
        None
    }

    fn choose_slab_slot_for_grow_locked(&self) -> Option<usize> {
        let slabs = self.slabs_mut();
        let mut i = 0usize;
        while i < slabs.len() {
            if slabs[i].base.is_null() {
                return Some(i);
            }
            i += 1;
        }
        if slabs.try_reserve(1).is_err() {
            return None;
        }
        slabs.push(SlabMeta::empty());
        Some(slabs.len() - 1)
    }

    fn grow_locked(&self) -> bool {
        let objs = self.objs_per_slab();
        let Some(bytes) = objs.checked_mul(self.stride) else {
            return false;
        };
        let Some(base) = crate::alloc::alloc_zeroed(bytes, self.align) else {
            return false;
        };
        if Self::decode_head_ptr((base as usize) & FREE_HEAD_PTR_MASK) as usize != base as usize {
            crate::alloc::dealloc(base);
            panic!("SlabPool pointer not encodable in 48-bit tagged head");
        }
        let Some(slab_idx) = self.choose_slab_slot_for_grow_locked() else {
            crate::alloc::dealloc(base);
            return false;
        };
        if slab_idx > u32::MAX as usize {
            crate::alloc::dealloc(base);
            return false;
        }
        self.slabs_mut()[slab_idx] = SlabMeta {
            base,
            live: AtomicUsize::new(0),
        };

        unsafe {
            let mut head = self.load_head_ptr(Ordering::Relaxed);
            let mut i = 0usize;
            while i < objs {
                let node = base.add(i * self.stride) as *mut FreeNode;
                (*node).next = head;
                (*node).slab_idx = slab_idx as u32;
                head = node;
                i += 1;
            }
            self.store_head_ptr_with_bumped_tag(head, Ordering::Release);
        }
        true
    }

    fn try_alloc_fast(&self) -> Option<*mut T> {
        let _guard = self.enter_fast_path();
        let node = self.pop_free_node();
        if node.is_null() {
            return None;
        }
        let slabs = self.slabs();
        let idx = unsafe { (*node).slab_idx as usize };
        let node_addr = node as usize;
        let slab_idx = if self.slab_contains_addr_in(slabs, idx, node_addr) {
            idx
        } else {
            let Some(found) = self.find_slab_index_in(slabs, node as *mut u8) else {
                self.push_free_node(node);
                return None;
            };
            unsafe {
                (*node).slab_idx = found as u32;
            }
            found
        };
        slabs[slab_idx].live.fetch_add(1, Ordering::Relaxed);
        Some(node as *mut T)
    }

    pub fn alloc_slot(&self) -> Option<*mut T> {
        loop {
            if let Some(ptr) = self.try_alloc_fast() {
                return Some(ptr);
            }
            let _maint = self.begin_maintenance();
            if !self.load_head_ptr(Ordering::Acquire).is_null() {
                continue;
            }
            if !self.grow_locked() {
                return None;
            }
        }
    }

    fn release_empty_slab_locked(&self, slab_idx: usize) -> bool {
        let slabs = self.slabs_mut();
        if slab_idx >= slabs.len() {
            return false;
        }
        let meta = &slabs[slab_idx];
        if meta.base.is_null() || meta.live.load(Ordering::Acquire) != 0 {
            return false;
        }
        let Some((lo, hi)) = self.slab_range_in(slabs, slab_idx) else {
            return false;
        };

        // Purge all nodes of this slab from free list before returning memory.
        let mut head = self.load_head_ptr(Ordering::Relaxed);
        let mut prev: *mut FreeNode = null_mut();
        let mut cur = head;
        unsafe {
            while !cur.is_null() {
                let next = (*cur).next;
                let cur_addr = cur as usize;
                let in_target =
                    ((*cur).slab_idx as usize) == slab_idx || (cur_addr >= lo && cur_addr < hi);
                if in_target {
                    if prev.is_null() {
                        head = next;
                    } else {
                        (*prev).next = next;
                    }
                } else {
                    prev = cur;
                }
                cur = next;
            }
        }
        self.store_head_ptr_with_bumped_tag(head, Ordering::Release);

        let base = slabs[slab_idx].base;
        crate::alloc::dealloc(base);
        slabs[slab_idx] = SlabMeta::empty();
        true
    }

    fn shrink_if_needed_locked(&self) {
        debug_assert!(SLAB_SHRINK_KEEP_LOW_WATERMARK < SLAB_SHRINK_HIGH_WATERMARK);

        let mut active = 0usize;
        let mut empty = 0usize;
        let mut i = 0usize;
        let slabs = self.slabs();
        while i < slabs.len() {
            let meta = &slabs[i];
            if !meta.base.is_null() {
                active = active.saturating_add(1);
                if meta.live.load(Ordering::Relaxed) == 0 {
                    empty = empty.saturating_add(1);
                }
            }
            i += 1;
        }
        if active <= 1 || empty < SLAB_SHRINK_HIGH_WATERMARK {
            return;
        }

        // Hysteresis: once we cross the high watermark, shrink down to low watermark.
        while active > 1 && empty > SLAB_SHRINK_KEEP_LOW_WATERMARK {
            let mut victim: Option<usize> = None;
            let mut j = 0usize;
            let slabs = self.slabs();
            while j < slabs.len() {
                let meta = &slabs[j];
                if !meta.base.is_null() && meta.live.load(Ordering::Relaxed) == 0 {
                    victim = Some(j);
                    break;
                }
                j += 1;
            }
            let Some(victim_idx) = victim else {
                break;
            };
            if !self.release_empty_slab_locked(victim_idx) {
                break;
            }
            active = active.saturating_sub(1);
            empty = empty.saturating_sub(1);
        }
    }

    #[inline(always)]
    fn should_probe_shrink(&self) -> bool {
        (self.shrink_probe.fetch_add(1, Ordering::Relaxed) & 0x3f) == 0
    }

    pub unsafe fn free_slot(&self, ptr: *mut T) {
        if ptr.is_null() {
            return;
        }
        let do_shrink = {
            let _guard = self.enter_fast_path();
            let node = ptr as *mut FreeNode;
            let slabs = self.slabs();
            let idx = (*node).slab_idx as usize;
            let ptr_addr = ptr as usize;
            let slab_idx = if self.slab_contains_addr_in(slabs, idx, ptr_addr) {
                idx
            } else {
                let Some(found) = self.find_slab_index_in(slabs, ptr as *mut u8) else {
                    return;
                };
                (*node).slab_idx = found as u32;
                found
            };
            let live = &slabs[slab_idx].live;
            let mut cur = live.load(Ordering::Relaxed);
            while cur > 0 {
                match live.compare_exchange_weak(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed)
                {
                    Ok(_) => break,
                    Err(actual) => cur = actual,
                }
            }
            self.push_free_node(node);
            self.should_probe_shrink()
        };

        if do_shrink {
            if let Some(_maint) = self.try_begin_maintenance() {
                self.shrink_if_needed_locked();
            }
        }
    }
}

impl<T> Drop for SlabPool<T> {
    fn drop(&mut self) {
        self.maintenance.store(true, Ordering::Release);
        while self.fast_ops.load(Ordering::Acquire) != 0 {
            spin_loop();
        }
        let slabs = unsafe { &mut *self.slabs.get() };
        let mut i = 0usize;
        while i < slabs.len() {
            let base = slabs[i].base;
            if !base.is_null() {
                crate::alloc::dealloc(base);
                slabs[i] = SlabMeta::empty();
            }
            i += 1;
        }
        self.store_head_ptr_with_bumped_tag(null_mut(), Ordering::Release);
        self.maintenance.store(false, Ordering::Release);
    }
}

pub struct ObjectStore<T> {
    pool: SlabPool<T>,
    slots: Vec<*mut T>,
    free_ids: Vec<u32>,
}

impl<T> ObjectStore<T> {
    pub fn new() -> Self {
        let mut slots = Vec::new();
        let _ = slots.try_reserve(1);
        slots.push(null_mut());
        Self {
            pool: SlabPool::new(),
            slots,
            free_ids: Vec::new(),
        }
    }

    fn alloc_id(&mut self) -> Option<u32> {
        if let Some(id) = self.free_ids.pop() {
            return Some(id);
        }
        let id = self.slots.len() as u32;
        if self.slots.try_reserve(1).is_err() {
            return None;
        }
        self.slots.push(null_mut());
        Some(id)
    }

    pub fn alloc_slot_with_id(&mut self) -> Option<(u32, *mut T)> {
        let id = self.alloc_id()?;
        let Some(ptr) = self.pool.alloc_slot() else {
            return None;
        };
        self.slots[id as usize] = ptr;
        Some((id, ptr))
    }

    pub fn alloc_with(&mut self, f: impl FnOnce(u32) -> T) -> Option<u32> {
        let (id, ptr) = self.alloc_slot_with_id()?;
        unsafe {
            ptr.write(f(id));
        }
        Some(id)
    }

    pub fn get_ptr(&self, id: u32) -> *mut T {
        let idx = id as usize;
        if idx == 0 || idx >= self.slots.len() {
            return null_mut();
        }
        self.slots[idx]
    }

    pub fn contains(&self, id: u32) -> bool {
        !self.get_ptr(id).is_null()
    }

    pub fn free(&mut self, id: u32) -> bool {
        let idx = id as usize;
        if idx == 0 || idx >= self.slots.len() {
            return false;
        }
        let ptr = self.slots[idx];
        if ptr.is_null() {
            return false;
        }
        self.slots[idx] = null_mut();
        unsafe {
            core::ptr::drop_in_place(ptr);
            self.pool.free_slot(ptr);
        }
        if self.free_ids.try_reserve(1).is_ok() {
            self.free_ids.push(id);
        }
        true
    }

    pub fn for_each_live_id(&self, mut f: impl FnMut(u32)) {
        let mut i = 1usize;
        while i < self.slots.len() {
            if !self.slots[i].is_null() {
                f(i as u32);
            }
            i += 1;
        }
    }

    pub fn for_each_live_ptr(&self, mut f: impl FnMut(u32, *mut T)) {
        let mut i = 1usize;
        while i < self.slots.len() {
            let ptr = self.slots[i];
            if !ptr.is_null() {
                f(i as u32, ptr);
            }
            i += 1;
        }
    }
}
