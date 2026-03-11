use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::mm::{KernelVa, PhysAddr};

const PAGE_SIZE: usize = 4096;
const NONE_I16: i16 = -1;
const NONE_U16: u16 = u16::MAX;

const MAX_PAGES: usize = 1024; // 4 MiB / 4 KiB
const MAX_ARENAS: usize = 32;
const MAX_ORDER: usize = 10; // 2^10 pages = 1024 pages
const NUM_ORDERS: usize = MAX_ORDER + 1;
const DYNAMIC_MIN_ARENA_PAGES: usize = 64; // 256 KiB
const DYNAMIC_MAX_ARENA_PAGES: usize = MAX_PAGES;
const DYNAMIC_LOW_WATER_PAGES: usize = DYNAMIC_MIN_ARENA_PAGES * 8; // 2 MiB
const DYNAMIC_HIGH_WATER_PAGES: usize = DYNAMIC_MIN_ARENA_PAGES * 16; // 4 MiB
const RECLAIM_CHECK_INTERVAL_FREE_OPS: u32 = 64;
const MAX_DIRECT_ALLOCS: usize = 1024;
const MAX_PENDING_PHYS_FREES: usize = MAX_ARENAS + MAX_DIRECT_ALLOCS;

const SLAB_MIN_SHIFT: usize = 3; // 8 bytes
const SLAB_MAX_SHIFT: usize = 11; // 2048 bytes
const SLAB_MIN_SIZE: usize = 1 << SLAB_MIN_SHIFT;
const SLAB_MAX_SIZE: usize = 1 << SLAB_MAX_SHIFT;
const NUM_CACHES: usize = SLAB_MAX_SHIFT - SLAB_MIN_SHIFT + 1;
const CACHE_SIZES: [u16; NUM_CACHES] = [8, 16, 32, 64, 128, 256, 512, 1024, 2048];

const PAGE_KIND_UNUSED: u8 = 0;
const PAGE_KIND_FREE_HEAD: u8 = 1;
const PAGE_KIND_FREE_TAIL: u8 = 2;
const PAGE_KIND_SLAB: u8 = 3;
const PAGE_KIND_LARGE_HEAD: u8 = 4;
const PAGE_KIND_LARGE_TAIL: u8 = 5;

#[derive(Clone, Copy)]
pub struct KmallocStats {
    pub alloc_calls: u64,
    pub free_calls: u64,
    pub small_allocs: u64,
    pub large_allocs: u64,
    pub alloc_failures: u64,
    pub invalid_frees: u64,
}

impl KmallocStats {
    const fn new() -> Self {
        Self {
            alloc_calls: 0,
            free_calls: 0,
            small_allocs: 0,
            large_allocs: 0,
            alloc_failures: 0,
            invalid_frees: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct KmallocSnapshot {
    pub stats: KmallocStats,
    pub alloc_fail_precheck: u64,
    pub alloc_fail_small_oom: u64,
    pub alloc_fail_large_oom: u64,
    pub alloc_fail_corruption: u64,
    pub invalid_free_bad_ptr: u64,
    pub invalid_free_double: u64,
    pub small_alloc_by_cache: [u64; NUM_CACHES],
    pub small_free_by_cache: [u64; NUM_CACHES],
    pub large_alloc_by_order: [u64; NUM_ORDERS],
    pub free_blocks_by_order: [u16; NUM_ORDERS],
    pub partial_slabs_by_cache: [u16; NUM_CACHES],
    pub full_slabs_by_cache: [u16; NUM_CACHES],
    pub largest_free_order: u8,
    pub free_pages_total: usize,
    pub dynamic_arena_count: usize,
    pub dynamic_pages_total: usize,
    pub dynamic_pages_peak: usize,
    pub dynamic_arena_grow_count: u64,
    pub dynamic_arena_release_count: u64,
    pub reclaim_runs: u64,
    pub reclaim_pages_released: u64,
    pub direct_active_allocs: usize,
    pub direct_pages_total: usize,
    pub direct_pages_peak: usize,
    pub direct_alloc_count: u64,
    pub direct_free_count: u64,
    pub direct_alloc_failures: u64,
}

#[derive(Clone, Copy)]
struct PendingPhysFree {
    valid: bool,
    pa: PhysAddr,
    kva: KernelVa,
    pages: usize,
}

impl PendingPhysFree {
    const fn empty() -> Self {
        Self {
            valid: false,
            pa: PhysAddr::new(0),
            kva: KernelVa::new(0),
            pages: 0,
        }
    }
}

#[inline]
fn align_up(value: usize, align: usize) -> Option<usize> {
    if !align.is_power_of_two() {
        return None;
    }
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

#[inline]
fn pages_for_bytes(bytes: usize) -> Option<usize> {
    bytes
        .max(1)
        .checked_add(PAGE_SIZE - 1)
        .map(|n| n / PAGE_SIZE)
}

struct SpinLock {
    locked: AtomicBool,
}

impl SpinLock {
    const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> SpinGuard<'_> {
        while self.locked.swap(true, Ordering::Acquire) {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        SpinGuard { lock: self }
    }

    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

struct SpinGuard<'a> {
    lock: &'a SpinLock,
}

impl Drop for SpinGuard<'_> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

#[derive(Clone, Copy)]
struct CacheMeta {
    obj_size: u16,
    partial_head: i16,
}

impl CacheMeta {
    const fn empty() -> Self {
        Self {
            obj_size: 0,
            partial_head: NONE_I16,
        }
    }
}

#[derive(Clone, Copy)]
struct PageMeta {
    kind: u8,
    order: u8,
    cache: u8,
    _pad: u8,
    next: i16,
    prev: i16,
    head: u16,
    free_obj: u16,
    inuse: u16,
    total: u16,
}

impl PageMeta {
    const fn empty() -> Self {
        Self {
            kind: PAGE_KIND_UNUSED,
            order: 0,
            cache: 0,
            _pad: 0,
            next: NONE_I16,
            prev: NONE_I16,
            head: 0,
            free_obj: NONE_U16,
            inuse: 0,
            total: 0,
        }
    }
}

struct AllocState {
    initialized: bool,
    heap_base: KernelVa,
    heap_pages: usize,
    free_heads: [i16; NUM_ORDERS],
    pages: [PageMeta; MAX_PAGES],
    caches: [CacheMeta; NUM_CACHES],
    stats: KmallocStats,
    alloc_fail_precheck: u64,
    alloc_fail_small_oom: u64,
    alloc_fail_large_oom: u64,
    alloc_fail_corruption: u64,
    invalid_free_bad_ptr: u64,
    invalid_free_double: u64,
    small_alloc_by_cache: [u64; NUM_CACHES],
    small_free_by_cache: [u64; NUM_CACHES],
    large_alloc_by_order: [u64; NUM_ORDERS],
}

impl AllocState {
    const fn new() -> Self {
        Self {
            initialized: false,
            heap_base: KernelVa::new(0),
            heap_pages: 0,
            free_heads: [NONE_I16; NUM_ORDERS],
            pages: [const { PageMeta::empty() }; MAX_PAGES],
            caches: [const { CacheMeta::empty() }; NUM_CACHES],
            stats: KmallocStats::new(),
            alloc_fail_precheck: 0,
            alloc_fail_small_oom: 0,
            alloc_fail_large_oom: 0,
            alloc_fail_corruption: 0,
            invalid_free_bad_ptr: 0,
            invalid_free_double: 0,
            small_alloc_by_cache: [0; NUM_CACHES],
            small_free_by_cache: [0; NUM_CACHES],
            large_alloc_by_order: [0; NUM_ORDERS],
        }
    }

    fn init(&mut self, heap_base: KernelVa, heap_size: usize) {
        self.initialized = false;
        self.heap_base = heap_base;
        self.heap_pages = core::cmp::min(MAX_PAGES, heap_size / PAGE_SIZE);
        self.free_heads = [NONE_I16; NUM_ORDERS];

        let mut i = 0usize;
        while i < MAX_PAGES {
            self.pages[i] = PageMeta::empty();
            i += 1;
        }

        let mut c = 0usize;
        while c < NUM_CACHES {
            self.caches[c].obj_size = CACHE_SIZES[c];
            self.caches[c].partial_head = NONE_I16;
            c += 1;
        }
        self.stats = KmallocStats::new();
        self.alloc_fail_precheck = 0;
        self.alloc_fail_small_oom = 0;
        self.alloc_fail_large_oom = 0;
        self.alloc_fail_corruption = 0;
        self.invalid_free_bad_ptr = 0;
        self.invalid_free_double = 0;
        self.small_alloc_by_cache = [0; NUM_CACHES];
        self.small_free_by_cache = [0; NUM_CACHES];
        self.large_alloc_by_order = [0; NUM_ORDERS];

        // Build buddy free lists from available pages.
        let mut idx = 0usize;
        let mut remain = self.heap_pages;
        while remain != 0 {
            let mut order = MAX_ORDER;
            while order > 0 && (1usize << order) > remain {
                order -= 1;
            }
            self.free_list_insert(order, idx);
            idx += 1usize << order;
            remain -= 1usize << order;
        }

        self.initialized = true;
    }

    fn page_addr(&self, page_idx: usize) -> KernelVa {
        KernelVa::new(self.heap_base.get() + (page_idx * PAGE_SIZE) as u64)
    }

    fn ptr_to_page(&self, ptr: usize) -> Option<usize> {
        let heap_base = self.heap_base.get() as usize;
        if ptr < heap_base {
            return None;
        }
        let off = ptr - heap_base;
        let idx = off / PAGE_SIZE;
        if idx >= self.heap_pages {
            return None;
        }
        Some(idx)
    }

    #[inline]
    fn mark_invalid_free_bad_ptr(&mut self) {
        self.stats.invalid_frees = self.stats.invalid_frees.saturating_add(1);
        self.invalid_free_bad_ptr = self.invalid_free_bad_ptr.saturating_add(1);
    }

    #[inline]
    fn mark_invalid_free_double(&mut self) {
        self.stats.invalid_frees = self.stats.invalid_frees.saturating_add(1);
        self.invalid_free_double = self.invalid_free_double.saturating_add(1);
    }

    fn mark_block_unused(&mut self, idx: usize, order: usize) {
        let n = 1usize << order;
        let mut i = 0usize;
        while i < n {
            self.pages[idx + i] = PageMeta::empty();
            i += 1;
        }
    }

    fn mark_free_block(&mut self, idx: usize, order: usize) {
        self.pages[idx] = PageMeta {
            kind: PAGE_KIND_FREE_HEAD,
            order: order as u8,
            cache: 0,
            _pad: 0,
            next: NONE_I16,
            prev: NONE_I16,
            head: idx as u16,
            free_obj: NONE_U16,
            inuse: 0,
            total: 0,
        };
        let n = 1usize << order;
        let mut i = 1usize;
        while i < n {
            self.pages[idx + i] = PageMeta {
                kind: PAGE_KIND_FREE_TAIL,
                order: order as u8,
                cache: 0,
                _pad: 0,
                next: NONE_I16,
                prev: NONE_I16,
                head: idx as u16,
                free_obj: NONE_U16,
                inuse: 0,
                total: 0,
            };
            i += 1;
        }
    }

    fn mark_large_block(&mut self, idx: usize, order: usize) {
        self.pages[idx] = PageMeta {
            kind: PAGE_KIND_LARGE_HEAD,
            order: order as u8,
            cache: 0,
            _pad: 0,
            next: NONE_I16,
            prev: NONE_I16,
            head: idx as u16,
            free_obj: NONE_U16,
            inuse: 0,
            total: 0,
        };
        let n = 1usize << order;
        let mut i = 1usize;
        while i < n {
            self.pages[idx + i] = PageMeta {
                kind: PAGE_KIND_LARGE_TAIL,
                order: order as u8,
                cache: 0,
                _pad: 0,
                next: NONE_I16,
                prev: NONE_I16,
                head: idx as u16,
                free_obj: NONE_U16,
                inuse: 0,
                total: 0,
            };
            i += 1;
        }
    }

    fn free_list_insert(&mut self, order: usize, idx: usize) {
        self.mark_free_block(idx, order);
        let head = self.free_heads[order];
        self.pages[idx].next = head;
        self.pages[idx].prev = NONE_I16;
        if head != NONE_I16 {
            self.pages[head as usize].prev = idx as i16;
        }
        self.free_heads[order] = idx as i16;
    }

    fn free_list_remove(&mut self, order: usize, idx: usize) {
        let next = self.pages[idx].next;
        let prev = self.pages[idx].prev;
        if prev != NONE_I16 {
            self.pages[prev as usize].next = next;
        } else {
            self.free_heads[order] = next;
        }
        if next != NONE_I16 {
            self.pages[next as usize].prev = prev;
        }
        self.pages[idx].next = NONE_I16;
        self.pages[idx].prev = NONE_I16;
    }

    fn buddy_alloc(&mut self, target_order: usize) -> Option<usize> {
        let mut cur = target_order;
        while cur <= MAX_ORDER {
            let head = self.free_heads[cur];
            if head != NONE_I16 {
                let idx = head as usize;
                self.free_list_remove(cur, idx);
                self.mark_block_unused(idx, cur);

                let mut split_order = cur;
                while split_order > target_order {
                    split_order -= 1;
                    let buddy_idx = idx + (1usize << split_order);
                    self.free_list_insert(split_order, buddy_idx);
                }
                return Some(idx);
            }
            cur += 1;
        }
        None
    }

    fn buddy_free(&mut self, mut idx: usize, mut order: usize) {
        self.mark_block_unused(idx, order);
        while order < MAX_ORDER {
            let buddy = idx ^ (1usize << order);
            if buddy >= self.heap_pages {
                break;
            }
            let b = self.pages[buddy];
            if b.kind != PAGE_KIND_FREE_HEAD || b.order as usize != order {
                break;
            }
            self.free_list_remove(order, buddy);
            self.mark_block_unused(buddy, order);
            if buddy < idx {
                idx = buddy;
            }
            order += 1;
        }
        self.free_list_insert(order, idx);
    }

    fn cache_add_partial(&mut self, cache_idx: usize, page_idx: usize) {
        let head = self.caches[cache_idx].partial_head;
        self.pages[page_idx].prev = NONE_I16;
        self.pages[page_idx].next = head;
        if head != NONE_I16 {
            self.pages[head as usize].prev = page_idx as i16;
        }
        self.caches[cache_idx].partial_head = page_idx as i16;
    }

    fn cache_remove_partial(&mut self, cache_idx: usize, page_idx: usize) {
        let is_head = self.caches[cache_idx].partial_head == page_idx as i16;
        let next = self.pages[page_idx].next;
        let prev = self.pages[page_idx].prev;
        if !is_head && next == NONE_I16 && prev == NONE_I16 {
            return;
        }

        if prev != NONE_I16 {
            self.pages[prev as usize].next = next;
        } else {
            self.caches[cache_idx].partial_head = next;
        }
        if next != NONE_I16 {
            self.pages[next as usize].prev = prev;
        }
        self.pages[page_idx].next = NONE_I16;
        self.pages[page_idx].prev = NONE_I16;
    }

    fn create_slab_page(&mut self, cache_idx: usize) -> Option<usize> {
        let page_idx = self.buddy_alloc(0)?;
        let obj_size = self.caches[cache_idx].obj_size as usize;
        let total = PAGE_SIZE / obj_size;
        if total == 0 || total > NONE_U16 as usize {
            self.buddy_free(page_idx, 0);
            return None;
        }

        self.pages[page_idx] = PageMeta {
            kind: PAGE_KIND_SLAB,
            order: 0,
            cache: cache_idx as u8,
            _pad: 0,
            next: NONE_I16,
            prev: NONE_I16,
            head: page_idx as u16,
            free_obj: 0,
            inuse: 0,
            total: total as u16,
        };

        let page_base = self.page_addr(page_idx).get() as usize;
        let mut i = 0usize;
        while i < total {
            let ptr = (page_base + i * obj_size) as *mut u8;
            let next = if i + 1 < total {
                (i + 1) as u16
            } else {
                NONE_U16
            };
            unsafe {
                (ptr as *mut u16).write_unaligned(next);
            }
            i += 1;
        }

        self.cache_add_partial(cache_idx, page_idx);
        Some(page_idx)
    }

    fn alloc_small(&mut self, cache_idx: usize) -> *mut u8 {
        let mut page_idx = self.caches[cache_idx].partial_head;
        if page_idx == NONE_I16 {
            page_idx = match self.create_slab_page(cache_idx) {
                Some(idx) => idx as i16,
                None => {
                    self.alloc_fail_small_oom = self.alloc_fail_small_oom.saturating_add(1);
                    return null_mut();
                }
            };
        }

        let pidx = page_idx as usize;
        let obj_size = self.caches[cache_idx].obj_size as usize;
        let obj_idx = self.pages[pidx].free_obj;
        let total = self.pages[pidx].total;
        if obj_idx == NONE_U16 || obj_idx >= total {
            // Corrupted freelist head; quarantine this slab page from further allocs.
            self.cache_remove_partial(cache_idx, pidx);
            self.pages[pidx].free_obj = NONE_U16;
            self.alloc_fail_corruption = self.alloc_fail_corruption.saturating_add(1);
            return null_mut();
        }

        let obj_ptr =
            (self.page_addr(pidx).get() as usize + obj_idx as usize * obj_size) as *mut u8;
        let next = unsafe { (obj_ptr as *const u16).read_unaligned() };
        if next != NONE_U16 && next >= total {
            // Corrupted next pointer; stop using this slab page for allocation.
            self.cache_remove_partial(cache_idx, pidx);
            self.pages[pidx].free_obj = NONE_U16;
            self.alloc_fail_corruption = self.alloc_fail_corruption.saturating_add(1);
            return null_mut();
        }
        self.pages[pidx].free_obj = next;
        self.pages[pidx].inuse = self.pages[pidx].inuse.saturating_add(1);
        if self.pages[pidx].free_obj == NONE_U16 {
            self.cache_remove_partial(cache_idx, pidx);
        }
        self.stats.small_allocs = self.stats.small_allocs.saturating_add(1);
        self.small_alloc_by_cache[cache_idx] =
            self.small_alloc_by_cache[cache_idx].saturating_add(1);
        obj_ptr
    }

    fn free_small(&mut self, page_idx: usize, ptr: usize) {
        let cache_idx = self.pages[page_idx].cache as usize;
        if cache_idx >= NUM_CACHES {
            self.mark_invalid_free_bad_ptr();
            return;
        }
        let obj_size = self.caches[cache_idx].obj_size as usize;
        let page_base = self.page_addr(page_idx).get() as usize;
        if ptr < page_base || ptr >= page_base + PAGE_SIZE {
            self.mark_invalid_free_bad_ptr();
            return;
        }

        let off = ptr - page_base;
        if off % obj_size != 0 {
            self.mark_invalid_free_bad_ptr();
            return;
        }
        let obj_idx = (off / obj_size) as u16;
        if obj_idx >= self.pages[page_idx].total {
            self.mark_invalid_free_bad_ptr();
            return;
        }
        if self.pages[page_idx].inuse == 0 {
            self.mark_invalid_free_bad_ptr();
            return;
        }
        match self.slab_freelist_contains(page_idx, obj_idx, obj_size) {
            Ok(true) => {
                self.mark_invalid_free_double();
                return;
            }
            Err(()) => {
                self.mark_invalid_free_bad_ptr();
                return;
            }
            Ok(false) => {}
        }

        let was_full = self.pages[page_idx].free_obj == NONE_U16;
        unsafe {
            (ptr as *mut u16).write_unaligned(self.pages[page_idx].free_obj);
        }
        self.pages[page_idx].free_obj = obj_idx;
        self.pages[page_idx].inuse -= 1;
        self.small_free_by_cache[cache_idx] = self.small_free_by_cache[cache_idx].saturating_add(1);

        if was_full {
            self.cache_add_partial(cache_idx, page_idx);
        }

        if self.pages[page_idx].inuse == 0 {
            self.cache_remove_partial(cache_idx, page_idx);
            self.mark_block_unused(page_idx, 0);
            self.buddy_free(page_idx, 0);
        }
    }

    fn slab_freelist_contains(
        &self,
        page_idx: usize,
        obj_idx: u16,
        obj_size: usize,
    ) -> Result<bool, ()> {
        let total = self.pages[page_idx].total as usize;
        if total == 0 {
            return Err(());
        }
        let page_base = self.page_addr(page_idx).get() as usize;
        let mut cur = self.pages[page_idx].free_obj;
        let mut steps = 0usize;
        while cur != NONE_U16 {
            let cur_usize = cur as usize;
            if cur_usize >= total {
                return Err(());
            }
            if cur == obj_idx {
                return Ok(true);
            }
            let cur_ptr = (page_base + cur_usize * obj_size) as *const u16;
            let next = unsafe { cur_ptr.read_unaligned() };
            if next != NONE_U16 && next as usize >= total {
                return Err(());
            }
            cur = next;
            steps += 1;
            if steps > total {
                return Err(());
            }
        }
        Ok(false)
    }

    fn pages_to_order(pages: usize) -> Option<usize> {
        if pages == 0 {
            return None;
        }
        let mut order = 0usize;
        let mut n = 1usize;
        while n < pages {
            n <<= 1;
            order += 1;
            if order > MAX_ORDER {
                return None;
            }
        }
        Some(order)
    }

    fn alloc_large(&mut self, size: usize, align: usize) -> *mut u8 {
        let needed_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        let mut order = match Self::pages_to_order(needed_pages.max(1)) {
            Some(v) => v,
            None => return null_mut(),
        };

        let align_pages = if align <= PAGE_SIZE {
            1usize
        } else {
            (align + PAGE_SIZE - 1) / PAGE_SIZE
        };
        let align_order = match Self::pages_to_order(align_pages) {
            Some(v) => v,
            None => return null_mut(),
        };
        if align_order > order {
            order = align_order;
        }

        let idx = match self.buddy_alloc(order) {
            Some(v) => v,
            None => {
                self.alloc_fail_large_oom = self.alloc_fail_large_oom.saturating_add(1);
                return null_mut();
            }
        };
        self.mark_large_block(idx, order);
        self.stats.large_allocs = self.stats.large_allocs.saturating_add(1);
        self.large_alloc_by_order[order] = self.large_alloc_by_order[order].saturating_add(1);
        self.page_addr(idx).as_mut_ptr::<u8>()
    }

    fn free_large(&mut self, page_idx: usize, ptr: usize) -> bool {
        let page_base = self.page_addr(page_idx).get() as usize;
        if ptr != page_base {
            return false;
        }
        let order = self.pages[page_idx].order as usize;
        self.mark_block_unused(page_idx, order);
        self.buddy_free(page_idx, order);
        true
    }

    fn cache_index_for(bytes: usize, align: usize) -> Option<usize> {
        let req = core::cmp::max(bytes, align.max(1));
        if req > SLAB_MAX_SIZE {
            return None;
        }
        let n = req.next_power_of_two().max(SLAB_MIN_SIZE);
        if n > SLAB_MAX_SIZE {
            return None;
        }
        Some((n.trailing_zeros() as usize) - SLAB_MIN_SHIFT)
    }

    fn alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        self.stats.alloc_calls = self.stats.alloc_calls.saturating_add(1);
        if !self.initialized || size == 0 {
            self.stats.alloc_failures = self.stats.alloc_failures.saturating_add(1);
            self.alloc_fail_precheck = self.alloc_fail_precheck.saturating_add(1);
            return null_mut();
        }
        let align = align.max(1);
        if let Some(cache_idx) = Self::cache_index_for(size, align) {
            let ptr = self.alloc_small(cache_idx);
            if ptr.is_null() {
                self.stats.alloc_failures = self.stats.alloc_failures.saturating_add(1);
            }
            return ptr;
        }
        let ptr = self.alloc_large(size, align);
        if ptr.is_null() {
            self.stats.alloc_failures = self.stats.alloc_failures.saturating_add(1);
        }
        ptr
    }

    fn free(&mut self, ptr: *mut u8) {
        self.stats.free_calls = self.stats.free_calls.saturating_add(1);
        if !self.initialized || ptr.is_null() {
            self.mark_invalid_free_bad_ptr();
            return;
        }
        let p = ptr as usize;
        let Some(page_idx) = self.ptr_to_page(p) else {
            self.mark_invalid_free_bad_ptr();
            return;
        };
        match self.pages[page_idx].kind {
            PAGE_KIND_SLAB => self.free_small(page_idx, p),
            PAGE_KIND_LARGE_HEAD => {
                if !self.free_large(page_idx, p) {
                    self.mark_invalid_free_bad_ptr();
                }
            }
            _ => {
                self.mark_invalid_free_bad_ptr();
            }
        }
    }

    fn contains(&self, ptr: *mut u8) -> bool {
        if !self.initialized || ptr.is_null() {
            return false;
        }
        self.ptr_to_page(ptr as usize).is_some()
    }

    fn free_pages_total(&self) -> usize {
        let mut total = 0usize;
        let mut order = 0usize;
        while order < NUM_ORDERS {
            total =
                total.saturating_add((self.count_free_blocks_for_order(order) as usize) << order);
            order += 1;
        }
        total
    }

    fn is_completely_free(&self) -> bool {
        self.initialized && self.free_pages_total() == self.heap_pages
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn count_free_blocks_for_order(&self, order: usize) -> u16 {
        let mut count = 0usize;
        let mut steps = 0usize;
        let mut cur = self.free_heads[order];
        while cur != NONE_I16 {
            count += 1;
            let idx = cur as usize;
            if idx >= self.heap_pages {
                return u16::MAX;
            }
            cur = self.pages[idx].next;
            steps += 1;
            if steps > self.heap_pages {
                return u16::MAX;
            }
        }
        core::cmp::min(count, u16::MAX as usize) as u16
    }

    fn snapshot(&self) -> KmallocSnapshot {
        let mut free_blocks_by_order = [0u16; NUM_ORDERS];
        let mut largest_free_order = 0u8;
        let mut free_pages_total = 0usize;
        let mut order = 0usize;
        while order < NUM_ORDERS {
            let blocks = self.count_free_blocks_for_order(order);
            free_blocks_by_order[order] = blocks;
            if blocks != 0 {
                largest_free_order = order as u8;
            }
            free_pages_total = free_pages_total.saturating_add((blocks as usize) << order);
            order += 1;
        }

        let mut partial_slabs_by_cache = [0u16; NUM_CACHES];
        let mut full_slabs_by_cache = [0u16; NUM_CACHES];
        let mut page = 0usize;
        while page < self.heap_pages {
            let meta = self.pages[page];
            if meta.kind == PAGE_KIND_SLAB {
                let cache_idx = meta.cache as usize;
                if cache_idx < NUM_CACHES {
                    if meta.free_obj == NONE_U16 {
                        full_slabs_by_cache[cache_idx] =
                            full_slabs_by_cache[cache_idx].saturating_add(1);
                    } else {
                        partial_slabs_by_cache[cache_idx] =
                            partial_slabs_by_cache[cache_idx].saturating_add(1);
                    }
                }
            }
            page += 1;
        }

        KmallocSnapshot {
            stats: self.stats,
            alloc_fail_precheck: self.alloc_fail_precheck,
            alloc_fail_small_oom: self.alloc_fail_small_oom,
            alloc_fail_large_oom: self.alloc_fail_large_oom,
            alloc_fail_corruption: self.alloc_fail_corruption,
            invalid_free_bad_ptr: self.invalid_free_bad_ptr,
            invalid_free_double: self.invalid_free_double,
            small_alloc_by_cache: self.small_alloc_by_cache,
            small_free_by_cache: self.small_free_by_cache,
            large_alloc_by_order: self.large_alloc_by_order,
            free_blocks_by_order,
            partial_slabs_by_cache,
            full_slabs_by_cache,
            largest_free_order,
            free_pages_total,
            dynamic_arena_count: 0,
            dynamic_pages_total: 0,
            dynamic_pages_peak: 0,
            dynamic_arena_grow_count: 0,
            dynamic_arena_release_count: 0,
            reclaim_runs: 0,
            reclaim_pages_released: 0,
            direct_active_allocs: 0,
            direct_pages_total: 0,
            direct_pages_peak: 0,
            direct_alloc_count: 0,
            direct_free_count: 0,
            direct_alloc_failures: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct ArenaMeta {
    active: bool,
    dynamic: bool,
    base_kva: KernelVa,
    backing_pa: PhysAddr,
    pages: usize,
}

impl ArenaMeta {
    const fn empty() -> Self {
        Self {
            active: false,
            dynamic: false,
            base_kva: KernelVa::new(0),
            backing_pa: PhysAddr::new(0),
            pages: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct ArenaRange {
    start: KernelVa,
    end: KernelVa,
    arena_idx: u8,
}

impl ArenaRange {
    const fn empty() -> Self {
        Self {
            start: KernelVa::new(0),
            end: KernelVa::new(0),
            arena_idx: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct DirectAllocMeta {
    active: bool,
    base_kva: KernelVa,
    size: usize,
    backing_pa: PhysAddr,
    pages: usize,
}

impl DirectAllocMeta {
    const fn empty() -> Self {
        Self {
            active: false,
            base_kva: KernelVa::new(0),
            size: 0,
            backing_pa: PhysAddr::new(0),
            pages: 0,
        }
    }

    fn end_kva(&self) -> KernelVa {
        KernelVa::new(self.base_kva.get().saturating_add(self.size as u64))
    }
}

enum AllocPlan {
    Ready(*mut u8),
    GrowDynamic { pages: usize },
    Direct,
}

struct KmallocManager {
    arenas: [AllocState; MAX_ARENAS],
    metas: [ArenaMeta; MAX_ARENAS],
    ranges: [ArenaRange; MAX_ARENAS],
    range_count: usize,
    alloc_hint: usize,
    dynamic_pages_total: usize,
    dynamic_pages_peak: usize,
    dynamic_arena_grow_count: u64,
    dynamic_arena_release_count: u64,
    reclaim_runs: u64,
    reclaim_pages_released: u64,
    free_ops_since_reclaim: u32,
    direct_allocs: [DirectAllocMeta; MAX_DIRECT_ALLOCS],
    direct_active_allocs: usize,
    direct_pages_total: usize,
    direct_pages_peak: usize,
    direct_alloc_count: u64,
    direct_free_count: u64,
    direct_alloc_failures: u64,
}

impl KmallocManager {
    const fn new() -> Self {
        Self {
            arenas: [const { AllocState::new() }; MAX_ARENAS],
            metas: [const { ArenaMeta::empty() }; MAX_ARENAS],
            ranges: [const { ArenaRange::empty() }; MAX_ARENAS],
            range_count: 0,
            alloc_hint: 0,
            dynamic_pages_total: 0,
            dynamic_pages_peak: 0,
            dynamic_arena_grow_count: 0,
            dynamic_arena_release_count: 0,
            reclaim_runs: 0,
            reclaim_pages_released: 0,
            free_ops_since_reclaim: 0,
            direct_allocs: [const { DirectAllocMeta::empty() }; MAX_DIRECT_ALLOCS],
            direct_active_allocs: 0,
            direct_pages_total: 0,
            direct_pages_peak: 0,
            direct_alloc_count: 0,
            direct_free_count: 0,
            direct_alloc_failures: 0,
        }
    }

    fn init(&mut self, heap_base: usize, heap_size: usize) {
        let heap_base = KernelVa::new(heap_base as u64);
        let mut i = 0usize;
        while i < MAX_ARENAS {
            self.arenas[i].reset();
            self.metas[i] = ArenaMeta::empty();
            i += 1;
        }
        self.reset_bookkeeping();

        let mut pages_left = heap_size / PAGE_SIZE;
        let mut page_cursor = 0usize;
        let mut slot = 0usize;
        while slot < MAX_ARENAS && pages_left != 0 {
            let pages = core::cmp::min(MAX_PAGES, pages_left);
            let base = KernelVa::new(heap_base.get() + (page_cursor * PAGE_SIZE) as u64);
            self.arenas[slot].init(base, pages * PAGE_SIZE);
            self.metas[slot] = ArenaMeta {
                active: true,
                dynamic: false,
                base_kva: base,
                backing_pa: PhysAddr::new(0),
                pages,
            };
            self.insert_range(
                slot,
                base,
                KernelVa::new(base.get() + (pages * PAGE_SIZE) as u64),
            );

            page_cursor += pages;
            pages_left -= pages;
            slot += 1;
        }
        self.alloc_hint = 0;
    }

    fn reset_bookkeeping(&mut self) {
        self.ranges = [const { ArenaRange::empty() }; MAX_ARENAS];
        self.range_count = 0;
        self.alloc_hint = 0;
        self.dynamic_pages_total = 0;
        self.dynamic_pages_peak = 0;
        self.dynamic_arena_grow_count = 0;
        self.dynamic_arena_release_count = 0;
        self.reclaim_runs = 0;
        self.reclaim_pages_released = 0;
        self.free_ops_since_reclaim = 0;
        self.direct_allocs = [const { DirectAllocMeta::empty() }; MAX_DIRECT_ALLOCS];
        self.direct_active_allocs = 0;
        self.direct_pages_total = 0;
        self.direct_pages_peak = 0;
        self.direct_alloc_count = 0;
        self.direct_free_count = 0;
        self.direct_alloc_failures = 0;
    }

    fn insert_range(&mut self, arena_idx: usize, start: KernelVa, end: KernelVa) {
        if self.range_count >= MAX_ARENAS || start.get() >= end.get() {
            return;
        }
        let mut pos = 0usize;
        while pos < self.range_count && self.ranges[pos].start.get() < start.get() {
            pos += 1;
        }
        let mut i = self.range_count;
        while i > pos {
            self.ranges[i] = self.ranges[i - 1];
            i -= 1;
        }
        self.ranges[pos] = ArenaRange {
            start,
            end,
            arena_idx: arena_idx as u8,
        };
        self.range_count += 1;
    }

    fn remove_range(&mut self, arena_idx: usize) {
        let mut pos = 0usize;
        while pos < self.range_count {
            if self.ranges[pos].arena_idx as usize == arena_idx {
                break;
            }
            pos += 1;
        }
        if pos >= self.range_count {
            return;
        }
        while pos + 1 < self.range_count {
            self.ranges[pos] = self.ranges[pos + 1];
            pos += 1;
        }
        self.range_count -= 1;
        self.ranges[self.range_count] = ArenaRange::empty();
    }

    fn find_arena_by_ptr(&self, ptr: usize) -> Option<usize> {
        if self.range_count == 0 {
            return None;
        }
        let ptr = KernelVa::new(ptr as u64);
        let mut lo = 0usize;
        let mut hi = self.range_count;
        while lo < hi {
            let mid = lo + ((hi - lo) >> 1);
            if self.ranges[mid].start.get() <= ptr.get() {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return None;
        }
        let entry = self.ranges[lo - 1];
        if ptr.get() < entry.end.get() {
            Some(entry.arena_idx as usize)
        } else {
            None
        }
    }

    fn find_free_slot(&self) -> Option<usize> {
        let mut i = 1usize;
        while i < MAX_ARENAS {
            if !self.metas[i].active {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn choose_dynamic_arena_pages(min_pages: usize) -> Option<usize> {
        if min_pages == 0 {
            return Some(DYNAMIC_MIN_ARENA_PAGES);
        }
        if min_pages > DYNAMIC_MAX_ARENA_PAGES {
            return None;
        }
        let mut pages = DYNAMIC_MIN_ARENA_PAGES;
        while pages < min_pages {
            pages <<= 1;
            if pages > DYNAMIC_MAX_ARENA_PAGES {
                return None;
            }
        }
        Some(pages)
    }

    fn plan_dynamic_growth(&self, size: usize, align: usize) -> Option<usize> {
        if self.find_free_slot().is_none() {
            return None;
        }
        let needed_pages = pages_for_bytes(size.max(align.max(1)))?;
        Self::choose_dynamic_arena_pages(needed_pages)
    }

    fn install_dynamic_arena(&mut self, pa: PhysAddr, pages: usize) -> Option<usize> {
        let slot = self.find_free_slot()?;
        let kva = crate::mm::linear_map::phys_to_kva(pa)?;
        self.arenas[slot].init(kva, pages * PAGE_SIZE);
        self.metas[slot] = ArenaMeta {
            active: true,
            dynamic: true,
            base_kva: kva,
            backing_pa: pa,
            pages,
        };
        self.insert_range(
            slot,
            kva,
            KernelVa::new(kva.get() + (pages * PAGE_SIZE) as u64),
        );
        self.dynamic_pages_total = self.dynamic_pages_total.saturating_add(pages);
        if self.dynamic_pages_total > self.dynamic_pages_peak {
            self.dynamic_pages_peak = self.dynamic_pages_total;
        }
        self.dynamic_arena_grow_count = self.dynamic_arena_grow_count.saturating_add(1);
        Some(slot)
    }

    fn detach_dynamic_arena(&mut self, idx: usize) -> PendingPhysFree {
        let meta = self.metas[idx];
        if !meta.active || !meta.dynamic {
            return PendingPhysFree::empty();
        }
        self.remove_range(idx);
        if self.alloc_hint == idx {
            self.alloc_hint = 0;
        }
        self.arenas[idx].reset();
        self.metas[idx] = ArenaMeta::empty();
        self.dynamic_pages_total = self.dynamic_pages_total.saturating_sub(meta.pages);
        self.dynamic_arena_release_count = self.dynamic_arena_release_count.saturating_add(1);
        PendingPhysFree {
            valid: true,
            pa: meta.backing_pa,
            kva: KernelVa::new(0),
            pages: meta.pages,
        }
    }

    fn push_pending_free(
        pending: &mut [PendingPhysFree; MAX_PENDING_PHYS_FREES],
        pending_count: &mut usize,
        rec: PendingPhysFree,
    ) {
        if !rec.valid || rec.pa.is_null() || *pending_count >= MAX_PENDING_PHYS_FREES {
            return;
        }
        pending[*pending_count] = rec;
        *pending_count += 1;
    }

    fn dynamic_free_pages_total(&self) -> usize {
        let mut total = 0usize;
        let mut i = 1usize;
        while i < MAX_ARENAS {
            if self.metas[i].active && self.metas[i].dynamic {
                total = total.saturating_add(self.arenas[i].free_pages_total());
            }
            i += 1;
        }
        total
    }

    fn pick_reclaim_victim(&self) -> Option<usize> {
        let mut victim = None;
        let mut victim_pages = 0usize;
        let mut i = 1usize;
        while i < MAX_ARENAS {
            if self.metas[i].active && self.metas[i].dynamic && self.arenas[i].is_completely_free()
            {
                let pages = self.metas[i].pages;
                if pages > victim_pages {
                    victim = Some(i);
                    victim_pages = pages;
                }
            }
            i += 1;
        }
        victim
    }

    fn maybe_collect_reclaim_candidates(
        &mut self,
        pending: &mut [PendingPhysFree; MAX_PENDING_PHYS_FREES],
        pending_count: &mut usize,
        force: bool,
    ) {
        let dynamic_free = self.dynamic_free_pages_total();
        if !force {
            self.free_ops_since_reclaim = self.free_ops_since_reclaim.saturating_add(1);
            let urgent = dynamic_free >= DYNAMIC_HIGH_WATER_PAGES.saturating_mul(2);
            if !urgent && self.free_ops_since_reclaim < RECLAIM_CHECK_INTERVAL_FREE_OPS {
                return;
            }
            self.free_ops_since_reclaim = 0;
        }
        if dynamic_free <= DYNAMIC_HIGH_WATER_PAGES {
            return;
        }

        self.reclaim_runs = self.reclaim_runs.saturating_add(1);
        let mut free_pages = dynamic_free;
        while free_pages > DYNAMIC_LOW_WATER_PAGES {
            let Some(idx) = self.pick_reclaim_victim() else {
                break;
            };
            let rec = self.detach_dynamic_arena(idx);
            if !rec.valid {
                break;
            }
            free_pages = free_pages.saturating_sub(rec.pages);
            self.reclaim_pages_released =
                self.reclaim_pages_released.saturating_add(rec.pages as u64);
            Self::push_pending_free(pending, pending_count, rec);
        }
    }

    fn alloc_from_existing_arenas(&mut self, size: usize, align: usize) -> *mut u8 {
        let hint = self.alloc_hint.min(MAX_ARENAS - 1);
        if self.metas[hint].active {
            let ptr = self.arenas[hint].alloc(size, align);
            if !ptr.is_null() {
                self.alloc_hint = hint;
                return ptr;
            }
        }

        let mut i = 0usize;
        while i < MAX_ARENAS {
            if i != hint && self.metas[i].active {
                let ptr = self.arenas[i].alloc(size, align);
                if !ptr.is_null() {
                    self.alloc_hint = i;
                    return ptr;
                }
            }
            i += 1;
        }
        null_mut()
    }

    fn finish_grow_and_alloc(
        &mut self,
        size: usize,
        align: usize,
        pa: PhysAddr,
        pages: usize,
        pending: &mut [PendingPhysFree; MAX_PENDING_PHYS_FREES],
        pending_count: &mut usize,
    ) -> *mut u8 {
        let Some(slot) = self.install_dynamic_arena(pa, pages) else {
            Self::push_pending_free(
                pending,
                pending_count,
                PendingPhysFree {
                    valid: true,
                    pa,
                    kva: KernelVa::new(0),
                    pages,
                },
            );
            return self.alloc_from_existing_arenas(size, align);
        };

        self.alloc_hint = slot;
        let ptr = self.arenas[slot].alloc(size, align);
        if !ptr.is_null() {
            return ptr;
        }

        let rec = self.detach_dynamic_arena(slot);
        Self::push_pending_free(pending, pending_count, rec);
        null_mut()
    }

    fn should_use_direct_path(&self, size: usize, align: usize) -> bool {
        let align = align.max(1);
        let Some(needed_pages) = pages_for_bytes(size.max(align)) else {
            return true;
        };
        if needed_pages > MAX_PAGES {
            return true;
        }
        let Some(align_pages) = pages_for_bytes(align) else {
            return true;
        };
        align_pages > MAX_PAGES
    }

    fn alloc_plan(&mut self, size: usize, align: usize) -> AllocPlan {
        if self.should_use_direct_path(size, align) {
            return AllocPlan::Direct;
        }
        let ptr = self.alloc_from_existing_arenas(size, align);
        if !ptr.is_null() {
            return AllocPlan::Ready(ptr);
        }
        match self.plan_dynamic_growth(size, align) {
            Some(pages) => AllocPlan::GrowDynamic { pages },
            None => AllocPlan::Direct,
        }
    }

    fn find_free_direct_slot(&self) -> Option<usize> {
        let mut i = 0usize;
        while i < MAX_DIRECT_ALLOCS {
            if !self.direct_allocs[i].active {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn find_direct_alloc_exact(&self, ptr: KernelVa) -> Option<usize> {
        let mut i = 0usize;
        while i < MAX_DIRECT_ALLOCS {
            let meta = self.direct_allocs[i];
            if meta.active && meta.base_kva == ptr {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn contains_direct_range(&self, ptr: KernelVa) -> bool {
        let mut i = 0usize;
        while i < MAX_DIRECT_ALLOCS {
            let meta = self.direct_allocs[i];
            if meta.active && ptr.get() >= meta.base_kva.get() && ptr.get() < meta.end_kva().get() {
                return true;
            }
            i += 1;
        }
        false
    }

    fn alloc_direct_install(
        &mut self,
        base_kva: KernelVa,
        size: usize,
        pa: PhysAddr,
        pages: usize,
    ) -> bool {
        let Some(slot) = self.find_free_direct_slot() else {
            self.direct_alloc_failures = self.direct_alloc_failures.saturating_add(1);
            return false;
        };
        self.direct_allocs[slot] = DirectAllocMeta {
            active: true,
            base_kva,
            size,
            backing_pa: pa,
            pages,
        };
        self.direct_active_allocs = self.direct_active_allocs.saturating_add(1);
        self.direct_pages_total = self.direct_pages_total.saturating_add(pages);
        if self.direct_pages_total > self.direct_pages_peak {
            self.direct_pages_peak = self.direct_pages_total;
        }
        self.direct_alloc_count = self.direct_alloc_count.saturating_add(1);
        true
    }

    fn remove_direct_alloc(&mut self, slot: usize) -> PendingPhysFree {
        if slot >= MAX_DIRECT_ALLOCS {
            return PendingPhysFree::empty();
        }
        let meta = self.direct_allocs[slot];
        if !meta.active {
            return PendingPhysFree::empty();
        }
        self.direct_allocs[slot] = DirectAllocMeta::empty();
        self.direct_active_allocs = self.direct_active_allocs.saturating_sub(1);
        self.direct_pages_total = self.direct_pages_total.saturating_sub(meta.pages);
        self.direct_free_count = self.direct_free_count.saturating_add(1);
        PendingPhysFree {
            valid: true,
            pa: meta.backing_pa,
            kva: meta.base_kva,
            pages: meta.pages,
        }
    }

    fn note_direct_alloc_failure(&mut self) {
        self.direct_alloc_failures = self.direct_alloc_failures.saturating_add(1);
    }

    fn dealloc(
        &mut self,
        ptr: *mut u8,
        pending: &mut [PendingPhysFree; MAX_PENDING_PHYS_FREES],
        pending_count: &mut usize,
    ) {
        if ptr.is_null() {
            return;
        }

        let addr = KernelVa::new(ptr as u64);
        if let Some(slot) = self.find_direct_alloc_exact(addr) {
            let rec = self.remove_direct_alloc(slot);
            Self::push_pending_free(pending, pending_count, rec);
            return;
        }

        if let Some(idx) = self.find_arena_by_ptr(addr.get() as usize) {
            self.arenas[idx].free(ptr);
            if self.metas[idx].dynamic {
                self.maybe_collect_reclaim_candidates(pending, pending_count, false);
            }
            return;
        }

        if self.contains_direct_range(addr) {
            if self.metas[0].active {
                self.arenas[0].free(ptr);
            }
            return;
        }

        // Keep invalid-free accounting behavior.
        if self.metas[0].active {
            self.arenas[0].free(ptr);
        }
    }

    fn contains(&self, ptr: *mut u8) -> bool {
        if ptr.is_null() {
            return false;
        }
        let addr = KernelVa::new(ptr as u64);
        if self.find_arena_by_ptr(addr.get() as usize).is_some() {
            return true;
        }
        self.contains_direct_range(addr)
    }

    fn stats(&self) -> KmallocStats {
        let mut out = KmallocStats::new();
        let mut i = 0usize;
        while i < MAX_ARENAS {
            if self.metas[i].active {
                let s = self.arenas[i].stats;
                out.alloc_calls = out.alloc_calls.saturating_add(s.alloc_calls);
                out.free_calls = out.free_calls.saturating_add(s.free_calls);
                out.small_allocs = out.small_allocs.saturating_add(s.small_allocs);
                out.large_allocs = out.large_allocs.saturating_add(s.large_allocs);
                out.alloc_failures = out.alloc_failures.saturating_add(s.alloc_failures);
                out.invalid_frees = out.invalid_frees.saturating_add(s.invalid_frees);
            }
            i += 1;
        }
        out.alloc_calls = out
            .alloc_calls
            .saturating_add(self.direct_alloc_count)
            .saturating_add(self.direct_alloc_failures);
        out.free_calls = out.free_calls.saturating_add(self.direct_free_count);
        out.large_allocs = out.large_allocs.saturating_add(self.direct_alloc_count);
        out.alloc_failures = out
            .alloc_failures
            .saturating_add(self.direct_alloc_failures);
        out
    }

    fn snapshot(&self) -> KmallocSnapshot {
        let mut out = KmallocSnapshot {
            stats: KmallocStats::new(),
            alloc_fail_precheck: 0,
            alloc_fail_small_oom: 0,
            alloc_fail_large_oom: 0,
            alloc_fail_corruption: 0,
            invalid_free_bad_ptr: 0,
            invalid_free_double: 0,
            small_alloc_by_cache: [0; NUM_CACHES],
            small_free_by_cache: [0; NUM_CACHES],
            large_alloc_by_order: [0; NUM_ORDERS],
            free_blocks_by_order: [0; NUM_ORDERS],
            partial_slabs_by_cache: [0; NUM_CACHES],
            full_slabs_by_cache: [0; NUM_CACHES],
            largest_free_order: 0,
            free_pages_total: 0,
            dynamic_arena_count: 0,
            dynamic_pages_total: self.dynamic_pages_total,
            dynamic_pages_peak: self.dynamic_pages_peak,
            dynamic_arena_grow_count: self.dynamic_arena_grow_count,
            dynamic_arena_release_count: self.dynamic_arena_release_count,
            reclaim_runs: self.reclaim_runs,
            reclaim_pages_released: self.reclaim_pages_released,
            direct_active_allocs: self.direct_active_allocs,
            direct_pages_total: self.direct_pages_total,
            direct_pages_peak: self.direct_pages_peak,
            direct_alloc_count: self.direct_alloc_count,
            direct_free_count: self.direct_free_count,
            direct_alloc_failures: self.direct_alloc_failures,
        };

        let mut i = 0usize;
        while i < MAX_ARENAS {
            if self.metas[i].active {
                let s = self.arenas[i].snapshot();
                out.stats.alloc_calls = out.stats.alloc_calls.saturating_add(s.stats.alloc_calls);
                out.stats.free_calls = out.stats.free_calls.saturating_add(s.stats.free_calls);
                out.stats.small_allocs =
                    out.stats.small_allocs.saturating_add(s.stats.small_allocs);
                out.stats.large_allocs =
                    out.stats.large_allocs.saturating_add(s.stats.large_allocs);
                out.stats.alloc_failures = out
                    .stats
                    .alloc_failures
                    .saturating_add(s.stats.alloc_failures);
                out.stats.invalid_frees = out
                    .stats
                    .invalid_frees
                    .saturating_add(s.stats.invalid_frees);
                out.alloc_fail_precheck = out
                    .alloc_fail_precheck
                    .saturating_add(s.alloc_fail_precheck);
                out.alloc_fail_small_oom = out
                    .alloc_fail_small_oom
                    .saturating_add(s.alloc_fail_small_oom);
                out.alloc_fail_large_oom = out
                    .alloc_fail_large_oom
                    .saturating_add(s.alloc_fail_large_oom);
                out.alloc_fail_corruption = out
                    .alloc_fail_corruption
                    .saturating_add(s.alloc_fail_corruption);
                out.invalid_free_bad_ptr = out
                    .invalid_free_bad_ptr
                    .saturating_add(s.invalid_free_bad_ptr);
                out.invalid_free_double = out
                    .invalid_free_double
                    .saturating_add(s.invalid_free_double);
                out.free_pages_total = out.free_pages_total.saturating_add(s.free_pages_total);
                if s.largest_free_order > out.largest_free_order {
                    out.largest_free_order = s.largest_free_order;
                }

                let mut c = 0usize;
                while c < NUM_CACHES {
                    out.small_alloc_by_cache[c] =
                        out.small_alloc_by_cache[c].saturating_add(s.small_alloc_by_cache[c]);
                    out.small_free_by_cache[c] =
                        out.small_free_by_cache[c].saturating_add(s.small_free_by_cache[c]);
                    out.partial_slabs_by_cache[c] =
                        out.partial_slabs_by_cache[c].saturating_add(s.partial_slabs_by_cache[c]);
                    out.full_slabs_by_cache[c] =
                        out.full_slabs_by_cache[c].saturating_add(s.full_slabs_by_cache[c]);
                    c += 1;
                }

                let mut o = 0usize;
                while o < NUM_ORDERS {
                    out.large_alloc_by_order[o] =
                        out.large_alloc_by_order[o].saturating_add(s.large_alloc_by_order[o]);
                    out.free_blocks_by_order[o] =
                        out.free_blocks_by_order[o].saturating_add(s.free_blocks_by_order[o]);
                    o += 1;
                }

                if self.metas[i].dynamic {
                    out.dynamic_arena_count = out.dynamic_arena_count.saturating_add(1);
                }
            }
            i += 1;
        }

        out.stats.alloc_calls = out
            .stats
            .alloc_calls
            .saturating_add(self.direct_alloc_count)
            .saturating_add(self.direct_alloc_failures);
        out.stats.free_calls = out.stats.free_calls.saturating_add(self.direct_free_count);
        out.stats.large_allocs = out
            .stats
            .large_allocs
            .saturating_add(self.direct_alloc_count);
        out.stats.alloc_failures = out
            .stats
            .alloc_failures
            .saturating_add(self.direct_alloc_failures);

        out
    }
}

struct GlobalKmalloc {
    lock: SpinLock,
    state: UnsafeCell<KmallocManager>,
}

unsafe impl Sync for GlobalKmalloc {}

static KMALLOC: GlobalKmalloc = GlobalKmalloc {
    lock: SpinLock::new(),
    state: UnsafeCell::new(KmallocManager::new()),
};

#[inline]
fn with_state_mut<R>(f: impl FnOnce(&mut KmallocManager) -> R) -> R {
    let _guard = KMALLOC.lock.lock();
    unsafe { f(&mut *KMALLOC.state.get()) }
}

fn drain_pending_frees(pending: &[PendingPhysFree; MAX_PENDING_PHYS_FREES], pending_count: usize) {
    let mut i = 0usize;
    while i < pending_count {
        let rec = pending[i];
        if rec.valid {
            if !rec.kva.is_null() {
                let _ = crate::mm::kernel_vm::kvunmap(rec.kva, rec.pages);
            }
            crate::mm::phys::free_pages(rec.pa, rec.pages);
        }
        i += 1;
    }
}

fn alloc_direct(size: usize, align: usize) -> *mut u8 {
    if size == 0 {
        with_state_mut(|s| s.note_direct_alloc_failure());
        return null_mut();
    }

    let Some(pages) = pages_for_bytes(size) else {
        with_state_mut(|s| s.note_direct_alloc_failure());
        return null_mut();
    };
    let Some(pa) = crate::mm::phys::alloc_pages(pages) else {
        with_state_mut(|s| s.note_direct_alloc_failure());
        return null_mut();
    };
    let Some(kva) = crate::mm::kernel_vm::kvmap_pages(pa, pages, align.max(1)) else {
        crate::mm::phys::free_pages(pa, pages);
        with_state_mut(|s| s.note_direct_alloc_failure());
        return null_mut();
    };

    let installed = with_state_mut(|s| s.alloc_direct_install(kva, size, pa, pages));
    if installed {
        kva.as_mut_ptr::<u8>()
    } else {
        let _ = crate::mm::kernel_vm::kvunmap(kva, pages);
        crate::mm::phys::free_pages(pa, pages);
        null_mut()
    }
}

pub fn init(heap_base: usize, heap_size: usize) {
    with_state_mut(|s| s.init(heap_base, heap_size));
}

pub fn alloc(size: usize, align: usize) -> *mut u8 {
    let plan = {
        let _guard = KMALLOC.lock.lock();
        let state = unsafe { &mut *KMALLOC.state.get() };
        state.alloc_plan(size, align.max(1))
    };

    match plan {
        AllocPlan::Ready(ptr) => ptr,
        AllocPlan::Direct => alloc_direct(size, align),
        AllocPlan::GrowDynamic { pages } => {
            let Some(pa) = crate::mm::phys::alloc_pages(pages) else {
                return alloc_direct(size, align);
            };
            let mut pending = [const { PendingPhysFree::empty() }; MAX_PENDING_PHYS_FREES];
            let mut pending_count = 0usize;
            let ptr = {
                let _guard = KMALLOC.lock.lock();
                let state = unsafe { &mut *KMALLOC.state.get() };
                state.finish_grow_and_alloc(
                    size,
                    align.max(1),
                    pa,
                    pages,
                    &mut pending,
                    &mut pending_count,
                )
            };
            drain_pending_frees(&pending, pending_count);
            if !ptr.is_null() {
                return ptr;
            }
            alloc_direct(size, align)
        }
    }
}

pub fn dealloc(ptr: *mut u8) {
    let mut pending = [const { PendingPhysFree::empty() }; MAX_PENDING_PHYS_FREES];
    let mut pending_count = 0usize;
    {
        let _guard = KMALLOC.lock.lock();
        let state = unsafe { &mut *KMALLOC.state.get() };
        state.dealloc(ptr, &mut pending, &mut pending_count);
    }
    drain_pending_frees(&pending, pending_count);
}

pub fn reclaim_idle_dynamic() {
    let mut pending = [const { PendingPhysFree::empty() }; MAX_PENDING_PHYS_FREES];
    let mut pending_count = 0usize;
    {
        let _guard = KMALLOC.lock.lock();
        let state = unsafe { &mut *KMALLOC.state.get() };
        state.maybe_collect_reclaim_candidates(&mut pending, &mut pending_count, true);
    }
    drain_pending_frees(&pending, pending_count);
}

pub fn alloc_zeroed(size: usize, align: usize) -> *mut u8 {
    let ptr = alloc(size, align);
    if !ptr.is_null() {
        unsafe {
            core::ptr::write_bytes(ptr, 0, size);
        }
    }
    ptr
}

pub fn contains(ptr: *mut u8) -> bool {
    with_state_mut(|s| s.contains(ptr))
}

pub fn stats() -> KmallocStats {
    with_state_mut(|s| s.stats())
}

pub fn snapshot() -> KmallocSnapshot {
    with_state_mut(|s| s.snapshot())
}
