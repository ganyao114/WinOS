use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

const PAGE_SIZE: usize = 4096;
const NONE_I16: i16 = -1;
const NONE_U16: u16 = u16::MAX;

const MAX_PAGES: usize = 1024; // 4 MiB / 4 KiB
const MAX_ORDER: usize = 10; // 2^10 pages = 1024 pages
const NUM_ORDERS: usize = MAX_ORDER + 1;

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
    heap_base: usize,
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
            heap_base: 0,
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

    fn init(&mut self, heap_base: usize, heap_size: usize) {
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

    fn page_addr(&self, page_idx: usize) -> usize {
        self.heap_base + page_idx * PAGE_SIZE
    }

    fn ptr_to_page(&self, ptr: usize) -> Option<usize> {
        if ptr < self.heap_base {
            return None;
        }
        let off = ptr - self.heap_base;
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

        let page_base = self.page_addr(page_idx);
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

        let obj_ptr = (self.page_addr(pidx) + obj_idx as usize * obj_size) as *mut u8;
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
        self.small_alloc_by_cache[cache_idx] = self.small_alloc_by_cache[cache_idx].saturating_add(1);
        obj_ptr
    }

    fn free_small(&mut self, page_idx: usize, ptr: usize) {
        let cache_idx = self.pages[page_idx].cache as usize;
        if cache_idx >= NUM_CACHES {
            self.mark_invalid_free_bad_ptr();
            return;
        }
        let obj_size = self.caches[cache_idx].obj_size as usize;
        let page_base = self.page_addr(page_idx);
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
        let page_base = self.page_addr(page_idx);
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
        self.page_addr(idx) as *mut u8
    }

    fn free_large(&mut self, page_idx: usize, ptr: usize) -> bool {
        let page_base = self.page_addr(page_idx);
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
        }
    }
}

struct GlobalKmalloc {
    lock: SpinLock,
    state: UnsafeCell<AllocState>,
}

unsafe impl Sync for GlobalKmalloc {}

static KMALLOC: GlobalKmalloc = GlobalKmalloc {
    lock: SpinLock::new(),
    state: UnsafeCell::new(AllocState::new()),
};

#[inline]
fn with_state_mut<R>(f: impl FnOnce(&mut AllocState) -> R) -> R {
    let _guard = KMALLOC.lock.lock();
    unsafe { f(&mut *KMALLOC.state.get()) }
}

pub fn init(heap_base: usize, heap_size: usize) {
    with_state_mut(|s| s.init(heap_base, heap_size));
}

pub fn alloc(size: usize, align: usize) -> *mut u8 {
    with_state_mut(|s| s.alloc(size, align))
}

pub fn dealloc(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    with_state_mut(|s| s.free(ptr));
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
    with_state_mut(|s| s.stats)
}

pub fn snapshot() -> KmallocSnapshot {
    with_state_mut(|s| s.snapshot())
}
