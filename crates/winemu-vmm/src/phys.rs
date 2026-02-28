const PAGE_SIZE: u64 = 4096;

// Reserve top 64 MiB of GuestMemory for kernel physical-page hypercalls.
pub const PHYS_POOL_BASE: u64 = 0x5C00_0000;
pub const PHYS_POOL_END: u64 = 0x6000_0000;

const TOTAL_PAGES: usize = ((PHYS_POOL_END - PHYS_POOL_BASE) / PAGE_SIZE) as usize;
const BITMAP_WORDS: usize = (TOTAL_PAGES + 63) / 64;

pub struct PhysPagePool {
    bitmap: [u64; BITMAP_WORDS], // 1 = free, 0 = used
}

impl PhysPagePool {
    pub const fn new() -> Self {
        Self {
            bitmap: [u64::MAX; BITMAP_WORDS],
        }
    }

    #[inline]
    fn bit_get(&self, idx: usize) -> bool {
        let w = idx / 64;
        let b = idx % 64;
        ((self.bitmap[w] >> b) & 1) != 0
    }

    #[inline]
    fn bit_set(&mut self, idx: usize, free: bool) {
        let w = idx / 64;
        let b = idx % 64;
        if free {
            self.bitmap[w] |= 1u64 << b;
        } else {
            self.bitmap[w] &= !(1u64 << b);
        }
    }

    fn range_all_free(&self, start: usize, pages: usize) -> bool {
        let end = start + pages;
        let mut i = start;
        while i < end {
            if !self.bit_get(i) {
                return false;
            }
            i += 1;
        }
        true
    }

    fn range_all_used(&self, start: usize, pages: usize) -> bool {
        let end = start + pages;
        let mut i = start;
        while i < end {
            if self.bit_get(i) {
                return false;
            }
            i += 1;
        }
        true
    }

    fn mark_range(&mut self, start: usize, pages: usize, free: bool) {
        let end = start + pages;
        let mut i = start;
        while i < end {
            self.bit_set(i, free);
            i += 1;
        }
    }

    pub fn alloc_contiguous(&mut self, pages: usize) -> Option<u64> {
        if pages == 0 || pages > TOTAL_PAGES {
            return None;
        }
        let last = TOTAL_PAGES - pages;
        let mut start = 0usize;
        while start <= last {
            if self.range_all_free(start, pages) {
                self.mark_range(start, pages, false);
                return Some(PHYS_POOL_BASE + start as u64 * PAGE_SIZE);
            }
            start += 1;
        }
        None
    }

    pub fn free_contiguous(&mut self, gpa: u64, pages: usize) -> bool {
        if pages == 0 || (gpa & (PAGE_SIZE - 1)) != 0 {
            return false;
        }
        if gpa < PHYS_POOL_BASE || gpa >= PHYS_POOL_END {
            return false;
        }
        let start = ((gpa - PHYS_POOL_BASE) / PAGE_SIZE) as usize;
        let end = start.saturating_add(pages);
        if end > TOTAL_PAGES {
            return false;
        }
        if !self.range_all_used(start, pages) {
            return false;
        }
        self.mark_range(start, pages, true);
        true
    }
}
