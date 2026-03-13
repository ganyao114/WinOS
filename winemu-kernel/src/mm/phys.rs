// PhysAllocator — 内核侧物理页管理器
// 批量从 VMM 获取物理页，内部以 4KB 粒度管理，减少 hypercall 次数。
// 每个 chunk = 64 个 4KB 页 = 256KB，用 u64 bitmap 管理。
// no_std，固定大小数组，零堆分配。

use crate::hypercall;
use crate::mm::PhysAddr;
use crate::spin::SpinLock;

/// 每个 chunk 包含的 4KB 页数（= u64 bitmap 位数）
const CHUNK_PAGES: usize = 64;
/// 每个 chunk 的字节大小
const CHUNK_SIZE: usize = CHUNK_PAGES * 4096;
const PAGE_SIZE: u64 = 4096;
/// 最大 chunk 数。覆盖整个 guest 物理地址窗，避免人为把页分配器卡死在 16MB。
const MAX_CHUNKS: usize =
    ((crate::arch::mmu::GUEST_PHYS_LIMIT - crate::arch::mmu::GUEST_PHYS_BASE) as usize)
        / CHUNK_SIZE;
/// 低水位：空闲页低于此值触发 grow
const LOW_PAGES: usize = 16;
/// 高水位：空闲页超过此值触发 shrink
const HIGH_PAGES: usize = 128;

#[derive(Clone, Copy)]
struct PhysChunk {
    base_pa: PhysAddr,
    bitmap: u64, // 1 = free, 0 = allocated
}

impl PhysChunk {
    const fn empty() -> Self {
        Self {
            base_pa: PhysAddr::new(0),
            bitmap: 0,
        }
    }
}

pub struct PhysAllocator {
    chunks: [PhysChunk; MAX_CHUNKS],
    chunk_count: usize,
    free_page_count: usize,
}

impl PhysAllocator {
    pub const fn new() -> Self {
        Self {
            chunks: [PhysChunk::empty(); MAX_CHUNKS],
            chunk_count: 0,
            free_page_count: 0,
        }
    }

    /// Allocate a single 4KB physical page.
    pub fn alloc_page(&mut self) -> Option<PhysAddr> {
        if self.free_page_count < LOW_PAGES {
            self.grow();
        }
        for i in 0..self.chunk_count {
            let chunk = &mut self.chunks[i];
            if chunk.bitmap != 0 {
                let bit = chunk.bitmap.trailing_zeros() as u64;
                chunk.bitmap &= !(1u64 << bit);
                self.free_page_count = self.free_page_count.saturating_sub(1);
                return chunk.base_pa.checked_add(bit * PAGE_SIZE);
            }
        }
        // Pool empty even after grow attempt — try once more
        self.grow();
        for i in 0..self.chunk_count {
            let chunk = &mut self.chunks[i];
            if chunk.bitmap != 0 {
                let bit = chunk.bitmap.trailing_zeros() as u64;
                chunk.bitmap &= !(1u64 << bit);
                self.free_page_count = self.free_page_count.saturating_sub(1);
                return chunk.base_pa.checked_add(bit * PAGE_SIZE);
            }
        }
        None
    }

    /// Allocate n contiguous 4KB pages. Small requests use chunk cache;
    /// large requests bypass cache and request directly from VMM.
    /// Returns the first physical page address, or None.
    pub fn alloc_pages(&mut self, n: usize) -> Option<PhysAddr> {
        if n == 0 {
            return None;
        }
        // Large allocations bypass the chunk cache and request contiguous pages
        // directly from VMM to avoid the single-chunk (64 pages) limit.
        if n > CHUNK_PAGES {
            return self.alloc_pages_direct(n);
        }
        if n == 1 {
            return self.alloc_page();
        }

        if self.free_page_count < n + LOW_PAGES {
            self.grow();
        }

        let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
        for attempt in 0..2 {
            for i in 0..self.chunk_count {
                if let Some(bit) = find_contiguous(self.chunks[i].bitmap, n, mask) {
                    let clear_mask = mask << bit;
                    self.chunks[i].bitmap &= !clear_mask;
                    self.free_page_count = self.free_page_count.saturating_sub(n);
                    return self.chunks[i].base_pa.checked_add((bit as u64) * PAGE_SIZE);
                }
            }
            if attempt == 0 {
                self.grow();
            }
        }
        None
    }

    /// Free a single 4KB page.
    pub fn free_page(&mut self, pa: PhysAddr) {
        if (pa.get() & (PAGE_SIZE - 1)) != 0 {
            return;
        }
        if let Some((idx, bit)) = self.locate(pa) {
            let mask = 1u64 << bit;
            if (self.chunks[idx].bitmap & mask) != 0 {
                return; // double free / invalid free
            }
            self.chunks[idx].bitmap |= mask;
            self.free_page_count += 1;
            self.try_shrink();
        }
    }

    /// Free n contiguous 4KB pages starting at `pa`.
    pub fn free_pages(&mut self, pa: PhysAddr, n: usize) {
        if n == 0 || (pa.get() & (PAGE_SIZE - 1)) != 0 {
            return;
        }
        if n > CHUNK_PAGES {
            self.free_pages_direct(pa, n);
            return;
        }
        if let Some((idx, start_bit)) = self.locate(pa) {
            let start = start_bit as usize;
            if start + n > CHUNK_PAGES {
                return;
            }
            let mask = if n == CHUNK_PAGES {
                u64::MAX
            } else {
                ((1u64 << n) - 1) << start_bit
            };
            if (self.chunks[idx].bitmap & mask) != 0 {
                return; // partially already free => invalid free
            }
            self.chunks[idx].bitmap |= mask;
            self.free_page_count += n;
            self.try_shrink();
        }
    }

    /// Current free page count.
    pub fn free_count(&self) -> usize {
        self.free_page_count
    }

    /// Locate which chunk and bit index a GPA belongs to.
    fn locate(&self, pa: PhysAddr) -> Option<(usize, u32)> {
        for i in 0..self.chunk_count {
            let c = &self.chunks[i];
            if pa.get() >= c.base_pa.get() && pa.get() < c.base_pa.get() + CHUNK_SIZE as u64 {
                let bit = ((pa.get() - c.base_pa.get()) / PAGE_SIZE) as u32;
                return Some((i, bit));
            }
        }
        None
    }

    fn alloc_pages_direct(&mut self, n: usize) -> Option<PhysAddr> {
        let pages = u64::try_from(n).ok()?;
        let pa = PhysAddr::new(hypercall::alloc_phys_pages(pages));
        if pa.is_null() {
            None
        } else {
            Some(pa)
        }
    }

    fn free_pages_direct(&mut self, pa: PhysAddr, n: usize) {
        let Some(pages) = u64::try_from(n).ok() else {
            return;
        };
        let _ = hypercall::free_phys_pages(pa.get(), pages);
    }

    /// Request a new chunk from VMM via ALLOC_PHYS_PAGES hypercall.
    fn grow(&mut self) {
        if self.chunk_count >= MAX_CHUNKS {
            return;
        }
        let pa = PhysAddr::new(hypercall::alloc_phys_pages(CHUNK_PAGES as u64));
        if pa.is_null() {
            return;
        }
        let idx = self.chunk_count;
        self.chunks[idx] = PhysChunk {
            base_pa: pa,
            bitmap: u64::MAX, // all 64 pages free
        };
        self.chunk_count += 1;
        self.free_page_count += CHUNK_PAGES;
    }

    /// Return fully-free chunks to VMM when above high watermark.
    fn try_shrink(&mut self) {
        while self.free_page_count > HIGH_PAGES && self.chunk_count > 0 {
            // Find a chunk with all pages free
            let mut found = None;
            for i in 0..self.chunk_count {
                if self.chunks[i].bitmap == u64::MAX {
                    found = Some(i);
                    break;
                }
            }
            let idx = match found {
                Some(i) => i,
                None => break, // no fully-free chunk
            };
            let pa = self.chunks[idx].base_pa;
            hypercall::free_phys_pages(pa.get(), CHUNK_PAGES as u64);
            // Remove by swapping with last
            self.chunk_count -= 1;
            if idx < self.chunk_count {
                self.chunks[idx] = self.chunks[self.chunk_count];
            }
            self.free_page_count -= CHUNK_PAGES;
        }
    }
}

/// Find `n` contiguous set bits in `bitmap`. Returns starting bit index.
fn find_contiguous(bitmap: u64, n: usize, mask: u64) -> Option<u32> {
    if n > 64 {
        return None;
    }
    let limit = 64 - n;
    for shift in 0..=limit {
        let test = mask << shift;
        if bitmap & test == test {
            return Some(shift as u32);
        }
    }
    None
}

static PHYS_GLOBAL: SpinLock<PhysAllocator> = SpinLock::new(PhysAllocator::new());

#[inline]
fn with_phys_mut<R>(f: impl FnOnce(&mut PhysAllocator) -> R) -> R {
    let mut guard = PHYS_GLOBAL.lock();
    f(&mut guard)
}

pub fn alloc_pages(num_pages: usize) -> Option<PhysAddr> {
    with_phys_mut(|p| p.alloc_pages(num_pages))
}

pub fn free_pages(pa: PhysAddr, num_pages: usize) {
    with_phys_mut(|p| p.free_pages(pa, num_pages));
}

pub fn free_page_count() -> usize {
    with_phys_mut(|p| p.free_count())
}
