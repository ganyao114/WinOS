// GPA allocator — buddy system with host memory pool.
//
// Design:
//   - Minimum block = host page size (queried at runtime via sysconf)
//   - Buddy orders: 0=host_page, 1=2*host_page, ... MAX_ORDER-1
//   - Pool grows via mmap when free blocks run low
//   - Pool shrinks via munmap when free blocks exceed high watermark
//   - Buddy merge on free eliminates external fragmentation
//   - GPA space is a flat range [dynamic_base, limit)
//
// alloc(size) takes bytes, requires 4KB alignment, returns None otherwise.
// Internally rounds up to host page alignment for hv_vm_map.

use std::collections::BTreeSet;
use std::sync::OnceLock;
use winemu_core::addr::Gpa;

pub const DEFAULT_PHYS_POOL_MB: usize = 64;
pub const MIN_PHYS_POOL_MB: usize = 16;

/// Query host page size once via sysconf(_SC_PAGESIZE).
fn host_page_size() -> usize {
    static HPS: OnceLock<usize> = OnceLock::new();
    *HPS.get_or_init(|| {
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(ps > 0, "sysconf(_SC_PAGESIZE) failed");
        ps as usize
    })
}

/// Guest page size
const GUEST_PAGE_SIZE: usize = 4096;

/// Maximum buddy order
const MAX_ORDER: usize = 21;
/// Pool low watermark (in host pages)
const POOL_LOW_PAGES: usize = 16;
/// Pool grow batch order (64 host pages; must stay power-of-two)
const POOL_GROW_ORDER: usize = 6;
/// Pool high watermark — shrink when exceeded (in host pages)
const POOL_HIGH_PAGES: usize = 256;

/// Size in bytes for a given buddy order
#[inline]
fn order_size(order: usize) -> usize {
    host_page_size() << order
}

/// Minimum order that can hold `size` bytes
#[inline]
fn size_to_order(size: usize) -> usize {
    let hps = host_page_size();
    let mut order = 0;
    while (hps << order) < size {
        order += 1;
    }
    order
}

/// Buddy address for a block at `gpa` of given `order`
#[inline]
fn buddy_gpa(gpa: u64, order: usize, base: u64) -> u64 {
    let offset = gpa - base;
    base + (offset ^ (order_size(order) as u64))
}

/// Align `v` up to host page boundary
#[inline]
fn align_up_host(v: u64) -> u64 {
    let mask = host_page_size() as u64 - 1;
    (v + mask) & !mask
}

/// Align `v` down to host page boundary
#[inline]
fn align_down_host(v: u64) -> u64 {
    let mask = host_page_size() as u64 - 1;
    v & !mask
}

/// Align `v` up to a power-of-two boundary.
#[inline]
fn align_up_pow2(v: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (v + align - 1) & !(align - 1)
}

struct HostChunk {
    hva: *mut u8,
    gpa: u64,
    size: usize,
}

pub struct GpaAllocator {
    free_lists: [BTreeSet<u64>; MAX_ORDER],
    next_gpa: u64,
    limit: u64,
    chunks: Vec<HostChunk>,
    free_page_count: usize,
}

unsafe impl Send for GpaAllocator {}
unsafe impl Sync for GpaAllocator {}

impl GpaAllocator {
    pub fn new(base_gpa: u64, initial_size: u64) -> Self {
        Self {
            free_lists: Default::default(),
            next_gpa: align_up_host(base_gpa + initial_size),
            limit: base_gpa + 4 * 1024 * 1024 * 1024,
            chunks: Vec::new(),
            free_page_count: 0,
        }
    }

    pub fn with_limit(mut self, limit_gpa: u64) -> Self {
        self.limit = align_down_host(limit_gpa).max(self.next_gpa);
        self
    }

    pub fn free_bytes(&self) -> usize {
        self.free_page_count * host_page_size()
    }

    fn grow_pool(&mut self, min_order: usize) -> bool {
        let chunk_order = min_order.max(POOL_GROW_ORDER);
        if chunk_order >= MAX_ORDER {
            return false;
        }

        let size = order_size(chunk_order);
        let gpa = align_up_pow2(self.next_gpa, size as u64);
        let Some(chunk_end) = gpa.checked_add(size as u64) else {
            return false;
        };
        if chunk_end > self.limit {
            return false;
        }

        // SAFETY: We request an anonymous private mapping owned by this allocator.
        let hva = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if hva == libc::MAP_FAILED {
            return false;
        }
        let hva = hva as *mut u8;

        self.chunks.push(HostChunk { hva, gpa, size });
        self.next_gpa = chunk_end;
        self.free_lists[chunk_order].insert(gpa);
        self.free_page_count += 1usize << chunk_order;

        true
    }

    /// Allocate `size` bytes of guest physical memory.
    /// `size` must be 4KB-aligned, otherwise returns None.
    /// Internally rounds up to host page alignment for hv_vm_map.
    /// Returns (gpa, hva). Caller must call hv_vm_map.
    pub fn alloc(&mut self, size: usize) -> Option<(Gpa, *mut u8)> {
        if size == 0 || (size & (GUEST_PAGE_SIZE - 1)) != 0 {
            return None;
        }
        let alloc_size = align_up_host(size as u64) as usize;
        let order = size_to_order(alloc_size);
        if order >= MAX_ORDER {
            return None;
        }

        while self.free_page_count < (1usize << order).saturating_add(POOL_LOW_PAGES) {
            if !self.grow_pool(order) {
                break;
            }
        }

        let gpa = loop {
            if let Some(gpa) = self.alloc_order(order) {
                break gpa;
            }
            if !self.grow_pool(order) {
                return None;
            }
        };
        let hva = self.resolve_hva(gpa, alloc_size)?;
        // SAFETY: `resolve_hva` returned a valid writable mapping spanning `alloc_size`.
        unsafe { std::ptr::write_bytes(hva, 0, alloc_size) };
        Some((Gpa(gpa), hva))
    }

    /// Actual allocated size (rounded up to host page) for a given request.
    pub fn alloc_size_for(&self, size: usize) -> usize {
        align_up_host(size as u64) as usize
    }

    /// Free a previously allocated region.
    /// `size` is the original requested size (must be 4KB-aligned).
    pub fn free(&mut self, gpa: u64, size: usize) -> Option<usize> {
        if size == 0
            || (size & (GUEST_PAGE_SIZE - 1)) != 0
            || (gpa & (GUEST_PAGE_SIZE as u64 - 1)) != 0
        {
            return None;
        }
        let alloc_size = align_up_host(size as u64) as usize;
        let order = size_to_order(alloc_size);
        if order >= MAX_ORDER {
            return None;
        }
        let Some((chunk_base, chunk_size)) =
            self.find_chunk(gpa).map(|chunk| (chunk.gpa, chunk.size))
        else {
            return None;
        };
        let block_size = order_size(order) as u64;
        if ((gpa - chunk_base) & (block_size - 1)) != 0 {
            return None;
        }
        if gpa + block_size > chunk_base + chunk_size as u64 {
            return None;
        }
        if self.resolve_hva(gpa, alloc_size).is_none() {
            return None;
        }

        self.free_order(gpa, order);
        self.shrink_pool();
        Some(alloc_size)
    }

    fn alloc_order(&mut self, order: usize) -> Option<u64> {
        if let Some(&gpa) = self.free_lists[order].iter().next() {
            self.free_lists[order].remove(&gpa);
            self.free_page_count -= 1usize << order;
            return Some(gpa);
        }
        if order + 1 >= MAX_ORDER {
            return None;
        }
        let parent = self.alloc_order(order + 1)?;
        let buddy = parent + order_size(order) as u64;
        self.free_lists[order].insert(buddy);
        self.free_page_count += 1usize << order;
        Some(parent)
    }

    fn resolve_hva(&self, gpa: u64, size: usize) -> Option<*mut u8> {
        for chunk in &self.chunks {
            let end = chunk.gpa + chunk.size as u64;
            if gpa >= chunk.gpa && gpa + size as u64 <= end {
                let offset = (gpa - chunk.gpa) as usize;
                // SAFETY: `offset` is within the chunk because the bounds check above
                // guarantees `[gpa, gpa + size)` lies inside this host mapping.
                return Some(unsafe { chunk.hva.add(offset) });
            }
        }
        None
    }

    fn free_order(&mut self, gpa: u64, order: usize) {
        self.free_page_count += 1usize << order;
        if order + 1 < MAX_ORDER {
            if let Some((base, chunk_size)) =
                self.find_chunk(gpa).map(|chunk| (chunk.gpa, chunk.size))
            {
                let block_size = order_size(order) as u64;
                let chunk_end = base + chunk_size as u64;
                let bud = buddy_gpa(gpa, order, base);
                if bud >= base
                    && bud + block_size <= chunk_end
                    && self.free_lists[order].remove(&bud)
                {
                    self.free_page_count -= 1usize << order;
                    self.free_page_count -= 1usize << order;
                    self.free_order(gpa.min(bud), order + 1);
                    return;
                }
            }
        }
        self.free_lists[order].insert(gpa);
    }

    /// Release entire chunks back to the OS when free pages exceed high watermark.
    /// Only chunks where every page is free can be returned.
    fn shrink_pool(&mut self) {
        if self.free_page_count <= POOL_HIGH_PAGES {
            return;
        }
        let hps = host_page_size();
        let mut i = 0;
        while i < self.chunks.len() {
            if self.free_page_count <= POOL_HIGH_PAGES {
                break;
            }
            let chunk_gpa = self.chunks[i].gpa;
            let chunk_size = self.chunks[i].size;
            let chunk_pages = chunk_size / hps;

            // Count free pages belonging to this chunk
            let mut free_in_chunk = 0usize;
            for order in 0..MAX_ORDER {
                let blk_size = order_size(order) as u64;
                let chunk_end = chunk_gpa + chunk_size as u64;
                for &gpa in self.free_lists[order].range(chunk_gpa..chunk_end) {
                    // Block must be fully within chunk
                    if gpa + blk_size <= chunk_end {
                        free_in_chunk += 1usize << order;
                    }
                }
            }

            if free_in_chunk < chunk_pages {
                i += 1;
                continue;
            }

            // Chunk is entirely free — remove blocks from free lists
            for order in 0..MAX_ORDER {
                let blk_size = order_size(order) as u64;
                let chunk_end = chunk_gpa + chunk_size as u64;
                let in_chunk: Vec<u64> = self.free_lists[order]
                    .range(chunk_gpa..chunk_end)
                    .filter(|&&g| g + blk_size <= chunk_end)
                    .copied()
                    .collect();
                for g in in_chunk {
                    self.free_lists[order].remove(&g);
                }
            }
            self.free_page_count -= chunk_pages;

            // munmap host memory
            let chunk = self.chunks.remove(i);
            // SAFETY: `chunk.hva`/`chunk.size` originate from a successful `mmap`
            // owned by this allocator and are no longer referenced after removal.
            unsafe {
                libc::munmap(chunk.hva as *mut libc::c_void, chunk.size);
            }
            // don't increment i — next chunk shifted into this slot
        }
    }

    fn find_chunk(&self, gpa: u64) -> Option<&HostChunk> {
        self.chunks
            .iter()
            .find(|chunk| gpa >= chunk.gpa && gpa < chunk.gpa + chunk.size as u64)
    }

    /// Resolve HVA for a GPA (public, for hv_vm_map by caller).
    pub fn hva_for_gpa(&self, gpa: u64) -> Option<*mut u8> {
        self.resolve_hva(gpa, host_page_size())
    }
}
