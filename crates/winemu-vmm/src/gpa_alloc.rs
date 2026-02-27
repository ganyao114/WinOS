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
const MAX_ORDER: usize = 11;
/// Pool low watermark (in host pages)
const POOL_LOW_PAGES: usize = 16;
/// Pool grow batch (in host pages)
const POOL_GROW_PAGES: usize = 64;
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

    pub fn free_bytes(&self) -> usize {
        self.free_page_count * host_page_size()
    }

    fn grow_pool(&mut self) -> bool {
        let hps = host_page_size();
        let size = POOL_GROW_PAGES * hps;
        let gpa = self.next_gpa;
        if gpa + size as u64 > self.limit {
            return false;
        }

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
        self.next_gpa = gpa + size as u64;

        // Insert into buddy free lists at largest aligned orders
        let mut offset = 0u64;
        let mut remaining = POOL_GROW_PAGES;
        while remaining > 0 {
            let mut order = MAX_ORDER - 1;
            loop {
                let pages = 1usize << order;
                let block_gpa = gpa + offset;
                let aligned = (block_gpa & (order_size(order) as u64 - 1)) == 0;
                if pages <= remaining && aligned { break; }
                if order == 0 { break; }
                order -= 1;
            }
            let pages = 1usize << order;
            self.free_lists[order].insert(gpa + offset);
            self.free_page_count += pages;
            offset += order_size(order) as u64;
            remaining -= pages;
        }

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
        if order >= MAX_ORDER { return None; }

        while self.free_page_count < (1usize << order) + POOL_LOW_PAGES {
            if !self.grow_pool() { break; }
        }

        let gpa = self.alloc_order(order)?;
        let hva = self.resolve_hva(gpa, alloc_size)?;
        unsafe { std::ptr::write_bytes(hva, 0, alloc_size); }
        Some((Gpa(gpa), hva))
    }

    /// Actual allocated size (rounded up to host page) for a given request.
    pub fn alloc_size_for(&self, size: usize) -> usize {
        align_up_host(size as u64) as usize
    }

    /// Free a previously allocated region.
    /// `size` is the original requested size (must be 4KB-aligned).
    pub fn free(&mut self, gpa: u64, size: usize) -> Option<usize> {
        if size == 0 || (size & (GUEST_PAGE_SIZE - 1)) != 0 {
            return None;
        }
        let alloc_size = align_up_host(size as u64) as usize;
        let order = size_to_order(alloc_size);
        if order >= MAX_ORDER { return None; }

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
        if order + 1 >= MAX_ORDER { return None; }
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
                return Some(unsafe { chunk.hva.add(offset) });
            }
        }
        None
    }

    fn free_order(&mut self, gpa: u64, order: usize) {
        self.free_page_count += 1usize << order;
        if order + 1 < MAX_ORDER {
            if let Some(base) = self.find_chunk_base(gpa) {
                let bud = buddy_gpa(gpa, order, base);
                if self.free_lists[order].remove(&bud) {
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
                for &gpa in self.free_lists[order]
                    .range(chunk_gpa..chunk_end)
                {
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
            unsafe {
                libc::munmap(chunk.hva as *mut libc::c_void, chunk.size);
            }
            // don't increment i — next chunk shifted into this slot
        }
    }

    fn find_chunk_base(&self, gpa: u64) -> Option<u64> {
        for chunk in &self.chunks {
            if gpa >= chunk.gpa && gpa < chunk.gpa + chunk.size as u64 {
                return Some(chunk.gpa);
            }
        }
        None
    }

    /// Resolve HVA for a GPA (public, for hv_vm_map by caller).
    pub fn hva_for_gpa(&self, gpa: u64) -> Option<*mut u8> {
        self.resolve_hva(gpa, host_page_size())
    }
}