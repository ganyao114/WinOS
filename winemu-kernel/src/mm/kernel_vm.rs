use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::mmu::{KERNEL_VMAP_BASE, KERNEL_VMAP_LIMIT};
use crate::mm::{KernelVa, PhysAddr};
use crate::nt::constants::PAGE_SIZE_4K;

const PAGE_SIZE: usize = PAGE_SIZE_4K as usize;
const VMAP_PAGE_COUNT: usize = ((KERNEL_VMAP_LIMIT - KERNEL_VMAP_BASE) / PAGE_SIZE_4K) as usize;
const BITMAP_WORDS: usize = (VMAP_PAGE_COUNT + 63) / 64;

struct KernelVmState {
    used: [u64; BITMAP_WORDS],
}

impl KernelVmState {
    const fn new() -> Self {
        Self {
            used: [0; BITMAP_WORDS],
        }
    }
}

struct KernelVmGlobal {
    locked: AtomicBool,
    state: UnsafeCell<KernelVmState>,
}

// SAFETY: shared access to `state` is serialized by `locked`.
unsafe impl Sync for KernelVmGlobal {}

static KERNEL_VM: KernelVmGlobal = KernelVmGlobal {
    locked: AtomicBool::new(false),
    state: UnsafeCell::new(KernelVmState::new()),
};

struct KernelVmGuard;

impl Drop for KernelVmGuard {
    fn drop(&mut self) {
        KERNEL_VM.locked.store(false, Ordering::Release);
    }
}

pub fn init() {
    debug_assert!(KERNEL_VMAP_BASE < KERNEL_VMAP_LIMIT);
    debug_assert!(VMAP_PAGE_COUNT != 0);
}

pub fn kvmap_pages(pa: PhysAddr, pages: usize, align: usize) -> Option<KernelVa> {
    if pa.is_null() || pages == 0 || !is_page_aligned(pa.get()) {
        return None;
    }

    let align = normalize_alignment(align)?;
    let _guard = lock_kernel_vm();
    let state = state_mut();
    let start = find_free_range(state, pages, align)?;
    mark_range(state, start, pages, true);

    let base = page_index_to_kva(start)?;
    if crate::arch::mmu::map_kernel_pages(base.get(), pa.get(), pages) {
        Some(base)
    } else {
        mark_range(state, start, pages, false);
        None
    }
}

pub fn kvunmap(base: KernelVa, pages: usize) -> bool {
    let Some(start) = kva_to_page_index(base) else {
        return false;
    };
    if pages == 0
        || start
            .checked_add(pages)
            .is_none_or(|end| end > VMAP_PAGE_COUNT)
    {
        return false;
    }

    let _guard = lock_kernel_vm();
    if !crate::arch::mmu::unmap_kernel_pages(base.get(), pages) {
        return false;
    }

    let state = state_mut();
    mark_range(state, start, pages, false);
    true
}

pub fn contains(kva: KernelVa) -> bool {
    kva.get() >= KERNEL_VMAP_BASE && kva.get() < KERNEL_VMAP_LIMIT
}

fn normalize_alignment(align: usize) -> Option<usize> {
    let align = align.max(PAGE_SIZE);
    if !align.is_power_of_two() {
        return None;
    }
    Some(align)
}

fn page_index_to_kva(index: usize) -> Option<KernelVa> {
    let offset = (index as u64).checked_mul(PAGE_SIZE_4K)?;
    KERNEL_VMAP_BASE.checked_add(offset).map(KernelVa::new)
}

fn kva_to_page_index(kva: KernelVa) -> Option<usize> {
    if !contains(kva) || !is_page_aligned(kva.get()) {
        return None;
    }
    let offset = kva.get().checked_sub(KERNEL_VMAP_BASE)?;
    Some((offset / PAGE_SIZE_4K) as usize)
}

fn is_page_aligned(addr: u64) -> bool {
    (addr & (PAGE_SIZE_4K - 1)) == 0
}

fn find_free_range(state: &KernelVmState, pages: usize, align: usize) -> Option<usize> {
    if pages == 0 || pages > VMAP_PAGE_COUNT {
        return None;
    }

    let mut start = 0usize;
    while start
        .checked_add(pages)
        .is_some_and(|end| end <= VMAP_PAGE_COUNT)
    {
        let Some(base) = page_index_to_kva(start) else {
            return None;
        };
        if (base.get() as usize) & (align - 1) == 0 && range_is_clear(state, start, pages) {
            return Some(start);
        }
        start += 1;
    }
    None
}

fn range_is_clear(state: &KernelVmState, start: usize, pages: usize) -> bool {
    let mut i = 0usize;
    while i < pages {
        if bit_is_set(state, start + i) {
            return false;
        }
        i += 1;
    }
    true
}

fn bit_is_set(state: &KernelVmState, index: usize) -> bool {
    let word = index / 64;
    let bit = index % 64;
    (state.used[word] & (1u64 << bit)) != 0
}

fn mark_range(state: &mut KernelVmState, start: usize, pages: usize, used: bool) {
    let mut i = 0usize;
    while i < pages {
        let index = start + i;
        let word = index / 64;
        let bit = index % 64;
        let mask = 1u64 << bit;
        if used {
            state.used[word] |= mask;
        } else {
            state.used[word] &= !mask;
        }
        i += 1;
    }
}

fn lock_kernel_vm() -> KernelVmGuard {
    while KERNEL_VM
        .locked
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        spin_loop();
    }
    KernelVmGuard
}

fn state_mut() -> &'static mut KernelVmState {
    // SAFETY: `KernelVmGuard` provides exclusive access to the shared state.
    unsafe { &mut *KERNEL_VM.state.get() }
}
