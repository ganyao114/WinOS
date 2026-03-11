use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::mmu::{KERNEL_KMAP_BASE, KERNEL_KMAP_LIMIT};
use crate::mm::{KernelVa, PhysAddr};
use crate::nt::constants::PAGE_SIZE_4K;
use crate::sched::types::MAX_VCPUS;

const PAGE_SIZE: u64 = PAGE_SIZE_4K;
const KMAP_LOCAL_SLOTS_PER_CPU: usize = 8;
const KMAP_PAGE_COUNT: usize = ((KERNEL_KMAP_LIMIT - KERNEL_KMAP_BASE) / PAGE_SIZE_4K) as usize;

struct KmapState {
    used_masks: [u16; MAX_VCPUS],
}

impl KmapState {
    const fn new() -> Self {
        Self {
            used_masks: [0; MAX_VCPUS],
        }
    }
}

struct KmapGlobal {
    locked: AtomicBool,
    state: UnsafeCell<KmapState>,
}

// SAFETY: shared access to `state` is serialized by `locked`.
unsafe impl Sync for KmapGlobal {}

static KMAP: KmapGlobal = KmapGlobal {
    locked: AtomicBool::new(false),
    state: UnsafeCell::new(KmapState::new()),
};

struct KmapGuardInner;

impl Drop for KmapGuardInner {
    fn drop(&mut self) {
        KMAP.locked.store(false, Ordering::Release);
    }
}

pub struct KmapGuard {
    cpu: usize,
    slot: usize,
    kva: KernelVa,
    _not_send: PhantomData<*mut ()>,
}

impl KmapGuard {
    pub fn kva(&self) -> KernelVa {
        self.kva
    }

    pub fn as_ptr<T>(&self) -> *const T {
        self.kva.as_ptr()
    }

    pub fn as_mut_ptr<T>(&mut self) -> *mut T {
        self.kva.as_mut_ptr()
    }
}

impl Drop for KmapGuard {
    fn drop(&mut self) {
        let _guard = lock_kmap();
        let _ = crate::arch::mmu::unmap_kernel_pages(self.kva.get(), 1);
        let state = state_mut();
        state.used_masks[self.cpu] &= !(1u16 << self.slot);
    }
}

pub fn init() {
    debug_assert!(MAX_VCPUS * KMAP_LOCAL_SLOTS_PER_CPU <= KMAP_PAGE_COUNT);
}

pub fn kmap_local_page(pa: PhysAddr) -> Option<KmapGuard> {
    if pa.is_null() || !is_page_aligned(pa.get()) {
        return None;
    }

    let cpu = crate::sched::vcpu_id() as usize;
    if cpu >= MAX_VCPUS {
        return None;
    }

    let _guard = lock_kmap();
    let state = state_mut();
    let slot = find_free_slot(state, cpu)?;
    let kva = slot_kva(cpu, slot)?;

    state.used_masks[cpu] |= 1u16 << slot;
    if crate::arch::mmu::map_kernel_pages(kva.get(), pa.get(), 1) {
        Some(KmapGuard {
            cpu,
            slot,
            kva,
            _not_send: PhantomData,
        })
    } else {
        state.used_masks[cpu] &= !(1u16 << slot);
        None
    }
}

fn find_free_slot(state: &KmapState, cpu: usize) -> Option<usize> {
    let mut slot = 0usize;
    while slot < KMAP_LOCAL_SLOTS_PER_CPU {
        if (state.used_masks[cpu] & (1u16 << slot)) == 0 {
            return Some(slot);
        }
        slot += 1;
    }
    None
}

fn slot_kva(cpu: usize, slot: usize) -> Option<KernelVa> {
    let slot_index = cpu
        .checked_mul(KMAP_LOCAL_SLOTS_PER_CPU)?
        .checked_add(slot)?;
    if slot_index >= KMAP_PAGE_COUNT {
        return None;
    }
    let offset = (slot_index as u64).checked_mul(PAGE_SIZE)?;
    KERNEL_KMAP_BASE.checked_add(offset).map(KernelVa::new)
}

fn is_page_aligned(addr: u64) -> bool {
    (addr & (PAGE_SIZE - 1)) == 0
}

fn lock_kmap() -> KmapGuardInner {
    while KMAP
        .locked
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        spin_loop();
    }
    KmapGuardInner
}

fn state_mut() -> &'static mut KmapState {
    // SAFETY: `KmapGuardInner` provides exclusive access to the shared state.
    unsafe { &mut *KMAP.state.get() }
}
