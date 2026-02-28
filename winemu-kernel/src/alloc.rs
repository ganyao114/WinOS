// kmalloc allocator wrapper for guest kernel heap.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicBool, Ordering};

extern "C" {
    static __heap_start: u8;
}

const HEAP_SIZE: usize = 4 * 1024 * 1024;
const PAGE_SIZE: usize = 4096;
const PHYS_FALLBACK_MAGIC: u64 = 0x5048_5953_4D45_4D31; // "PHYSMEM1"

static mut HEAP_BASE: usize = 0;

struct KernelBumpAllocator;

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
}

struct SpinGuard<'a> {
    lock: &'a SpinLock,
}

impl Drop for SpinGuard<'_> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

struct PhysState {
    lock: SpinLock,
    inner: UnsafeCell<crate::mm::phys::PhysAllocator>,
}

unsafe impl Sync for PhysState {}

static PHYS_STATE: PhysState = PhysState {
    lock: SpinLock::new(),
    inner: UnsafeCell::new(crate::mm::phys::PhysAllocator::new()),
};

#[repr(C)]
#[derive(Clone, Copy)]
struct PhysFallbackHeader {
    magic: u64,
    base_gpa: u64,
    user_ptr: u64,
    pages: u32,
    _reserved: u32,
}

#[global_allocator]
static GLOBAL_ALLOCATOR: KernelBumpAllocator = KernelBumpAllocator;

unsafe impl GlobalAlloc for KernelBumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        alloc(layout.size(), layout.align()).unwrap_or(core::ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        dealloc(ptr);
    }
}

#[inline]
fn with_phys_alloc_mut<R>(f: impl FnOnce(&mut crate::mm::phys::PhysAllocator) -> R) -> R {
    let _guard = PHYS_STATE.lock.lock();
    unsafe { f(&mut *PHYS_STATE.inner.get()) }
}

#[inline]
fn align_up(value: usize, align: usize) -> Option<usize> {
    if !align.is_power_of_two() {
        return None;
    }
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

#[inline]
fn pages_for_size(size: usize) -> Option<usize> {
    size.max(1)
        .checked_add(PAGE_SIZE - 1)
        .map(|n| n / PAGE_SIZE)
}

#[inline]
fn read_phys_header(ptr: *mut u8) -> Option<(PhysFallbackHeader, *mut PhysFallbackHeader)> {
    if ptr.is_null() {
        return None;
    }
    let p = ptr as usize;
    if p < size_of::<PhysFallbackHeader>() {
        return None;
    }
    let hdr_ptr = (p - size_of::<PhysFallbackHeader>()) as *mut PhysFallbackHeader;
    let hdr = unsafe { core::ptr::read_unaligned(hdr_ptr) };
    if hdr.magic != PHYS_FALLBACK_MAGIC || hdr.user_ptr != ptr as u64 || hdr.pages == 0 {
        return None;
    }
    if (hdr.base_gpa & (PAGE_SIZE as u64 - 1)) != 0 {
        return None;
    }
    let alloc_bytes = (hdr.pages as usize).checked_mul(PAGE_SIZE)?;
    let user = hdr.user_ptr as usize;
    let base = hdr.base_gpa as usize;
    let min_user = base.checked_add(size_of::<PhysFallbackHeader>())?;
    let max_user = base.checked_add(alloc_bytes)?;
    if user < min_user || user >= max_user {
        return None;
    }
    Some((hdr, hdr_ptr))
}

fn alloc_phys_fallback(size: usize, align: usize, zeroed: bool) -> Option<*mut u8> {
    let align = align.max(1).max(align_of::<PhysFallbackHeader>());
    if !align.is_power_of_two() {
        return None;
    }
    let prefix = size_of::<PhysFallbackHeader>().checked_add(align - 1)?;
    let total = size.max(1).checked_add(prefix)?;
    let pages = pages_for_size(total)?;
    if pages > u32::MAX as usize {
        return None;
    }
    let gpa = with_phys_alloc_mut(|p| p.alloc_pages(pages))?;
    let base = gpa as usize;
    let user = align_up(base.checked_add(size_of::<PhysFallbackHeader>())?, align)?;
    let hdr_ptr = (user - size_of::<PhysFallbackHeader>()) as *mut PhysFallbackHeader;
    let hdr = PhysFallbackHeader {
        magic: PHYS_FALLBACK_MAGIC,
        base_gpa: gpa,
        user_ptr: user as u64,
        pages: pages as u32,
        _reserved: 0,
    };
    unsafe {
        core::ptr::write_unaligned(hdr_ptr, hdr);
    }
    let ptr = user as *mut u8;
    if zeroed {
        unsafe {
            core::ptr::write_bytes(ptr, 0, size);
        }
    }
    Some(ptr)
}

fn dealloc_phys_fallback(ptr: *mut u8) -> bool {
    if ptr.is_null() {
        return true;
    }
    let Some((hdr, hdr_ptr)) = read_phys_header(ptr) else {
        return false;
    };
    unsafe {
        (*hdr_ptr).magic = 0;
    }
    with_phys_alloc_mut(|p| p.free_pages(hdr.base_gpa, hdr.pages as usize));
    true
}

pub fn init() {
    let base = core::ptr::addr_of!(__heap_start) as usize;
    let base = (base + 15) & !15;
    unsafe {
        HEAP_BASE = base;
    }
    crate::mm::kmalloc::init(base, HEAP_SIZE);
}

pub fn alloc(size: usize, align: usize) -> Option<*mut u8> {
    let ptr = crate::mm::kmalloc::alloc(size, align);
    if !ptr.is_null() {
        return Some(ptr);
    }
    alloc_phys_fallback(size, align, false)
}

pub fn dealloc(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    if crate::mm::kmalloc::contains(ptr) {
        crate::mm::kmalloc::dealloc(ptr);
        return;
    }
    let _ = dealloc_phys_fallback(ptr);
}

pub fn heap_end() -> u64 {
    unsafe { (HEAP_BASE + HEAP_SIZE) as u64 }
}

pub fn alloc_zeroed(size: usize, align: usize) -> Option<*mut u8> {
    let ptr = crate::mm::kmalloc::alloc_zeroed(size, align);
    if !ptr.is_null() {
        return Some(ptr);
    }
    alloc_phys_fallback(size, align, true)
}
