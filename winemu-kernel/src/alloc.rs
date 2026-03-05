// kmalloc allocator wrapper for guest kernel heap.

use core::alloc::{GlobalAlloc, Layout};

extern "C" {
    static __heap_start: u8;
}

const HEAP_SIZE: usize = 4 * 1024 * 1024;

static mut HEAP_BASE: usize = 0;

struct KernelBumpAllocator;

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
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

pub fn dealloc(ptr: *mut u8) {
    crate::mm::kmalloc::dealloc(ptr);
}

pub fn heap_end() -> u64 {
    unsafe { (HEAP_BASE + HEAP_SIZE) as u64 }
}

pub fn alloc_zeroed(size: usize, align: usize) -> Option<*mut u8> {
    let ptr = crate::mm::kmalloc::alloc_zeroed(size, align);
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}
