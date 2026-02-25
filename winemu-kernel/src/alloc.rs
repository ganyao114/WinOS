// 简单 bump allocator — 用于 Guest Kernel 早期堆分配
// 单线程内核，无需原子操作（LDXR/STXR 在 MMU 关闭时 fault）

extern "C" {
    static __heap_start: u8;
}

const HEAP_SIZE: usize = 4 * 1024 * 1024;

static mut HEAP_BASE: usize = 0;
static mut BUMP: usize = 0;

pub fn init() {
    let base = core::ptr::addr_of!(__heap_start) as usize;
    let base = (base + 15) & !15;
    unsafe {
        HEAP_BASE = base;
        BUMP = 0;
    }
}

pub fn alloc(size: usize, align: usize) -> Option<*mut u8> {
    unsafe {
        let base = HEAP_BASE;
        let ptr = base + BUMP;
        let aligned = (ptr + align - 1) & !(align - 1);
        let new_bump = aligned - base + size;
        if new_bump > HEAP_SIZE {
            return None;
        }
        BUMP = new_bump;
        Some(aligned as *mut u8)
    }
}

pub fn alloc_zeroed(size: usize, align: usize) -> Option<*mut u8> {
    let ptr = alloc(size, align)?;
    unsafe { core::ptr::write_bytes(ptr, 0, size); }
    Some(ptr)
}
