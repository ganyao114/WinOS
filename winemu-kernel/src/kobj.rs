use crate::rust_alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::null_mut;

const DEFAULT_SLAB_BYTES: usize = 16 * 1024;

#[repr(C)]
struct FreeNode {
    next: *mut FreeNode,
}

fn align_up(v: usize, align: usize) -> usize {
    (v + align - 1) & !(align - 1)
}

pub struct SlabPool<T> {
    free_list: *mut FreeNode,
    slabs: Vec<*mut u8>,
    stride: usize,
    align: usize,
    slab_bytes: usize,
    _marker: PhantomData<T>,
}

impl<T> SlabPool<T> {
    pub fn new() -> Self {
        let align = align_of::<T>().max(align_of::<FreeNode>());
        let stride = align_up(size_of::<T>().max(size_of::<FreeNode>()), align);
        Self {
            free_list: null_mut(),
            slabs: Vec::new(),
            stride,
            align,
            slab_bytes: DEFAULT_SLAB_BYTES.max(stride),
            _marker: PhantomData,
        }
    }

    fn grow(&mut self) -> bool {
        // Defensive recovery: if allocator metadata was clobbered by a transient bug,
        // rebuild the layout from type information instead of panicking.
        if self.align == 0 || !self.align.is_power_of_two() || self.stride == 0 {
            self.align = align_of::<T>().max(align_of::<FreeNode>());
            self.stride = align_up(size_of::<T>().max(size_of::<FreeNode>()), self.align);
            if self.stride == 0 {
                return false;
            }
            self.slab_bytes = self.slab_bytes.max(self.stride).max(DEFAULT_SLAB_BYTES);
        }

        let objs = (self.slab_bytes / self.stride).max(1);
        let Some(bytes) = objs.checked_mul(self.stride) else {
            return false;
        };
        let Some(base) = crate::alloc::alloc_zeroed(bytes, self.align) else {
            return false;
        };
        if self.slabs.try_reserve(1).is_err() {
            return false;
        }
        self.slabs.push(base);

        unsafe {
            let mut i = 0usize;
            while i < objs {
                let node = base.add(i * self.stride) as *mut FreeNode;
                (*node).next = self.free_list;
                self.free_list = node;
                i += 1;
            }
        }
        true
    }

    pub fn alloc_slot(&mut self) -> Option<*mut T> {
        if self.free_list.is_null() && !self.grow() {
            return None;
        }
        let node = self.free_list;
        if node.is_null() {
            return None;
        }
        unsafe {
            self.free_list = (*node).next;
        }
        Some(node as *mut T)
    }

    pub unsafe fn free_slot(&mut self, ptr: *mut T) {
        if ptr.is_null() {
            return;
        }
        let node = ptr as *mut FreeNode;
        (*node).next = self.free_list;
        self.free_list = node;
    }
}

pub struct ObjectStore<T> {
    pool: SlabPool<T>,
    slots: Vec<*mut T>,
    free_ids: Vec<u32>,
}

impl<T> ObjectStore<T> {
    pub fn new() -> Self {
        let mut slots = Vec::new();
        let _ = slots.try_reserve(1);
        slots.push(null_mut());
        Self {
            pool: SlabPool::new(),
            slots,
            free_ids: Vec::new(),
        }
    }

    fn alloc_id(&mut self) -> Option<u32> {
        crate::hypercall::debug_u64(0xC510_0001);
        if let Some(id) = self.free_ids.pop() {
            crate::hypercall::debug_u64(0xC510_0002);
            return Some(id);
        }
        let id = self.slots.len() as u32;
        crate::hypercall::debug_u64(0xC510_0003);
        if self.slots.try_reserve(1).is_err() {
            crate::hypercall::debug_u64(0xC510_E001);
            return None;
        }
        crate::hypercall::debug_u64(0xC510_0004);
        self.slots.push(null_mut());
        crate::hypercall::debug_u64(0xC510_0005);
        Some(id)
    }

    pub fn alloc_slot_with_id(&mut self) -> Option<(u32, *mut T)> {
        crate::hypercall::debug_u64(0xC511_0001);
        let id = self.alloc_id()?;
        crate::hypercall::debug_u64(0xC511_0002);
        let Some(ptr) = self.pool.alloc_slot() else {
            crate::hypercall::debug_u64(0xC511_E001);
            return None;
        };
        crate::hypercall::debug_u64(0xC511_0003);
        self.slots[id as usize] = ptr;
        crate::hypercall::debug_u64(0xC511_0004);
        Some((id, ptr))
    }

    pub fn alloc_with(&mut self, f: impl FnOnce(u32) -> T) -> Option<u32> {
        let (id, ptr) = self.alloc_slot_with_id()?;
        unsafe {
            ptr.write(f(id));
        }
        Some(id)
    }

    pub fn get_ptr(&self, id: u32) -> *mut T {
        let idx = id as usize;
        if idx == 0 || idx >= self.slots.len() {
            return null_mut();
        }
        self.slots[idx]
    }

    pub fn contains(&self, id: u32) -> bool {
        !self.get_ptr(id).is_null()
    }

    pub fn free(&mut self, id: u32) -> bool {
        let idx = id as usize;
        if idx == 0 || idx >= self.slots.len() {
            return false;
        }
        let ptr = self.slots[idx];
        if ptr.is_null() {
            return false;
        }
        self.slots[idx] = null_mut();
        unsafe {
            core::ptr::drop_in_place(ptr);
            self.pool.free_slot(ptr);
        }
        if self.free_ids.try_reserve(1).is_ok() {
            self.free_ids.push(id);
        }
        true
    }

    pub fn for_each_live_id(&self, mut f: impl FnMut(u32)) {
        let mut i = 1usize;
        while i < self.slots.len() {
            if !self.slots[i].is_null() {
                f(i as u32);
            }
            i += 1;
        }
    }

    pub fn for_each_live_ptr(&self, mut f: impl FnMut(u32, *mut T)) {
        let mut i = 1usize;
        while i < self.slots.len() {
            let ptr = self.slots[i];
            if !ptr.is_null() {
                f(i as u32, ptr);
            }
            i += 1;
        }
    }
}
