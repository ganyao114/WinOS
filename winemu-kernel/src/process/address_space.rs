use crate::nt::constants::PAGE_SIZE_4K;

const PAGE_TABLE_ENTRIES: usize = 512;

pub struct ProcessAddressSpace {
    ttbr0: u64,
    l0: *mut u64,
    l1: *mut u64,
    l2: *mut u64,
}

impl ProcessAddressSpace {
    pub fn new_bootstrap_clone() -> Option<Self> {
        let (src_l0, src_l1, src_l2) = crate::mm::bootstrap_user_tables();
        Self::clone_from_tables(src_l0, src_l1, src_l2)
    }

    pub fn clone_from(parent: &ProcessAddressSpace) -> Option<Self> {
        Self::clone_from_tables(parent.l0 as *const u64, parent.l1 as *const u64, parent.l2 as *const u64)
    }

    pub fn ttbr0(&self) -> u64 {
        self.ttbr0
    }

    fn clone_from_tables(src_l0: *const u64, src_l1: *const u64, src_l2: *const u64) -> Option<Self> {
        let l0 = alloc_table()?;
        let l1 = match alloc_table() {
            Some(ptr) => ptr,
            None => {
                crate::alloc::dealloc(l0 as *mut u8);
                return None;
            }
        };
        let l2 = match alloc_table() {
            Some(ptr) => ptr,
            None => {
                crate::alloc::dealloc(l1 as *mut u8);
                crate::alloc::dealloc(l0 as *mut u8);
                return None;
            }
        };

        unsafe {
            core::ptr::copy_nonoverlapping(src_l0, l0, PAGE_TABLE_ENTRIES);
            core::ptr::copy_nonoverlapping(src_l1, l1, PAGE_TABLE_ENTRIES);
            core::ptr::copy_nonoverlapping(src_l2, l2, PAGE_TABLE_ENTRIES);

            *l0.add(0) = ((l1 as u64) & !0xfff) | 0b11;
            *l1.add(1) = ((l2 as u64) & !0xfff) | 0b11;
        }

        Some(Self {
            ttbr0: l0 as u64,
            l0,
            l1,
            l2,
        })
    }
}

impl Drop for ProcessAddressSpace {
    fn drop(&mut self) {
        if !self.l2.is_null() {
            crate::alloc::dealloc(self.l2 as *mut u8);
            self.l2 = core::ptr::null_mut();
        }
        if !self.l1.is_null() {
            crate::alloc::dealloc(self.l1 as *mut u8);
            self.l1 = core::ptr::null_mut();
        }
        if !self.l0.is_null() {
            crate::alloc::dealloc(self.l0 as *mut u8);
            self.l0 = core::ptr::null_mut();
        }
        self.ttbr0 = 0;
    }
}

fn alloc_table() -> Option<*mut u64> {
    crate::alloc::alloc_zeroed(PAGE_SIZE_4K as usize, PAGE_SIZE_4K as usize).map(|p| p as *mut u64)
}
