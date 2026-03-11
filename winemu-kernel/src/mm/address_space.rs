use crate::mm::page_table_access::{self as pt, ProcessUserTables, UserTableRoot};
use crate::mm::{PhysAddr, UserVa};
use crate::nt::constants::PAGE_SIZE_4K;

const PAGE_MASK_4K: u64 = !(PAGE_SIZE_4K - 1);

pub const USER_VA_BASE: u64 = 0x7000_0000;
pub const USER_VA_LIMIT: u64 = 0x8000_0000;
pub const USER_ACCESS_BASE: u64 = 0x4000_0000;

pub struct ProcessAddressSpace {
    tables: ProcessUserTables,
}

impl ProcessAddressSpace {
    pub fn new_bootstrap_clone() -> Option<Self> {
        let tables = ProcessUserTables::new_bootstrap_clone(USER_VA_BASE, USER_VA_LIMIT)?;
        Some(Self { tables })
    }

    pub fn clone_from(parent: &ProcessAddressSpace) -> Option<Self> {
        let tables = ProcessUserTables::clone_from(&parent.tables, USER_VA_BASE, USER_VA_LIMIT)?;
        Some(Self { tables })
    }

    pub fn ttbr0(&self) -> u64 {
        self.tables.ttbr0()
    }

    pub fn translate_user_va_for_access(&self, va: UserVa, access: u8) -> Option<PhysAddr> {
        self.tables.translate_user_va_for_access(va, access)
    }

    pub fn map_user_range(
        &mut self,
        base: UserVa,
        pa_base: PhysAddr,
        size: u64,
        prot: u32,
    ) -> bool {
        let size = page_align_up(size);
        if !is_valid_user_range(base.get(), size) {
            return false;
        }

        let page_count = (size / PAGE_SIZE_4K) as usize;
        let mut mapped = 0usize;
        while mapped < page_count {
            let Some(va) = base.checked_add((mapped as u64) * PAGE_SIZE_4K) else {
                return false;
            };
            let Some(pa) = pa_base.checked_add((mapped as u64) * PAGE_SIZE_4K) else {
                return false;
            };
            if !self.map_user_page(va, pa, prot) {
                let mut rollback = 0usize;
                while rollback < mapped {
                    let Some(unmap_va) = base.checked_add((rollback as u64) * PAGE_SIZE_4K) else {
                        break;
                    };
                    let _ = self.unmap_user_page(unmap_va);
                    rollback += 1;
                }
                flush_tlb_all();
                return false;
            }
            mapped += 1;
        }

        flush_tlb_all();
        true
    }

    pub fn unmap_user_range(&mut self, base: UserVa, size: u64) -> bool {
        let size = page_align_up(size);
        if !is_valid_user_range(base.get(), size) {
            return false;
        }

        let page_count = (size / PAGE_SIZE_4K) as usize;
        for i in 0..page_count {
            let Some(va) = base.checked_add((i as u64) * PAGE_SIZE_4K) else {
                return false;
            };
            let _ = self.unmap_user_page(va);
        }

        flush_tlb_all();
        true
    }

    pub fn protect_user_range(&mut self, base: UserVa, size: u64, prot: u32) -> bool {
        let size = page_align_up(size);
        if !is_valid_user_range(base.get(), size) {
            return false;
        }

        let page_count = (size / PAGE_SIZE_4K) as usize;
        for i in 0..page_count {
            let Some(va) = base.checked_add((i as u64) * PAGE_SIZE_4K) else {
                return false;
            };
            if !self.protect_user_page(va, prot) {
                return false;
            }
        }

        flush_tlb_all();
        true
    }

    fn map_user_page(&mut self, va: UserVa, pa: PhysAddr, prot: u32) -> bool {
        if !is_page_aligned(va.get()) || !is_page_aligned(pa.get()) || !is_valid_user_va(va.get()) {
            return false;
        }

        self.tables
            .map_page(va, pa, prot, USER_VA_BASE, USER_VA_LIMIT)
    }

    fn unmap_user_page(&mut self, va: UserVa) -> bool {
        if !is_page_aligned(va.get()) || !is_valid_user_va(va.get()) {
            return false;
        }

        self.tables.clear_page(va, USER_VA_BASE, USER_VA_LIMIT)
    }

    fn protect_user_page(&mut self, va: UserVa, prot: u32) -> bool {
        if !is_page_aligned(va.get()) || !is_valid_user_va(va.get()) {
            return false;
        }

        self.tables
            .protect_page(va, prot, USER_VA_BASE, USER_VA_LIMIT)
    }
}

pub(crate) fn translate_current_user_va_for_access(va: UserVa, access: u8) -> Option<PhysAddr> {
    pt::translate_user_va(UserTableRoot::current(), va, access)
}

fn is_page_aligned(v: u64) -> bool {
    (v & (PAGE_SIZE_4K - 1)) == 0
}

fn page_align_up(v: u64) -> u64 {
    (v + (PAGE_SIZE_4K - 1)) & PAGE_MASK_4K
}

fn is_valid_user_va(va: u64) -> bool {
    va >= USER_VA_BASE && va < USER_VA_LIMIT
}

fn is_valid_user_range(base: u64, size: u64) -> bool {
    if size == 0 || !is_page_aligned(base) || !is_page_aligned(size) {
        return false;
    }
    if base < USER_VA_BASE || base >= USER_VA_LIMIT {
        return false;
    }
    let Some(end) = base.checked_add(size) else {
        return false;
    };
    end <= USER_VA_LIMIT
}

fn flush_tlb_all() {
    crate::arch::mmu::flush_tlb_global();
}
