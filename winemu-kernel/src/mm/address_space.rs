use crate::arch::mmu::{self, PageTableEntryKind, UserDescLevel};
use crate::nt::constants::PAGE_SIZE_4K;

const PAGE_TABLE_ENTRIES: usize = mmu::PAGE_TABLE_ENTRIES;
const PAGE_MASK_4K: u64 = !(PAGE_SIZE_4K - 1);

pub const USER_VA_BASE: u64 = 0x7000_0000;
pub const USER_VA_LIMIT: u64 = 0x8000_0000;
pub const USER_ACCESS_BASE: u64 = 0x4000_0000;

pub struct ProcessAddressSpace {
    ttbr0: u64,
    l0: *mut u64,
    l1: *mut u64,
    l2: *mut u64,
    l3_tables: [*mut u64; PAGE_TABLE_ENTRIES],
}

impl ProcessAddressSpace {
    pub fn new_bootstrap_clone() -> Option<Self> {
        let (src_l0, src_l1, src_l2) = crate::mm::bootstrap_user_tables();
        Self::clone_from_tables(src_l0, src_l1, src_l2)
    }

    pub fn clone_from(parent: &ProcessAddressSpace) -> Option<Self> {
        Self::clone_from_tables(
            parent.l0 as *const u64,
            parent.l1 as *const u64,
            parent.l2 as *const u64,
        )
    }

    pub fn ttbr0(&self) -> u64 {
        self.ttbr0
    }

    pub fn translate_user_va_for_access(&self, va: u64, access: u8) -> Option<u64> {
        if !is_user_accessible_va(va) {
            return None;
        }

        // SAFETY: l0 points to a valid page table and index is always within 0..512.
        let l0e = unsafe { *self.l0.add(mmu::l0_index(va)) };
        if mmu::desc_kind(l0e) != PageTableEntryKind::TableOrPage {
            return None;
        }
        let l1 = mmu::table_addr(l0e) as *const u64;
        if l1.is_null() {
            return None;
        }

        // SAFETY: l1 is decoded from a valid table descriptor and index is bounded.
        let l1e = unsafe { *l1.add(mmu::l1_index(va)) };
        match mmu::desc_kind(l1e) {
            PageTableEntryKind::Invalid => return None,
            PageTableEntryKind::Block => {
                return mmu::translate_user_desc(l1e, va, UserDescLevel::L1Block, access);
            }
            PageTableEntryKind::TableOrPage => {}
            PageTableEntryKind::Reserved => return None,
        }

        let l2 = mmu::table_addr(l1e) as *const u64;
        if l2.is_null() {
            return None;
        }
        // SAFETY: l2 is decoded from a valid table descriptor and index is bounded.
        let l2e = unsafe { *l2.add(mmu::l2_index(va)) };
        match mmu::desc_kind(l2e) {
            PageTableEntryKind::Invalid => return None,
            PageTableEntryKind::Block => {
                return mmu::translate_user_desc(l2e, va, UserDescLevel::L2Block, access);
            }
            PageTableEntryKind::TableOrPage => {}
            PageTableEntryKind::Reserved => return None,
        }

        let l3 = mmu::table_addr(l2e) as *const u64;
        if l3.is_null() {
            return None;
        }
        // SAFETY: l3 is decoded from a valid table descriptor and index is bounded.
        let l3e = unsafe { *l3.add(mmu::l3_index(va)) };
        if mmu::desc_kind(l3e) != PageTableEntryKind::TableOrPage {
            return None;
        }
        mmu::translate_user_desc(l3e, va, UserDescLevel::L3Page, access)
    }

    pub fn map_user_range(&mut self, base: u64, gpa_base: u64, size: u64, prot: u32) -> bool {
        let size = page_align_up(size);
        if !is_valid_user_range(base, size) {
            return false;
        }

        let page_count = (size / PAGE_SIZE_4K) as usize;
        let mut mapped = 0usize;
        while mapped < page_count {
            let va = base + (mapped as u64) * PAGE_SIZE_4K;
            let pa = gpa_base + (mapped as u64) * PAGE_SIZE_4K;
            if !self.map_user_page(va, pa, prot) {
                let mut rollback = 0usize;
                while rollback < mapped {
                    let unmap_va = base + (rollback as u64) * PAGE_SIZE_4K;
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

    pub fn unmap_user_range(&mut self, base: u64, size: u64) -> bool {
        let size = page_align_up(size);
        if !is_valid_user_range(base, size) {
            return false;
        }

        let page_count = (size / PAGE_SIZE_4K) as usize;
        for i in 0..page_count {
            let va = base + (i as u64) * PAGE_SIZE_4K;
            let _ = self.unmap_user_page(va);
        }

        flush_tlb_all();
        true
    }

    pub fn protect_user_range(&mut self, base: u64, size: u64, prot: u32) -> bool {
        let size = page_align_up(size);
        if !is_valid_user_range(base, size) {
            return false;
        }

        let page_count = (size / PAGE_SIZE_4K) as usize;
        for i in 0..page_count {
            let va = base + (i as u64) * PAGE_SIZE_4K;
            if !self.protect_user_page(va, prot) {
                return false;
            }
        }

        flush_tlb_all();
        true
    }

    fn clone_from_tables(
        src_l0: *const u64,
        src_l1: *const u64,
        src_l2: *const u64,
    ) -> Option<Self> {
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
        }

        let mut aspace = Self {
            ttbr0: l0 as u64,
            l0,
            l1,
            l2,
            l3_tables: [core::ptr::null_mut(); PAGE_TABLE_ENTRIES],
        };

        // SAFETY: l0/l1/l2 are freshly allocated process root page tables.
        unsafe {
            mmu::install_process_root_tables(aspace.l0, aspace.l1, aspace.l2);
        }

        if !aspace.clone_l2_child_tables() {
            return None;
        }

        Some(aspace)
    }

    fn clone_l2_child_tables(&mut self) -> bool {
        for idx in 0..PAGE_TABLE_ENTRIES {
            if l2_entry_in_user_window(idx) {
                // SAFETY: l2 is a valid page table and idx is loop-bounded.
                unsafe {
                    *self.l2.add(idx) = 0;
                }
                continue;
            }
            // SAFETY: l2 is a valid page table and idx is loop-bounded.
            let l2e = unsafe { *self.l2.add(idx) };
            if mmu::desc_kind(l2e) == PageTableEntryKind::TableOrPage {
                let src_l3 = mmu::table_addr(l2e) as *const u64;
                if src_l3.is_null() {
                    return false;
                }
                let Some(new_l3) = alloc_table() else {
                    return false;
                };
                // SAFETY: src_l3/new_l3 are valid 4KB tables and idx is in bounds.
                unsafe {
                    core::ptr::copy_nonoverlapping(src_l3, new_l3, PAGE_TABLE_ENTRIES);
                    *self.l2.add(idx) = mmu::make_table_desc(new_l3 as u64);
                }
                self.l3_tables[idx] = new_l3;
            }
        }
        true
    }

    fn map_user_page(&mut self, va: u64, pa: u64, prot: u32) -> bool {
        if !is_page_aligned(va) || !is_page_aligned(pa) || !is_valid_user_va(va) {
            return false;
        }

        let l2_idx = mmu::l2_index(va);
        if !l2_entry_in_user_window(l2_idx) {
            return false;
        }

        let Some(l3) = self.ensure_l3_table(l2_idx) else {
            return false;
        };
        let l3_idx = mmu::l3_index(va);
        let pte = mmu::build_user_pte(pa, prot);
        // SAFETY: l3 points to a live table and l3_idx is within [0, 511].
        unsafe {
            *l3.add(l3_idx) = pte;
        }
        true
    }

    fn unmap_user_page(&mut self, va: u64) -> bool {
        if !is_page_aligned(va) || !is_valid_user_va(va) {
            return false;
        }

        let l2_idx = mmu::l2_index(va);
        if !l2_entry_in_user_window(l2_idx) {
            return false;
        }

        // SAFETY: l2 points to a live table and l2_idx is within [0, 511].
        let l2e = unsafe { *self.l2.add(l2_idx) };
        if mmu::desc_kind(l2e) != PageTableEntryKind::TableOrPage {
            return true;
        }
        let l3 = mmu::table_addr(l2e) as *mut u64;
        if l3.is_null() {
            return false;
        }
        // SAFETY: l3 points to a live table and index is within [0, 511].
        unsafe {
            *l3.add(mmu::l3_index(va)) = 0;
        }
        true
    }

    fn protect_user_page(&mut self, va: u64, prot: u32) -> bool {
        if !is_page_aligned(va) || !is_valid_user_va(va) {
            return false;
        }

        let l2_idx = mmu::l2_index(va);
        if !l2_entry_in_user_window(l2_idx) {
            return false;
        }

        // SAFETY: l2 points to a live table and l2_idx is within [0, 511].
        let l2e = unsafe { *self.l2.add(l2_idx) };
        match mmu::desc_kind(l2e) {
            PageTableEntryKind::Invalid
            | PageTableEntryKind::Block
            | PageTableEntryKind::Reserved => {
                return true;
            }
            PageTableEntryKind::TableOrPage => {}
        }

        let l3 = mmu::table_addr(l2e) as *mut u64;
        if l3.is_null() {
            return true;
        }

        let idx = mmu::l3_index(va);
        // SAFETY: l3 points to a live table and idx is within [0, 511].
        let old = unsafe { *l3.add(idx) };
        if mmu::desc_kind(old) != PageTableEntryKind::TableOrPage {
            return true;
        }

        let pa = mmu::table_addr(old);
        let new_pte = mmu::build_user_pte(pa, prot);
        // SAFETY: l3 points to a live table and idx is within [0, 511].
        unsafe {
            *l3.add(idx) = new_pte;
        }
        true
    }

    fn ensure_l3_table(&mut self, l2_idx: usize) -> Option<*mut u64> {
        // SAFETY: l2 points to a live table and l2_idx is bounded by caller.
        let l2e = unsafe { *self.l2.add(l2_idx) };
        match mmu::desc_kind(l2e) {
            PageTableEntryKind::TableOrPage => {
                let ptr = mmu::table_addr(l2e) as *mut u64;
                if ptr.is_null() {
                    None
                } else {
                    Some(ptr)
                }
            }
            PageTableEntryKind::Block => self.split_l2_block(l2_idx, l2e),
            _ => self.alloc_empty_l3(l2_idx),
        }
    }

    fn alloc_empty_l3(&mut self, l2_idx: usize) -> Option<*mut u64> {
        let l3 = alloc_table()?;
        // SAFETY: l2 points to a live table and l2_idx is bounded by caller.
        unsafe {
            *self.l2.add(l2_idx) = mmu::make_table_desc(l3 as u64);
        }
        self.l3_tables[l2_idx] = l3;
        Some(l3)
    }

    fn split_l2_block(&mut self, l2_idx: usize, l2e: u64) -> Option<*mut u64> {
        let l3 = alloc_table()?;
        let block_base = mmu::table_addr(l2e);

        for i in 0..PAGE_TABLE_ENTRIES {
            let page_pa = block_base + (i as u64) * PAGE_SIZE_4K;
            // SAFETY: l3 is a freshly allocated page table and i is loop-bounded.
            unsafe {
                *l3.add(i) = mmu::split_l2_block_entry_to_l3_page(l2e, page_pa);
            }
        }

        // SAFETY: l2 points to a live table and l2_idx is bounded by caller.
        unsafe {
            *self.l2.add(l2_idx) = 0;
        }
        flush_tlb_all();
        // SAFETY: l2 points to a live table and l2_idx is bounded by caller.
        unsafe {
            *self.l2.add(l2_idx) = mmu::make_table_desc(l3 as u64);
        }
        self.l3_tables[l2_idx] = l3;
        Some(l3)
    }
}

impl Drop for ProcessAddressSpace {
    fn drop(&mut self) {
        for entry in self.l3_tables.iter_mut() {
            if !entry.is_null() {
                crate::alloc::dealloc(*entry as *mut u8);
                *entry = core::ptr::null_mut();
            }
        }
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

fn is_page_aligned(v: u64) -> bool {
    (v & (PAGE_SIZE_4K - 1)) == 0
}

fn page_align_up(v: u64) -> u64 {
    (v + (PAGE_SIZE_4K - 1)) & PAGE_MASK_4K
}

fn is_valid_user_va(va: u64) -> bool {
    va >= USER_VA_BASE && va < USER_VA_LIMIT
}

fn is_user_accessible_va(va: u64) -> bool {
    va >= USER_ACCESS_BASE && va < USER_VA_LIMIT
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

fn l2_entry_in_user_window(idx: usize) -> bool {
    mmu::l2_index_in_user_window(USER_VA_BASE, USER_VA_LIMIT, idx)
}

fn flush_tlb_all() {
    crate::arch::mmu::flush_tlb_global();
}
