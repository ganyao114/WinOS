use crate::nt::constants::PAGE_SIZE_4K;

const PAGE_TABLE_ENTRIES: usize = 512;

const PAGE_MASK_4K: u64 = !(PAGE_SIZE_4K - 1);
const L2_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
const L2_BLOCK_MASK: u64 = !(L2_BLOCK_SIZE - 1);

const DESC_TYPE_MASK: u64 = 0b11;
const DESC_INVALID: u64 = 0b00;
const DESC_BLOCK: u64 = 0b01;
const DESC_TABLE_OR_PAGE: u64 = 0b11;
const TABLE_ADDR_MASK: u64 = !0xFFF;

const AP_EL1_RW: u64 = 0b00 << 6;
const AP_EL0_RW: u64 = 0b01 << 6;
const AP_EL0_RO: u64 = 0b11 << 6;

const ATTR_MASK_PAGE: u64 = (0x7 << 2) | (0x3 << 6) | (0x3 << 8) | (1 << 10) | (1 << 53) | (1 << 54);
const PTE_COMMON: u64 = (0b11 << 8) | (1 << 10); // Inner shareable + AF
const PTE_UXN: u64 = 1 << 54;
const PTE_PXN: u64 = 1 << 53;

pub const USER_VA_BASE: u64 = 0x7000_0000;
pub const USER_VA_LIMIT: u64 = 0x8000_0000;

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
        Self::clone_from_tables(parent.l0 as *const u64, parent.l1 as *const u64, parent.l2 as *const u64)
    }

    pub fn ttbr0(&self) -> u64 {
        self.ttbr0
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
        }

        let mut aspace = Self {
            ttbr0: l0 as u64,
            l0,
            l1,
            l2,
            l3_tables: [core::ptr::null_mut(); PAGE_TABLE_ENTRIES],
        };

        unsafe {
            *aspace.l0.add(0) = ((aspace.l1 as u64) & TABLE_ADDR_MASK) | DESC_TABLE_OR_PAGE;
            *aspace.l1.add(1) = ((aspace.l2 as u64) & TABLE_ADDR_MASK) | DESC_TABLE_OR_PAGE;
        }

        if !aspace.clone_l2_child_tables() {
            return None;
        }

        Some(aspace)
    }

    fn clone_l2_child_tables(&mut self) -> bool {
        for idx in 0..PAGE_TABLE_ENTRIES {
            if l2_entry_in_user_window(idx) {
                unsafe {
                    *self.l2.add(idx) = DESC_INVALID;
                }
                continue;
            }
            let l2e = unsafe { *self.l2.add(idx) };
            if (l2e & DESC_TYPE_MASK) == DESC_TABLE_OR_PAGE {
                let src_l3 = (l2e & TABLE_ADDR_MASK) as *const u64;
                if src_l3.is_null() {
                    return false;
                }
                let Some(new_l3) = alloc_table() else {
                    return false;
                };
                unsafe {
                    core::ptr::copy_nonoverlapping(src_l3, new_l3, PAGE_TABLE_ENTRIES);
                    *self.l2.add(idx) = ((new_l3 as u64) & TABLE_ADDR_MASK) | DESC_TABLE_OR_PAGE;
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

        let l2_idx = l2_index(va);
        if !l2_entry_in_user_window(l2_idx) {
            return false;
        }

        let Some(l3) = self.ensure_l3_table(l2_idx) else {
            return false;
        };
        let l3_idx = l3_index(va);
        let pte = build_user_pte(pa, prot);
        unsafe {
            *l3.add(l3_idx) = pte;
        }
        true
    }

    fn unmap_user_page(&mut self, va: u64) -> bool {
        if !is_page_aligned(va) || !is_valid_user_va(va) {
            return false;
        }

        let l2_idx = l2_index(va);
        if !l2_entry_in_user_window(l2_idx) {
            return false;
        }

        let l2e = unsafe { *self.l2.add(l2_idx) };
        if (l2e & DESC_TYPE_MASK) != DESC_TABLE_OR_PAGE {
            return true;
        }
        let l3 = (l2e & TABLE_ADDR_MASK) as *mut u64;
        if l3.is_null() {
            return false;
        }
        unsafe {
            *l3.add(l3_index(va)) = 0;
        }
        true
    }

    fn protect_user_page(&mut self, va: u64, prot: u32) -> bool {
        if !is_page_aligned(va) || !is_valid_user_va(va) {
            return false;
        }

        let l2_idx = l2_index(va);
        if !l2_entry_in_user_window(l2_idx) {
            return false;
        }

        let l2e = unsafe { *self.l2.add(l2_idx) };
        let l2_kind = l2e & DESC_TYPE_MASK;
        if l2_kind == DESC_INVALID || l2_kind == DESC_BLOCK {
            return true;
        }
        if l2_kind != DESC_TABLE_OR_PAGE {
            return true;
        }

        let l3 = (l2e & TABLE_ADDR_MASK) as *mut u64;
        if l3.is_null() {
            return true;
        }

        let idx = l3_index(va);
        let old = unsafe { *l3.add(idx) };
        if (old & DESC_TYPE_MASK) != DESC_TABLE_OR_PAGE {
            return true;
        }

        let pa = old & TABLE_ADDR_MASK;
        let new_pte = build_user_pte(pa, prot);
        unsafe {
            *l3.add(idx) = new_pte;
        }
        true
    }

    fn ensure_l3_table(&mut self, l2_idx: usize) -> Option<*mut u64> {
        let l2e = unsafe { *self.l2.add(l2_idx) };
        match l2e & DESC_TYPE_MASK {
            DESC_TABLE_OR_PAGE => {
                let ptr = (l2e & TABLE_ADDR_MASK) as *mut u64;
                if ptr.is_null() {
                    None
                } else {
                    Some(ptr)
                }
            }
            DESC_BLOCK => self.split_l2_block(l2_idx, l2e),
            _ => self.alloc_empty_l3(l2_idx),
        }
    }

    fn alloc_empty_l3(&mut self, l2_idx: usize) -> Option<*mut u64> {
        let l3 = alloc_table()?;
        unsafe {
            *self.l2.add(l2_idx) = ((l3 as u64) & TABLE_ADDR_MASK) | DESC_TABLE_OR_PAGE;
        }
        self.l3_tables[l2_idx] = l3;
        Some(l3)
    }

    fn split_l2_block(&mut self, l2_idx: usize, l2e: u64) -> Option<*mut u64> {
        let l3 = alloc_table()?;
        let block_base = l2e & L2_BLOCK_MASK;
        let attrs = l2e & ATTR_MASK_PAGE;

        for i in 0..PAGE_TABLE_ENTRIES {
            let page_pa = block_base + (i as u64) * PAGE_SIZE_4K;
            unsafe {
                *l3.add(i) = (page_pa & TABLE_ADDR_MASK) | attrs | DESC_TABLE_OR_PAGE;
            }
        }

        unsafe {
            *self.l2.add(l2_idx) = 0;
        }
        flush_tlb_all();
        unsafe {
            *self.l2.add(l2_idx) = ((l3 as u64) & TABLE_ADDR_MASK) | DESC_TABLE_OR_PAGE;
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

fn l2_index(va: u64) -> usize {
    ((va >> 21) & 0x1FF) as usize
}

fn l3_index(va: u64) -> usize {
    ((va >> 12) & 0x1FF) as usize
}

fn l2_entry_in_user_window(idx: usize) -> bool {
    let start = l2_index(USER_VA_BASE);
    let end = l2_index(USER_VA_LIMIT - 1);
    idx >= start && idx <= end
}

fn decode_nt_prot(prot: u32) -> (bool, bool, bool) {
    match prot & 0xFF {
        0x01 => (false, false, false), // PAGE_NOACCESS
        0x02 => (true, false, false),  // PAGE_READONLY
        0x04 | 0x08 => (true, true, false), // PAGE_READWRITE / WRITECOPY
        0x10 => (false, false, true), // PAGE_EXECUTE
        0x20 => (true, false, true),  // PAGE_EXECUTE_READ
        0x40 | 0x80 => (true, true, true), // PAGE_EXECUTE_READWRITE / EXECUTE_WRITECOPY
        _ => (true, true, false),
    }
}

fn build_user_pte(pa: u64, prot: u32) -> u64 {
    let (read, write, exec) = decode_nt_prot(prot);
    let mut desc = (pa & TABLE_ADDR_MASK) | PTE_COMMON | DESC_TABLE_OR_PAGE;

    if write {
        desc |= AP_EL0_RW;
    } else if read || exec {
        desc |= AP_EL0_RO;
    } else {
        desc |= AP_EL1_RW;
    }

    if !exec {
        desc |= PTE_UXN | PTE_PXN;
    }

    desc
}

fn flush_tlb_all() {
    crate::arch::mmu::dsb_ishst();
    crate::arch::mmu::tlbi_vmalle1is();
    crate::arch::mmu::dsb_ish();
    crate::arch::mmu::isb();
}
