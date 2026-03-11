use crate::arch::mmu::{self, PageTableEntryKind, UserDescLevel};
use crate::mm::{KernelVa, PhysAddr, UserVa};
use crate::nt::constants::PAGE_SIZE_4K;

const PAGE_TABLE_ENTRIES: usize = mmu::PAGE_TABLE_ENTRIES;
const PAGE_MASK_4K: u64 = !(PAGE_SIZE_4K - 1);

pub const USER_VA_BASE: u64 = 0x7000_0000;
pub const USER_VA_LIMIT: u64 = 0x8000_0000;
pub const USER_ACCESS_BASE: u64 = 0x4000_0000;

#[derive(Clone, Copy)]
struct TablePage {
    pa: PhysAddr,
    kva: KernelVa,
}

impl TablePage {
    const fn empty() -> Self {
        Self {
            pa: PhysAddr::new(0),
            kva: KernelVa::new(0),
        }
    }

    fn is_allocated(self) -> bool {
        !self.pa.is_null() && !self.kva.is_null()
    }
}

pub struct ProcessAddressSpace {
    ttbr0: PhysAddr,
    l0: TablePage,
    l1: TablePage,
    l2: TablePage,
    l3_tables: [TablePage; PAGE_TABLE_ENTRIES],
}

impl ProcessAddressSpace {
    pub fn new_bootstrap_clone() -> Option<Self> {
        let (src_l0, src_l1, src_l2) = crate::mm::bootstrap_user_tables();
        Self::clone_from_tables(src_l0, src_l1, src_l2)
    }

    pub fn clone_from(parent: &ProcessAddressSpace) -> Option<Self> {
        Self::clone_from_tables(
            parent.l0.kva.as_ptr::<u64>(),
            parent.l1.kva.as_ptr::<u64>(),
            parent.l2.kva.as_ptr::<u64>(),
        )
    }

    pub fn ttbr0(&self) -> u64 {
        self.ttbr0.get()
    }

    pub fn translate_user_va_for_access(&self, va: UserVa, access: u8) -> Option<PhysAddr> {
        translate_user_va_in_table(self.l0.kva, va, access)
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

    fn clone_from_tables(
        src_l0: *const u64,
        src_l1: *const u64,
        src_l2: *const u64,
    ) -> Option<Self> {
        let l0 = alloc_table()?;
        let l1 = match alloc_table() {
            Some(ptr) => ptr,
            None => {
                dealloc_table(l0);
                return None;
            }
        };
        let l2 = match alloc_table() {
            Some(ptr) => ptr,
            None => {
                dealloc_table(l1);
                dealloc_table(l0);
                return None;
            }
        };

        unsafe {
            core::ptr::copy_nonoverlapping(
                src_l0,
                l0.kva.as_mut_ptr::<u64>(),
                PAGE_TABLE_ENTRIES,
            );
            core::ptr::copy_nonoverlapping(
                src_l1,
                l1.kva.as_mut_ptr::<u64>(),
                PAGE_TABLE_ENTRIES,
            );
            core::ptr::copy_nonoverlapping(
                src_l2,
                l2.kva.as_mut_ptr::<u64>(),
                PAGE_TABLE_ENTRIES,
            );
        }

        let mut aspace = Self {
            ttbr0: l0.pa,
            l0,
            l1,
            l2,
            l3_tables: [TablePage::empty(); PAGE_TABLE_ENTRIES],
        };

        // SAFETY: l0/l1/l2 are freshly allocated process root page tables.
        unsafe {
            mmu::install_process_root_tables(
                aspace.l0.pa.get(),
                aspace.l1.pa.get(),
                aspace.l2.pa.get(),
            );
        }

        if !aspace.clone_l2_child_tables() {
            return None;
        }

        Some(aspace)
    }

    fn clone_l2_child_tables(&mut self) -> bool {
        for idx in 0..PAGE_TABLE_ENTRIES {
            if !l2_entry_in_user_window(idx) {
                continue;
            }
            // SAFETY: l2 is a valid page table and idx is loop-bounded.
            let l2e = read_table_entry(self.l2.kva, idx);
            if mmu::desc_kind(l2e) == PageTableEntryKind::TableOrPage {
                let Some(src_l3) = table_desc_kva(l2e) else {
                    return false;
                };
                let Some(new_l3) = alloc_table() else {
                    return false;
                };
                // SAFETY: src_l3/new_l3 are valid 4KB tables and idx is in bounds.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src_l3.as_ptr::<u64>(),
                        new_l3.kva.as_mut_ptr::<u64>(),
                        PAGE_TABLE_ENTRIES,
                    );
                }
                write_table_entry(self.l2.kva, idx, mmu::make_table_desc(new_l3.pa.get()));
                self.l3_tables[idx] = new_l3;
            }
        }
        true
    }

    fn map_user_page(&mut self, va: UserVa, pa: PhysAddr, prot: u32) -> bool {
        if !is_page_aligned(va.get()) || !is_page_aligned(pa.get()) || !is_valid_user_va(va.get()) {
            return false;
        }

        let l2_idx = mmu::l2_index(va.get());
        if !l2_entry_in_user_window(l2_idx) {
            return false;
        }

        let Some(l3) = self.ensure_l3_table(l2_idx) else {
            return false;
        };
        let l3_idx = mmu::l3_index(va.get());
        let pte = mmu::build_user_pte(pa.get(), prot);
        write_table_entry(l3, l3_idx, pte);
        true
    }

    fn unmap_user_page(&mut self, va: UserVa) -> bool {
        if !is_page_aligned(va.get()) || !is_valid_user_va(va.get()) {
            return false;
        }

        let l2_idx = mmu::l2_index(va.get());
        if !l2_entry_in_user_window(l2_idx) {
            return false;
        }

        // SAFETY: l2 points to a live table and l2_idx is within [0, 511].
        let l2e = read_table_entry(self.l2.kva, l2_idx);
        if mmu::desc_kind(l2e) != PageTableEntryKind::TableOrPage {
            return true;
        }
        let Some(l3) = table_desc_kva(l2e) else {
            return false;
        };
        write_table_entry(l3, mmu::l3_index(va.get()), 0);
        true
    }

    fn protect_user_page(&mut self, va: UserVa, prot: u32) -> bool {
        if !is_page_aligned(va.get()) || !is_valid_user_va(va.get()) {
            return false;
        }

        let l2_idx = mmu::l2_index(va.get());
        if !l2_entry_in_user_window(l2_idx) {
            return false;
        }

        // SAFETY: l2 points to a live table and l2_idx is within [0, 511].
        let l2e = read_table_entry(self.l2.kva, l2_idx);
        match mmu::desc_kind(l2e) {
            PageTableEntryKind::Invalid
            | PageTableEntryKind::Block
            | PageTableEntryKind::Reserved => {
                return true;
            }
            PageTableEntryKind::TableOrPage => {}
        }

        let Some(l3) = table_desc_kva(l2e) else {
            return true;
        };

        let idx = mmu::l3_index(va.get());
        // SAFETY: l3 points to a live table and idx is within [0, 511].
        let old = read_table_entry(l3, idx);
        if mmu::desc_kind(old) != PageTableEntryKind::TableOrPage {
            return true;
        }

        let pa = mmu::table_addr(old);
        let new_pte = mmu::build_user_pte(pa, prot);
        // SAFETY: l3 points to a live table and idx is within [0, 511].
        write_table_entry(l3, idx, new_pte);
        true
    }

    fn ensure_l3_table(&mut self, l2_idx: usize) -> Option<KernelVa> {
        // SAFETY: l2 points to a live table and l2_idx is bounded by caller.
        let l2e = read_table_entry(self.l2.kva, l2_idx);
        match mmu::desc_kind(l2e) {
            PageTableEntryKind::TableOrPage => table_desc_kva(l2e),
            PageTableEntryKind::Block => self.split_l2_block(l2_idx, l2e),
            _ => self.alloc_empty_l3(l2_idx),
        }
    }

    fn alloc_empty_l3(&mut self, l2_idx: usize) -> Option<KernelVa> {
        let l3 = alloc_table()?;
        // SAFETY: l2 points to a live table and l2_idx is bounded by caller.
        write_table_entry(self.l2.kva, l2_idx, mmu::make_table_desc(l3.pa.get()));
        self.l3_tables[l2_idx] = l3;
        Some(l3.kva)
    }

    fn split_l2_block(&mut self, l2_idx: usize, l2e: u64) -> Option<KernelVa> {
        let l3 = alloc_table()?;
        let block_base = mmu::table_addr(l2e);

        for i in 0..PAGE_TABLE_ENTRIES {
            let page_pa = block_base + (i as u64) * PAGE_SIZE_4K;
            // SAFETY: l3 is a freshly allocated page table and i is loop-bounded.
            write_table_entry(l3.kva, i, mmu::split_l2_block_entry_to_l3_page(l2e, page_pa));
        }

        // SAFETY: l2 points to a live table and l2_idx is bounded by caller.
        write_table_entry(self.l2.kva, l2_idx, 0);
        flush_tlb_all();
        // SAFETY: l2 points to a live table and l2_idx is bounded by caller.
        write_table_entry(self.l2.kva, l2_idx, mmu::make_table_desc(l3.pa.get()));
        self.l3_tables[l2_idx] = l3;
        Some(l3.kva)
    }
}

pub(crate) fn translate_current_user_va_for_access(va: UserVa, access: u8) -> Option<PhysAddr> {
    let ttbr0 = PhysAddr::new(mmu::current_user_table_root() & PAGE_MASK_4K);
    let l0 = crate::mm::linear_map::phys_to_kva(ttbr0)?;
    translate_user_va_in_table(l0, va, access)
}

impl Drop for ProcessAddressSpace {
    fn drop(&mut self) {
        for entry in self.l3_tables.iter_mut() {
            if entry.is_allocated() {
                dealloc_table(*entry);
                *entry = TablePage::empty();
            }
        }
        if self.l2.is_allocated() {
            dealloc_table(self.l2);
            self.l2 = TablePage::empty();
        }
        if self.l1.is_allocated() {
            dealloc_table(self.l1);
            self.l1 = TablePage::empty();
        }
        if self.l0.is_allocated() {
            dealloc_table(self.l0);
            self.l0 = TablePage::empty();
        }
        self.ttbr0 = PhysAddr::new(0);
    }
}

fn alloc_table() -> Option<TablePage> {
    let pa = crate::mm::phys::alloc_pages(1)?;
    let Some(kva) = crate::mm::linear_map::phys_to_kva(pa) else {
        crate::mm::phys::free_pages(pa, 1);
        return None;
    };
    if !crate::mm::linear_map::memset_phys(pa, 0, PAGE_SIZE_4K as usize) {
        crate::mm::phys::free_pages(pa, 1);
        return None;
    }
    Some(TablePage { pa, kva })
}

fn dealloc_table(table: TablePage) {
    crate::mm::phys::free_pages(table.pa, 1);
}

fn table_desc_kva(desc: u64) -> Option<KernelVa> {
    let raw = mmu::table_addr(desc);
    if raw == 0 {
        None
    } else {
        crate::mm::linear_map::phys_to_kva(PhysAddr::new(raw)).or(Some(KernelVa::new(raw)))
    }
}

fn read_table_entry(table: KernelVa, idx: usize) -> u64 {
    // SAFETY: caller provides a live page-table KVA and a bounded index.
    unsafe { *table.as_ptr::<u64>().add(idx) }
}

fn translate_user_va_in_table(l0: KernelVa, va: UserVa, access: u8) -> Option<PhysAddr> {
    if !is_user_accessible_va(va.get()) {
        return None;
    }

    let l0e = read_table_entry(l0, mmu::l0_index(va.get()));
    if mmu::desc_kind(l0e) != PageTableEntryKind::TableOrPage {
        return None;
    }
    let l1 = table_desc_kva(l0e)?;

    let l1e = read_table_entry(l1, mmu::l1_index(va.get()));
    match mmu::desc_kind(l1e) {
        PageTableEntryKind::Invalid => return None,
        PageTableEntryKind::Block => {
            return mmu::translate_user_desc(l1e, va.get(), UserDescLevel::L1Block, access)
                .map(PhysAddr::new);
        }
        PageTableEntryKind::TableOrPage => {}
        PageTableEntryKind::Reserved => return None,
    }

    let l2 = table_desc_kva(l1e)?;
    let l2e = read_table_entry(l2, mmu::l2_index(va.get()));
    match mmu::desc_kind(l2e) {
        PageTableEntryKind::Invalid => return None,
        PageTableEntryKind::Block => {
            return mmu::translate_user_desc(l2e, va.get(), UserDescLevel::L2Block, access)
                .map(PhysAddr::new);
        }
        PageTableEntryKind::TableOrPage => {}
        PageTableEntryKind::Reserved => return None,
    }

    let l3 = table_desc_kva(l2e)?;
    let l3e = read_table_entry(l3, mmu::l3_index(va.get()));
    if mmu::desc_kind(l3e) != PageTableEntryKind::TableOrPage {
        return None;
    }
    mmu::translate_user_desc(l3e, va.get(), UserDescLevel::L3Page, access).map(PhysAddr::new)
}

fn write_table_entry(table: KernelVa, idx: usize, value: u64) {
    // SAFETY: caller provides a live page-table KVA and a bounded index.
    unsafe {
        *table.as_mut_ptr::<u64>().add(idx) = value;
    }
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
