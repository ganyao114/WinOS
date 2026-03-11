use crate::arch::mmu;
use crate::mm::page_table_access::{
    self as pt, OwnedTablePage, TablePageRef, UserPageEditor, UserTableRoot,
};
use crate::mm::{PhysAddr, UserVa};
use crate::nt::constants::PAGE_SIZE_4K;

const PAGE_TABLE_ENTRIES: usize = mmu::PAGE_TABLE_ENTRIES;
const PAGE_MASK_4K: u64 = !(PAGE_SIZE_4K - 1);

pub const USER_VA_BASE: u64 = 0x7000_0000;
pub const USER_VA_LIMIT: u64 = 0x8000_0000;
pub const USER_ACCESS_BASE: u64 = 0x4000_0000;

pub struct ProcessAddressSpace {
    ttbr0: PhysAddr,
    l0: OwnedTablePage,
    l1: OwnedTablePage,
    l2: OwnedTablePage,
    l3_tables: [OwnedTablePage; PAGE_TABLE_ENTRIES],
}

impl ProcessAddressSpace {
    pub fn new_bootstrap_clone() -> Option<Self> {
        let (src_l0, src_l1, src_l2) = crate::mm::bootstrap_user_tables();
        Self::clone_from_tables(
            TablePageRef::kernel(src_l0),
            TablePageRef::kernel(src_l1),
            TablePageRef::kernel(src_l2),
        )
    }

    pub fn clone_from(parent: &ProcessAddressSpace) -> Option<Self> {
        Self::clone_from_tables(
            parent.l0.table_ref(),
            parent.l1.table_ref(),
            parent.l2.table_ref(),
        )
    }

    pub fn ttbr0(&self) -> u64 {
        self.ttbr0.get()
    }

    pub fn translate_user_va_for_access(&self, va: UserVa, access: u8) -> Option<PhysAddr> {
        pt::translate_user_va(UserTableRoot::phys(self.l0.phys_addr()), va, access)
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
        src_l0: TablePageRef,
        src_l1: TablePageRef,
        src_l2: TablePageRef,
    ) -> Option<Self> {
        let l0 = OwnedTablePage::clone_from(src_l0)?;
        let l1 = match OwnedTablePage::clone_from(src_l1) {
            Some(ptr) => ptr,
            None => {
                l0.free();
                return None;
            }
        };
        let l2 = match OwnedTablePage::clone_from(src_l2) {
            Some(ptr) => ptr,
            None => {
                l1.free();
                l0.free();
                return None;
            }
        };

        let mut aspace = Self {
            ttbr0: l0.phys_addr(),
            l0,
            l1,
            l2,
            l3_tables: [OwnedTablePage::empty(); PAGE_TABLE_ENTRIES],
        };

        // SAFETY: l0/l1/l2 are freshly allocated process root page tables.
        unsafe {
            mmu::install_process_root_tables(
                aspace.l0.phys_addr(),
                aspace.l1.phys_addr(),
                aspace.l2.phys_addr(),
            );
        }

        if !aspace
            .user_page_editor()
            .clone_l2_child_tables(&mut aspace.l3_tables)
        {
            return None;
        }

        Some(aspace)
    }

    fn map_user_page(&mut self, va: UserVa, pa: PhysAddr, prot: u32) -> bool {
        if !is_page_aligned(va.get()) || !is_page_aligned(pa.get()) || !is_valid_user_va(va.get()) {
            return false;
        }

        let Some(edit) = self.user_page_editor().map_page(va, pa, prot) else {
            return false;
        };
        edit.record_owned_l3(&mut self.l3_tables);
        true
    }

    fn unmap_user_page(&mut self, va: UserVa) -> bool {
        if !is_page_aligned(va.get()) || !is_valid_user_va(va.get()) {
            return false;
        }

        let Some(edit) = self.user_page_editor().clear_page(va) else {
            return false;
        };
        edit.record_owned_l3(&mut self.l3_tables);
        true
    }

    fn protect_user_page(&mut self, va: UserVa, prot: u32) -> bool {
        if !is_page_aligned(va.get()) || !is_valid_user_va(va.get()) {
            return false;
        }

        let Some(edit) = self.user_page_editor().protect_page(va, prot) else {
            return false;
        };
        edit.record_owned_l3(&mut self.l3_tables);
        true
    }

    #[inline(always)]
    fn user_page_editor(&self) -> UserPageEditor {
        UserPageEditor::new(self.l2.table_ref(), USER_VA_BASE, USER_VA_LIMIT)
    }
}

pub(crate) fn translate_current_user_va_for_access(va: UserVa, access: u8) -> Option<PhysAddr> {
    pt::translate_user_va(UserTableRoot::current(), va, access)
}

impl Drop for ProcessAddressSpace {
    fn drop(&mut self) {
        for entry in self.l3_tables.iter_mut() {
            if entry.is_allocated() {
                entry.free();
                *entry = OwnedTablePage::empty();
            }
        }
        if self.l2.is_allocated() {
            self.l2.free();
            self.l2 = OwnedTablePage::empty();
        }
        if self.l1.is_allocated() {
            self.l1.free();
            self.l1 = OwnedTablePage::empty();
        }
        if self.l0.is_allocated() {
            self.l0.free();
            self.l0 = OwnedTablePage::empty();
        }
        self.ttbr0 = PhysAddr::new(0);
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
