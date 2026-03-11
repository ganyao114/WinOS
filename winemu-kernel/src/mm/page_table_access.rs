use crate::arch::mmu::{self, PageTableEntryKind, UserDescLevel};
use crate::mm::UserVa;
use crate::mm::{KernelVa, PhysAddr};
use crate::nt::constants::PAGE_SIZE_4K;

const TABLE_U64S: usize = (PAGE_SIZE_4K as usize) / core::mem::size_of::<u64>();

#[derive(Clone, Copy)]
pub(crate) enum TablePageRef {
    Kernel(KernelVa),
    Phys(PhysAddr),
}

#[derive(Clone, Copy)]
pub(crate) struct OwnedTablePage {
    pa: PhysAddr,
}

#[derive(Clone, Copy)]
pub(crate) struct UserTableRoot(TablePageRef);

#[derive(Clone, Copy)]
pub(crate) struct TableEntryRef {
    table: TablePageRef,
    index: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct UserPteRef(TableEntryRef);

#[derive(Clone, Copy)]
pub(crate) struct EnsuredUserL3 {
    table: TablePageRef,
    owned: Option<OwnedTablePage>,
}

#[derive(Clone, Copy)]
pub(crate) struct UserPageEditor {
    l2_table: TablePageRef,
    user_va_base: u64,
    user_va_limit: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct UserPageEdit {
    owned_l3: Option<(usize, OwnedTablePage)>,
}

#[derive(Clone, Copy)]
struct UserPageSlot {
    pte: UserPteRef,
    edit: UserPageEdit,
}

impl TablePageRef {
    #[inline(always)]
    pub(crate) const fn kernel(kva: KernelVa) -> Self {
        Self::Kernel(kva)
    }

    #[inline(always)]
    pub(crate) const fn phys(pa: PhysAddr) -> Self {
        Self::Phys(pa)
    }
}

impl OwnedTablePage {
    #[inline(always)]
    pub(crate) const fn empty() -> Self {
        Self {
            pa: PhysAddr::new(0),
        }
    }

    #[inline(always)]
    pub(crate) fn is_allocated(self) -> bool {
        !self.pa.is_null()
    }

    #[inline(always)]
    pub(crate) const fn phys_addr(self) -> PhysAddr {
        self.pa
    }

    #[inline(always)]
    pub(crate) const fn table_ref(self) -> TablePageRef {
        TablePageRef::phys(self.pa)
    }

    pub(crate) fn alloc() -> Option<Self> {
        let pa = crate::mm::phys::alloc_pages(1)?;
        if !crate::mm::linear_map::memset_phys(pa, 0, PAGE_SIZE_4K as usize) {
            crate::mm::phys::free_pages(pa, 1);
            return None;
        }
        Some(Self { pa })
    }

    pub(crate) fn clone_from(src: TablePageRef) -> Option<Self> {
        let table = Self::alloc()?;
        if !copy_table_page(table.table_ref(), src) {
            table.free();
            return None;
        }
        Some(table)
    }

    pub(crate) fn clone_from_entry(entry: TableEntryRef) -> Option<Self> {
        let table = Self::alloc()?;
        if !clone_table_from_entry(table.table_ref(), entry) {
            table.free();
            return None;
        }
        Some(table)
    }

    pub(crate) fn from_split_l2_block_entry(entry: TableEntryRef) -> Option<Self> {
        let table = Self::alloc()?;
        if !split_l2_block_entry_into_l3(table.table_ref(), entry) {
            table.free();
            return None;
        }
        Some(table)
    }

    #[inline(always)]
    pub(crate) fn install_into(self, entry: TableEntryRef) -> bool {
        install_table(entry, self.pa)
    }

    #[inline(always)]
    pub(crate) fn free(self) {
        if self.is_allocated() {
            crate::mm::phys::free_pages(self.pa, 1);
        }
    }
}

impl UserTableRoot {
    #[inline(always)]
    pub(crate) const fn kernel(kva: KernelVa) -> Self {
        Self(TablePageRef::kernel(kva))
    }

    #[inline(always)]
    pub(crate) const fn phys(pa: PhysAddr) -> Self {
        Self(TablePageRef::phys(pa))
    }

    #[inline(always)]
    pub(crate) fn current() -> Self {
        let ttbr0 =
            PhysAddr::new(crate::arch::mmu::current_user_table_root() & !(PAGE_SIZE_4K - 1));
        Self::phys(ttbr0)
    }

    #[inline(always)]
    pub(crate) const fn table_ref(self) -> TablePageRef {
        self.0
    }
}

impl TableEntryRef {
    #[inline(always)]
    pub(crate) const fn new(table: TablePageRef, index: usize) -> Self {
        Self { table, index }
    }

    #[inline(always)]
    pub(crate) const fn index(self) -> usize {
        self.index
    }

    #[inline(always)]
    pub(crate) fn read(self) -> Option<u64> {
        read_table_u64(self.table, self.index)
    }

    #[inline(always)]
    pub(crate) fn write(self, value: u64) -> bool {
        write_table_u64(self.table, self.index, value)
    }

    #[inline(always)]
    pub(crate) fn kind(self) -> Option<PageTableEntryKind> {
        self.read().map(mmu::desc_kind)
    }

    #[inline(always)]
    pub(crate) fn child_table(self) -> Option<TablePageRef> {
        child_table(self)
    }

    #[inline(always)]
    pub(crate) fn install_table(self, child_pa: PhysAddr) -> bool {
        install_table(self, child_pa)
    }

    #[inline(always)]
    pub(crate) fn clear(self) -> bool {
        clear_entry(self)
    }
}

impl UserPteRef {
    #[inline(always)]
    pub(crate) fn new(l3_table: TablePageRef, va: UserVa) -> Self {
        Self(table_entry(l3_table, mmu::l3_index(va.get())))
    }

    #[inline(always)]
    pub(crate) fn kind(self) -> Option<PageTableEntryKind> {
        self.0.kind()
    }

    #[inline(always)]
    pub(crate) fn read(self) -> Option<u64> {
        self.0.read()
    }

    #[inline(always)]
    pub(crate) fn map(self, pa: PhysAddr, prot: u32) -> bool {
        self.0.write(mmu::build_user_pte(pa, prot))
    }

    #[inline(always)]
    pub(crate) fn clear(self) -> bool {
        self.0.clear()
    }

    pub(crate) fn protect_present(self, prot: u32) -> bool {
        let Some(old) = self.read() else {
            return false;
        };
        if mmu::desc_kind(old) != PageTableEntryKind::TableOrPage {
            return false;
        }
        self.0
            .write(mmu::build_user_pte(mmu::table_addr(old), prot))
    }
}

impl EnsuredUserL3 {
    #[inline(always)]
    pub(crate) const fn table_ref(self) -> TablePageRef {
        self.table
    }

    #[inline(always)]
    pub(crate) const fn owned_table(self) -> Option<OwnedTablePage> {
        self.owned
    }
}

impl UserPageEditor {
    #[inline(always)]
    pub(crate) const fn new(l2_table: TablePageRef, user_va_base: u64, user_va_limit: u64) -> Self {
        Self {
            l2_table,
            user_va_base,
            user_va_limit,
        }
    }

    pub(crate) fn map_page(self, va: UserVa, pa: PhysAddr, prot: u32) -> Option<UserPageEdit> {
        let slot = self.ensure_page_slot(va)?;
        if !slot.pte.map(pa, prot) {
            return None;
        }
        Some(slot.edit)
    }

    pub(crate) fn clear_page(self, va: UserVa) -> Option<UserPageEdit> {
        let Some(slot) = self.existing_page_slot(va)? else {
            return Some(UserPageEdit::unchanged());
        };
        if !slot.pte.clear() {
            return None;
        }
        Some(slot.edit)
    }

    pub(crate) fn protect_page(self, va: UserVa, prot: u32) -> Option<UserPageEdit> {
        let Some(slot) = self.existing_page_slot(va)? else {
            return Some(UserPageEdit::unchanged());
        };
        if slot.pte.kind()? != PageTableEntryKind::TableOrPage {
            return Some(slot.edit);
        }
        if !slot.pte.protect_present(prot) {
            return None;
        }
        Some(slot.edit)
    }

    pub(crate) fn clone_l2_child_tables(self, l3_tables: &mut [OwnedTablePage]) -> bool {
        for (idx, owned_l3) in l3_tables.iter_mut().enumerate() {
            if !mmu::l2_index_in_user_window(self.user_va_base, self.user_va_limit, idx) {
                continue;
            }
            let l2_entry = table_entry(self.l2_table, idx);
            let kind = l2_entry
                .kind()
                .expect("clone_l2_child_tables: bounded l2 index");
            if kind != PageTableEntryKind::TableOrPage {
                continue;
            }

            let Some(new_l3) = OwnedTablePage::clone_from_entry(l2_entry) else {
                return false;
            };
            assert!(
                new_l3.install_into(l2_entry),
                "clone_l2_child_tables: bounded l2 index"
            );
            *owned_l3 = new_l3;
        }
        true
    }

    fn l2_entry(self, va: UserVa) -> Option<TableEntryRef> {
        let l2_idx = mmu::l2_index(va.get());
        if !mmu::l2_index_in_user_window(self.user_va_base, self.user_va_limit, l2_idx) {
            return None;
        }
        Some(table_entry(self.l2_table, l2_idx))
    }

    fn ensure_page_slot(self, va: UserVa) -> Option<UserPageSlot> {
        let l2_entry = self.l2_entry(va)?;
        let ensured = ensure_user_l3_table(l2_entry)?;
        let edit = match ensured.owned_table() {
            Some(l3) => UserPageEdit::with_owned_l3(l2_entry.index(), l3),
            None => UserPageEdit::unchanged(),
        };
        Some(UserPageSlot {
            pte: UserPteRef::new(ensured.table_ref(), va),
            edit,
        })
    }

    fn existing_page_slot(self, va: UserVa) -> Option<Option<UserPageSlot>> {
        let l2_entry = self.l2_entry(va)?;
        match l2_entry.kind()? {
            PageTableEntryKind::Invalid
            | PageTableEntryKind::Block
            | PageTableEntryKind::Reserved => return Some(None),
            PageTableEntryKind::TableOrPage => {}
        }
        let Some(l3) = l2_entry.child_table() else {
            return None;
        };
        Some(Some(UserPageSlot {
            pte: UserPteRef::new(l3, va),
            edit: UserPageEdit::unchanged(),
        }))
    }
}

impl UserPageEdit {
    #[inline(always)]
    const fn unchanged() -> Self {
        Self { owned_l3: None }
    }

    #[inline(always)]
    const fn with_owned_l3(l2_index: usize, table: OwnedTablePage) -> Self {
        Self {
            owned_l3: Some((l2_index, table)),
        }
    }

    #[inline(always)]
    pub(crate) fn record_owned_l3(self, l3_tables: &mut [OwnedTablePage]) {
        if let Some((l2_index, table)) = self.owned_l3 {
            debug_assert!(l2_index < l3_tables.len());
            l3_tables[l2_index] = table;
        }
    }
}

#[inline(always)]
pub(crate) const fn table_entry(table: TablePageRef, index: usize) -> TableEntryRef {
    TableEntryRef::new(table, index)
}

#[inline(always)]
pub(crate) fn read_table_u64(table: TablePageRef, index: usize) -> Option<u64> {
    if index >= TABLE_U64S {
        return None;
    }
    match table {
        TablePageRef::Kernel(kva) => {
            // SAFETY: `index < TABLE_U64S`, so the read stays within the 4KB page table.
            Some(unsafe { *kva.as_ptr::<u64>().add(index) })
        }
        TablePageRef::Phys(pa) => crate::mm::kmap::read_fixmap_u64(pa, index),
    }
}

#[inline(always)]
pub(crate) fn write_table_u64(table: TablePageRef, index: usize, value: u64) -> bool {
    if index >= TABLE_U64S {
        return false;
    }
    match table {
        TablePageRef::Kernel(kva) => {
            // SAFETY: `index < TABLE_U64S`, so the write stays within the 4KB page table.
            unsafe {
                *kva.as_mut_ptr::<u64>().add(index) = value;
            }
            true
        }
        TablePageRef::Phys(pa) => crate::mm::kmap::write_fixmap_u64(pa, index, value),
    }
}

pub(crate) fn copy_table_page(dst: TablePageRef, src: TablePageRef) -> bool {
    match (dst, src) {
        (TablePageRef::Kernel(dst_kva), TablePageRef::Kernel(src_kva)) => {
            // SAFETY: both table pages are valid 4KB kernel mappings. `ptr::copy`
            // preserves overlap semantics if the caller aliases source/destination.
            unsafe {
                core::ptr::copy(
                    src_kva.as_ptr::<u64>(),
                    dst_kva.as_mut_ptr::<u64>(),
                    TABLE_U64S,
                );
            }
            true
        }
        (TablePageRef::Kernel(dst_kva), TablePageRef::Phys(src_pa)) => {
            crate::mm::kmap::with_fixmap_page(src_pa, |src| {
                // SAFETY: `src` is a temporary fixmap mapping of a single 4KB
                // table page, and `dst_kva` is a live kernel mapping.
                unsafe {
                    core::ptr::copy(src.as_ptr::<u64>(), dst_kva.as_mut_ptr::<u64>(), TABLE_U64S);
                }
            })
            .is_some()
        }
        (TablePageRef::Phys(dst_pa), TablePageRef::Kernel(src_kva)) => {
            crate::mm::kmap::with_fixmap_page(dst_pa, |dst| {
                // SAFETY: `dst` is a temporary fixmap mapping of a single 4KB
                // table page, and `src_kva` is a live kernel mapping.
                unsafe {
                    core::ptr::copy(src_kva.as_ptr::<u64>(), dst.as_mut_ptr::<u64>(), TABLE_U64S);
                }
            })
            .is_some()
        }
        (TablePageRef::Phys(dst_pa), TablePageRef::Phys(src_pa)) => {
            if dst_pa == src_pa {
                return true;
            }
            crate::mm::kmap::with_fixmap_page(src_pa, |src| {
                crate::mm::kmap::with_fixmap_page(dst_pa, |dst| {
                    // SAFETY: both temporary fixmap mappings refer to valid 4KB
                    // table pages. `ptr::copy` preserves overlap semantics.
                    unsafe {
                        core::ptr::copy(src.as_ptr::<u64>(), dst.as_mut_ptr::<u64>(), TABLE_U64S);
                    }
                })
            })
            .is_some()
        }
    }
}

#[inline(always)]
pub(crate) fn table_desc_pa(desc: u64) -> Option<PhysAddr> {
    let pa = mmu::table_addr(desc);
    if pa.is_null() {
        None
    } else {
        Some(pa)
    }
}

#[inline(always)]
pub(crate) fn table_ref_from_desc(desc: u64) -> Option<TablePageRef> {
    table_desc_pa(desc).map(TablePageRef::phys)
}

#[inline(always)]
pub(crate) fn child_table(entry: TableEntryRef) -> Option<TablePageRef> {
    table_ref_from_desc(entry.read()?)
}

#[inline(always)]
pub(crate) fn install_table(entry: TableEntryRef, child_pa: PhysAddr) -> bool {
    entry.write(mmu::make_table_desc(child_pa))
}

#[inline(always)]
pub(crate) fn clear_entry(entry: TableEntryRef) -> bool {
    entry.write(0)
}

#[inline(always)]
pub(crate) fn clone_table_from_entry(dst: TablePageRef, entry: TableEntryRef) -> bool {
    let Some(src) = child_table(entry) else {
        return false;
    };
    copy_table_page(dst, src)
}

pub(crate) fn split_l2_block_into_l3(dst: TablePageRef, block_desc: u64) -> bool {
    if mmu::desc_kind(block_desc) != PageTableEntryKind::Block {
        return false;
    }

    let block_base = mmu::table_addr(block_desc);
    for i in 0..mmu::PAGE_TABLE_ENTRIES {
        let Some(page_pa) = block_base.checked_add((i as u64) * PAGE_SIZE_4K) else {
            return false;
        };
        if !write_table_u64(
            dst,
            i,
            mmu::split_l2_block_entry_to_l3_page(block_desc, page_pa),
        ) {
            return false;
        }
    }
    true
}

pub(crate) fn split_l2_block_entry_into_l3(dst: TablePageRef, entry: TableEntryRef) -> bool {
    let Some(block_desc) = entry.read() else {
        return false;
    };
    split_l2_block_into_l3(dst, block_desc)
}

pub(crate) fn ensure_user_l3_table(l2_entry: TableEntryRef) -> Option<EnsuredUserL3> {
    match l2_entry.kind()? {
        PageTableEntryKind::TableOrPage => Some(EnsuredUserL3 {
            table: l2_entry.child_table()?,
            owned: None,
        }),
        PageTableEntryKind::Block => {
            let l3 = OwnedTablePage::from_split_l2_block_entry(l2_entry)?;
            if !l2_entry.clear() {
                l3.free();
                return None;
            }
            crate::arch::mmu::flush_tlb_global();
            if !l3.install_into(l2_entry) {
                l3.free();
                return None;
            }
            Some(EnsuredUserL3 {
                table: l3.table_ref(),
                owned: Some(l3),
            })
        }
        PageTableEntryKind::Invalid | PageTableEntryKind::Reserved => {
            let l3 = OwnedTablePage::alloc()?;
            if !l3.install_into(l2_entry) {
                l3.free();
                return None;
            }
            Some(EnsuredUserL3 {
                table: l3.table_ref(),
                owned: Some(l3),
            })
        }
    }
}

pub(crate) fn translate_user_va(root: UserTableRoot, va: UserVa, access: u8) -> Option<PhysAddr> {
    if !is_user_accessible_va(va.get()) {
        return None;
    }

    let l0e = read_table_u64(root.table_ref(), mmu::l0_index(va.get()))?;
    if mmu::desc_kind(l0e) != PageTableEntryKind::TableOrPage {
        return None;
    }

    let l1 = table_ref_from_desc(l0e)?;
    let l1e = read_table_u64(l1, mmu::l1_index(va.get()))?;
    match mmu::desc_kind(l1e) {
        PageTableEntryKind::Invalid => return None,
        PageTableEntryKind::Block => {
            return mmu::translate_user_desc(l1e, va.get(), UserDescLevel::L1Block, access);
        }
        PageTableEntryKind::TableOrPage => {}
        PageTableEntryKind::Reserved => return None,
    }

    let l2 = table_ref_from_desc(l1e)?;
    let l2e = read_table_u64(l2, mmu::l2_index(va.get()))?;
    match mmu::desc_kind(l2e) {
        PageTableEntryKind::Invalid => return None,
        PageTableEntryKind::Block => {
            return mmu::translate_user_desc(l2e, va.get(), UserDescLevel::L2Block, access);
        }
        PageTableEntryKind::TableOrPage => {}
        PageTableEntryKind::Reserved => return None,
    }

    let l3 = table_ref_from_desc(l2e)?;
    let l3e = read_table_u64(l3, mmu::l3_index(va.get()))?;
    if mmu::desc_kind(l3e) != PageTableEntryKind::TableOrPage {
        return None;
    }
    mmu::translate_user_desc(l3e, va.get(), UserDescLevel::L3Page, access)
}

#[inline(always)]
fn is_user_accessible_va(va: u64) -> bool {
    va >= crate::process::USER_ACCESS_BASE && va < crate::process::USER_VA_LIMIT
}
