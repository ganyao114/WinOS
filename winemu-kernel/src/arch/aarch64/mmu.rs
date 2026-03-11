use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::nt::constants::PAGE_SIZE_4K;

#[derive(Clone, Copy)]
#[repr(C, align(4096))]
struct PageTable([u64; 512]);

static mut L0_TABLE: PageTable = PageTable([0u64; 512]);
static mut L1_TABLE: PageTable = PageTable([0u64; 512]);
static mut L2_TABLE: PageTable = PageTable([0u64; 512]);
static mut PHYSMAP_L2_TABLE: PageTable = PageTable([0u64; 512]);
static mut KERNEL_VM_L2_TABLE: PageTable = PageTable([0u64; 512]);
static mut KERNEL_VM_L3_TABLES: [PageTable; PAGE_TABLE_ENTRIES] =
    [const { PageTable([0u64; 512]) }; PAGE_TABLE_ENTRIES];
static MM_GLOBAL_READY: AtomicU32 = AtomicU32::new(0);
static KERNEL_TABLES_LOCKED: AtomicBool = AtomicBool::new(false);

pub const PAGE_TABLE_ENTRIES: usize = 512;
pub const GUEST_PHYS_BASE: u64 = 0x4000_0000;
pub const GUEST_PHYS_LIMIT: u64 = 0x8000_0000;
pub const KERNEL_PHYSMAP_BASE: u64 = 0x8000_0000;
pub const KERNEL_PHYSMAP_LIMIT: u64 = KERNEL_PHYSMAP_BASE + (GUEST_PHYS_LIMIT - GUEST_PHYS_BASE);

const DESC_TYPE_MASK: u64 = 0b11;
const DESC_INVALID: u64 = 0b00;
const DESC_BLOCK: u64 = 0b01;
const DESC_TABLE_OR_PAGE: u64 = 0b11;

const TABLE_ADDR_MASK: u64 = !0xFFF;
const DESC_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

const L1_BLOCK_SIZE: u64 = 1024 * 1024 * 1024;
const L1_BLOCK_MASK: u64 = !(L1_BLOCK_SIZE - 1);
const L2_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
const L2_BLOCK_MASK: u64 = !(L2_BLOCK_SIZE - 1);

pub const KERNEL_VM_BASE: u64 = 0xC000_0000;
pub const KERNEL_VM_LIMIT: u64 = KERNEL_VM_BASE + L1_BLOCK_SIZE;
pub const KERNEL_KMAP_BASE: u64 = KERNEL_VM_BASE;
pub const KERNEL_KMAP_LIMIT: u64 = KERNEL_KMAP_BASE + L2_BLOCK_SIZE;
pub const KERNEL_FIXMAP_BASE: u64 = KERNEL_KMAP_BASE;
pub const KERNEL_FIXMAP_LIMIT: u64 = KERNEL_KMAP_LIMIT;
pub const KERNEL_VMAP_BASE: u64 = KERNEL_KMAP_LIMIT;
pub const KERNEL_VMAP_LIMIT: u64 = KERNEL_VM_LIMIT;

const AP_EL1_RW: u64 = 0b00 << 6;
const AP_EL0_RW: u64 = 0b01 << 6;
const AP_EL0_RO: u64 = 0b11 << 6;

const ATTR_MASK_PAGE: u64 =
    (0x7 << 2) | (0x3 << 6) | (0x3 << 8) | (1 << 10) | (1 << 53) | (1 << 54);
const PTE_COMMON: u64 = (0b11 << 8) | (1 << 10);
const PTE_UXN: u64 = 1 << 54;
const PTE_PXN: u64 = 1 << 53;
const KERNEL_VM_L1_INDEX: usize = (KERNEL_VM_BASE / L1_BLOCK_SIZE) as usize;

struct KernelTablesGuard;

impl Drop for KernelTablesGuard {
    fn drop(&mut self) {
        KERNEL_TABLES_LOCKED.store(false, Ordering::Release);
    }
}

#[inline(always)]
pub fn dsb_ishst() {
    unsafe {
        core::arch::asm!("dsb ishst", options(nostack));
    }
}

#[inline(always)]
pub fn tlbi_vmalle1is() {
    unsafe {
        core::arch::asm!("tlbi vmalle1is", options(nostack));
    }
}

#[inline(always)]
pub fn dsb_ish() {
    unsafe {
        core::arch::asm!("dsb ish", options(nostack));
    }
}

#[inline(always)]
pub fn isb() {
    unsafe {
        core::arch::asm!("isb", options(nostack));
    }
}

#[inline(always)]
pub fn write_mair_el1(mair: u64) {
    unsafe {
        core::arch::asm!("msr mair_el1, {}", in(reg) mair, options(nostack));
    }
}

#[inline(always)]
pub fn read_id_aa64mmfr0_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, id_aa64mmfr0_el1", out(reg) val, options(nostack));
    }
    val
}

#[inline(always)]
pub fn write_tcr_el1(tcr: u64) {
    unsafe {
        core::arch::asm!("msr tcr_el1, {}", in(reg) tcr, options(nostack));
    }
}

#[inline(always)]
pub fn write_ttbr0_el1(ttbr0: u64) {
    unsafe {
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) ttbr0, options(nostack));
    }
}

#[inline(always)]
pub fn read_ttbr0_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) val, options(nostack));
    }
    val
}

#[inline(always)]
pub fn read_sctlr_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) val, options(nostack));
    }
    val
}

#[inline(always)]
pub fn write_sctlr_el1(sctlr: u64) {
    unsafe {
        core::arch::asm!("msr sctlr_el1, {}", in(reg) sctlr, options(nostack));
    }
}

#[inline(always)]
pub fn memory_features_raw() -> u64 {
    read_id_aa64mmfr0_el1()
}

#[inline(always)]
pub fn physical_addr_range(features_raw: u64) -> u8 {
    (features_raw & 0xF) as u8
}

#[inline(always)]
pub fn supports_4k_granule(features_raw: u64) -> bool {
    ((features_raw >> 28) & 0xF) == 0
}

#[inline(always)]
pub fn supports_64k_granule(features_raw: u64) -> bool {
    ((features_raw >> 24) & 0xF) == 0
}

#[inline(always)]
pub fn current_user_table_root() -> u64 {
    read_ttbr0_el1()
}

#[inline(always)]
pub fn set_user_table_root(root: u64) {
    write_ttbr0_el1(root);
}

#[inline(always)]
pub fn flush_tlb_global() {
    dsb_ishst();
    tlbi_vmalle1is();
    dsb_ish();
    isb();
}

#[inline(always)]
pub fn apply_translation_config(memory_attrs: u64, translation_control: u64, user_table_root: u64) {
    write_mair_el1(memory_attrs);
    write_tcr_el1(translation_control);
    write_ttbr0_el1(user_table_root);
    dsb_ish();
    isb();
}

#[inline(always)]
pub fn read_system_control() -> u64 {
    read_sctlr_el1()
}

#[inline(always)]
pub fn write_system_control(value: u64) {
    write_sctlr_el1(value);
}

#[inline(always)]
pub fn instruction_barrier() {
    isb();
}

pub fn bootstrap_user_tables() -> (*const u64, *const u64, *const u64) {
    // SAFETY: boot page tables are static and live for the entire kernel lifetime.
    unsafe {
        (
            (*core::ptr::addr_of!(L0_TABLE)).0.as_ptr(),
            (*core::ptr::addr_of!(L1_TABLE)).0.as_ptr(),
            (*core::ptr::addr_of!(L2_TABLE)).0.as_ptr(),
        )
    }
}

pub fn init_global_bootstrap() {
    if MM_GLOBAL_READY.load(Ordering::Acquire) != 0 {
        return;
    }
    crate::kdebug!("mm::init_global_bootstrap: setup_mapping");
    // SAFETY: bootstrap mapping writes only dedicated static boot tables before use.
    unsafe {
        setup_kernel_mapping();
    }
    MM_GLOBAL_READY.store(1, Ordering::Release);
    crate::kdebug!("mm::init_global_bootstrap: done");
}

pub fn init_per_cpu() {
    if MM_GLOBAL_READY.load(Ordering::Acquire) == 0 {
        crate::kwarn!("mm::init_per_cpu before global init, auto-bootstrap");
        init_global_bootstrap();
    }
    crate::kdebug!("mm::init_per_cpu: enable_mmu");
    // SAFETY: per-cpu MMU enable sequence touches only CPU-local system registers.
    unsafe {
        enable_mmu();
    }
    crate::kdebug!("mm::init_per_cpu: done");
}

#[inline(always)]
pub fn l0_index(va: u64) -> usize {
    ((va >> 39) & 0x1FF) as usize
}

#[inline(always)]
pub fn l1_index(va: u64) -> usize {
    ((va >> 30) & 0x1FF) as usize
}

#[inline(always)]
pub fn l2_index(va: u64) -> usize {
    ((va >> 21) & 0x1FF) as usize
}

#[inline(always)]
pub fn l3_index(va: u64) -> usize {
    ((va >> 12) & 0x1FF) as usize
}

#[inline(always)]
pub fn table_addr(desc: u64) -> u64 {
    desc & TABLE_ADDR_MASK
}

#[inline(always)]
pub fn make_table_desc(table_pa: u64) -> u64 {
    (table_pa & TABLE_ADDR_MASK) | DESC_TABLE_OR_PAGE
}

#[inline(always)]
pub fn desc_kind_raw(desc: u64) -> u8 {
    match desc & DESC_TYPE_MASK {
        DESC_INVALID => 0,
        DESC_BLOCK => 1,
        DESC_TABLE_OR_PAGE => 3,
        _ => 2,
    }
}

pub fn translate_user_desc(desc: u64, va: u64, level: u8, access: u8) -> Option<u64> {
    let (base_mask, span) = match level {
        1 => (L1_BLOCK_MASK, L1_BLOCK_SIZE),
        2 => (L2_BLOCK_MASK, L2_BLOCK_SIZE),
        3 => (TABLE_ADDR_MASK, PAGE_SIZE_4K),
        _ => return None,
    };

    let (readable, writable) = desc_user_perms(desc);
    if access == crate::mm::VM_ACCESS_READ && !readable {
        return None;
    }
    if access == crate::mm::VM_ACCESS_WRITE && !writable {
        return None;
    }

    let base = desc & base_mask & DESC_ADDR_MASK;
    let offset = va & (span - 1);
    base.checked_add(offset)
}

pub fn build_user_pte(pa: u64, prot: u32) -> u64 {
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

pub fn split_l2_block_entry_to_l3_page(block_desc: u64, page_pa: u64) -> u64 {
    let attrs = block_desc & ATTR_MASK_PAGE;
    (page_pa & TABLE_ADDR_MASK) | attrs | DESC_TABLE_OR_PAGE
}

pub fn l2_index_in_user_window(user_va_base: u64, user_va_limit: u64, idx: usize) -> bool {
    if user_va_limit <= user_va_base {
        return false;
    }
    let start = l2_index(user_va_base);
    let end = l2_index(user_va_limit - 1);
    idx >= start && idx <= end
}

pub unsafe fn install_process_root_tables(l0_pa: u64, l1_pa: u64, l2_pa: u64) {
    let physmap_l2 = core::ptr::addr_of!(PHYSMAP_L2_TABLE) as u64;
    let kernel_vm_l2 = core::ptr::addr_of!(KERNEL_VM_L2_TABLE) as u64;
    let l0_ok = crate::mm::kmap::write_fixmap_u64(
        crate::mm::PhysAddr::new(l0_pa),
        0,
        make_table_desc(l1_pa),
    );
    let l1_ok = crate::mm::kmap::write_fixmap_u64(
        crate::mm::PhysAddr::new(l1_pa),
        1,
        make_table_desc(l2_pa),
    ) && crate::mm::kmap::write_fixmap_u64(
        crate::mm::PhysAddr::new(l1_pa),
        2,
        make_table_desc(physmap_l2),
    ) && crate::mm::kmap::write_fixmap_u64(
        crate::mm::PhysAddr::new(l1_pa),
        KERNEL_VM_L1_INDEX,
        make_table_desc(kernel_vm_l2),
    );
    assert!(
        l0_ok && l1_ok,
        "install_process_root_tables: failed to map root tables"
    );
}

pub fn map_kernel_pages(va: u64, pa: u64, pages: usize) -> bool {
    if MM_GLOBAL_READY.load(Ordering::Acquire) == 0 || !kernel_vm_range_valid(va, pages) {
        return false;
    }
    if !is_page_aligned(pa) {
        return false;
    }

    let _guard = lock_kernel_tables();
    let mut mapped = 0usize;
    while mapped < pages {
        let offset = (mapped as u64) * PAGE_SIZE_4K;
        let Some(cur_va) = va.checked_add(offset) else {
            rollback_kernel_pages(va, mapped);
            return false;
        };
        let Some(cur_pa) = pa.checked_add(offset) else {
            rollback_kernel_pages(va, mapped);
            return false;
        };
        let Some(pte) = kernel_vm_pte_ptr(cur_va) else {
            rollback_kernel_pages(va, mapped);
            return false;
        };
        // SAFETY: `pte` points into the shared kernel L3 table for `cur_va`.
        let old = unsafe { *pte };
        if desc_kind_raw(old) != 0 {
            rollback_kernel_pages(va, mapped);
            return false;
        }
        // SAFETY: `pte` points into the shared kernel L3 table for `cur_va`.
        unsafe {
            *pte = build_kernel_rw_pte(cur_pa);
        }
        mapped += 1;
    }

    flush_tlb_global();
    true
}

pub fn unmap_kernel_pages(va: u64, pages: usize) -> bool {
    if MM_GLOBAL_READY.load(Ordering::Acquire) == 0 || !kernel_vm_range_valid(va, pages) {
        return false;
    }

    let _guard = lock_kernel_tables();
    let mut unmapped = false;
    let mut i = 0usize;
    while i < pages {
        let cur_va = va + (i as u64) * PAGE_SIZE_4K;
        let Some(pte) = kernel_vm_pte_ptr(cur_va) else {
            return false;
        };
        // SAFETY: `pte` points into the shared kernel L3 table for `cur_va`.
        let old = unsafe { *pte };
        if desc_kind_raw(old) == 3 {
            // SAFETY: `pte` points into the shared kernel L3 table for `cur_va`.
            unsafe {
                *pte = 0;
            }
            unmapped = true;
        }
        i += 1;
    }

    if unmapped {
        flush_tlb_global();
    }
    true
}

fn decode_nt_prot(prot: u32) -> (bool, bool, bool) {
    match prot & 0xFF {
        0x01 => (false, false, false),      // PAGE_NOACCESS
        0x02 => (true, false, false),       // PAGE_READONLY
        0x04 => (true, true, false),        // PAGE_READWRITE
        0x08 => (true, false, false),       // PAGE_WRITECOPY: map RO, write fault triggers COW
        0x10 => (false, false, true),       // PAGE_EXECUTE
        0x20 => (true, false, true),        // PAGE_EXECUTE_READ
        0x40 | 0x80 => (true, false, true), // W^X: downgrade RWX to RX
        _ => (true, true, false),
    }
}

fn desc_user_perms(desc: u64) -> (bool, bool) {
    match (desc >> 6) & 0b11 {
        0b01 => (true, true),
        0b11 => (true, false),
        _ => (false, false),
    }
}

unsafe fn setup_kernel_mapping() {
    // Use a 48-bit VA layout (T0SZ=16) with TTBR0 -> L0 -> L1 -> L2.
    //
    // L0[0] -> L1 table
    // L1[1] -> L2 table for VA 0x4000_0000..0x7fff_ffff (1GB window)
    // L1[2] -> PHYSMAP_L2 table for VA 0x8000_0000..0xbfff_ffff (EL1-only physmap)
    // L2[i] -> 2MB block identity map
    //   i=0  : EL1 RW only (kernel image/early stacks)
    //   i>0  : EL0+EL1 RW (user image/stack/TEB/PEB/heap)
    let l1_addr = core::ptr::addr_of!(L1_TABLE) as u64;
    let l2_addr = core::ptr::addr_of!(L2_TABLE) as u64;
    let physmap_l2_addr = core::ptr::addr_of!(PHYSMAP_L2_TABLE) as u64;
    let kernel_vm_l2_addr = core::ptr::addr_of!(KERNEL_VM_L2_TABLE) as u64;
    let l0_desc = (l1_addr & !0xfffu64) | 0b11;
    // SAFETY: L0_TABLE is a private static boot table and this index is in bounds.
    unsafe {
        (*core::ptr::addr_of_mut!(L0_TABLE)).0[0] = l0_desc;
    }
    let l1_desc = (l2_addr & !0xfffu64) | 0b11;
    // SAFETY: L1_TABLE is a private static boot table and this index is in bounds.
    unsafe {
        (*core::ptr::addr_of_mut!(L1_TABLE)).0[1] = l1_desc;
    }
    let physmap_l1_desc = (physmap_l2_addr & !0xfffu64) | 0b11;
    // SAFETY: L1_TABLE is a private static boot table and this index is in bounds.
    unsafe {
        (*core::ptr::addr_of_mut!(L1_TABLE)).0[2] = physmap_l1_desc;
    }
    let kernel_vm_l1_desc = (kernel_vm_l2_addr & !0xfffu64) | 0b11;
    // SAFETY: L1_TABLE is a private static boot table and this index is in bounds.
    unsafe {
        (*core::ptr::addr_of_mut!(L1_TABLE)).0[KERNEL_VM_L1_INDEX] = kernel_vm_l1_desc;
    }

    let user_l2_start = ((crate::process::USER_VA_BASE - 0x4000_0000u64) >> 21) as usize;
    let guard_l2_idx = user_l2_start.saturating_sub(1);
    for i in 0..512usize {
        let block_addr = GUEST_PHYS_BASE + ((i as u64) << 21);
        // [1:0]=01 block, AttrIdx=0, SH=inner-shareable, AF=1
        let mut desc = block_addr | (1 << 10) | (0b11 << 8) | 0b01;
        if i != 0 && i != guard_l2_idx {
            desc |= 0b01 << 6; // AP=01: EL0+EL1 RW
        }
        // SAFETY: L2 table has exactly 512 entries and loop index is bounded.
        unsafe {
            (*core::ptr::addr_of_mut!(L2_TABLE)).0[i] = desc;
        }
    }

    for i in 0..512usize {
        let block_addr = GUEST_PHYS_BASE + ((i as u64) << 21);
        let desc = block_addr | (1 << 10) | (0b11 << 8) | PTE_UXN | PTE_PXN | DESC_BLOCK;
        // SAFETY: PHYSMAP_L2_TABLE has exactly 512 entries and loop index is bounded.
        unsafe {
            (*core::ptr::addr_of_mut!(PHYSMAP_L2_TABLE)).0[i] = desc;
        }
    }

    for i in 0..PAGE_TABLE_ENTRIES {
        let l3_addr =
            // SAFETY: `KERNEL_VM_L3_TABLES` is a static array of page tables and `i` is bounded.
            unsafe { core::ptr::addr_of!((*core::ptr::addr_of!(KERNEL_VM_L3_TABLES))[i]) as u64 };
        // SAFETY: KERNEL_VM_L2_TABLE has exactly 512 entries and `i` is bounded.
        unsafe {
            (*core::ptr::addr_of_mut!(KERNEL_VM_L2_TABLE)).0[i] = make_table_desc(l3_addr);
        }
    }
}

unsafe fn enable_mmu() {
    flush_tlb_global();
    crate::kdebug!("mmu: tlbi done");

    // MAIR_EL1 attr0 = normal memory (inner/outer WB WA).
    let mair: u64 = 0x00ff;
    crate::kdebug!("mmu: mair prepared");

    let features = crate::arch::mmu::memory_features();
    let mmfr0 = features.raw;
    let parange = features.physical_addr_range as u64;
    let tgran4 = (mmfr0 >> 28) & 0xf;
    let tgran64 = (mmfr0 >> 24) & 0xf;

    // TCR_EL1:
    //   T0SZ=16 (48-bit VA)
    //   IRGN0/ORGN0=WB WA
    //   SH0=inner-shareable
    //   TG0=0b00 (4KB granule)
    //   EPD1=1
    //   IPS=PARange from ID_AA64MMFR0_EL1
    let tcr: u64 = 16
        | (0b01u64 << 8)
        | (0b01u64 << 10)
        | (0b11u64 << 12)
        | (0b00u64 << 14)
        | (1u64 << 23)
        | (parange << 32);

    crate::kdebug!(
        "mmu: mmfr0={:#x} tgran4={:#x} tgran64={:#x} tcr={:#x}",
        mmfr0,
        tgran4,
        tgran64,
        tcr
    );
    crate::arch::mmu::mmu_init(crate::arch::mmu::TranslationConfig {
        memory_attrs: mair,
        translation_control: tcr,
        user_table_root: core::ptr::addr_of!(L0_TABLE) as u64,
    });
    crate::kdebug!("mmu: tcr done");
    crate::kdebug!("mmu: ttbr0 done");

    let l0_addr = core::ptr::addr_of!(L0_TABLE) as u64;
    let l1_addr = core::ptr::addr_of!(L1_TABLE) as u64;
    let l2_addr = core::ptr::addr_of!(L2_TABLE) as u64;
    let physmap_l2_addr = core::ptr::addr_of!(PHYSMAP_L2_TABLE) as u64;
    let kernel_vm_l2_addr = core::ptr::addr_of!(KERNEL_VM_L2_TABLE) as u64;
    let (l0e0, l1e1, l1e2, l1e3, l2e0, l2e1, physmap_l2e0, kernel_vm_l2e0) =
        // SAFETY: page table statics are initialized above and read-only here.
        unsafe {
            (
                (*core::ptr::addr_of!(L0_TABLE)).0[0],
                (*core::ptr::addr_of!(L1_TABLE)).0[1],
                (*core::ptr::addr_of!(L1_TABLE)).0[2],
                (*core::ptr::addr_of!(L1_TABLE)).0[KERNEL_VM_L1_INDEX],
                (*core::ptr::addr_of!(L2_TABLE)).0[0],
                (*core::ptr::addr_of!(L2_TABLE)).0[1],
                (*core::ptr::addr_of!(PHYSMAP_L2_TABLE)).0[0],
                (*core::ptr::addr_of!(KERNEL_VM_L2_TABLE)).0[0],
            )
        };
    crate::kdebug!(
        "mmu: L0_TABLE={:#x} L1_TABLE={:#x} L2_TABLE={:#x} PHYSMAP_L2={:#x} KERNEL_VM_L2={:#x}",
        l0_addr,
        l1_addr,
        l2_addr,
        physmap_l2_addr,
        kernel_vm_l2_addr
    );
    crate::kdebug!(
        "mmu: L0[0]={:#x} L1[1]={:#x} L1[2]={:#x} L1[3]={:#x} L2[0]={:#x} L2[1]={:#x} PHYSMAP_L2[0]={:#x} KERNEL_VM_L2[0]={:#x}",
        l0e0,
        l1e1,
        l1e2,
        l1e3,
        l2e0,
        l2e1,
        physmap_l2e0,
        kernel_vm_l2e0
    );

    let mut sctlr = read_system_control();
    crate::kdebug!("mmu: sctlr before {:#x}", sctlr);

    // Enable MMU + caches.
    // Clear SA/SA0 for bring-up and clear control bits that can restrict
    // execution on writable/user-accessible mappings during early boot.
    // Keep SPAN=1 so EL0->EL1 exceptions don't force PAN=1; syscall handlers
    // need to dereference user pointers (handle out params, stack args).
    sctlr |= 1 | (1 << 2) | (1 << 12); // M=1, C=1, I=1
    sctlr &= !((1 << 3) | (1 << 4) | (1 << 19) | (1 << 20) | (1 << 22));
    sctlr |= 1 << 23; // SPAN=1
    crate::kdebug!("mmu: sctlr target {:#x}", sctlr);
    crate::kdebug!("mmu: enabling MMU...");
    crate::kdebug!("mmu: write sctlr");
    write_system_control(sctlr);
    crate::kdebug!("mmu: wrote sctlr");
    instruction_barrier();
    crate::kdebug!("mmu: isb after sctlr");
}

#[inline(always)]
fn build_kernel_rw_pte(pa: u64) -> u64 {
    (pa & TABLE_ADDR_MASK) | PTE_COMMON | AP_EL1_RW | PTE_UXN | PTE_PXN | DESC_TABLE_OR_PAGE
}

#[inline(always)]
fn is_page_aligned(addr: u64) -> bool {
    (addr & (PAGE_SIZE_4K - 1)) == 0
}

#[inline(always)]
fn kernel_vm_range_valid(va: u64, pages: usize) -> bool {
    if pages == 0 || !is_page_aligned(va) {
        return false;
    }
    let Some(size) = (pages as u64).checked_mul(PAGE_SIZE_4K) else {
        return false;
    };
    let Some(end) = va.checked_add(size) else {
        return false;
    };
    kernel_subrange_valid(va, end, KERNEL_KMAP_BASE, KERNEL_KMAP_LIMIT)
        || kernel_subrange_valid(va, end, KERNEL_VMAP_BASE, KERNEL_VMAP_LIMIT)
}

#[inline(always)]
fn kernel_subrange_valid(va: u64, end: u64, base: u64, limit: u64) -> bool {
    va >= base && va < limit && end <= limit
}

fn lock_kernel_tables() -> KernelTablesGuard {
    while KERNEL_TABLES_LOCKED
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        spin_loop();
    }
    KernelTablesGuard
}

fn rollback_kernel_pages(base_va: u64, pages: usize) {
    let mut i = 0usize;
    while i < pages {
        let cur_va = base_va + (i as u64) * PAGE_SIZE_4K;
        if let Some(pte) = kernel_vm_pte_ptr(cur_va) {
            // SAFETY: `pte` points into the shared kernel L3 table for `cur_va`.
            unsafe {
                *pte = 0;
            }
        }
        i += 1;
    }
}

fn kernel_vm_pte_ptr(va: u64) -> Option<*mut u64> {
    if !kernel_vm_range_valid(va, 1) || l1_index(va) != KERNEL_VM_L1_INDEX {
        return None;
    }

    let l2e =
        // SAFETY: `KERNEL_VM_L2_TABLE` is a global static table and index is bounded.
        unsafe { (*core::ptr::addr_of!(KERNEL_VM_L2_TABLE)).0[l2_index(va)] };
    if desc_kind_raw(l2e) != 3 {
        return None;
    }

    let l3 = table_addr(l2e) as *mut u64;
    if l3.is_null() {
        return None;
    }

    let idx = l3_index(va);
    // SAFETY: `l3` points to a live L3 page table and `idx < 512`.
    Some(unsafe { l3.add(idx) })
}
