// MMU 初始化 — ARM64 EL1 (4KB granule)
pub mod kmalloc;
pub mod phys;
pub mod vaspace;

#[repr(C, align(4096))]
struct PageTable([u64; 512]);

static mut L0_TABLE: PageTable = PageTable([0u64; 512]);
static mut L1_TABLE: PageTable = PageTable([0u64; 512]);
static mut L2_TABLE: PageTable = PageTable([0u64; 512]);

pub fn bootstrap_user_tables() -> (*const u64, *const u64, *const u64) {
    unsafe {
        (
            (*core::ptr::addr_of!(L0_TABLE)).0.as_ptr(),
            (*core::ptr::addr_of!(L1_TABLE)).0.as_ptr(),
            (*core::ptr::addr_of!(L2_TABLE)).0.as_ptr(),
        )
    }
}

pub fn switch_process_ttbr0(new_ttbr0: u64) {
    if new_ttbr0 == 0 {
        return;
    }
    let cur = crate::arch::mmu::current_user_table_root();
    if (cur & !0xfff) == (new_ttbr0 & !0xfff) {
        return;
    }

    crate::arch::mmu::switch_user_table_root(new_ttbr0);
}

pub fn init() {
    crate::kdebug!("mm::init: setup_mapping");
    unsafe { setup_kernel_mapping(); }
    crate::kdebug!("mm::init: enable_mmu");
    unsafe { enable_mmu(); }
    crate::kdebug!("mm::init: done");
}

unsafe fn setup_kernel_mapping() {
    // Use a 48-bit VA layout (T0SZ=16) with TTBR0 -> L0 -> L1 -> L2.
    //
    // L0[0] -> L1 table
    // L1[1] -> L2 table for VA 0x4000_0000..0x7fff_ffff (1GB window)
    // L2[i] -> 2MB block identity map
    //   i=0  : EL1 RW only (kernel image/early stacks)
    //   i>0  : EL0+EL1 RW (user image/stack/TEB/PEB/heap)
    let l1_addr = core::ptr::addr_of!(L1_TABLE) as u64;
    let l2_addr = core::ptr::addr_of!(L2_TABLE) as u64;
    let l0_desc = (l1_addr & !0xfffu64) | 0b11; // next-level table descriptor
    (*core::ptr::addr_of_mut!(L0_TABLE)).0[0] = l0_desc;
    let l1_desc = (l2_addr & !0xfffu64) | 0b11; // next-level table descriptor
    (*core::ptr::addr_of_mut!(L1_TABLE)).0[1] = l1_desc;

    let user_l2_start = ((crate::process::USER_VA_BASE - 0x4000_0000u64) >> 21) as usize;
    let guard_l2_idx = user_l2_start.saturating_sub(1);
    for i in 0..512usize {
        let block_addr = 0x4000_0000u64 + ((i as u64) << 21); // 2MB per L2 entry
        // [1:0]=01 block, AttrIdx=0, SH=inner-shareable, AF=1
        let mut desc = block_addr | (1 << 10) | (0b11 << 8) | 0b01;
        if i != 0 && i != guard_l2_idx {
            desc |= 0b01 << 6; // AP=01: EL0+EL1 RW
        }
        (*core::ptr::addr_of_mut!(L2_TABLE)).0[i] = desc;
    }
}

unsafe fn enable_mmu() {
    crate::arch::mmu::flush_tlb_global();
    crate::kdebug!("mmu: tlbi done");

    // MAIR_EL1 attr0 = normal memory (inner/outer WB WA)
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
    let l0e0 = (*core::ptr::addr_of!(L0_TABLE)).0[0];
    let l1e1 = (*core::ptr::addr_of!(L1_TABLE)).0[1];
    let l2e0 = (*core::ptr::addr_of!(L2_TABLE)).0[0];
    let l2e1 = (*core::ptr::addr_of!(L2_TABLE)).0[1];
    crate::kdebug!(
        "mmu: L0_TABLE={:#x} L1_TABLE={:#x} L2_TABLE={:#x}",
        l0_addr,
        l1_addr,
        l2_addr
    );
    crate::kdebug!(
        "mmu: L0[0]={:#x} L1[1]={:#x} L2[0]={:#x} L2[1]={:#x}",
        l0e0,
        l1e1,
        l2e0,
        l2e1
    );

    let mut sctlr = crate::arch::mmu::read_system_control();
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
    crate::arch::mmu::write_system_control(sctlr);
    crate::kdebug!("mmu: wrote sctlr");
    crate::arch::mmu::instruction_barrier();
    crate::kdebug!("mmu: isb after sctlr");
}
