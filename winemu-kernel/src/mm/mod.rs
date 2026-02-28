// MMU 初始化 — ARM64 EL1 (4KB granule)
pub mod kmalloc;
pub mod phys;

#[repr(C, align(4096))]
struct PageTable([u64; 512]);

static mut L0_TABLE: PageTable = PageTable([0u64; 512]);
static mut L1_TABLE: PageTable = PageTable([0u64; 512]);
static mut L2_TABLE: PageTable = PageTable([0u64; 512]);

pub fn init() {
    crate::hypercall::debug_print("mm::init: setup_mapping\n");
    unsafe { setup_kernel_mapping(); }
    crate::hypercall::debug_print("mm::init: enable_mmu\n");
    unsafe { enable_mmu(); }
    crate::hypercall::debug_print("mm::init: done\n");
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

    for i in 0..512usize {
        let block_addr = 0x4000_0000u64 + ((i as u64) << 21); // 2MB per L2 entry
        // [1:0]=01 block, AttrIdx=0, SH=inner-shareable, AF=1
        let mut desc = block_addr | (1 << 10) | (0b11 << 8) | 0b01;
        if i != 0 {
            desc |= 0b01 << 6; // AP=01: EL0+EL1 RW
        }
        (*core::ptr::addr_of_mut!(L2_TABLE)).0[i] = desc;
    }
}

unsafe fn enable_mmu() {
    use core::arch::asm;

    asm!("dsb ishst", options(nostack));
    asm!("tlbi vmalle1is", options(nostack));
    asm!("dsb ish", options(nostack));
    asm!("isb", options(nostack));
    crate::hypercall::debug_print("mmu: tlbi done\n");

    // MAIR_EL1 attr0 = normal memory (inner/outer WB WA)
    let mair: u64 = 0x00ff;
    asm!("msr mair_el1, {}", in(reg) mair, options(nostack));
    crate::hypercall::debug_print("mmu: mair done\n");

    let mmfr0: u64;
    asm!("mrs {}, id_aa64mmfr0_el1", out(reg) mmfr0, options(nostack));
    let parange = mmfr0 & 0xf;
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

    crate::hypercall::debug_print("mmu: mmfr0=");
    crate::hypercall::debug_u64(mmfr0);
    crate::hypercall::debug_print(" tgran4=");
    crate::hypercall::debug_u64(tgran4);
    crate::hypercall::debug_print(" tgran64=");
    crate::hypercall::debug_u64(tgran64);
    crate::hypercall::debug_print(" tcr=");
    crate::hypercall::debug_u64(tcr);
    crate::hypercall::debug_print("\n");
    asm!("msr tcr_el1, {}", in(reg) tcr, options(nostack));
    crate::hypercall::debug_print("mmu: tcr done\n");

    let ttbr0 = core::ptr::addr_of!(L0_TABLE) as u64;
    asm!("msr ttbr0_el1, {}", in(reg) ttbr0, options(nostack));
    crate::hypercall::debug_print("mmu: ttbr0 done\n");

    asm!("dsb ish", options(nostack));
    asm!("isb", options(nostack));

    let l0_addr = core::ptr::addr_of!(L0_TABLE) as u64;
    let l1_addr = core::ptr::addr_of!(L1_TABLE) as u64;
    let l2_addr = core::ptr::addr_of!(L2_TABLE) as u64;
    let l0e0 = (*core::ptr::addr_of!(L0_TABLE)).0[0];
    let l1e1 = (*core::ptr::addr_of!(L1_TABLE)).0[1];
    let l2e0 = (*core::ptr::addr_of!(L2_TABLE)).0[0];
    let l2e1 = (*core::ptr::addr_of!(L2_TABLE)).0[1];
    crate::hypercall::debug_print("mmu: L0_TABLE @ ");
    crate::hypercall::debug_u64(l0_addr);
    crate::hypercall::debug_print("\n");
    crate::hypercall::debug_print("mmu: L1_TABLE @ ");
    crate::hypercall::debug_u64(l1_addr);
    crate::hypercall::debug_print("\n");
    crate::hypercall::debug_print("mmu: L2_TABLE @ ");
    crate::hypercall::debug_u64(l2_addr);
    crate::hypercall::debug_print("\n");
    crate::hypercall::debug_print("mmu: L0[0]=");
    crate::hypercall::debug_u64(l0e0);
    crate::hypercall::debug_print(" L1[1]=");
    crate::hypercall::debug_u64(l1e1);
    crate::hypercall::debug_print(" L2[0]=");
    crate::hypercall::debug_u64(l2e0);
    crate::hypercall::debug_print(" L2[1]=");
    crate::hypercall::debug_u64(l2e1);
    crate::hypercall::debug_print("\n");

    let mut sctlr: u64;
    asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nostack));
    crate::hypercall::debug_print("mmu: sctlr before ");
    crate::hypercall::debug_u64(sctlr);
    crate::hypercall::debug_print("\n");

    // Enable MMU + caches.
    // Clear SA/SA0 for bring-up and clear control bits that can restrict
    // execution on writable/user-accessible mappings during early boot.
    // Keep SPAN=1 so EL0->EL1 exceptions don't force PAN=1; syscall handlers
    // need to dereference user pointers (handle out params, stack args).
    sctlr |= 1 | (1 << 2) | (1 << 12); // M=1, C=1, I=1
    sctlr &= !((1 << 3) | (1 << 4) | (1 << 19) | (1 << 20) | (1 << 22));
    sctlr |= 1 << 23; // SPAN=1
    crate::hypercall::debug_print("mmu: sctlr target ");
    crate::hypercall::debug_u64(sctlr);
    crate::hypercall::debug_print("\n");
    crate::hypercall::debug_print("mmu: enabling MMU...\n");
    crate::hypercall::debug_print("mmu: write sctlr\n");
    asm!("msr sctlr_el1, {}", in(reg) sctlr, options(nostack));
    crate::hypercall::debug_print("mmu: wrote sctlr\n");
    asm!("isb", options(nostack));
    crate::hypercall::debug_print("mmu: isb after sctlr\n");
}
