// MMU 初始化 — ARM64 EL1
// 参考值来自 Ryujinx AppleHv (HvAddressSpace.cs)

#[repr(C, align(4096))]
struct PageTable([u64; 512]);

static mut L0_TABLE: PageTable = PageTable([0u64; 512]);
static mut L1_TABLE: PageTable = PageTable([0u64; 512]);

pub fn init() {
    // Enable MMU with identity mapping for the kernel/user memory range.
    // LDXR/STXR (atomics) require MMU to be enabled on Apple Silicon / HVF.
    crate::hypercall::debug_print("mm::init: setup_mapping\n");
    unsafe { setup_kernel_mapping(); }
    crate::hypercall::debug_print("mm::init: enable_mmu\n");
    unsafe { enable_mmu(); }
    crate::hypercall::debug_print("mm::init: done\n");
}

unsafe fn setup_kernel_mapping() {
    // With T0SZ=25 (39-bit VA, 4KB granule), translation starts at level 1.
    // TTBR0 points directly to L1_TABLE (512 entries, each covers 1GB).
    //
    // L1[1] → 1GB block covering 0x4000_0000–0x7FFF_FFFF
    //   (kernel at 0x40000000, HVF guest memory 0x40000000–0x60000000)
    //
    // Block descriptor bits:
    //   [1:0]  = 0b01  block descriptor
    //   [4:2]  = 0b000 AttrIdx=0 → MAIR attr0 = 0xFF (normal WB)
    //   [7:6]  = 0b01  AP: RW at EL0 and EL1  ← must allow EL0 access
    //   [9:8]  = 0b11  SH: inner-shareable
    //   [10]   = 1     AF: access flag (avoid AF fault)
    //   [47:30]= output address (1GB aligned)
    let block_addr: u64 = 0x4000_0000;
    let desc = block_addr | (1 << 10) | (0b11 << 8) | (0b01 << 6) | 0b01;
    (*core::ptr::addr_of_mut!(L1_TABLE)).0[1] = desc;
}

unsafe fn enable_mmu() {
    use core::arch::asm;

    // Ensure page table writes are visible to the page table walker
    asm!("dsb ish", options(nostack));

    // Invalidate all TLB entries for EL1 (both EL0 and EL1 translations)
    asm!("tlbi vmalle1", options(nostack));
    asm!("dsb ish", options(nostack));
    asm!("isb", options(nostack));

    crate::hypercall::debug_print("mmu: tlbi done\n");

    // MAIR_EL1: attr0 = normal memory (inner/outer WB WA)
    let mair: u64 = 0x00FF;
    asm!("msr mair_el1, {}", in(reg) mair, options(nostack));

    crate::hypercall::debug_print("mmu: mair done\n");

    // TCR_EL1: T0SZ=25 (39-bit VA), TG0=4KB, inner/outer WB WA, inner-shareable
    // EPD1=1 to disable TTBR1 walks (kernel uses low addresses only)
    // IPS=010 (40-bit PA) to match Apple Silicon
    let tcr: u64 = (0x0000_0011_B519_3519 & !0x7_0000_0000u64)  // clear IPS
                 | (0b010u64 << 32)   // IPS = 40-bit PA
                 | (1 << 23);         // EPD1 = 1
    asm!("msr tcr_el1, {}", in(reg) tcr, options(nostack));

    crate::hypercall::debug_print("mmu: tcr done\n");

    // TTBR0_EL1 → L1_TABLE (level-1 root for 39-bit VA)
    let ttbr0 = core::ptr::addr_of!(L1_TABLE) as u64;
    asm!("msr ttbr0_el1, {}", in(reg) ttbr0, options(nostack));

    crate::hypercall::debug_print("mmu: ttbr0 done\n");

    // Ensure all system register writes complete before enabling MMU
    asm!("isb", options(nostack));

    crate::hypercall::debug_print("mmu: isb done, enabling...\n");

    // SCTLR_EL1: enable MMU (M=1), I-cache (I=1), D-cache (C=1)
    let sctlr: u64 = 0x0000_0000_00C5_0835 | 1;
    asm!("msr sctlr_el1, {}", in(reg) sctlr, options(nostack));

    // Synchronize after MMU enable — required by ARM spec
    asm!("isb", options(nostack));
}
