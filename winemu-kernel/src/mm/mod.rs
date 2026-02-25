// MMU 初始化 — ARM64 EL1
// 参考值来自 Ryujinx AppleHv (HvAddressSpace.cs)

#[repr(C, align(4096))]
struct PageTable([u64; 512]);

static mut L0_TABLE: PageTable = PageTable([0u64; 512]);
static mut L1_TABLE: PageTable = PageTable([0u64; 512]);

pub fn init() {
    // MMU disabled for Phase 2 — identity-mapped physical memory is sufficient.
    // The kernel runs at 0x40000000 with direct physical access.
}

unsafe fn setup_kernel_mapping() {
    // L0[0] → L1 table (covers 0x0000_0000 - 0x3FFF_FFFF_FFFF)
    let l1_phys = core::ptr::addr_of!(L1_TABLE) as u64;
    // Table descriptor: bits[1:0]=0b11, bits[47:12]=next-level table PA
    (*core::ptr::addr_of_mut!(L0_TABLE)).0[0] = (l1_phys & 0x0000_FFFF_FFFF_F000) | 0b11;

    // L1[1] → 1GB block covering 0x4000_0000 (kernel load address)
    // Block descriptor: AF=1, SH=inner-shareable, AP=RW-EL1, AttrIdx=0 (normal)
    // bits[1:0]=0b01 (block), bit[10]=AF, bits[9:8]=SH=0b11, bits[7:6]=AP=0b00
    let block_addr: u64 = 0x4000_0000; // 1GB aligned
    (*core::ptr::addr_of_mut!(L1_TABLE)).0[1] = block_addr | (1 << 10) | (0b11 << 8) | 0b01;
}

unsafe fn enable_mmu() {
    use core::arch::asm;

    // MAIR_EL1: attr0 = normal memory (inner/outer WB WA), attr1 = device-nGnRnE
    let mair: u64 = 0x00FF; // attr0=0xFF (normal), attr1=0x00 (device)
    asm!("msr mair_el1, {}", in(reg) mair, options(nostack));

    // TCR_EL1: Ryujinx reference value 0x00000011B5193519
    // T0SZ=25 (39-bit VA), T1SZ=25, TG0=4KB, TG1=4KB, IPS=40-bit PA
    let tcr: u64 = 0x0000_0011_B519_3519;
    asm!("msr tcr_el1, {}", in(reg) tcr, options(nostack));

    // TTBR0_EL1 → L0 table (user space, low addresses)
    let ttbr0 = core::ptr::addr_of!(L0_TABLE) as u64;
    asm!("msr ttbr0_el1, {}", in(reg) ttbr0, options(nostack));

    // TTBR1_EL1 → same table for now (kernel space, high addresses)
    asm!("msr ttbr1_el1, {}", in(reg) ttbr0, options(nostack));

    asm!("isb", options(nostack));

    // SCTLR_EL1: enable MMU (bit 0), I-cache (bit 12), C-cache (bit 2)
    // Keep EE=0 (little-endian), SA=0, no WXN
    let sctlr: u64 = 0x0000_0000_00C5_0835 | 1; // base safe value | M
    asm!("msr sctlr_el1, {}", in(reg) sctlr, options(nostack));

    asm!("isb", options(nostack));
}
