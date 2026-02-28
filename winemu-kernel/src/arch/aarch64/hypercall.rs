use crate::nt::SvcFrame;

/// Generic HVC ABI: x0=nr, x1-x6=args, return in x0.
#[inline(always)]
pub fn call6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "stp x19, x20, [sp, #-16]!",
            "stp x21, x22, [sp, #-16]!",
            "stp x23, x24, [sp, #-16]!",
            "stp x25, x26, [sp, #-16]!",
            "stp x27, x28, [sp, #-16]!",
            "stp x29, x30, [sp, #-16]!",
            "hvc #0",
            "ldp x29, x30, [sp], #16",
            "ldp x27, x28, [sp], #16",
            "ldp x25, x26, [sp], #16",
            "ldp x23, x24, [sp], #16",
            "ldp x21, x22, [sp], #16",
            "ldp x19, x20, [sp], #16",
            inout("x0") nr => ret,
            in("x1") a0,
            in("x2") a1,
            in("x3") a2,
            in("x4") a3,
            in("x5") a4,
            in("x6") a5,
            lateout("x20") _,
            lateout("x21") _,
            lateout("x22") _,
            lateout("x23") _,
            lateout("x24") _,
            lateout("x25") _,
            lateout("x26") _,
            lateout("x27") _,
            lateout("x28") _,
            lateout("x30") _,
            clobber_abi("C"),
            options()
        );
    }
    ret
}

/// Forward a guest NT syscall frame to VMM fallback dispatcher.
#[inline(always)]
pub fn forward_nt_syscall(frame: &SvcFrame, nr: u16, table: u8) -> u64 {
    let mut ret: u64;
    unsafe {
        core::arch::asm!(
            "stp x19, x20, [sp, #-16]!",
            "stp x21, x22, [sp, #-16]!",
            "stp x23, x24, [sp, #-16]!",
            "stp x25, x26, [sp, #-16]!",
            "stp x27, x28, [sp, #-16]!",
            "stp x29, x30, [sp, #-16]!",
            "hvc #0",
            "ldp x29, x30, [sp], #16",
            "ldp x27, x28, [sp], #16",
            "ldp x25, x26, [sp], #16",
            "ldp x23, x24, [sp], #16",
            "ldp x21, x22, [sp], #16",
            "ldp x19, x20, [sp], #16",
            inout("x0") winemu_shared::nr::NT_SYSCALL => ret,
            in("x1") frame.x[1],
            in("x2") frame.x[2],
            in("x3") frame.x[3],
            in("x4") frame.x[4],
            in("x5") frame.x[5],
            in("x6") frame.x[6],
            in("x7") frame.x[7],
            in("x9") nr as u64,
            in("x10") table as u64,
            in("x11") frame.x[0],
            in("x12") frame as *const SvcFrame as u64,
            lateout("x20") _,
            lateout("x21") _,
            lateout("x22") _,
            lateout("x23") _,
            lateout("x24") _,
            lateout("x25") _,
            lateout("x26") _,
            lateout("x27") _,
            lateout("x28") _,
            lateout("x30") _,
            clobber_abi("C"),
            options()
        );
    }
    ret
}
