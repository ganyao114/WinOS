// sched/cpu.rs — vCPU 身份：current_tid, vcpu_id, set_current_cpu_thread

pub fn current_tid() -> u32 {
    crate::arch::cpu::current_cpu_local() as u32
}

pub fn vcpu_id() -> usize {
    let local = crate::arch::cpu::current_cpu_local();
    let vid = (local >> 32) as usize;
    if vid != 0 || (local as u32) != 0 {
        return vid;
    }
    bootstrap_vcpu_id()
}

#[inline(always)]
fn bootstrap_vcpu_id() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        let mpidr: u64;
        unsafe {
            core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack, nomem));
        }
        (mpidr as usize) & 0xff
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

pub fn set_current_cpu_thread(vcpu_id: usize, tid: u32) {
    let val = ((vcpu_id as u64) << 32) | (tid as u64);
    crate::arch::cpu::set_current_cpu_local(val);
}
