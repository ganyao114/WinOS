use super::{
    ffi::{self, hv_vcpu_exit_t, hv_vcpuid_t},
    timer::HvfVTimer,
};
use crate::{
    types::{DebugCaps, Regs, SpecialRegs, VmExit},
    Vcpu,
};
use std::sync::OnceLock;
use std::time::Duration;
use winemu_core::{Result, WinemuError};

const ESR_EC_DEBUG_LOWER_EL: u64 = 0x30;
const ESR_EC_DEBUG_CURRENT_EL: u64 = 0x31;
const ESR_EC_SOFTWARE_STEP_LOWER_EL: u64 = 0x32;
const ESR_EC_SOFTWARE_STEP_CURRENT_EL: u64 = 0x33;
const ESR_EC_WATCHPOINT_LOWER_EL: u64 = 0x34;
const ESR_EC_WATCHPOINT_CURRENT_EL: u64 = 0x35;
const ESR_EC_BRK64: u64 = 0x3c;
const PSTATE_SS: u64 = 1 << 21;
const MDSCR_EL1_SS: u64 = 1 << 0;
const MDSCR_EL1_KDE: u64 = 1 << 13;
const MDSCR_EL1_MDE: u64 = 1 << 15;

pub struct HvfVcpu {
    id: hv_vcpuid_t,
    logical_id: u32,
    exit: *const hv_vcpu_exit_t,
    vtimer: HvfVTimer,
    use_vtimer_exit: bool,
}

// Safety: HvfVcpu is only used from one thread at a time (vCPU thread)
unsafe impl Send for HvfVcpu {}

impl HvfVcpu {
    fn wfi_idle_hint_inner(&self) -> Option<Duration> {
        let cntv_ctl = self.get_sys_reg(ffi::HV_SYS_REG_CNTV_CTL_EL0).ok()?;
        let enabled = (cntv_ctl & 0x1) != 0;
        let masked = (cntv_ctl & 0x2) != 0;
        if !enabled || masked {
            return None;
        }

        let cval = self.get_sys_reg(ffi::HV_SYS_REG_CNTV_CVAL_EL0).ok()?;
        let mut offset = 0u64;
        let ret = unsafe { ffi::hv_vcpu_get_vtimer_offset(self.id, &mut offset as *mut u64) };
        if ret != ffi::HV_SUCCESS {
            return None;
        }

        let now_abs = unsafe { ffi::mach_absolute_time() };
        let now_cntvct = now_abs.saturating_sub(offset);
        let remain_ticks = cval.saturating_sub(now_cntvct);
        if remain_ticks == 0 {
            return Some(Duration::from_micros(20));
        }
        Some(mach_ticks_to_duration(remain_ticks))
    }

    pub fn new(logical_id: u32) -> Result<Self> {
        let mut id: hv_vcpuid_t = 0;
        let mut exit: *const hv_vcpu_exit_t = std::ptr::null();
        let ret = unsafe { ffi::hv_vcpu_create(&mut id, &mut exit, std::ptr::null_mut()) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!(
                "hv_vcpu_create failed: {:#x}",
                ret
            )));
        }
        let mut vcpu = Self {
            id,
            logical_id,
            exit,
            vtimer: HvfVTimer::new(),
            use_vtimer_exit: std::env::var("WINEMU_HVF_VTIMER_EXIT")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
        };
        vcpu.init_el1()?;
        Ok(vcpu)
    }

    /// 初始化 vCPU 为 EL1h 模式，PC 指向 Guest Kernel 入口
    fn init_el1(&mut self) -> Result<()> {
        // Program virtual MPIDR_EL1 affinity so guest can identify CPUs
        // deterministically by vCPU creation order (Aff0=id).
        let mpidr = (self.logical_id as u64) & 0xff;
        self.set_sys_reg(ffi::HV_SYS_REG_MPIDR_EL1, mpidr)?;

        // PC = Guest Kernel 加载地址
        self.set_reg(ffi::HV_REG_PC, 0x4000_0000)?;

        // PSTATE = EL1h (0x05): D/A/I/F 全屏蔽，SP 使用 EL1 的 SP_EL1
        self.set_reg(ffi::HV_REG_CPSR, 0x3C5)?; // EL1h + DAIF masked

        // SCTLR_EL1: 最小安全值，MMU 关闭（Guest Kernel 自己开启）
        // bit 29 (LSMAOE)=1, bit 28 (nTLSMD)=1, bit 23 (SPAN)=1, bit 22 (EIS)=1,
        // bit 20 (TSCXT)=1, bit 11 (EOS)=1 — 这些是 ARMv8.0 reset 值
        self.set_sys_reg(ffi::HV_SYS_REG_SCTLR_EL1, 0x00C50838)?;

        // TCR_EL1: Ryujinx 参考值
        self.set_sys_reg(ffi::HV_SYS_REG_TCR_EL1, 0x0000_0011_B519_3519)?;

        // MAIR_EL1: attr0=normal memory
        self.set_sys_reg(ffi::HV_SYS_REG_MAIR_EL1, 0xFF)?;

        // CPACR_EL1: FPEN=0b11 — allow FP/SIMD at EL0 and EL1 (no trapping)
        self.set_sys_reg(ffi::HV_SYS_REG_CPACR_EL1, 0x0030_0000)?;
        log::debug!(
            "init_el1: CPACR_EL1 set to {:#x}",
            self.get_sys_reg(ffi::HV_SYS_REG_CPACR_EL1)
                .unwrap_or(0xdead)
        );

        // VBAR_EL1: 暂设为 0，Guest Kernel 启动后会设置
        self.set_sys_reg(ffi::HV_SYS_REG_VBAR_EL1, 0)?;

        Ok(())
    }

    fn get_reg(&self, reg: ffi::hv_reg_t) -> Result<u64> {
        let mut val = 0u64;
        let ret = unsafe { ffi::hv_vcpu_get_reg(self.id, reg, &mut val) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!(
                "hv_vcpu_get_reg({}) failed: {:#x}",
                reg, ret
            )));
        }
        Ok(val)
    }

    fn set_reg(&mut self, reg: ffi::hv_reg_t, val: u64) -> Result<()> {
        let ret = unsafe { ffi::hv_vcpu_set_reg(self.id, reg, val) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!(
                "hv_vcpu_set_reg({}) failed: {:#x}",
                reg, ret
            )));
        }
        Ok(())
    }

    fn get_sys_reg(&self, reg: ffi::hv_sys_reg_t) -> Result<u64> {
        let mut val = 0u64;
        let ret = unsafe { ffi::hv_vcpu_get_sys_reg(self.id, reg, &mut val) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!(
                "hv_vcpu_get_sys_reg({:#x}) failed: {:#x}",
                reg, ret
            )));
        }
        Ok(val)
    }

    fn set_sys_reg(&mut self, reg: ffi::hv_sys_reg_t, val: u64) -> Result<()> {
        let ret = unsafe { ffi::hv_vcpu_set_sys_reg(self.id, reg, val) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!(
                "hv_vcpu_set_sys_reg({:#x}) failed: {:#x}",
                reg, ret
            )));
        }
        Ok(())
    }

    fn parse_exit(&mut self) -> Result<VmExit> {
        let exit = unsafe { &*self.exit };
        // Raw exit dumps are too noisy at debug level during normal guest execution.
        log::trace!(
            "parse_exit: reason={} syndrome={:#x} va={:#x} pa={:#x}",
            exit.reason,
            exit.exception.syndrome,
            exit.exception.virtual_address,
            exit.exception.physical_address
        );
        if exit.reason == ffi::HV_EXIT_REASON_VTIMER_ACTIVATED {
            if !self.use_vtimer_exit {
                return Ok(VmExit::Wfi);
            }
            let pstate = self.get_reg(ffi::HV_REG_CPSR).unwrap_or(0);
            let running_el0 = ((pstate >> 2) & 0x3) == 0;
            self.vtimer.on_vtimer_activated(self.id, running_el0)?;
            return Ok(VmExit::Timer);
        }
        if exit.reason == ffi::HV_EXIT_REASON_CANCELED {
            let pc = self.get_reg(ffi::HV_REG_PC).unwrap_or(0);
            let pstate = self.get_reg(ffi::HV_REG_CPSR).unwrap_or(0);
            let elr = self.get_sys_reg(ffi::HV_SYS_REG_ELR_EL1).unwrap_or(0);
            let esr = self.get_sys_reg(ffi::HV_SYS_REG_ESR_EL1).unwrap_or(0);
            let far = self.get_sys_reg(ffi::HV_SYS_REG_FAR_EL1).unwrap_or(0);
            return Err(WinemuError::Hypervisor(format!(
                "hv_vcpu_run canceled: pc={:#x} pstate={:#x} elr_el1={:#x} esr_el1={:#x} far_el1={:#x}",
                pc, pstate, elr, esr, far
            )));
        }
        // reason == 1 means Exception on HVF ARM64
        if exit.reason != ffi::HV_EXIT_REASON_EXCEPTION {
            return Ok(VmExit::Unknown(exit.reason));
        }
        let esr = exit.exception.syndrome;
        let ec = (esr >> 26) & 0x3F;
        // Log CPACR_EL1 when we see an abort to diagnose FP trap issues
        if ec == 0x07 || ec == 0x20 || ec == 0x21 {
            let cpacr = self
                .get_sys_reg(ffi::HV_SYS_REG_CPACR_EL1)
                .unwrap_or(0xdead);
            log::debug!("parse_exit: ec={:#x} cpacr_el1={:#x}", ec, cpacr);
        }
        // When guest jumps to exception vector at 0x200 (VBAR=0), log the saved
        // ELR_EL1/ESR_EL1 to reveal the *original* fault that triggered the vector.
        if exit.exception.virtual_address == 0x200 {
            let elr = self.get_sys_reg(ffi::HV_SYS_REG_ELR_EL1).unwrap_or(0xdead);
            let esr1 = self.get_sys_reg(ffi::HV_SYS_REG_ESR_EL1).unwrap_or(0xdead);
            let spsr = self.get_sys_reg(ffi::HV_SYS_REG_SPSR_EL1).unwrap_or(0xdead);
            let far = self.get_sys_reg(ffi::HV_SYS_REG_FAR_EL1).unwrap_or(0xdead);
            log::error!("GUEST EXCEPTION VECTOR HIT: elr_el1={:#x} esr_el1={:#x} spsr_el1={:#x} far_el1={:#x}",
                elr, esr1, spsr, far);
        }
        match ec {
            0x01 => {
                // Trapped WFI/WFE (EC=0x01). HVF traps this synchronously;
                // VMM advances PC and re-enters guest.
                Ok(VmExit::Wfi)
            }
            0x15 => {
                // SVC from EL0 — should not reach host in WinEmu design,
                // but handle defensively
                Ok(VmExit::Unknown(0x15))
            }
            0x16 => {
                // HVC — hypercall from Guest Kernel
                let mut x = [0u64; 7];
                for i in 0u32..7 {
                    x[i as usize] = self.get_reg(ffi::HV_REG_X0 + i)?;
                }
                Ok(VmExit::Hypercall {
                    nr: x[0],
                    args: [x[1], x[2], x[3], x[4], x[5], x[6]],
                })
            }
            ESR_EC_DEBUG_LOWER_EL
            | ESR_EC_DEBUG_CURRENT_EL
            | ESR_EC_SOFTWARE_STEP_LOWER_EL
            | ESR_EC_SOFTWARE_STEP_CURRENT_EL
            | ESR_EC_WATCHPOINT_LOWER_EL
            | ESR_EC_WATCHPOINT_CURRENT_EL
            | ESR_EC_BRK64 => {
                let pc = self.get_reg(ffi::HV_REG_PC).unwrap_or(0);
                let pstate = self.get_reg(ffi::HV_REG_CPSR).unwrap_or(0);
                log::debug!(
                    "hvf debug exit: ec={:#x} syndrome={:#x} pc={:#x} pstate={:#x} va={:#x} pa={:#x}",
                    ec,
                    exit.exception.syndrome,
                    pc,
                    pstate,
                    exit.exception.virtual_address,
                    exit.exception.physical_address
                );
                Ok(VmExit::DebugException {
                    syndrome: exit.exception.syndrome,
                    virtual_address: exit.exception.virtual_address,
                    physical_address: exit.exception.physical_address,
                })
            }
            0x24 | 0x25 => {
                // Data Abort — MMIO
                let far = exit.exception.virtual_address;
                let iss = esr & 0x1FFFFFF;
                let is_write = (iss >> 6) & 1 != 0;
                let sas = (iss >> 10) & 3;
                let size = 1u8 << sas;
                if is_write {
                    let rt = (iss & 0x1F) as u32;
                    let data = self.get_reg(rt)?;
                    Ok(VmExit::MmioWrite {
                        addr: far,
                        data,
                        size,
                    })
                } else {
                    Ok(VmExit::MmioRead { addr: far, size })
                }
            }
            _ => Ok(VmExit::Unknown(ec as u32)),
        }
    }
}

impl Drop for HvfVcpu {
    fn drop(&mut self) {
        unsafe {
            ffi::hv_vcpu_destroy(self.id);
        }
    }
}

impl HvfVcpu {
    fn run_vcpu(&mut self) -> Result<VmExit> {
        self.vtimer.prepare_run(self.id, self.use_vtimer_exit)?;
        self.run_inner()
    }
}

impl HvfVcpu {
    fn run_inner(&mut self) -> Result<VmExit> {
        let timeout_ms = std::env::var("WINEMU_HVF_RUN_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&v| v > 0);
        let ret = if let Some(ms) = timeout_ms {
            use std::sync::mpsc;
            use std::time::Duration;

            let (tx, rx) = mpsc::channel::<()>();
            let id = self.id;
            let handle = std::thread::spawn(move || {
                if rx.recv_timeout(Duration::from_millis(ms)).is_err() {
                    let mut ids = [id];
                    let r = unsafe { ffi::hv_vcpus_exit(ids.as_mut_ptr(), 1) };
                    log::warn!("hvf watchdog: forced vcpu exit id={} ret={:#x}", id, r);
                }
            });

            let ret = unsafe { ffi::hv_vcpu_run(self.id) };
            let _ = tx.send(());
            let _ = handle.join();
            ret
        } else {
            unsafe { ffi::hv_vcpu_run(self.id) }
        };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!(
                "hv_vcpu_run failed: {:#x}",
                ret
            )));
        }
        self.parse_exit()
    }
}

impl Vcpu for HvfVcpu {
    fn debug_caps(&self) -> DebugCaps {
        DebugCaps {
            async_interrupt: true,
            debug_exception_trap: true,
            sw_breakpoint_candidate: true,
            hw_single_step_candidate: true,
            hw_breakpoint_candidate: false,
            watchpoint_candidate: false,
        }
    }

    fn run(&mut self) -> Result<VmExit> {
        self.run_vcpu()
    }

    fn regs(&self) -> Result<Regs> {
        let mut r = Regs::default();
        for i in 0u32..31 {
            r.x[i as usize] = self.get_reg(i)?;
        }
        r.pc = self.get_reg(ffi::HV_REG_PC)?;
        r.pstate = self.get_reg(ffi::HV_REG_CPSR)?;
        // EL bits [3:2]: 0b00 = EL0, 0b01 = EL1
        // SPSel bit [0]: 0 = SP_EL0, 1 = SP_ELx
        // At EL0 the active SP is always SP_EL0.
        // At EL1 with SPSel=1 (pstate[0]=1) the active SP is SP_EL1.
        let el = (r.pstate >> 2) & 0x3;
        r.sp = if el == 0 {
            self.get_sys_reg(ffi::HV_SYS_REG_SP_EL0)?
        } else {
            self.get_sys_reg(ffi::HV_SYS_REG_SP_EL1)?
        };
        Ok(r)
    }

    fn set_regs(&mut self, r: &Regs) -> Result<()> {
        for i in 0u32..31 {
            self.set_reg(i, r.x[i as usize])?;
        }
        self.set_reg(ffi::HV_REG_PC, r.pc)?;
        let el = (r.pstate >> 2) & 0x3;
        if el == 0 {
            // Preserve SP_EL1 across EL0 context restore — HVF may reset it
            // when CPSR is written with EL0 bits.
            let sp_el1 = self.get_sys_reg(ffi::HV_SYS_REG_SP_EL1).unwrap_or(0);
            self.set_reg(ffi::HV_REG_CPSR, r.pstate)?;
            self.set_sys_reg(ffi::HV_SYS_REG_SP_EL0, r.sp)?;
            self.set_sys_reg(ffi::HV_SYS_REG_SP_EL1, sp_el1)?;
        } else {
            self.set_reg(ffi::HV_REG_CPSR, r.pstate)?;
            self.set_sys_reg(ffi::HV_SYS_REG_SP_EL1, r.sp)?;
        }
        Ok(())
    }

    fn special_regs(&self) -> Result<SpecialRegs> {
        let mut sr = SpecialRegs::default();
        sr.data[0] = self.get_sys_reg(ffi::HV_SYS_REG_SCTLR_EL1)?;
        sr.data[1] = self.get_sys_reg(ffi::HV_SYS_REG_TCR_EL1)?;
        sr.data[2] = self.get_sys_reg(ffi::HV_SYS_REG_TTBR0_EL1)?;
        sr.data[3] = self.get_sys_reg(ffi::HV_SYS_REG_TTBR1_EL1)?;
        sr.data[4] = self.get_sys_reg(ffi::HV_SYS_REG_MAIR_EL1)?;
        sr.data[5] = self.get_sys_reg(ffi::HV_SYS_REG_VBAR_EL1)?;
        Ok(sr)
    }

    fn set_special_regs(&mut self, sr: &SpecialRegs) -> Result<()> {
        self.set_sys_reg(ffi::HV_SYS_REG_SCTLR_EL1, sr.data[0])?;
        self.set_sys_reg(ffi::HV_SYS_REG_TCR_EL1, sr.data[1])?;
        self.set_sys_reg(ffi::HV_SYS_REG_TTBR0_EL1, sr.data[2])?;
        self.set_sys_reg(ffi::HV_SYS_REG_TTBR1_EL1, sr.data[3])?;
        self.set_sys_reg(ffi::HV_SYS_REG_MAIR_EL1, sr.data[4])?;
        self.set_sys_reg(ffi::HV_SYS_REG_VBAR_EL1, sr.data[5])?;
        Ok(())
    }

    fn advance_pc(&mut self, bytes: u64) -> Result<()> {
        let pc = self.get_reg(ffi::HV_REG_PC)?;
        self.set_reg(ffi::HV_REG_PC, pc + bytes)
    }

    fn set_return_value(&mut self, val: u64) -> Result<()> {
        self.set_reg(0, val)
    }

    fn elr_el1(&self) -> Result<u64> {
        self.get_sys_reg(ffi::HV_SYS_REG_ELR_EL1)
    }

    fn spsr_el1(&self) -> Result<u64> {
        self.get_sys_reg(ffi::HV_SYS_REG_SPSR_EL1)
    }

    fn sp_el0(&self) -> Result<u64> {
        self.get_sys_reg(ffi::HV_SYS_REG_SP_EL0)
    }

    fn set_pending_irq(&mut self, pending: bool) -> Result<()> {
        let ret = unsafe {
            ffi::hv_vcpu_set_pending_interrupt(self.id, ffi::HV_INTERRUPT_TYPE_IRQ, pending)
        };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!(
                "hv_vcpu_set_pending_interrupt(IRQ={}) failed: {:#x}",
                pending, ret
            )));
        }
        Ok(())
    }

    fn set_trap_debug_exceptions(&mut self, enabled: bool) -> Result<()> {
        let ret = unsafe { ffi::hv_vcpu_set_trap_debug_exceptions(self.id, enabled) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!(
                "hv_vcpu_set_trap_debug_exceptions({}) failed: {:#x}",
                enabled, ret
            )));
        }
        Ok(())
    }

    fn set_guest_single_step(&mut self, enabled: bool) -> Result<()> {
        let mut pstate = self.get_reg(ffi::HV_REG_CPSR)?;
        let mut mdscr = self.get_sys_reg(ffi::HV_SYS_REG_MDSCR_EL1)?;
        if enabled {
            pstate |= PSTATE_SS;
            mdscr |= MDSCR_EL1_SS | MDSCR_EL1_KDE | MDSCR_EL1_MDE;
        } else {
            pstate &= !PSTATE_SS;
            mdscr &= !(MDSCR_EL1_SS | MDSCR_EL1_KDE | MDSCR_EL1_MDE);
        }
        self.set_reg(ffi::HV_REG_CPSR, pstate)?;
        self.set_sys_reg(ffi::HV_SYS_REG_MDSCR_EL1, mdscr)
    }

    fn wfi_idle_hint(&self) -> Option<Duration> {
        self.wfi_idle_hint_inner()
    }
}

fn mach_ticks_to_duration(ticks: u64) -> Duration {
    let (numer, denom) = mach_timebase();
    if denom == 0 {
        return Duration::from_micros(200);
    }
    let nanos = ((ticks as u128) * (numer as u128) / (denom as u128)) as u64;
    Duration::from_nanos(nanos)
}

fn mach_timebase() -> (u32, u32) {
    static TIMEBASE: OnceLock<(u32, u32)> = OnceLock::new();
    *TIMEBASE.get_or_init(|| {
        let mut info = ffi::mach_timebase_info_data_t { numer: 0, denom: 0 };
        let ret = unsafe { ffi::mach_timebase_info(&mut info as *mut _) };
        if ret != 0 || info.denom == 0 {
            (1, 1)
        } else {
            (info.numer, info.denom)
        }
    })
}
