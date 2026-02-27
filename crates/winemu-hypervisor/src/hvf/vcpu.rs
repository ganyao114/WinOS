use winemu_core::{Result, WinemuError};
use crate::{Vcpu, types::{Regs, SpecialRegs, VmExit}};
use super::ffi::{self, hv_vcpuid_t, hv_vcpu_exit_t};

pub struct HvfVcpu {
    id: hv_vcpuid_t,
    exit: *const hv_vcpu_exit_t,
}

// Safety: HvfVcpu is only used from one thread at a time (vCPU thread)
unsafe impl Send for HvfVcpu {}

impl HvfVcpu {
    pub fn new() -> Result<Self> {
        let mut id: hv_vcpuid_t = 0;
        let mut exit: *const hv_vcpu_exit_t = std::ptr::null();
        let ret = unsafe {
            ffi::hv_vcpu_create(&mut id, &mut exit, std::ptr::null_mut())
        };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(
                format!("hv_vcpu_create failed: {:#x}", ret),
            ));
        }
        let mut vcpu = Self { id, exit };
        vcpu.init_el1()?;
        Ok(vcpu)
    }

    /// 初始化 vCPU 为 EL1h 模式，PC 指向 Guest Kernel 入口
    fn init_el1(&mut self) -> Result<()> {
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
        log::debug!("init_el1: CPACR_EL1 set to {:#x}", self.get_sys_reg(ffi::HV_SYS_REG_CPACR_EL1).unwrap_or(0xdead));

        // VBAR_EL1: 暂设为 0，Guest Kernel 启动后会设置
        self.set_sys_reg(ffi::HV_SYS_REG_VBAR_EL1, 0)?;

        Ok(())
    }

    fn get_reg(&self, reg: ffi::hv_reg_t) -> Result<u64> {
        let mut val = 0u64;
        let ret = unsafe { ffi::hv_vcpu_get_reg(self.id, reg, &mut val) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!("hv_vcpu_get_reg({}) failed: {:#x}", reg, ret)));
        }
        Ok(val)
    }

    fn set_reg(&mut self, reg: ffi::hv_reg_t, val: u64) -> Result<()> {
        let ret = unsafe { ffi::hv_vcpu_set_reg(self.id, reg, val) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!("hv_vcpu_set_reg({}) failed: {:#x}", reg, ret)));
        }
        Ok(())
    }

    fn get_sys_reg(&self, reg: ffi::hv_sys_reg_t) -> Result<u64> {
        let mut val = 0u64;
        let ret = unsafe { ffi::hv_vcpu_get_sys_reg(self.id, reg, &mut val) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!("hv_vcpu_get_sys_reg({:#x}) failed: {:#x}", reg, ret)));
        }
        Ok(val)
    }

    fn set_sys_reg(&mut self, reg: ffi::hv_sys_reg_t, val: u64) -> Result<()> {
        let ret = unsafe { ffi::hv_vcpu_set_sys_reg(self.id, reg, val) };
        if ret != ffi::HV_SUCCESS {
            return Err(WinemuError::Hypervisor(format!("hv_vcpu_set_sys_reg({:#x}) failed: {:#x}", reg, ret)));
        }
        Ok(())
    }

    fn parse_exit(&self) -> Result<VmExit> {
        let exit = unsafe { &*self.exit };
        // Log raw exit struct for debugging
        log::debug!("parse_exit: reason={} syndrome={:#x} va={:#x} pa={:#x}",
            exit.reason, exit.exception.syndrome,
            exit.exception.virtual_address, exit.exception.physical_address);
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
            let cpacr = self.get_sys_reg(ffi::HV_SYS_REG_CPACR_EL1).unwrap_or(0xdead);
            log::debug!("parse_exit: ec={:#x} cpacr_el1={:#x}", ec, cpacr);
        }
        // When guest jumps to exception vector at 0x200 (VBAR=0), log the saved
        // ELR_EL1/ESR_EL1 to reveal the *original* fault that triggered the vector.
        if exit.exception.virtual_address == 0x200 {
            let elr  = self.get_sys_reg(ffi::HV_SYS_REG_ELR_EL1).unwrap_or(0xdead);
            let esr1 = self.get_sys_reg(ffi::HV_SYS_REG_ESR_EL1).unwrap_or(0xdead);
            let spsr = self.get_sys_reg(ffi::HV_SYS_REG_SPSR_EL1).unwrap_or(0xdead);
            let far  = self.get_sys_reg(ffi::HV_SYS_REG_FAR_EL1).unwrap_or(0xdead);
            log::error!("GUEST EXCEPTION VECTOR HIT: elr_el1={:#x} esr_el1={:#x} spsr_el1={:#x} far_el1={:#x}",
                elr, esr1, spsr, far);
        }
        match ec {
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
                    Ok(VmExit::MmioWrite { addr: far, data, size })
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
        unsafe { ffi::hv_vcpu_destroy(self.id); }
    }
}

impl Vcpu for HvfVcpu {
    fn run(&mut self) -> Result<VmExit> {
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
            return Err(WinemuError::Hypervisor(format!("hv_vcpu_run failed: {:#x}", ret)));
        }
        self.parse_exit()
    }

    fn regs(&self) -> Result<Regs> {
        let mut r = Regs::default();
        for i in 0u32..31 {
            r.x[i as usize] = self.get_reg(i)?;
        }
        r.pc     = self.get_reg(ffi::HV_REG_PC)?;
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
        self.set_sys_reg(ffi::HV_SYS_REG_TCR_EL1,   sr.data[1])?;
        self.set_sys_reg(ffi::HV_SYS_REG_TTBR0_EL1, sr.data[2])?;
        self.set_sys_reg(ffi::HV_SYS_REG_TTBR1_EL1, sr.data[3])?;
        self.set_sys_reg(ffi::HV_SYS_REG_MAIR_EL1,  sr.data[4])?;
        self.set_sys_reg(ffi::HV_SYS_REG_VBAR_EL1,  sr.data[5])?;
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
}
