#![allow(non_camel_case_types, dead_code)]

pub type hv_return_t = i32;
pub type hv_vcpuid_t = u64;
pub type hv_memory_flags_t = u64;
pub type hv_reg_t = u32;
pub type hv_sys_reg_t = u16;

pub const HV_SUCCESS: hv_return_t = 0;
pub const HV_EXIT_REASON_CANCELED: u32 = 0;
pub const HV_EXIT_REASON_EXCEPTION: u32 = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: u32 = 2;
pub const HV_MEMORY_READ: hv_memory_flags_t = 1 << 0;
pub const HV_MEMORY_WRITE: hv_memory_flags_t = 1 << 1;
pub const HV_MEMORY_EXEC: hv_memory_flags_t = 1 << 2;
pub const HV_INTERRUPT_TYPE_IRQ: u32 = 0;

// ARM64 system register IDs (from <Hypervisor/hv_vcpu_types.h>)
pub const HV_SYS_REG_SCTLR_EL1: u16 = 0xc080;
pub const HV_SYS_REG_TTBR0_EL1: u16 = 0xc100;
pub const HV_SYS_REG_TTBR1_EL1: u16 = 0xc101;
pub const HV_SYS_REG_TCR_EL1: u16 = 0xc102;
pub const HV_SYS_REG_SPSR_EL1: u16 = 0xc200;
pub const HV_SYS_REG_ELR_EL1: u16 = 0xc201;
pub const HV_SYS_REG_SP_EL0: u16 = 0xc208;
pub const HV_SYS_REG_ESR_EL1: u16 = 0xc290;
pub const HV_SYS_REG_FAR_EL1: u16 = 0xc300;
pub const HV_SYS_REG_MAIR_EL1: u16 = 0xc510;
pub const HV_SYS_REG_VBAR_EL1: u16 = 0xc600;
pub const HV_SYS_REG_SP_EL1: u16 = 0xe208;
pub const HV_SYS_REG_CPACR_EL1: u16 = 0xc082;
pub const HV_SYS_REG_CNTV_CTL_EL0: u16 = 0xdf19;
pub const HV_SYS_REG_CNTV_CVAL_EL0: u16 = 0xdf1a;

#[repr(C)]
pub struct hv_vcpu_exit_t {
    pub reason: u32,
    pub _pad: u32, // Apple SDK has 4 bytes padding before exception
    pub exception: hv_vcpu_exit_exception_t,
}

#[repr(C)]
pub struct hv_vcpu_exit_exception_t {
    pub syndrome: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[repr(C)]
pub struct mach_timebase_info_data_t {
    pub numer: u32,
    pub denom: u32,
}

extern "C" {
    pub fn hv_vm_create(config: *mut std::ffi::c_void) -> hv_return_t;
    pub fn hv_vm_destroy() -> hv_return_t;
    pub fn hv_vm_map(uva: *mut u8, gpa: u64, size: usize, flags: hv_memory_flags_t) -> hv_return_t;
    pub fn hv_vm_unmap(gpa: u64, size: usize) -> hv_return_t;

    pub fn hv_vcpu_create(
        vcpu: *mut hv_vcpuid_t,
        exit: *mut *const hv_vcpu_exit_t,
        config: *mut std::ffi::c_void,
    ) -> hv_return_t;
    pub fn hv_vcpu_destroy(vcpu: hv_vcpuid_t) -> hv_return_t;
    pub fn hv_vcpu_run(vcpu: hv_vcpuid_t) -> hv_return_t;
    pub fn hv_vcpus_exit(vcpus: *mut hv_vcpuid_t, vcpu_count: u32) -> hv_return_t;

    pub fn hv_vcpu_get_reg(vcpu: hv_vcpuid_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_reg(vcpu: hv_vcpuid_t, reg: hv_reg_t, value: u64) -> hv_return_t;
    pub fn hv_vcpu_get_sys_reg(
        vcpu: hv_vcpuid_t,
        reg: hv_sys_reg_t,
        value: *mut u64,
    ) -> hv_return_t;
    pub fn hv_vcpu_set_sys_reg(vcpu: hv_vcpuid_t, reg: hv_sys_reg_t, value: u64) -> hv_return_t;
    pub fn hv_vcpu_set_pending_interrupt(
        vcpu: hv_vcpuid_t,
        r#type: u32,
        pending: bool,
    ) -> hv_return_t;
    pub fn hv_vcpu_set_vtimer_mask(vcpu: hv_vcpuid_t, vtimer_is_masked: bool) -> hv_return_t;
    pub fn hv_vcpu_get_vtimer_offset(vcpu: hv_vcpuid_t, vtimer_offset: *mut u64) -> hv_return_t;

    pub fn mach_absolute_time() -> u64;
    pub fn mach_timebase_info(info: *mut mach_timebase_info_data_t) -> i32;
}

// ARM64 general-purpose register IDs (hv_reg_t = u32)
pub const HV_REG_X0: u32 = 0;
pub const HV_REG_X1: u32 = 1;
pub const HV_REG_X2: u32 = 2;
pub const HV_REG_X3: u32 = 3;
pub const HV_REG_X4: u32 = 4;
pub const HV_REG_X5: u32 = 5;
pub const HV_REG_X6: u32 = 6;
pub const HV_REG_X7: u32 = 7;
pub const HV_REG_X8: u32 = 8;
pub const HV_REG_X9: u32 = 9;
pub const HV_REG_X10: u32 = 10;
pub const HV_REG_X11: u32 = 11;
pub const HV_REG_X12: u32 = 12;
pub const HV_REG_X13: u32 = 13;
pub const HV_REG_X14: u32 = 14;
pub const HV_REG_X15: u32 = 15;
pub const HV_REG_X16: u32 = 16;
pub const HV_REG_X17: u32 = 17;
pub const HV_REG_X18: u32 = 18;
pub const HV_REG_X19: u32 = 19;
pub const HV_REG_X20: u32 = 20;
pub const HV_REG_X21: u32 = 21;
pub const HV_REG_X22: u32 = 22;
pub const HV_REG_X23: u32 = 23;
pub const HV_REG_X24: u32 = 24;
pub const HV_REG_X25: u32 = 25;
pub const HV_REG_X26: u32 = 26;
pub const HV_REG_X27: u32 = 27;
pub const HV_REG_X28: u32 = 28;
pub const HV_REG_X29: u32 = 29;
pub const HV_REG_X30: u32 = 30;
pub const HV_REG_PC: u32 = 31;
pub const HV_REG_FPCR: u32 = 32;
pub const HV_REG_FPSR: u32 = 33;
pub const HV_REG_CPSR: u32 = 34;
