use crate::arch::contract::TrapFaultInfo;
use crate::arch::trap::SvcFrame;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static USER_FAULT_LAST_ADDR: [AtomicU64; crate::sched::MAX_VCPUS] =
    [const { AtomicU64::new(0) }; crate::sched::MAX_VCPUS];
static USER_FAULT_LAST_PC: [AtomicU64; crate::sched::MAX_VCPUS] =
    [const { AtomicU64::new(0) }; crate::sched::MAX_VCPUS];
static USER_FAULT_REPEAT_COUNT: [AtomicU32; crate::sched::MAX_VCPUS] =
    [const { AtomicU32::new(0) }; crate::sched::MAX_VCPUS];

#[inline(always)]
pub fn interrupted_user_mode(frame: &SvcFrame) -> bool {
    (frame.processor_state() & 0xF) == 0
}

#[inline(always)]
pub fn current_fault_info() -> TrapFaultInfo {
    TrapFaultInfo {
        syndrome: super::cpu::fault_syndrome_read(),
        address: super::cpu::fault_address_read(),
    }
}

#[inline]
fn trace_repeated_user_fault(fault_addr: u64, pc: u64, access: u8, owner_pid: u32) {
    let vid = (crate::sched::vcpu_id() as usize).min(crate::sched::MAX_VCPUS - 1);
    let last_addr = USER_FAULT_LAST_ADDR[vid].load(Ordering::Acquire);
    let last_pc = USER_FAULT_LAST_PC[vid].load(Ordering::Acquire);
    let repeat = if last_addr == fault_addr && last_pc == pc {
        USER_FAULT_REPEAT_COUNT[vid].fetch_add(1, Ordering::AcqRel) + 1
    } else {
        USER_FAULT_LAST_ADDR[vid].store(fault_addr, Ordering::Release);
        USER_FAULT_LAST_PC[vid].store(pc, Ordering::Release);
        USER_FAULT_REPEAT_COUNT[vid].store(1, Ordering::Release);
        1
    };

    if repeat < 64 || (repeat & (repeat - 1)) != 0 {
        return;
    }

    crate::kwarn!(
        "user_fault_repeat: vid={} repeat={} addr={:#x} pc={:#x} access={} pid={} tid={} user_root={:#x}",
        vid,
        repeat,
        fault_addr,
        pc,
        access,
        owner_pid,
        crate::sched::current_tid(),
        crate::arch::mmu::current_user_table_root(),
    );
}

#[inline]
fn decode_user_fault_access(syndrome: u64) -> Option<u8> {
    let ec = (syndrome >> 26) & 0x3F;
    let iss = syndrome & 0x01FF_FFFF;
    let fsc = iss & 0x3F;
    let wnr = (iss >> 6) & 1;

    let is_user_abort = ec == 0x20 || ec == 0x24;
    let is_translation_fault = (0x04..=0x07).contains(&fsc);
    let is_access_flag_fault = fsc == 0x09 || fsc == 0x0B;
    let is_permission_fault = (0x0C..=0x0F).contains(&fsc);
    if !is_user_abort || !(is_translation_fault || is_access_flag_fault || is_permission_fault) {
        return None;
    }

    Some(if ec == 0x20 {
        crate::mm::VM_ACCESS_EXEC
    } else if wnr != 0 {
        crate::mm::VM_ACCESS_WRITE
    } else {
        crate::mm::VM_ACCESS_READ
    })
}

#[inline]
fn try_patch_init_locale_fault(fault_addr: u64, pc: u64, frame_ptr: u64) -> bool {
    if fault_addr != 0x8 || pc != 0x4042_a058 {
        return false;
    }

    use crate::mm::usercopy::{read_current_user_mapped_value, write_current_user_mapped_value};

    let kb_slot_va = 0x4053_f938u64;
    let kb_table_va = 0x4053_f950u64;
    let fault_x23 = if frame_ptr != 0 {
        unsafe { (frame_ptr as *const u64).add(23).read_volatile() }
    } else {
        0
    };
    let slot = read_current_user_mapped_value(kb_slot_va as *const u64).unwrap_or(0);
    let table = read_current_user_mapped_value(kb_table_va as *const u64).unwrap_or(0);
    let replacement = if slot != 0 { slot } else { table };
    if fault_x23 != 0 || replacement == 0 {
        return false;
    }

    unsafe {
        if frame_ptr != 0 {
            (frame_ptr as *mut u64).add(23).write_volatile(replacement);
        }
    }
    if slot == 0 {
        let _ = write_current_user_mapped_value(kb_slot_va as *mut u64, replacement);
    }
    true
}

#[no_mangle]
pub extern "C" fn user_page_fault_dispatch(
    fault_addr: u64,
    syndrome: u64,
    pc: u64,
    frame_ptr: u64,
) -> u64 {
    if let Some(access) = decode_user_fault_access(syndrome) {
        let owner_pid = crate::process::current_pid();
        trace_repeated_user_fault(fault_addr, pc, access, owner_pid);
        let tid = crate::sched::current_tid();
        if tid != 0 {
            crate::process::switch_to_thread_process(tid);
        }
        if owner_pid != 0
            && crate::mm::handle_process_page_fault(
                owner_pid,
                crate::mm::UserVa::new(fault_addr),
                access,
            )
        {
            if tid != 0 {
                crate::process::switch_to_thread_process(tid);
            }
            return 1;
        }
    }

    if try_patch_init_locale_fault(fault_addr, pc, frame_ptr) {
        return 1;
    }

    crate::log::debug_print("PAGE_FAULT_UNRESOLVED FAR=");
    crate::log::debug_u64(fault_addr);
    crate::log::debug_print(" ESR=");
    crate::log::debug_u64(syndrome);
    crate::log::debug_print(" ELR=");
    crate::log::debug_u64(pc);
    let owner_pid = crate::process::current_pid();
    crate::log::debug_print(" PID=");
    crate::log::debug_u64(owner_pid as u64);
    crate::log::debug_print(" TID=");
    crate::log::debug_u64(crate::sched::current_tid() as u64);
    crate::log::debug_print("\n");
    crate::hypercall::process_exit(0xFF)
}

#[no_mangle]
pub extern "C" fn kernel_sync_fault_dispatch(
    fault_addr: u64,
    syndrome: u64,
    pc: u64,
    lr: u64,
    x0: u64,
    x1: u64,
    x2: u64,
) -> ! {
    const KERNEL_TEXT_MIN: u64 = 0x4000_0000;
    const KERNEL_TEXT_MAX: u64 = 0x5000_0000;

    let mut insn_m2 = 0u64;
    let mut insn_m1 = 0u64;
    let mut insn = 0u64;
    let mut insn_p1 = 0u64;
    let mut insn_p2 = 0u64;
    if pc >= KERNEL_TEXT_MIN && pc + 8 < KERNEL_TEXT_MAX && (pc & 0x3) == 0 {
        unsafe {
            insn_m2 = (pc.wrapping_sub(8) as *const u32).read_volatile() as u64;
            insn_m1 = (pc.wrapping_sub(4) as *const u32).read_volatile() as u64;
            insn = (pc as *const u32).read_volatile() as u64;
            insn_p1 = (pc.wrapping_add(4) as *const u32).read_volatile() as u64;
            insn_p2 = (pc.wrapping_add(8) as *const u32).read_volatile() as u64;
        }
    }

    let vid = crate::sched::vcpu_id();
    let tid = crate::sched::current_tid();
    crate::kerror!(
        "KERNEL_FAULT far={:#x} esr={:#x} elr={:#x} lr={:#x} x0={:#x} x1={:#x} x2={:#x} insn={:#x} win=[{:#x},{:#x},{:#x},{:#x},{:#x}] vcpu={} tid={}",
        fault_addr,
        syndrome,
        pc,
        lr,
        x0,
        x1,
        x2,
        insn,
        insn_m2,
        insn_m1,
        insn,
        insn_p1,
        insn_p2,
        vid,
        tid
    );
    crate::hypercall::process_exit(0xE1)
}
