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

#[inline]
fn user_fault_frame_read_u64(frame_ptr: u64, offset: usize) -> u64 {
    if frame_ptr == 0 {
        return 0;
    }
    let Some(addr) = frame_ptr.checked_add(offset as u64) else {
        return 0;
    };
    // SAFETY: `frame_ptr` is produced by the EL0 sync vector and points to the
    // saved user fault frame on the current thread stack for the duration of
    // this dispatch.
    unsafe { (addr as *const u64).read_volatile() }
}

#[inline]
fn read_user_u8(pid: u32, va: u64) -> Option<u8> {
    crate::mm::usercopy::read_user_at(pid, crate::mm::UserVa::new(va))
}

#[inline]
fn read_user_u64(pid: u32, va: u64) -> Option<u64> {
    let mut out = 0u64;
    for i in 0..8u64 {
        out |= (read_user_u8(pid, va.checked_add(i)?)? as u64) << (i * 8);
    }
    Some(out)
}

#[inline]
fn read_user_ascii(pid: u32, ptr: u64, buf: &mut [u8]) -> Option<usize> {
    if ptr == 0 || buf.is_empty() {
        return None;
    }
    let mut len = 0usize;
    while len < buf.len() {
        let ch = read_user_u8(pid, ptr.checked_add(len as u64)?)?;
        if ch == 0 {
            return if len == 0 { None } else { Some(len) };
        }
        if !(0x20..=0x7e).contains(&ch) {
            return None;
        }
        buf[len] = ch;
        len += 1;
    }
    None
}

#[inline]
fn log_user_fault_region(owner_pid: u32, label: &str, addr: u64) {
    let Some(info) = crate::mm::vm_query_region(owner_pid, crate::mm::UserVa::new(addr)) else {
        crate::kerror!(
            "user_fault_region: {} addr={:#x} region=none",
            label,
            addr
        );
        return;
    };
    crate::kerror!(
        "user_fault_region: {} addr={:#x} base={:#x} size={:#x} alloc_base={:#x} alloc_prot={:#x} prot={:#x} state={:#x} type={:#x}",
        label,
        addr,
        info.base.get(),
        info.size,
        info.allocation_base.get(),
        info.allocation_prot,
        info.prot,
        info.state,
        info.mem_type
    );
}

#[inline]
fn log_user_fault_thread_stack(owner_pid: u32, sp: u64) {
    let tid = crate::sched::current_tid();
    let Some((thread_stack_base, thread_stack_size, teb_va)) =
        crate::sched::with_thread(tid, |t| (t.stack_base, t.stack_size, t.teb_va))
    else {
        return;
    };
    crate::kerror!(
        "user_fault_thread: pid={} tid={} sp={:#x} stack_base={:#x} stack_size={:#x} teb={:#x}",
        owner_pid,
        tid,
        sp,
        thread_stack_base,
        thread_stack_size,
        teb_va
    );
    if teb_va == 0 {
        return;
    }
    let teb_stack_base =
        read_user_u64(owner_pid, teb_va.saturating_add(winemu_shared::teb::STACK_BASE as u64))
            .unwrap_or(0);
    let teb_stack_limit =
        read_user_u64(owner_pid, teb_va.saturating_add(winemu_shared::teb::STACK_LIMIT as u64))
            .unwrap_or(0);
    crate::kerror!(
        "user_fault_teb_stack: teb={:#x} stack_base={:#x} stack_limit={:#x}",
        teb_va,
        teb_stack_base,
        teb_stack_limit
    );
    let path_saved_fp = read_user_u64(owner_pid, sp.saturating_add(0x840)).unwrap_or(0);
    let path_saved_lr = read_user_u64(owner_pid, sp.saturating_add(0x848)).unwrap_or(0);
    let wrapper_saved_lr = read_user_u64(owner_pid, sp.saturating_add(0x850)).unwrap_or(0);
    let wrapper_caller_sp = sp.saturating_add(0x860);
    let caller_saved_fp = read_user_u64(owner_pid, sp.saturating_add(0x960)).unwrap_or(0);
    let caller_saved_lr = read_user_u64(owner_pid, sp.saturating_add(0x968)).unwrap_or(0);
    let caller_entry_sp = sp.saturating_add(0x970);
    crate::kerror!(
        "user_fault_stack_frames: path_saved_fp={:#x} path_saved_lr={:#x} wrapper_saved_lr={:#x} wrapper_caller_sp={:#x} caller_saved_fp={:#x} caller_saved_lr={:#x} caller_entry_sp={:#x}",
        path_saved_fp,
        path_saved_lr,
        wrapper_saved_lr,
        wrapper_caller_sp,
        caller_saved_fp,
        caller_saved_lr,
        caller_entry_sp
    );
    if path_saved_lr != 0 {
        log_loaded_module_for_addr("path_saved_lr", path_saved_lr);
    }
    if wrapper_saved_lr != 0 {
        log_loaded_module_for_addr("wrapper_saved_lr", wrapper_saved_lr);
    }
    if caller_saved_lr != 0 {
        log_loaded_module_for_addr("caller_saved_lr", caller_saved_lr);
    }
}

#[inline]
fn log_loaded_module_for_addr(label: &str, addr: u64) {
    let mut matched = false;
    crate::dll::for_each_loaded(|name, base, size, entry| {
        if matched || size == 0 {
            return;
        }
        let end = base.saturating_add(size as u64);
        if addr < base || addr >= end {
            return;
        }
        matched = true;
        crate::kerror!(
            "user_fault_module: {} addr={:#x} module={} base={:#x} size={:#x} entry={:#x}",
            label,
            addr,
            name,
            base,
            size,
            entry
        );
    });
    if !matched {
        crate::kerror!(
            "user_fault_module: {} addr={:#x} module=none",
            label,
            addr
        );
    }
}

#[inline]
fn log_user_ascii_ptr(owner_pid: u32, label: &str, ptr: u64) {
    let mut buf = [0u8; 64];
    let Some(len) = read_user_ascii(owner_pid, ptr, &mut buf) else {
        return;
    };
    let Ok(text) = core::str::from_utf8(&buf[..len]) else {
        return;
    };
    crate::kerror!(
        "user_fault_ptr: {}={:#x} ascii=\"{}\"",
        label,
        ptr,
        text
    );
}

#[inline]
fn log_user_fp_chain(owner_pid: u32, mut fp: u64, max_depth: usize) {
    for depth in 0..max_depth {
        if fp == 0 {
            break;
        }
        let Some(next_fp) = read_user_u64(owner_pid, fp) else {
            crate::kerror!("user_fault_bt[{}]: fp={:#x} unreadable", depth, fp);
            break;
        };
        let Some(ret) = read_user_u64(owner_pid, fp.saturating_add(8)) else {
            crate::kerror!("user_fault_bt[{}]: fp={:#x} ret=unreadable", depth, fp);
            break;
        };
        crate::kerror!(
            "user_fault_bt[{}]: fp={:#x} ret={:#x}",
            depth,
            fp,
            ret
        );
        if ret != 0 {
            log_loaded_module_for_addr("bt", ret);
        }
        if next_fp <= fp {
            break;
        }
        fp = next_fp;
    }
}

#[inline]
fn log_user_fault_translation_state(owner_pid: u32, fault_addr: u64, pc: u64, lr: u64) {
    let current_root = crate::arch::mmu::current_user_table_root();
    let expected_root =
        crate::process::with_process(owner_pid, |p| p.address_space.ttbr0()).unwrap_or(0);
    let current_elr_pa =
        crate::mm::address_space::translate_current_user_va_for_access(
            crate::mm::UserVa::new(pc),
            crate::mm::VM_ACCESS_EXEC,
        )
        .map(|pa| pa.get())
        .unwrap_or(0);
    let owner_elr_pa = crate::mm::usercopy::translate_user_va(
        owner_pid,
        crate::mm::UserVa::new(pc),
        crate::mm::VM_ACCESS_EXEC,
    )
    .map(|pa| pa.get())
    .unwrap_or(0);
    let current_far_pa =
        crate::mm::address_space::translate_current_user_va_for_access(
            crate::mm::UserVa::new(fault_addr),
            crate::mm::VM_ACCESS_EXEC,
        )
        .map(|pa| pa.get())
        .unwrap_or(0);
    let owner_far_pa = crate::mm::usercopy::translate_user_va(
        owner_pid,
        crate::mm::UserVa::new(fault_addr),
        crate::mm::VM_ACCESS_EXEC,
    )
    .map(|pa| pa.get())
    .unwrap_or(0);
    let current_lr_pa =
        crate::mm::address_space::translate_current_user_va_for_access(
            crate::mm::UserVa::new(lr),
            crate::mm::VM_ACCESS_EXEC,
        )
        .map(|pa| pa.get())
        .unwrap_or(0);
    let owner_lr_pa = crate::mm::usercopy::translate_user_va(
        owner_pid,
        crate::mm::UserVa::new(lr),
        crate::mm::VM_ACCESS_EXEC,
    )
    .map(|pa| pa.get())
    .unwrap_or(0);
    crate::kerror!(
        "user_fault_xlate: current_root={:#x} expected_root={:#x} far_cur={:#x} far_owner={:#x} elr_cur={:#x} elr_owner={:#x} lr_cur={:#x} lr_owner={:#x}",
        current_root,
        expected_root,
        current_far_pa,
        owner_far_pa,
        current_elr_pa,
        owner_elr_pa,
        current_lr_pa,
        owner_lr_pa
    );
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

    let owner_pid = crate::process::current_pid();
    let lr = user_fault_frame_read_u64(frame_ptr, 0x0f0);
    let fp = user_fault_frame_read_u64(frame_ptr, 0x0e8);
    let sp = user_fault_frame_read_u64(frame_ptr, 0x108);
    let x0 = user_fault_frame_read_u64(frame_ptr, 0x000);
    let x1 = user_fault_frame_read_u64(frame_ptr, 0x008);
    let x2 = user_fault_frame_read_u64(frame_ptr, 0x010);
    let x3 = user_fault_frame_read_u64(frame_ptr, 0x018);
    let x18 = user_fault_frame_read_u64(frame_ptr, 0x090);
    let x19 = user_fault_frame_read_u64(frame_ptr, 0x098);
    let x20 = user_fault_frame_read_u64(frame_ptr, 0x0a0);
    let x21 = user_fault_frame_read_u64(frame_ptr, 0x0a8);
    let x22 = user_fault_frame_read_u64(frame_ptr, 0x0b0);
    let x23 = user_fault_frame_read_u64(frame_ptr, 0x0b8);
    let tpidr = user_fault_frame_read_u64(frame_ptr, 0x118);
    let image_base = crate::process::with_process(owner_pid, |p| p.image_base).unwrap_or(0);
    crate::kerror!(
        "PAGE_FAULT_UNRESOLVED far={:#x} esr={:#x} elr={:#x} lr={:#x} fp={:#x} sp={:#x} x0={:#x} x1={:#x} x2={:#x} x3={:#x} x18={:#x} x19={:#x} x20={:#x} x21={:#x} x22={:#x} x23={:#x} tpidr={:#x} pid={} tid={} image_base={:#x}",
        fault_addr,
        syndrome,
        pc,
        lr,
        fp,
        sp,
        x0,
        x1,
        x2,
        x3,
        x18,
        x19,
        x20,
        x21,
        x22,
        x23,
        tpidr,
        owner_pid,
        crate::sched::current_tid(),
        image_base
    );
    log_user_fault_thread_stack(owner_pid, sp);
    log_user_fault_translation_state(owner_pid, fault_addr, pc, lr);
    log_user_fault_region(owner_pid, "far", fault_addr);
    log_user_fault_region(owner_pid, "sp", sp);
    log_user_fault_region(owner_pid, "x0", x0);
    log_user_fault_region(owner_pid, "elr", pc);
    if lr != 0 {
        log_user_fault_region(owner_pid, "lr", lr);
    }
    log_loaded_module_for_addr("elr", pc);
    if lr != 0 {
        log_loaded_module_for_addr("lr", lr);
    }
    log_loaded_module_for_addr("x18", x18);
    log_loaded_module_for_addr("x19", x19);
    log_loaded_module_for_addr("x20", x20);
    log_loaded_module_for_addr("x21", x21);
    log_loaded_module_for_addr("x23", x23);
    log_user_ascii_ptr(owner_pid, "x0", x0);
    log_user_ascii_ptr(owner_pid, "x1", x1);
    log_user_ascii_ptr(owner_pid, "x19", x19);
    log_user_fp_chain(owner_pid, fp, 8);
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
