#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc as rust_alloc;

mod alloc;
mod arch;
mod dll;
mod hypercall;
mod kobj;
mod ldr;
mod mm;
mod nt;
mod process;
mod sched;
mod teb;
mod timer;
mod vectors;

fn read_user_u64_debug(owner_pid: u32, va: u64) -> Option<u64> {
    if owner_pid == 0 || (va & 7) != 0 {
        return None;
    }
    let mut pa = crate::process::with_process(owner_pid, |p| {
        p.address_space
            .translate_user_va_for_access(va, crate::nt::state::VM_ACCESS_READ)
    })
    .flatten();
    if pa.is_none()
        && crate::nt::state::vm_handle_page_fault(owner_pid, va, crate::nt::state::VM_ACCESS_READ)
    {
        pa = crate::process::with_process(owner_pid, |p| {
            p.address_space
                .translate_user_va_for_access(va, crate::nt::state::VM_ACCESS_READ)
        })
        .flatten();
    }
    let pa = pa?;
    Some(unsafe { (pa as *const u64).read_volatile() })
}

fn read_user_u32_debug(owner_pid: u32, va: u64) -> Option<u32> {
    if owner_pid == 0 || (va & 3) != 0 {
        return None;
    }
    let mut pa = crate::process::with_process(owner_pid, |p| {
        p.address_space
            .translate_user_va_for_access(va, crate::nt::state::VM_ACCESS_READ)
    })
    .flatten();
    if pa.is_none()
        && crate::nt::state::vm_handle_page_fault(owner_pid, va, crate::nt::state::VM_ACCESS_READ)
    {
        pa = crate::process::with_process(owner_pid, |p| {
            p.address_space
                .translate_user_va_for_access(va, crate::nt::state::VM_ACCESS_READ)
        })
        .flatten();
    }
    let pa = pa?;
    Some(unsafe { (pa as *const u32).read_volatile() })
}

/// EL0 Data Abort / Instruction Abort handler.
/// Called from assembly with: far=faulting address, esr=syndrome, elr=faulting PC.
/// Returns 1 if fault resolved (demand paging), 0 if unresolvable.
#[no_mangle]
pub extern "C" fn el0_page_fault(far: u64, esr: u64, elr: u64, frame_ptr: u64) -> u64 {
    let ec = (esr >> 26) & 0x3F;
    let iss = esr & 0x01FF_FFFF;
    let fsc = iss & 0x3F;
    let wnr = (iss >> 6) & 1;

    let is_el0_abort = ec == 0x20 || ec == 0x24;
    let is_translation_fault = (0x04..=0x07).contains(&fsc);
    let is_access_flag_fault = fsc == 0x09 || fsc == 0x0B;
    let is_permission_fault = (0x0C..=0x0F).contains(&fsc);
    if is_el0_abort && (is_translation_fault || is_access_flag_fault || is_permission_fault) {
        let access = if ec == 0x20 {
            crate::nt::state::VM_ACCESS_EXEC
        } else if wnr != 0 {
            crate::nt::state::VM_ACCESS_WRITE
        } else {
            crate::nt::state::VM_ACCESS_READ
        };
        let owner_pid = crate::process::current_pid();
        if owner_pid != 0 && crate::nt::state::vm_handle_page_fault(owner_pid, far, access) {
            return 1;
        }
    }

    hypercall::debug_print("PAGE_FAULT_UNRESOLVED: ");
    hypercall::debug_u64(far);
    hypercall::debug_print(" ESR=");
    hypercall::debug_u64(esr);
    hypercall::debug_print(" ELR=");
    hypercall::debug_u64(elr);
    let owner_pid = crate::process::current_pid();
    hypercall::debug_print(" PID=");
    hypercall::debug_u64(owner_pid as u64);
        hypercall::debug_print(" TID=");
        hypercall::debug_u64(crate::sched::current_tid() as u64);
        let cur_tid = crate::sched::current_tid();
        if cur_tid != 0 && crate::sched::thread_exists(cur_tid) {
            crate::sched::with_thread(cur_tid, |t| {
                hypercall::debug_print(" LastTrapSP=");
                hypercall::debug_u64(t.ctx.sp);
                hypercall::debug_print(" LastTrapPC=");
                hypercall::debug_u64(t.ctx.pc);
            });
        } else {
            hypercall::debug_print(" LastTrapCtx=none");
        }
        if owner_pid != 0 {
            if let Some(info) = crate::nt::state::vm_query_region(owner_pid, far) {
                hypercall::debug_print(" Q.base=");
            hypercall::debug_u64(info.base);
            hypercall::debug_print(" Q.size=");
            hypercall::debug_u64(info.size);
            hypercall::debug_print(" Q.alloc_base=");
            hypercall::debug_u64(info.allocation_base);
            hypercall::debug_print(" Q.alloc_prot=");
            hypercall::debug_u64(info.allocation_prot as u64);
            hypercall::debug_print(" Q.prot=");
            hypercall::debug_u64(info.prot as u64);
            hypercall::debug_print(" Q.state=");
            hypercall::debug_u64(info.state as u64);
            hypercall::debug_print(" Q.type=");
            hypercall::debug_u64(info.mem_type as u64);
        } else {
            hypercall::debug_print(" Q.none");
            if let Some((any_owner, any_base, any_size, any_kind)) =
                crate::nt::state::vm_debug_find_region_any(far)
            {
                hypercall::debug_print(" AQ.owner=");
                hypercall::debug_u64(any_owner as u64);
                hypercall::debug_print(" AQ.base=");
                hypercall::debug_u64(any_base);
                hypercall::debug_print(" AQ.size=");
                hypercall::debug_u64(any_size);
                hypercall::debug_print(" AQ.kind=");
                hypercall::debug_u64(any_kind as u64);
            }
        }
    }
    if frame_ptr != 0 {
        let frame = frame_ptr as *const u64;
        let x0 = unsafe { frame.read_volatile() };
        let x1 = unsafe { frame.add(1).read_volatile() };
        let x2 = unsafe { frame.add(2).read_volatile() };
        let x3 = unsafe { frame.add(3).read_volatile() };
        let x4 = unsafe { frame.add(4).read_volatile() };
        let x18 = unsafe { frame.add(18).read_volatile() };
        let x29 = unsafe { frame.add(29).read_volatile() };
        let x30 = unsafe { frame.add(30).read_volatile() };
        // __el0_da frame saves SP_EL0 at +0x108 (index 33).
        let sp_el0 = unsafe { frame.add(33).read_volatile() };
        hypercall::debug_print(" X0=");
        hypercall::debug_u64(x0);
        hypercall::debug_print(" X1=");
        hypercall::debug_u64(x1);
        hypercall::debug_print(" X2=");
        hypercall::debug_u64(x2);
        hypercall::debug_print(" X3=");
        hypercall::debug_u64(x3);
        hypercall::debug_print(" X4=");
        hypercall::debug_u64(x4);
        hypercall::debug_print(" X18=");
        hypercall::debug_u64(x18);
        hypercall::debug_print(" SP=");
        hypercall::debug_u64(sp_el0);
        hypercall::debug_print(" X29=");
        hypercall::debug_u64(x29);
        hypercall::debug_print(" X30=");
        hypercall::debug_u64(x30);
        if owner_pid != 0 && x18 >= crate::process::USER_VA_BASE {
            if let Some(stack_base) =
                read_user_u64_debug(owner_pid, x18.saturating_add(winemu_shared::teb::STACK_BASE as u64))
            {
                hypercall::debug_print(" TEB.StackBase=");
                hypercall::debug_u64(stack_base);
            }
            if let Some(stack_limit) =
                read_user_u64_debug(owner_pid, x18.saturating_add(winemu_shared::teb::STACK_LIMIT as u64))
            {
                hypercall::debug_print(" TEB.StackLimit=");
                hypercall::debug_u64(stack_limit);
            }
        }
        if owner_pid != 0 && elr >= crate::process::USER_VA_BASE {
            if let Some(v) = read_user_u32_debug(owner_pid, elr.saturating_sub(8)) {
                hypercall::debug_print(" I-8=");
                hypercall::debug_u64(v as u64);
            }
            if let Some(v) = read_user_u32_debug(owner_pid, elr.saturating_sub(4)) {
                hypercall::debug_print(" I-4=");
                hypercall::debug_u64(v as u64);
            }
            if let Some(v) = read_user_u32_debug(owner_pid, elr) {
                hypercall::debug_print(" I0=");
                hypercall::debug_u64(v as u64);
            }
            if let Some(v) = read_user_u32_debug(owner_pid, elr.saturating_add(4)) {
                hypercall::debug_print(" I+4=");
                hypercall::debug_u64(v as u64);
            }
        }
        if x29 != 0 && owner_pid != 0 {
            let fp1 = read_user_u64_debug(owner_pid, x29);
            let lr0 = read_user_u64_debug(owner_pid, x29.saturating_add(8));
            if let Some(lr0) = lr0 {
                hypercall::debug_print(" LR0=");
                hypercall::debug_u64(lr0);
            }
            if let Some(fp1) = fp1 {
                if fp1 != 0 {
                    if let Some(lr1) = read_user_u64_debug(owner_pid, fp1.saturating_add(8)) {
                        hypercall::debug_print(" LR1=");
                        hypercall::debug_u64(lr1);
                    }
                }
            }
        }
        if owner_pid != 0 && sp_el0 >= crate::process::USER_VA_BASE {
            if let Some(v) = read_user_u64_debug(owner_pid, sp_el0.saturating_add(0x48)) {
                hypercall::debug_print(" SP+48=");
                hypercall::debug_u64(v);
            }
            if let Some(v) = read_user_u64_debug(owner_pid, sp_el0.saturating_add(0x108)) {
                hypercall::debug_print(" SP+108=");
                hypercall::debug_u64(v);
            }
            if let Some(v) = read_user_u64_debug(owner_pid, sp_el0.saturating_add(0x1e8)) {
                hypercall::debug_print(" SP+1E8=");
                hypercall::debug_u64(v);
            }
            if let Some(v) = read_user_u64_debug(owner_pid, sp_el0.saturating_add(0x208)) {
                hypercall::debug_print(" SP+208=");
                hypercall::debug_u64(v);
            }
        }
    }
    hypercall::debug_print("\n");
    hypercall::process_exit(0xFF)
}

/// EL1 synchronous exception handler for kernel faults.
/// Called from vectors with: far=fault address, esr=syndrome, elr=faulting PC.
#[no_mangle]
pub extern "C" fn el1_sync_fault(far: u64, esr: u64, elr: u64) -> ! {
    let insn_m2 = unsafe { (elr.wrapping_sub(8) as *const u32).read_volatile() as u64 };
    let insn_m1 = unsafe { (elr.wrapping_sub(4) as *const u32).read_volatile() as u64 };
    let insn = unsafe { (elr as *const u32).read_volatile() as u64 };
    let insn_p1 = unsafe { (elr.wrapping_add(4) as *const u32).read_volatile() as u64 };
    let insn_p2 = unsafe { (elr.wrapping_add(8) as *const u32).read_volatile() as u64 };
    hypercall::debug_print("KERNEL_FAULT: FAR=");
    hypercall::debug_u64(far);
    hypercall::debug_print(" ESR=");
    hypercall::debug_u64(esr);
    hypercall::debug_print(" ELR=");
    hypercall::debug_u64(elr);
    hypercall::debug_print(" INSN=");
    hypercall::debug_u64(insn);
    hypercall::debug_print(" WIN=");
    hypercall::debug_u64(insn_m2);
    hypercall::debug_print(",");
    hypercall::debug_u64(insn_m1);
    hypercall::debug_print(",");
    hypercall::debug_u64(insn);
    hypercall::debug_print(",");
    hypercall::debug_u64(insn_p1);
    hypercall::debug_print(",");
    hypercall::debug_u64(insn_p2);
    hypercall::debug_print("\n");
    loop { core::hint::spin_loop(); }
}

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    hypercall::debug_print("kernel_main: start\n");
    // Install vectors early so MMU-init faults can be diagnosed.
    vectors::install();
    mm::init();
    hypercall::debug_print("kernel_main: mmu ok\n");
    alloc::init();

    // ── 1. 通过 host fd 加载 EXE ─────────────────────────────
    let (exe_fd, exe_size) = hypercall::query_exe_info();
    if exe_fd == u64::MAX || exe_size == 0 {
        hypercall::debug_print("kernel: query_exe_info failed\n");
        hypercall::process_exit(1);
    }

    {
        let mut buf = [0u8; 32];
        let s = fmt_u64_hex(&mut buf, exe_size);
        hypercall::debug_print("kernel: exe_size=0x");
        hypercall::debug_print(s);
        hypercall::debug_print("\n");
    }

    // 读取 PE 可选头栈参数：reserve/commit
    let (stack_reserve, stack_commit) = {
        let mut hdr = [0u8; 512];
        let got = hypercall::host_read(exe_fd, hdr.as_mut_ptr(), 512, 0);
        if got >= 80 {
            let lfanew = u32::from_le_bytes([hdr[60], hdr[61], hdr[62], hdr[63]]) as usize;
            let oh = lfanew + 24;
            if oh + 88 <= got {
                let reserve = u64::from_le_bytes(hdr[oh + 72..oh + 80].try_into().unwrap_or([0; 8]));
                let commit = u64::from_le_bytes(hdr[oh + 80..oh + 88].try_into().unwrap_or([0; 8]));
                (reserve, commit)
            } else { (0x10_0000, 0x1000) }
        } else { (0x10_0000, 0x1000) }
    };

    hypercall::debug_print("kernel: calling ldr::load_from_fd\n");

    let loaded = unsafe { ldr::load_from_fd(exe_fd, exe_size, |dll_name, imp| dll::resolve_import(dll_name, imp)) };

    // 关闭 exe fd
    hypercall::host_close(exe_fd);

    let loaded = match loaded {
        Ok(img) => img,
        Err(_) => {
            hypercall::debug_print("kernel: PE load failed\n");
            hypercall::process_exit(1);
        }
    };

    // ── 3. 先建立 boot process，再在其地址空间初始化 TEB / PEB / 栈 ──
    if !process::init_boot_process(loaded.base, 0) {
        hypercall::debug_print("kernel: boot process init failed\n");
        hypercall::process_exit(1);
    }
    let boot_pid = process::boot_pid();
    if boot_pid == 0 {
        hypercall::debug_print("kernel: boot pid invalid\n");
        hypercall::process_exit(1);
    }

    let teb_peb = match teb::init(
        loaded.base,
        boot_pid,
        1,
        stack_reserve,
        stack_commit,
        "C:\\app.exe",
        "app.exe",
    ) {
        Some(t) => t,
        None => {
            hypercall::debug_print("kernel: teb init failed\n");
            hypercall::process_exit(1);
        }
    };

    if !process::init_boot_process(loaded.base, teb_peb.peb_va) {
        hypercall::debug_print("kernel: boot process update failed\n");
        hypercall::process_exit(1);
    }

    // ── 4. 通知 VMM 创建 Thread 0 ───────────────────────────
    let app_entry_va = loaded.base + loaded.entry_rva as u64;
    let entry_va = dll::resolve_import("ntdll.dll", ldr::ImportRef::Name("RtlUserThreadStart"))
        .unwrap_or(app_entry_va);
    if entry_va == app_entry_va {
        hypercall::debug_print("kernel: start thunk missing, fallback to app entry\n");
    } else {
        hypercall::debug_print("kernel: start thunk=");
        hypercall::debug_u64(entry_va);
        hypercall::debug_print(" app=");
        hypercall::debug_u64(app_entry_va);
        hypercall::debug_print("\n");
    }
    hypercall::debug_print("kernel: calling kernel_ready\n");
    hypercall::kernel_ready(entry_va, teb_peb.stack_base, teb_peb.teb_va, crate::alloc::heap_end());

    loop { core::hint::spin_loop(); }
}

fn fmt_u64_hex<'a>(buf: &'a mut [u8; 32], val: u64) -> &'a str {
    let hex = b"0123456789abcdef";
    for i in 0..16usize {
        let shift = (15 - i) * 4;
        buf[i] = hex[((val >> shift) & 0xF) as usize];
    }
    core::str::from_utf8(&buf[..16]).unwrap()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    hypercall::debug_print("KERNEL_PANIC");
    if let Some(loc) = info.location() {
        hypercall::debug_print(" at ");
        hypercall::debug_print(loc.file());
        hypercall::debug_print(":");
        let mut buf = [0u8; 32];
        let s = fmt_u64_dec(&mut buf, loc.line() as u64);
        hypercall::debug_print(s);
    }
    hypercall::debug_print("\n");
    loop { core::hint::spin_loop(); }
}

fn fmt_u64_dec<'a>(buf: &'a mut [u8; 32], mut val: u64) -> &'a str {
    if val == 0 {
        buf[0] = b'0';
        return core::str::from_utf8(&buf[..1]).unwrap_or("0");
    }
    let mut i = buf.len();
    while val != 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    core::str::from_utf8(&buf[i..]).unwrap_or("0")
}
