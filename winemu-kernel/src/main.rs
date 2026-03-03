#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc as rust_alloc;

mod alloc;
mod arch;
mod dll;
mod hypercall;
mod hostcall;
mod kobj;
mod ldr;
mod log;
mod mm;
mod nt;
mod process;
mod sched;
mod teb;
mod timer;
mod vectors;

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

    // kernelbase!init_locale compatibility:
    // Some startup paths dereference [x23+8] with x23==NULL while the module's
    // fallback slot is still zero but locale table pointer is already populated.
    // Patch slot from table and retry the faulting instruction once.
    if far == 0x8 && elr == 0x4042_a058 {
        let kb_slot_va = 0x4053_f938u64;
        let kb_table_va = 0x4053_f950u64;
        let fault_x23 = if frame_ptr != 0 {
            unsafe { (frame_ptr as *const u64).add(23).read_volatile() }
        } else {
            0
        };
        unsafe {
            let slot = (kb_slot_va as *const u64).read_volatile();
            let table = (kb_table_va as *const u64).read_volatile();
            let replacement = if slot != 0 { slot } else { table };
            if fault_x23 == 0 && replacement != 0 {
                if frame_ptr != 0 {
                    (frame_ptr as *mut u64).add(23).write_volatile(replacement);
                }
                if slot == 0 {
                    (kb_slot_va as *mut u64).write_volatile(replacement);
                }
                return 1;
            }
        }
    }

    crate::log::debug_print("PAGE_FAULT_UNRESOLVED FAR=");
    crate::log::debug_u64(far);
    crate::log::debug_print(" ESR=");
    crate::log::debug_u64(esr);
    crate::log::debug_print(" ELR=");
    crate::log::debug_u64(elr);
    let owner_pid = crate::process::current_pid();
    crate::log::debug_print(" PID=");
    crate::log::debug_u64(owner_pid as u64);
    crate::log::debug_print(" TID=");
    crate::log::debug_u64(crate::sched::current_tid() as u64);
    crate::log::debug_print("\n");
    hypercall::process_exit(0xFF)
}

/// EL1 synchronous exception handler for kernel faults.
/// Called from vectors with: far=fault address, esr=syndrome, elr=faulting PC.
#[no_mangle]
pub extern "C" fn el1_sync_fault(far: u64, esr: u64, elr: u64) -> ! {
    const KERNEL_TEXT_MIN: u64 = 0x4000_0000;
    const KERNEL_TEXT_MAX: u64 = 0x5000_0000;
    let mut insn_m2 = 0u64;
    let mut insn_m1 = 0u64;
    let mut insn = 0u64;
    let mut insn_p1 = 0u64;
    let mut insn_p2 = 0u64;
    if elr >= KERNEL_TEXT_MIN
        && elr + 8 < KERNEL_TEXT_MAX
        && (elr & 0x3) == 0
    {
        insn_m2 = unsafe { (elr.wrapping_sub(8) as *const u32).read_volatile() as u64 };
        insn_m1 = unsafe { (elr.wrapping_sub(4) as *const u32).read_volatile() as u64 };
        insn = unsafe { (elr as *const u32).read_volatile() as u64 };
        insn_p1 = unsafe { (elr.wrapping_add(4) as *const u32).read_volatile() as u64 };
        insn_p2 = unsafe { (elr.wrapping_add(8) as *const u32).read_volatile() as u64 };
    }
    crate::log::debug_print("KERNEL_FAULT: FAR=");
    crate::log::debug_u64(far);
    crate::log::debug_print(" ESR=");
    crate::log::debug_u64(esr);
    crate::log::debug_print(" ELR=");
    crate::log::debug_u64(elr);
    crate::log::debug_print(" INSN=");
    crate::log::debug_u64(insn);
    crate::log::debug_print(" WIN=");
    crate::log::debug_u64(insn_m2);
    crate::log::debug_print(",");
    crate::log::debug_u64(insn_m1);
    crate::log::debug_print(",");
    crate::log::debug_u64(insn);
    crate::log::debug_print(",");
    crate::log::debug_u64(insn_p1);
    crate::log::debug_print(",");
    crate::log::debug_u64(insn_p2);
    crate::log::debug_print("\n");
    hypercall::process_exit(0xE1)
}

fn register_process_boot_file_mappings(owner_pid: u32, exe_base: u64, exe_size: u64) {
    if owner_pid == 0 {
        return;
    }
    if !crate::nt::state::vm_track_existing_file_mapping(
        owner_pid,
        exe_base,
        exe_size,
        crate::nt::state::VM_FILE_MAPPING_DEFAULT_PROT,
    ) {
        crate::kwarn!(
            "kernel: track exe file mapping failed base={:#x} size={:#x}",
            exe_base,
            exe_size
        );
    }
    dll::for_each_loaded(|_name, base, size, _entry| {
        if base == 0 || size == 0 {
            return;
        }
        if !crate::nt::state::vm_track_existing_file_mapping(
            owner_pid,
            base,
            size as u64,
            crate::nt::state::VM_FILE_MAPPING_DEFAULT_PROT,
        ) {
            crate::kwarn!(
                "kernel: track dll file mapping failed base={:#x} size={:#x}",
                base,
                size
            );
        }
    });
}

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    crate::kinfo!("kernel_main: start");
    // Install vectors early so MMU-init faults can be diagnosed.
    vectors::install();
    mm::init();
    crate::kinfo!("kernel_main: mmu ok");
    alloc::init();
    hostcall::init();
    if hypercall::hostcall_setup() != winemu_shared::hostcall::HC_OK {
        crate::kwarn!("kernel: hostcall setup failed");
    }

    // ── 1. 通过 host fd 加载 EXE ─────────────────────────────
    let (exe_fd, exe_size) = hypercall::query_exe_info();
    if exe_fd == u64::MAX || exe_size == 0 {
        crate::kerror!("kernel: query_exe_info failed");
        hypercall::process_exit(1);
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

    let loaded = unsafe { ldr::load_from_fd(exe_fd, exe_size, |dll_name, imp| dll::resolve_import(dll_name, imp)) };

    // 关闭 exe fd
    hypercall::host_close(exe_fd);

    let loaded = match loaded {
        Ok(img) => img,
        Err(_) => {
            crate::kerror!("kernel: PE load failed");
            hypercall::process_exit(1);
        }
    };

    // ── 3. 先建立 boot process，再在其地址空间初始化 TEB / PEB / 栈 ──
    if !process::init_boot_process(loaded.base, 0) {
        crate::kerror!("kernel: boot process init failed");
        hypercall::process_exit(1);
    }
    let boot_pid = process::boot_pid();
    if boot_pid == 0 {
        crate::kerror!("kernel: boot pid invalid");
        hypercall::process_exit(1);
    }
    register_process_boot_file_mappings(boot_pid, loaded.base, loaded.size as u64);

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
            crate::kerror!("kernel: teb init failed");
            hypercall::process_exit(1);
        }
    };

    if !process::init_boot_process(loaded.base, teb_peb.peb_va) {
        crate::kerror!("kernel: boot process update failed");
        hypercall::process_exit(1);
    }

    // ── 4. 通知 VMM 创建 Thread 0 ───────────────────────────
    let app_entry_va = loaded.base + loaded.entry_rva as u64;
    let entry_va = dll::resolve_import("ntdll.dll", ldr::ImportRef::Name("RtlUserThreadStart"))
        .unwrap_or(app_entry_va);
    if entry_va == app_entry_va {
        crate::kwarn!("kernel: start thunk missing, fallback to app entry");
    }
    hypercall::kernel_ready(entry_va, teb_peb.stack_base, teb_peb.teb_va, crate::alloc::heap_end());

    loop { core::hint::spin_loop(); }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::log::debug_print("KERNEL_PANIC");
    if let Some(loc) = info.location() {
        crate::log::debug_print(" at ");
        crate::log::debug_print(loc.file());
        crate::log::debug_print(":");
        let mut buf = [0u8; 32];
        let s = fmt_u64_dec(&mut buf, loc.line() as u64);
        crate::log::debug_print(s);
    }
    crate::log::debug_print("\n");
    let snap = crate::mm::kmalloc::snapshot();
    crate::kdebug!(
        "panic kmalloc: free_pages={} dyn_arenas={} dyn_pages={} direct_active={} alloc_fail={} small_oom={} large_oom={} direct_fail={}",
        snap.free_pages_total,
        snap.dynamic_arena_count,
        snap.dynamic_pages_total,
        snap.direct_active_allocs,
        snap.stats.alloc_failures,
        snap.alloc_fail_small_oom,
        snap.alloc_fail_large_oom,
        snap.direct_alloc_failures
    );
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
