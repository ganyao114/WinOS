#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc as rust_alloc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

mod alloc;
mod arch;
mod dll;
mod hostcall;
mod hypercall;
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

#[no_mangle]
pub static __boot_primary_ready: AtomicU32 = AtomicU32::new(0);
static EL0_FAULT_LAST_FAR: [AtomicU64; sched::MAX_VCPUS] =
    [const { AtomicU64::new(0) }; sched::MAX_VCPUS];
static EL0_FAULT_LAST_ELR: [AtomicU64; sched::MAX_VCPUS] =
    [const { AtomicU64::new(0) }; sched::MAX_VCPUS];
static EL0_FAULT_REPEAT_COUNT: [AtomicU32; sched::MAX_VCPUS] =
    [const { AtomicU32::new(0) }; sched::MAX_VCPUS];

#[inline]
fn trace_el0_fault_repeat(far: u64, elr: u64, access: u8, owner_pid: u32) {
    let vid = (sched::vcpu_id() as usize).min(sched::MAX_VCPUS - 1);
    let last_far = EL0_FAULT_LAST_FAR[vid].load(Ordering::Acquire);
    let last_elr = EL0_FAULT_LAST_ELR[vid].load(Ordering::Acquire);
    let repeat = if last_far == far && last_elr == elr {
        EL0_FAULT_REPEAT_COUNT[vid].fetch_add(1, Ordering::AcqRel) + 1
    } else {
        EL0_FAULT_LAST_FAR[vid].store(far, Ordering::Release);
        EL0_FAULT_LAST_ELR[vid].store(elr, Ordering::Release);
        EL0_FAULT_REPEAT_COUNT[vid].store(1, Ordering::Release);
        1
    };

    if repeat < 64 || (repeat & (repeat - 1)) != 0 {
        return;
    }

    crate::kwarn!(
        "el0_fault_repeat: vid={} repeat={} far={:#x} elr={:#x} access={} pid={} tid={} ttbr0={:#x}",
        vid,
        repeat,
        far,
        elr,
        access,
        owner_pid,
        crate::sched::current_tid(),
        crate::arch::mmu::current_user_table_root(),
    );
}

#[inline(always)]
fn set_primary_boot_ready() {
    __boot_primary_ready.store(1, Ordering::Release);
    crate::arch::cpu::send_event();
}

#[inline(always)]
fn boot_vcpu_id_from_mpidr() -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        let mpidr: u64;
        unsafe {
            core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack, nomem));
        }
        let aff0 = (mpidr & 0xff) as u32;
        return aff0.min((sched::MAX_VCPUS - 1) as u32);
    }
    #[allow(unreachable_code)]
    0
}

#[no_mangle]
pub extern "C" fn kernel_secondary_main() -> ! {
    // Secondary CPUs must install vectors locally and then participate in the
    // kernel scheduler idle path. Waiting in bare WFE would never pick ready
    // threads.
    vectors::install();
    // MMU/system control registers are per-CPU; secondary CPUs need local MMU
    // init before touching scheduler global state under virtual addresses.
    mm::init_per_cpu();
    // TPIDR_EL1 must be initialized before any scheduler API usage.
    let boot_vid = boot_vcpu_id_from_mpidr();
    sched::init_cpu_local(boot_vid);
    let vid = (sched::vcpu_id() as usize).min(sched::MAX_VCPUS - 1);
    sched::register_idle_thread_for_vcpu(vid as u32);
    sched::enter_core_scheduler_entry(vid)
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
            crate::mm::VM_ACCESS_EXEC
        } else if wnr != 0 {
            crate::mm::VM_ACCESS_WRITE
        } else {
            crate::mm::VM_ACCESS_READ
        };
        let owner_pid = crate::process::current_pid();
        trace_el0_fault_repeat(far, elr, access, owner_pid);
        let tid = crate::sched::current_tid();
        if tid != 0 {
            crate::process::switch_to_thread_process(tid);
        }
        if owner_pid != 0
            && crate::mm::handle_process_page_fault(owner_pid, crate::mm::UserVa::new(far), access)
        {
            if tid != 0 {
                crate::process::switch_to_thread_process(tid);
            }
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
pub extern "C" fn el1_sync_fault(
    far: u64,
    esr: u64,
    elr: u64,
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
    if elr >= KERNEL_TEXT_MIN && elr + 8 < KERNEL_TEXT_MAX && (elr & 0x3) == 0 {
        insn_m2 = unsafe { (elr.wrapping_sub(8) as *const u32).read_volatile() as u64 };
        insn_m1 = unsafe { (elr.wrapping_sub(4) as *const u32).read_volatile() as u64 };
        insn = unsafe { (elr as *const u32).read_volatile() as u64 };
        insn_p1 = unsafe { (elr.wrapping_add(4) as *const u32).read_volatile() as u64 };
        insn_p2 = unsafe { (elr.wrapping_add(8) as *const u32).read_volatile() as u64 };
    }
    let vid = crate::sched::vcpu_id();
    let tid = crate::sched::current_tid();
    crate::kerror!(
        "KERNEL_FAULT far={:#x} esr={:#x} elr={:#x} lr={:#x} x0={:#x} x1={:#x} x2={:#x} insn={:#x} win=[{:#x},{:#x},{:#x},{:#x},{:#x}] vcpu={} tid={}",
        far,
        esr,
        elr,
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
    hypercall::process_exit(0xE1)
}

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    crate::kinfo!("kernel_main: start");
    // Install vectors early so MMU-init faults can be diagnosed.
    vectors::install();
    mm::init_global_bootstrap();
    mm::init_per_cpu();
    // kmalloc must be ready before any scheduler/object-store init, otherwise
    // early Vec allocations may fall back to untracked direct pages.
    alloc::init();
    // Primary vCPU scheduler bootstrap.
    sched::init_cpu_local(boot_vcpu_id_from_mpidr());
    sched::init_scheduler();
    sched::init_sync_state();
    crate::kinfo!("kernel_main: mmu ok");

    // Bootstrap process/thread context first so sync hostcall path runs under
    // kernel-thread semantics from the beginning of image loading.
    if !process::init_boot_process(0, 0) {
        crate::kerror!("kernel: bootstrap process init failed");
        hypercall::process_exit(1);
    }
    // Register thread0 (the boot thread) with the scheduler.
    {
        let _lock = sched::KSchedulerLock::lock();
        let vid = (sched::vcpu_id() as usize).min(sched::MAX_VCPUS - 1) as u32;
        let params = sched::UserThreadParams {
            pid: 0,
            entry: 0,
            stack_base: 0,
            stack_size: 0,
            teb_va: 0,
            arg: 0,
            // Scheduler-internal priority is inverted from NT (smaller = higher).
            priority: 23,
        };
        let tid = sched::create_user_thread_locked(params).expect("kernel: thread0 alloc failed");
        // Keep thread0 bound to bootstrap execution context, but do not leave
        // it in the ready queue before its user entry is fully initialized.
        sched::set_thread_state_locked(tid, sched::ThreadState::Running);
        sched::set_vcpu_current_thread(vid as usize, tid);
        sched::set_current_tid(tid);
        sched::set_thread_in_kernel_locked(tid, true);
    }

    hostcall::init();
    if hypercall::hostcall_setup() != winemu_shared::hostcall::HC_OK {
        crate::kwarn!("kernel: hostcall setup failed");
    }

    // ── 0. 加载版本化 NT syscall 分发表 ──────────────────────
    {
        let build = hypercall::query_windows_build();
        nt::sysno_table::load_for_build(build);
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
                let reserve =
                    u64::from_le_bytes(hdr[oh + 72..oh + 80].try_into().unwrap_or([0; 8]));
                let commit = u64::from_le_bytes(hdr[oh + 80..oh + 88].try_into().unwrap_or([0; 8]));
                (reserve, commit)
            } else {
                (0x10_0000, 0x1000)
            }
        } else {
            (0x10_0000, 0x1000)
        }
    };

    let loaded = unsafe {
        ldr::load_from_fd(exe_fd, exe_size, crate::mm::VmaType::ExeImage, |dll_name, imp| {
            dll::resolve_import(dll_name, imp)
        })
    };

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
    // Update thread0 metadata now that the boot process PID is known.
    // thread0 was created during early bootstrap with pid=0; bind it to the
    // boot process and account it once in process lifecycle tracking.
    let mut account_thread0 = false;
    {
        let tid = sched::current_tid();
        let _lock = sched::KSchedulerLock::lock();
        sched::with_thread_mut(tid, |t| {
            t.teb_va = teb_peb.teb_va;
            if t.pid == 0 {
                t.pid = boot_pid;
                account_thread0 = true;
            }
        });
    }
    if account_thread0 {
        process::on_thread_created(boot_pid, sched::current_tid());
    }

    // ── 4. 通知 VMM 内核已就绪 + 内核侧直入首用户线程 ───────────
    let app_entry_va = loaded.base + loaded.entry_rva as u64;
    let start_thunk_va =
        dll::resolve_import("ntdll.dll", ldr::ImportRef::Name("RtlUserThreadStart"))
            .unwrap_or(app_entry_va);
    if start_thunk_va == app_entry_va {
        crate::kwarn!("kernel: start thunk missing, fallback to app entry");
    }

    // Compatibility reservation: keep prior user VA layout stable.
    const SECONDARY_STACK_SIZE: u64 = 0x10000;
    let _ = crate::mm::vm_alloc_region_typed(
        boot_pid,
        0,
        SECONDARY_STACK_SIZE,
        0x04,
        crate::mm::VmaType::ThreadStack,
    );

    // KERNEL_READY is notify-only: it should not own thread0 launch semantics.
    hypercall::kernel_ready(
        start_thunk_va,
        teb_peb.stack_base,
        teb_peb.teb_va,
        crate::alloc::heap_end(),
        0,
        0,
    );

    let thread0_tid = sched::current_tid();
    if thread0_tid == 0 || !sched::thread_exists(thread0_tid) {
        crate::kerror!("kernel: thread0 missing");
        hypercall::process_exit(1);
    }
    let now = sched::current_ticks();
    {
        // Bootstrap path: avoid unlock-edge scheduling before we enter the
        // unified scheduler entry below.
        sched::SCHED_LOCK.acquire();
        sched::with_thread_mut(thread0_tid, |t| {
            t.ctx.pc = start_thunk_va;
            t.ctx.sp = teb_peb.stack_base;
            t.ctx.x[0] = app_entry_va;
            t.ctx.x[1] = teb_peb.peb_va;
            t.ctx.x[18] = teb_peb.teb_va;
            t.ctx.tpidr = teb_peb.teb_va;
            t.ctx.pstate = 0;
            t.slice_remaining_100ns = timer::DEFAULT_TIMESLICE_100NS;
            t.last_start_100ns = now;
            t.in_kernel = false;
        });
        // Re-queue thread0 only after its EL0 context is complete.
        sched::set_thread_state_locked(thread0_tid, sched::ThreadState::Ready);
        sched::SCHED_LOCK.release();
    }
    process::switch_to_thread_process(thread0_tid);

    // Release secondary CPUs from early boot hold loop only after thread0
    // bootstrap context is fully committed.
    set_primary_boot_ready();

    let vid = (sched::vcpu_id() as usize).min(sched::MAX_VCPUS - 1);
    crate::kinfo!(
        "kernel: thread0 tid={} enter bootstrap dispatch",
        thread0_tid
    );
    sched::register_idle_thread_for_vcpu(vid as u32);
    sched::enter_core_scheduler_entry(vid)
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
    loop {
        core::hint::spin_loop();
    }
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
