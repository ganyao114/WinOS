#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc as rust_alloc;
use core::sync::atomic::{AtomicU32, Ordering};

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
mod spin;
mod teb;
mod timer;
mod vectors;

#[no_mangle]
pub static __boot_primary_ready: AtomicU32 = AtomicU32::new(0);
#[inline(always)]
fn set_primary_boot_ready() {
    __boot_primary_ready.store(1, Ordering::Release);
    crate::arch::cpu::send_event();
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
    // The backend CPU-local register must be initialized before any scheduler
    // API usage.
    let boot_vid = crate::arch::cpu::boot_vcpu_id();
    sched::init_cpu_local(boot_vid);
    let vid = (sched::vcpu_id() as usize).min(sched::MAX_VCPUS - 1);
    sched::register_idle_thread_for_vcpu(vid as u32);
    sched::enter_core_scheduler_entry(vid)
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
    sched::init_cpu_local(crate::arch::cpu::boot_vcpu_id());
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
        ldr::load_from_fd(
            exe_fd,
            exe_size,
            crate::mm::VmaType::ExeImage,
            |dll_name, imp| dll::resolve_import(dll_name, imp),
        )
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
            crate::arch::context::initialize_user_thread_context(
                &mut t.ctx,
                crate::arch::context::UserThreadStart {
                    program_counter: start_thunk_va,
                    stack_pointer: teb_peb.stack_base,
                    thread_pointer: teb_peb.teb_va,
                    arg0: app_entry_va,
                    arg1: teb_peb.peb_va,
                },
            );
            t.slice_remaining_100ns = timer::DEFAULT_TIMESLICE_100NS;
            t.last_start_100ns = now;
            t.in_kernel = false;
        });
        // Re-queue thread0 only after its user context is complete.
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
