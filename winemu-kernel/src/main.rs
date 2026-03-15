#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc as rust_alloc;
use core::sync::atomic::{AtomicU32, Ordering};

mod alloc;
mod arch;
mod dll;
mod fs;
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
    // shared scheduler path. Waiting in bare WFE would never pick ready threads.
    vectors::install();
    // MMU/system control registers are per-CPU; secondary CPUs need local MMU
    // init before touching scheduler global state under virtual addresses.
    mm::init_per_cpu();
    // The backend CPU-local register must be initialized before any scheduler
    // API usage.
    let boot_vid = crate::arch::cpu::boot_vcpu_id();
    sched::init_cpu_local(boot_vid);
    sched::enter_current_core_scheduler()
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

    let thread0_tid = bootstrap_initial_kernel_thread_or_exit();

    hostcall::init();
    if hypercall::hostcall_setup() != winemu_shared::hostcall::HC_OK {
        crate::kwarn!("kernel: hostcall setup failed");
    }

    // ── 0. 加载版本化 NT syscall 分发表 ──────────────────────
    {
        let build = hypercall::query_windows_build();
        nt::sysno_table::load_for_build(build);
    }

    let initial_image = load_initial_user_image_or_exit();
    let boot_task = create_boot_user_task_or_exit(thread0_tid, &initial_image);
    boot_task.notify_kernel_ready();
    boot_task.prepare_initial_thread_launch();

    // Release secondary CPUs from early boot hold loop only after thread0
    // bootstrap context is fully committed.
    set_primary_boot_ready();

    crate::kinfo!(
        "kernel: boot task pid={} tid={} enter bootstrap dispatch",
        boot_task.pid,
        boot_task.tid
    );
    sched::enter_current_core_scheduler()
}

const BOOT_THREAD_PRIORITY: u8 = 23;
const DEFAULT_STACK_RESERVE: u64 = 0x10_0000;
const DEFAULT_STACK_COMMIT: u64 = 0x1000;
const COMPAT_SECONDARY_STACK_SIZE: u64 = 0x10000;

struct InitialUserImage {
    loaded: ldr::LoadedImage,
    stack_reserve: u64,
    stack_commit: u64,
}

struct BootUserTask {
    pid: u32,
    tid: u32,
    teb_peb: teb::TebPeb,
    app_entry_va: u64,
    start_thunk_va: u64,
}

impl BootUserTask {
    fn notify_kernel_ready(&self) {
        hypercall::kernel_ready(
            self.start_thunk_va,
            self.teb_peb.stack_base,
            self.teb_peb.teb_va,
            crate::alloc::heap_end(),
            0,
            0,
        );
    }

    fn prepare_initial_thread_launch(&self) {
        let now = sched::current_ticks();
        // Bootstrap path: avoid unlock-edge scheduling before we enter the
        // unified scheduler entry below.
        sched::lock::with_sched_raw_lock(|| {
            sched::prepare_boot_thread_user_entry_locked(
                self.tid,
                crate::arch::context::UserThreadStart {
                    program_counter: self.start_thunk_va,
                    stack_pointer: self.teb_peb.stack_base,
                    thread_pointer: self.teb_peb.teb_va,
                    arg0: self.app_entry_va,
                    arg1: self.teb_peb.peb_va,
                },
                now,
            );
        });
        process::switch_to_thread_process(self.tid);
    }
}

fn kernel_boot_exit(message: &str) -> ! {
    crate::kerror!("{}", message);
    hypercall::process_exit(1);
}

fn bootstrap_initial_kernel_thread_or_exit() -> u32 {
    if !process::init_boot_process(0, 0) {
        kernel_boot_exit("kernel: bootstrap process init failed");
    }
    let Some(thread0_tid) = ({
        let _lock = sched::KSchedulerLock::lock();
        sched::create_boot_thread_for_current_vcpu_locked(BOOT_THREAD_PRIORITY)
    }) else {
        kernel_boot_exit("kernel: thread0 alloc failed");
    };
    thread0_tid
}

fn open_initial_exe_or_exit() -> fs::bootstrap::InitialExe {
    let Ok(exe) = fs::bootstrap::open_initial_exe() else {
        kernel_boot_exit("kernel: query_exe_info failed");
    };
    if exe.size == 0 {
        kernel_boot_exit("kernel: query_exe_info failed");
    }
    exe
}

fn read_initial_exe_stack_params(exe_file: fs::FsFileHandle) -> (u64, u64) {
    let mut hdr = [0u8; 512];
    let got = fs::read_at(fs::FsReadRequest {
        file: exe_file,
        dst: hdr.as_mut_ptr(),
        len: hdr.len(),
        offset: 0,
    })
    .unwrap_or(0);
    if got < 80 {
        return (DEFAULT_STACK_RESERVE, DEFAULT_STACK_COMMIT);
    }

    let lfanew = u32::from_le_bytes([hdr[60], hdr[61], hdr[62], hdr[63]]) as usize;
    let optional_header = lfanew + 24;
    if optional_header + 88 > got {
        return (DEFAULT_STACK_RESERVE, DEFAULT_STACK_COMMIT);
    }

    let reserve = u64::from_le_bytes(
        hdr[optional_header + 72..optional_header + 80]
            .try_into()
            .unwrap_or([0; 8]),
    );
    let commit = u64::from_le_bytes(
        hdr[optional_header + 80..optional_header + 88]
            .try_into()
            .unwrap_or([0; 8]),
    );
    (reserve, commit)
}

fn load_initial_user_image_or_exit() -> InitialUserImage {
    let exe = open_initial_exe_or_exit();
    let stack = read_initial_exe_stack_params(exe.file);
    let loaded = unsafe {
        ldr::load_from_file(
            exe.file,
            exe.size,
            crate::mm::VmaType::ExeImage,
            |dll_name, imp| dll::resolve_import(dll_name, imp),
        )
    };
    fs::close(exe.file);

    let loaded = match loaded {
        Ok(img) => img,
        Err(err) => {
            crate::kerror!("kernel: PE load failed: {:?}", err);
            hypercall::process_exit(1);
        }
    };

    InitialUserImage {
        loaded,
        stack_reserve: stack.0,
        stack_commit: stack.1,
    }
}

fn resolve_boot_start_thunk(app_entry_va: u64) -> u64 {
    let start_thunk_va =
        dll::resolve_import("ntdll.dll", ldr::ImportRef::Name("WinEmuProcessStart"))
            .or_else(|| {
                dll::resolve_import("ntdll.dll", ldr::ImportRef::Name("RtlUserThreadStart"))
            })
            .unwrap_or(app_entry_va);
    if start_thunk_va == app_entry_va {
        crate::kwarn!("kernel: start thunk missing, fallback to app entry");
    }
    start_thunk_va
}

fn bind_boot_thread_to_process_or_exit(thread0_tid: u32, boot_pid: u32, teb_va: u64) {
    if thread0_tid == 0 || !sched::thread_exists(thread0_tid) {
        kernel_boot_exit("kernel: thread0 missing");
    }

    let mut account_thread0 = false;
    {
        let _lock = sched::KSchedulerLock::lock();
        sched::with_thread_mut(thread0_tid, |t| {
            t.teb_va = teb_va;
            if t.pid == 0 {
                t.pid = boot_pid;
                account_thread0 = true;
            }
        });
    }
    if account_thread0 {
        process::on_thread_created(boot_pid, thread0_tid);
    }
}

fn create_boot_user_task_or_exit(thread0_tid: u32, image: &InitialUserImage) -> BootUserTask {
    if !process::init_boot_process(image.loaded.base, 0) {
        kernel_boot_exit("kernel: boot process init failed");
    }

    let boot_pid = process::boot_pid();
    if boot_pid == 0 {
        kernel_boot_exit("kernel: boot pid invalid");
    }

    let Some(teb_peb) = teb::init(
        image.loaded.base,
        boot_pid,
        1,
        image.stack_reserve,
        image.stack_commit,
        "C:\\app.exe",
        "app.exe",
    ) else {
        kernel_boot_exit("kernel: teb init failed");
    };

    if !process::init_boot_process(image.loaded.base, teb_peb.peb_va) {
        kernel_boot_exit("kernel: boot process update failed");
    }

    bind_boot_thread_to_process_or_exit(thread0_tid, boot_pid, teb_peb.teb_va);

    let _ = crate::mm::vm_alloc_region_typed(
        boot_pid,
        0,
        COMPAT_SECONDARY_STACK_SIZE,
        0x04,
        crate::mm::VmaType::ThreadStack,
    );

    let app_entry_va = image.loaded.base + image.loaded.entry_rva as u64;
    BootUserTask {
        pid: boot_pid,
        tid: thread0_tid,
        teb_peb,
        app_entry_va,
        start_thunk_va: resolve_boot_start_thunk(app_entry_va),
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::log::debug_print("KERNEL_PANIC");
    let mut line = 0u64;
    if let Some(loc) = info.location() {
        crate::log::debug_print(" at ");
        crate::log::debug_print(loc.file());
        crate::log::debug_print(":");
        let mut buf = [0u8; 32];
        line = loc.line() as u64;
        let s = fmt_u64_dec(&mut buf, line);
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
    crate::hypercall::debug_trap(crate::hypercall::DEBUG_TRAP_KERNEL_PANIC, line, 0);
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
