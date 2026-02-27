// svc_dispatch — EL1 SVC 分发器
// 由 vectors.rs 的 SVC handler 汇编调用，处理所有来自 EL0 的 syscall。
// 若需要线程切换，直接修改 SvcFrame 中的寄存器，ERET 后进入新线程。

use crate::sched::{
    self, current_tid, vcpu_id, with_thread_mut, wake, block_current,
    spawn, schedule, sched_lock_acquire, sched_lock_release,
    register_thread0, ThreadState,
};
use crate::sched::sync::{
    self,
    EventType, STATUS_SUCCESS,
    event_alloc, event_set, event_reset, event_wait, event_free,
    mutex_alloc, mutex_acquire, mutex_release,
    semaphore_alloc, semaphore_wait, semaphore_release,
    make_handle, wait_handle, close_handle,
    HANDLE_TYPE_EVENT, HANDLE_TYPE_MUTEX, HANDLE_TYPE_SEMAPHORE,
};
use crate::hypercall;
use winemu_shared::nr;

// ── SvcFrame 镜像（与汇编布局一致）──────────────────────────

#[repr(C)]
pub struct SvcFrame {
    pub x:       [u64; 31],  // x0–x30  (+0x000)
    pub sp_el0:  u64,         // +0x0F8
    pub elr:     u64,         // +0x100
    pub spsr:    u64,         // +0x108
    pub tpidr:   u64,         // +0x110
    pub x8_orig: u64,         // +0x118  syscall tag
}

// ── NT syscall 号（Wine ARM64 约定）──────────────────────────

// Table 0 = Nt*, Table 1 = Win32k (ignored here)
// 只列出我们在 guest 内处理的号码
// 其余转发给 VMM via HVC NT_SYSCALL

const NR_CREATE_EVENT:          u16 = 0x0048;
const NR_SET_EVENT:             u16 = 0x00E2;
const NR_RESET_EVENT:           u16 = 0x00D6;
const NR_CLEAR_EVENT:           u16 = 0x0031; // alias
const NR_WAIT_SINGLE:           u16 = 0x0004;
const NR_WAIT_MULTIPLE:         u16 = 0x00F4; // approximate
const NR_CREATE_MUTEX:          u16 = 0x005A;
const NR_RELEASE_MUTANT:        u16 = 0x00C9;
const NR_CREATE_SEMAPHORE:      u16 = 0x006D;
const NR_RELEASE_SEMAPHORE:     u16 = 0x00CA;
const NR_CLOSE:                 u16 = 0x000F;
const NR_YIELD_EXECUTION:       u16 = 0x0101;
const NR_CREATE_THREAD:         u16 = 0x004B;
const NR_TERMINATE_THREAD:      u16 = 0x0053; // approximate
const NR_DELAY_EXECUTION:       u16 = 0x0034;

// ── 主分发函数（extern "C"，由汇编调用）─────────────────────

#[no_mangle]
pub extern "C" fn svc_dispatch(frame: &mut SvcFrame) {
    // Lazy-init: register Thread 0 on first SVC entry (TPIDR_EL1 starts at 0)
    if current_tid() == 0 {
        register_thread0(frame.tpidr);
    }

    let tag      = frame.x8_orig;
    let nr       = (tag & 0xFFF) as u16;
    let table    = ((tag >> 12) & 0x3) as u8;

    // Debug: log x[8], x8_orig, ELR, SPSR, ESR_EL1
    hypercall::debug_u64(0xDEBD_0000_0000_0000 | frame.x[8]);
    hypercall::debug_u64(0xDEBE_0000_0000_0000 | tag);
    hypercall::debug_u64(0xDEBF_0000_0000_0000 | frame.elr);
    hypercall::debug_u64(0xDEB0_0000_0000_0000 | frame.spsr);
    let esr: u64;
    unsafe { core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nostack, nomem)); }
    hypercall::debug_u64(0xDEB1_0000_0000_0000 | esr);

    // Table 1 = Win32k — always forward to VMM
    if table != 0 {
        forward_to_vmm(frame, nr, table);
        return;
    }

    match nr {
        NR_CREATE_EVENT     => handle_create_event(frame),
        NR_SET_EVENT        => handle_set_event(frame),
        NR_RESET_EVENT |
        NR_CLEAR_EVENT      => handle_reset_event(frame),
        NR_WAIT_SINGLE      => handle_wait_single(frame),
        NR_CREATE_MUTEX     => handle_create_mutex(frame),
        NR_RELEASE_MUTANT   => handle_release_mutant(frame),
        NR_CREATE_SEMAPHORE => handle_create_semaphore(frame),
        NR_RELEASE_SEMAPHORE => handle_release_semaphore(frame),
        NR_CLOSE            => handle_close(frame),
        NR_YIELD_EXECUTION  => handle_yield(frame),
        NR_CREATE_THREAD    => handle_create_thread(frame),
        NR_TERMINATE_THREAD => handle_terminate_thread(frame),
        NR_DELAY_EXECUTION  => handle_delay_execution(frame),
        _                   => forward_to_vmm(frame, nr, table),
    }

    // After any syscall that may have changed the ready queue,
    // check if we should switch to a higher-priority thread.
    maybe_preempt(frame);
}

// ── 上下文切换辅助 ────────────────────────────────────────────

/// 保存指定线程上下文到 KThread，从 frame 读取
fn save_ctx_for(tid: u32, frame: &SvcFrame) {
    with_thread_mut(tid, |t| {
        t.ctx.x.copy_from_slice(&frame.x);
        t.ctx.sp    = frame.sp_el0;
        t.ctx.pc    = frame.elr;
        t.ctx.pstate = frame.spsr;
        t.ctx.tpidr = frame.tpidr;
    });
}

/// 保存当前线程上下文（用于 wait 路径，schedule() 尚未更新 TPIDR_EL1）
fn save_current_ctx(frame: &SvcFrame) {
    save_ctx_for(current_tid(), frame);
}

/// 将目标线程上下文写入 frame（ERET 后进入该线程）
fn restore_ctx_to_frame(tid: u32, frame: &mut SvcFrame) {
    with_thread_mut(tid, |t| {
        frame.x.copy_from_slice(&t.ctx.x);
        frame.sp_el0 = t.ctx.sp;
        frame.elr    = t.ctx.pc;
        frame.spsr   = t.ctx.pstate;
        frame.tpidr  = t.ctx.tpidr;
    });
}

/// 若就绪队列中有更高优先级线程，执行上下文切换
fn maybe_preempt(frame: &mut SvcFrame) {
    let vid = vcpu_id();
    // Capture current tid BEFORE schedule() updates TPIDR_EL1
    let from = current_tid();
    let (_, to) = schedule(vid);
    if to == 0 {
        if crate::sched::all_threads_done() {
            hypercall::process_exit(0);
        }
        unsafe { core::arch::asm!("wfi", options(nostack, nomem)); }
        return;
    }
    if from != to {
        save_ctx_for(from, frame);
        restore_ctx_to_frame(to, frame);
        // Debug: log new thread's ELR after context switch
        hypercall::debug_u64(0xEEEE_0000_0000_0000 | frame.elr);
    }
}

// ── NtCreateEvent ─────────────────────────────────────────────
// x0 = EventHandle* (out), x1 = DesiredAccess, x2 = ObjectAttributes*
// x3 = EventType (0=Notification, 1=Sync), x4 = InitialState

fn handle_create_event(frame: &mut SvcFrame) {
    let ev_type = if frame.x[3] == 1 {
        EventType::SynchronizationEvent
    } else {
        EventType::NotificationEvent
    };
    let initial = frame.x[4] != 0;
    match event_alloc(ev_type, initial) {
        Some(idx) => {
            let h = make_handle(HANDLE_TYPE_EVENT, idx);
            // Write handle to *EventHandle (x0 = pointer)
            let out_ptr = frame.x[0] as *mut u64;
            unsafe { out_ptr.write_volatile(h); }
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        None => { frame.x[0] = 0xC000_0017u64; } // STATUS_INSUFFICIENT_RESOURCES
    }
}

// ── NtSetEvent ────────────────────────────────────────────────
// x0 = EventHandle, x1 = PreviousState* (optional, can be NULL)

fn handle_set_event(frame: &mut SvcFrame) {
    let h = frame.x[0];
    if sync::handle_type(h) != HANDLE_TYPE_EVENT {
        frame.x[0] = sync::STATUS_INVALID_HANDLE as u64;
        return;
    }
    frame.x[0] = event_set(sync::handle_idx(h)) as u64;
}

// ── NtResetEvent ──────────────────────────────────────────────

fn handle_reset_event(frame: &mut SvcFrame) {
    let h = frame.x[0];
    if sync::handle_type(h) != HANDLE_TYPE_EVENT {
        frame.x[0] = sync::STATUS_INVALID_HANDLE as u64;
        return;
    }
    frame.x[0] = event_reset(sync::handle_idx(h)) as u64;
}

// ── NtWaitForSingleObject ─────────────────────────────────────
// x0 = Handle, x1 = Alertable, x2 = Timeout* (LARGE_INTEGER*)

fn handle_wait_single(frame: &mut SvcFrame) {
    let h        = frame.x[0];
    let timeout_ptr = frame.x[2] as *const i64;
    let deadline = if timeout_ptr.is_null() {
        0u64 // wait forever
    } else {
        let rel = unsafe { timeout_ptr.read_volatile() };
        if rel < 0 {
            // relative timeout: -100ns units → convert to FILETIME
            // FILETIME = current_time - rel (rel is negative)
            let now = hypercall::query_system_time();
            now.wrapping_add((-rel) as u64)
        } else {
            rel as u64 // absolute FILETIME
        }
    };

    let status = wait_handle(h, deadline);

    // If wait_handle returned and we're still running, check if we
    // need to block at the VMM level (no runnable threads)
    if status == 0xDEAD_BEEF {
        // block_current returned next=0 → no runnable threads
        // trigger BLOCK_THREAD hypercall
        save_current_ctx(frame);
        hypercall::block_thread(0, deadline);
        // VMM resumes us here; re-check wait object
        let status2 = wait_handle(h, deadline);
        frame.x[0] = status2 as u64;
    } else {
        frame.x[0] = status as u64;
    }
}

// ── NtCreateMutant ────────────────────────────────────────────
// x0 = MutantHandle* (out), x1 = DesiredAccess, x2 = ObjAttr*
// x3 = InitialOwner (bool)

fn handle_create_mutex(frame: &mut SvcFrame) {
    let initial_owner = frame.x[3] != 0;
    match mutex_alloc(initial_owner) {
        Some(idx) => {
            let h = make_handle(HANDLE_TYPE_MUTEX, idx);
            let out_ptr = frame.x[0] as *mut u64;
            unsafe { out_ptr.write_volatile(h); }
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        None => { frame.x[0] = 0xC000_0017u64; }
    }
}

// ── NtReleaseMutant ───────────────────────────────────────────
// x0 = MutantHandle, x1 = PreviousCount* (optional)

fn handle_release_mutant(frame: &mut SvcFrame) {
    let h = frame.x[0];
    if sync::handle_type(h) != HANDLE_TYPE_MUTEX {
        frame.x[0] = sync::STATUS_INVALID_HANDLE as u64;
        return;
    }
    frame.x[0] = mutex_release(sync::handle_idx(h)) as u64;
}

// ── NtCreateSemaphore ─────────────────────────────────────────
// x0 = SemaphoreHandle* (out), x1 = DesiredAccess, x2 = ObjAttr*
// x3 = InitialCount, x4 = MaximumCount

fn handle_create_semaphore(frame: &mut SvcFrame) {
    let initial = frame.x[3] as i32;
    let maximum = frame.x[4] as i32;
    match semaphore_alloc(initial, maximum) {
        Some(idx) => {
            let h = make_handle(HANDLE_TYPE_SEMAPHORE, idx);
            let out_ptr = frame.x[0] as *mut u64;
            unsafe { out_ptr.write_volatile(h); }
            frame.x[0] = STATUS_SUCCESS as u64;
        }
        None => { frame.x[0] = 0xC000_0017u64; }
    }
}

// ── NtReleaseSemaphore ────────────────────────────────────────
// x0 = SemaphoreHandle, x1 = ReleaseCount, x2 = PreviousCount* (opt)

fn handle_release_semaphore(frame: &mut SvcFrame) {
    let h     = frame.x[0];
    let count = frame.x[1] as i32;
    if sync::handle_type(h) != HANDLE_TYPE_SEMAPHORE {
        frame.x[0] = sync::STATUS_INVALID_HANDLE as u64;
        return;
    }
    let prev = semaphore_release(sync::handle_idx(h), count);
    if let Some(ptr) = unsafe { (frame.x[2] as *mut u32).as_mut() } {
        unsafe { (ptr as *mut u32).write_volatile(prev); }
    }
    frame.x[0] = if prev & 0x8000_0000 != 0 { prev as u64 } else { STATUS_SUCCESS as u64 };
}

// ── NtClose ───────────────────────────────────────────────────

fn handle_close(frame: &mut SvcFrame) {
    let h = frame.x[0];
    // Only close handles we own; others forward to VMM
    let htype = sync::handle_type(h);
    if htype == HANDLE_TYPE_EVENT
        || htype == HANDLE_TYPE_MUTEX
        || htype == HANDLE_TYPE_SEMAPHORE
    {
        frame.x[0] = close_handle(h) as u64;
    } else {
        forward_to_vmm(frame, NR_CLOSE, 0);
    }
}

// ── NtYieldExecution ──────────────────────────────────────────

fn handle_yield(frame: &mut SvcFrame) {
    // Mark current thread as Ready so schedule() will pick another thread.
    // maybe_preempt (called by svc_dispatch) will do the actual switch.
    let cur = current_tid();
    with_thread_mut(cur, |t| {
        if t.state == ThreadState::Running {
            t.state = ThreadState::Ready;
            unsafe { (*crate::sched::SCHED.ready.get()).push(t); }
        }
    });
    frame.x[0] = STATUS_SUCCESS as u64;
}

// ── NtCreateThread ────────────────────────────────────────────
// Simplified: x0=ThreadHandle*(out), x3=ClientId*(out),
// x5=InitialTeb* (contains stack info), x6=CreateSuspended
// We use a simplified calling convention matching our test stubs.
// x0=out_handle, x1=entry_va, x2=arg, x3=teb_va, x4=stack_va

fn handle_create_thread(frame: &mut SvcFrame) {
    let entry_va = frame.x[1];
    let arg      = frame.x[2];
    let teb_va   = frame.x[3];
    let stack_va = frame.x[4];

    // Debug: log entry_va and stack_va
    hypercall::debug_u64(0xCCCC_0000_0000_0000 | entry_va);
    hypercall::debug_u64(0xDDDD_0000_0000_0000 | stack_va);

    let tid = spawn(entry_va, stack_va, arg, teb_va, 8);
    if tid == 0 {
        frame.x[0] = 0xC000_0017u64; // STATUS_INSUFFICIENT_RESOURCES
        return;
    }
    // Return TID as handle (simplified)
    let out_ptr = frame.x[0] as *mut u64;
    if !out_ptr.is_null() {
        unsafe { out_ptr.write_volatile(tid as u64); }
    }
    frame.x[0] = STATUS_SUCCESS as u64;
}

// ── NtTerminateThread ─────────────────────────────────────────

fn handle_terminate_thread(frame: &mut SvcFrame) {
    let cur = current_tid();
    with_thread_mut(cur, |t| t.state = ThreadState::Terminated);
    // maybe_preempt will pick the next thread (or WFI if none)
    frame.x[0] = STATUS_SUCCESS as u64;
}

// ── NtDelayExecution ──────────────────────────────────────────
// x0 = Alertable, x1 = DelayInterval* (LARGE_INTEGER, negative = relative)

fn handle_delay_execution(frame: &mut SvcFrame) {
    let interval_ptr = frame.x[1] as *const i64;
    if interval_ptr.is_null() {
        frame.x[0] = STATUS_SUCCESS as u64;
        return;
    }
    let interval = unsafe { interval_ptr.read_volatile() };
    if interval == 0 {
        // Zero delay = yield
        handle_yield(frame);
        return;
    }
    // Forward to VMM (needs host timer)
    forward_to_vmm(frame, NR_DELAY_EXECUTION, 0);
}

// ── EL1 fault handler ─────────────────────────────────────────

#[no_mangle]
pub extern "C" fn el1_fault_dispatch(frame: &mut SvcFrame) {
    let esr: u64;
    let far: u64;
    unsafe {
        core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nostack, nomem));
        core::arch::asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
    }
    hypercall::debug_u64(0xE100_0000_0000_0000 | esr);
    hypercall::debug_u64(0xE102_0000_0000_0000 | far);
    hypercall::debug_u64(0xE103_0000_0000_0000 | frame.elr);
    hypercall::debug_u64(0xE104_0000_0000_0000 | frame.spsr);
    hypercall::process_exit(0xE1);
}

// ── EL0 fault handler ─────────────────────────────────────────

#[no_mangle]
pub extern "C" fn el0_fault_dispatch(frame: &mut SvcFrame) {
    let esr: u64;
    let far: u64;
    unsafe {
        core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nostack, nomem));
        core::arch::asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
    }
    hypercall::debug_u64(0xFA01_0000_0000_0000 | esr);
    hypercall::debug_u64(0xFA02_0000_0000_0000 | far);
    hypercall::debug_u64(0xFA03_0000_0000_0000 | frame.elr);
    hypercall::debug_u64(0xFA04_0000_0000_0000 | frame.spsr);
    hypercall::process_exit(0xFF);
}

// ── VMM 转发 ──────────────────────────────────────────────────

fn forward_to_vmm(frame: &mut SvcFrame, nr: u16, table: u8) {
    // VMM (vcpu.rs) reads: x0=NT_SYSCALL, x9=syscall_nr, x10=table_nr, x11=orig_x0
    // x1-x7 pass remaining args as-is (VMM reads x1..x7 directly)
    let ret = unsafe {
        let mut r: u64;
        core::arch::asm!(
            "hvc #0",
            inout("x0") winemu_shared::nr::NT_SYSCALL => r,
            in("x1") frame.x[1],
            in("x2") frame.x[2],
            in("x3") frame.x[3],
            in("x4") frame.x[4],
            in("x5") frame.x[5],
            in("x6") frame.x[6],
            in("x7") frame.x[7],
            in("x9") nr as u64,
            in("x10") table as u64,
            in("x11") frame.x[0],
            options(nostack)
        );
        r
    };
    frame.x[0] = ret;
}
