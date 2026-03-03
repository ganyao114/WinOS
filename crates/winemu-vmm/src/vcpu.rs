use super::hypercall::{HypercallManager, HypercallResult};
use super::sched::{SchedResult, Scheduler, ThreadContext, ThreadId};
use std::sync::Arc;
use std::time::Duration;
use winemu_hypervisor::{types::VmExit, Vcpu};

pub fn vcpu_thread(
    vcpu_id: u32,
    mut vcpu: Box<dyn Vcpu>,
    hc_mgr: Arc<HypercallManager>,
    sched: Arc<Scheduler>,
    main_executor: bool,
) {
    const HOSTCALL_MAIN_BUDGET: usize = 32;
    // ── Phase 1: 直接运行 Guest Kernel，直到 KERNEL_READY ────────
    // 内核不是调度线程，用 ThreadId(0) 作为占位符
    let kernel_tid = ThreadId(0);
    'kernel: loop {
        if main_executor {
            let _ = hc_mgr.pump_hostcall_main_thread(HOSTCALL_MAIN_BUDGET);
        }
        let exit = match vcpu.run() {
            Ok(e) => e,
            Err(e) => {
                log::error!("vcpu{} kernel run error: {:?}", vcpu_id, e);
                return;
            }
        };
        match exit {
            VmExit::Wfi => {
                let _ = vcpu.advance_pc(4);
                if let Some(wait) = bounded_wfi_wait(vcpu.as_ref()) {
                    std::thread::park_timeout(wait);
                }
                continue 'kernel;
            }
            VmExit::Timer => {
                // Phase 1 should not arm timers; ignore defensively.
                continue 'kernel;
            }
            VmExit::Hypercall { nr, args } => {
                let is_ready = nr == winemu_shared::nr::KERNEL_READY;
                let result = hc_mgr.dispatch(nr, args, kernel_tid);
                match result {
                    HypercallResult::Sync(ret) => {
                        set_x0(&mut *vcpu, ret);
                        // HVF auto-advances PC past hvc — do NOT call advance_pc
                    }
                    HypercallResult::Sync2 { x0, x1 } => {
                        set_x0_x1(&mut *vcpu, x0, x1);
                    }
                    HypercallResult::Sched(SchedResult::Exit(code)) => {
                        log::info!("vcpu{} kernel exited: code={}", vcpu_id, code);
                        return;
                    }
                    HypercallResult::Sched(_) => {
                        // HVF auto-advances PC
                    }
                }
                if is_ready {
                    break 'kernel;
                }
            }
            VmExit::Halt | VmExit::Shutdown => {
                log::info!("vcpu{} kernel halted in phase 1", vcpu_id);
                return;
            }
            exit => {
                if let Ok(r) = vcpu.regs() {
                    log::warn!(
                        "vcpu{} phase1 unhandled vmexit: {:?} pc={:#x} pstate={:#x} sp={:#x}",
                        vcpu_id,
                        exit,
                        r.pc,
                        r.pstate,
                        r.sp
                    );
                } else {
                    log::warn!("vcpu{} phase1 unhandled vmexit: {:?}", vcpu_id, exit);
                }
                return;
            }
        }
    }

    log::info!("vcpu{} kernel ready — entering scheduler loop", vcpu_id);

    // ── Phase 2: 调度循环，运行 Guest 用户线程 ───────────────────
    sched.register_vcpu_thread(vcpu_id);
    let mut current: Option<ThreadId> = None;
    let mut external_irq_asserted = false;

    'run: loop {
        if main_executor {
            let _ = hc_mgr.pump_hostcall_main_thread(HOSTCALL_MAIN_BUDGET);
        }
        if sched.shutdown.load(std::sync::atomic::Ordering::Acquire) {
            log::info!("vcpu{} all threads terminated — shutting down", vcpu_id);
            break 'run;
        }
        if current.is_none() {
            current = sched.pop_ready();
            if current.is_none() {
                sched.set_vcpu_idle(vcpu_id, true);
                std::thread::park_timeout(Duration::from_millis(1));
                sched.set_vcpu_idle(vcpu_id, false);
                sched.check_timeouts();
                continue;
            }
        }
        sched.set_vcpu_idle(vcpu_id, false);
        let tid = current.unwrap();

        let ctx = match sched.take_ctx(tid) {
            Some(c) => c,
            None => {
                current = None;
                continue;
            }
        };
        restore_ctx(&mut *vcpu, &ctx);

        if !external_irq_asserted && sched.take_external_irq_request() {
            if let Err(e) = vcpu.set_pending_irq(true) {
                log::warn!("vcpu{} set_pending_irq(true) failed: {:?}", vcpu_id, e);
            } else {
                external_irq_asserted = true;
            }
        }

        let exit = match vcpu.run() {
            Ok(e) => e,
            Err(e) => {
                log::error!("vcpu{} run error: {:?}", vcpu_id, e);
                break;
            }
        };

        let clear_external_irq = external_irq_asserted
            && matches!(
                exit,
                VmExit::Hypercall { .. } | VmExit::Halt | VmExit::Shutdown
            );
        if clear_external_irq {
            if let Err(e) = vcpu.set_pending_irq(false) {
                log::warn!("vcpu{} set_pending_irq(false) failed: {:?}", vcpu_id, e);
            }
            external_irq_asserted = false;
        }

        match exit {
            VmExit::Wfi => {
                // HVF traps WFI/WFE as a synchronous exit. Emulate completion.
                let _ = vcpu.advance_pc(4);
                if let Some(wait) = bounded_wfi_wait(vcpu.as_ref()) {
                    sched.set_vcpu_idle(vcpu_id, true);
                    std::thread::park_timeout(wait);
                    sched.set_vcpu_idle(vcpu_id, false);
                }
                let ctx = save_ctx(&mut *vcpu);
                sched.save_ctx(tid, ctx);
                continue 'run;
            }
            VmExit::Timer => {
                // Timer IRQ is already marked pending in HVF backend.
                // Save current guest context first, otherwise next loop would
                // restore a stale context and lose the pending-IRQ return point.
                let ctx = save_ctx(&mut *vcpu);
                sched.save_ctx(tid, ctx);
                // Resume guest so EL1 IRQ vector can run and wake the scheduler.
                continue 'run;
            }
            VmExit::Hypercall { nr, args } => {
                let result = hc_mgr.dispatch(nr, args, tid);
                match result {
                    HypercallResult::Sync(ret) | HypercallResult::Sched(SchedResult::Sync(ret)) => {
                        set_x0(&mut *vcpu, ret);
                        let ctx = save_ctx(&mut *vcpu);
                        sched.save_ctx(tid, ctx);
                    }
                    HypercallResult::Sync2 { x0, x1 } => {
                        set_x0_x1(&mut *vcpu, x0, x1);
                        let ctx = save_ctx(&mut *vcpu);
                        sched.save_ctx(tid, ctx);
                    }
                    HypercallResult::Sched(SchedResult::Block(req)) => {
                        let ctx = save_ctx(&mut *vcpu);
                        sched.save_ctx(tid, ctx);
                        sched.set_waiting(tid, req);
                        current = None;
                    }
                    HypercallResult::Sched(SchedResult::Yield) => {
                        let ctx = save_ctx(&mut *vcpu);
                        sched.save_ctx(tid, ctx);
                        sched.push_ready(tid);
                        current = None;
                    }
                    HypercallResult::Sched(SchedResult::Exit(code)) => {
                        let ctx = save_ctx(&mut *vcpu);
                        sched.save_ctx(tid, ctx);
                        sched.terminate(tid, code);
                        current = None;
                    }
                }
            }
            VmExit::Halt | VmExit::Shutdown => {
                log::info!("vcpu{} halted", vcpu_id);
                break;
            }
            exit => {
                if let Ok(r) = vcpu.regs() {
                    log::warn!(
                        "vcpu{} unhandled vmexit: {:?} pc={:#x} pstate={:#x} sp={:#x}",
                        vcpu_id,
                        exit,
                        r.pc,
                        r.pstate,
                        r.sp
                    );
                } else {
                    log::warn!("vcpu{} unhandled vmexit: {:?}", vcpu_id, exit);
                }
                let _ = vcpu.advance_pc(4);
                let ctx = save_ctx(&mut *vcpu);
                sched.save_ctx(tid, ctx);
            }
        }
    }
}

// ── 寄存器辅助 ───────────────────────────────────────────────

fn restore_ctx(vcpu: &mut dyn Vcpu, ctx: &ThreadContext) {
    #[cfg(target_arch = "aarch64")]
    {
        let mut regs = vcpu.regs().unwrap();
        regs.x[..31].copy_from_slice(&ctx.gpr[..31]);
        regs.sp = ctx.gpr[31];
        regs.pc = ctx.gpr[32];
        regs.pstate = ctx.pstate;
        vcpu.set_regs(&regs).unwrap();
        // Verify SP was set correctly
        let check = vcpu.regs().unwrap();
        log::debug!(
            "restore_ctx: pc={:#x} sp={:#x} pstate={:#x} (wanted sp={:#x})",
            check.pc,
            check.sp,
            check.pstate,
            ctx.gpr[31]
        );
        if ctx.fp_dirty {
            // TODO: vcpu FP register API (Phase 3)
        }
    }
}

fn save_ctx(vcpu: &mut dyn Vcpu) -> ThreadContext {
    let mut ctx = ThreadContext::default();
    #[cfg(target_arch = "aarch64")]
    {
        let regs = vcpu.regs().unwrap();
        ctx.gpr[..31].copy_from_slice(&regs.x[..31]);
        ctx.gpr[31] = regs.sp;
        ctx.gpr[32] = regs.pc;
        ctx.pstate = regs.pstate as u64;
        // FP 延迟保存：暂不保存（Phase 3 加 fp_dirty 检测）
        ctx.fp_dirty = false;
    }
    ctx
}

fn set_x0(vcpu: &mut dyn Vcpu, val: u64) {
    vcpu.set_return_value(val).unwrap();
}

fn set_x0_x1(vcpu: &mut dyn Vcpu, x0: u64, x1: u64) {
    #[cfg(target_arch = "aarch64")]
    {
        let mut regs = vcpu.regs().unwrap();
        regs.x[0] = x0;
        regs.x[1] = x1;
        vcpu.set_regs(&regs).unwrap();
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = x1;
        vcpu.set_return_value(x0).unwrap();
    }
}

fn bounded_wfi_wait(vcpu: &dyn Vcpu) -> Option<Duration> {
    let hint = vcpu.wfi_idle_hint()?;
    let min_wait = Duration::from_micros(20);
    let max_wait = Duration::from_millis(10);
    Some(hint.clamp(min_wait, max_wait))
}
