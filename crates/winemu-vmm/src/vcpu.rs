use std::sync::Arc;
use std::time::Duration;
use winemu_hypervisor::{Vcpu, types::VmExit};
use super::hypercall::{HypercallManager, HypercallResult};
use super::sched::{Scheduler, ThreadId, ThreadContext, SchedResult};

pub fn vcpu_thread(
    vcpu_id: u32,
    mut vcpu: Box<dyn Vcpu>,
    hc_mgr: Arc<HypercallManager>,
    sched:  Arc<Scheduler>,
) {
    // ── Phase 1: 直接运行 Guest Kernel，直到 KERNEL_READY ────────
    // 内核不是调度线程，用 ThreadId(0) 作为占位符
    let kernel_tid = ThreadId(0);
    'kernel: loop {
        let exit = match vcpu.run() {
            Ok(e)  => e,
            Err(e) => { log::error!("vcpu{} kernel run error: {:?}", vcpu_id, e); return; }
        };
        match exit {
            VmExit::Hypercall { nr, args } => {
                let is_ready = nr == winemu_shared::nr::KERNEL_READY;
                let result = hc_mgr.dispatch(nr, args, kernel_tid);
                match result {
                    HypercallResult::Sync(ret) => {
                        set_x0(&mut *vcpu, ret);
                        // HVF auto-advances PC past hvc — do NOT call advance_pc
                    }
                    HypercallResult::Sched(SchedResult::Exit(code)) => {
                        log::info!("vcpu{} kernel exited: code={}", vcpu_id, code);
                        return;
                    }
                    HypercallResult::Sched(_) => {
                        // HVF auto-advances PC
                    }
                }
                if is_ready { break 'kernel; }
            }
            VmExit::Halt | VmExit::Shutdown => {
                log::info!("vcpu{} kernel halted in phase 1", vcpu_id);
                return;
            }
            exit => {
                if let Ok(r) = vcpu.regs() {
                    log::warn!("vcpu{} phase1 unhandled vmexit: {:?} pc={:#x} pstate={:#x} sp={:#x}",
                        vcpu_id, exit, r.pc, r.pstate, r.sp);
                } else {
                    log::warn!("vcpu{} phase1 unhandled vmexit: {:?}", vcpu_id, exit);
                }
                return;
            }
        }
    }

    log::info!("vcpu{} kernel ready — entering scheduler loop", vcpu_id);

    // ── Phase 2: 调度循环，运行 Guest 用户线程 ───────────────────
    sched.register_vcpu_thread();
    let mut current: Option<ThreadId> = None;

    'run: loop {
        if sched.shutdown.load(std::sync::atomic::Ordering::Acquire) {
            log::info!("vcpu{} all threads terminated — shutting down", vcpu_id);
            break 'run;
        }
        if current.is_none() {
            current = sched.pop_ready();
            if current.is_none() {
                std::thread::park_timeout(Duration::from_millis(1));
                sched.check_timeouts();
                continue;
            }
        }
        let tid = current.unwrap();

        let ctx = match sched.take_ctx(tid) {
            Some(c) => c,
            None => { current = None; continue; }
        };
        restore_ctx(&mut *vcpu, &ctx);

        let exit = match vcpu.run() {
            Ok(e)  => e,
            Err(e) => { log::error!("vcpu{} run error: {:?}", vcpu_id, e); break; }
        };

        match exit {
            VmExit::Hypercall { nr, args } => {
                if nr == winemu_shared::nr::NT_SYSCALL {
                    let regs = vcpu.regs().unwrap();
                    log::debug!("NT_SYSCALL hvc: x0={:#x} x8={:#x} x9={:#x} x10={:#x} x11={:#x} x12={:#x} x30={:#x} pc={:#x} sp={:#x}",
                        regs.x[0], regs.x[8], regs.x[9], regs.x[10], regs.x[11], regs.x[12], regs.x[30], regs.pc, regs.sp);
                    let syscall_nr = regs.x[9];
                    let table_nr   = regs.x[10];
                    // x11 = orig_x0: SVC handler does `mov x11, x0` before hvc
                    let x0 = regs.x[11];
                    let x1 = regs.x[1];
                    let x2 = regs.x[2];
                    let x3 = regs.x[3];
                    let x4 = regs.x[4];
                    let x5 = regs.x[5];
                    let x6 = regs.x[6];
                    let x7 = regs.x[7];
                    let sp_el1 = regs.sp; // SVC stack (SP_EL1) — for reading saved regs
                    let sp_el0 = vcpu.sp_el0().unwrap_or(0); // user stack — for reading stack args
                    // Read original x9/x10/x11/x12/x29/x30 from SVC stack (SP_EL1)
                    // before dispatching (dispatch may modify memory).
                    // SVC stack layout: [sp+0]=elr_orig,[sp+8]=spsr_orig,[sp+16]=x11_orig,[sp+24]=x12_orig,[sp+32]=x9_orig,[sp+40]=x10_orig,[sp+48]=x29_orig,[sp+56]=x30_orig
                    let svc_stack_saved = hc_mgr.read_svc_stack(sp_el1);
                    log::debug!("svc_stack: sp_el1={:#x} elr={:#x} spsr={:#x}", sp_el1, svc_stack_saved[0], svc_stack_saved[1]);
                    let full_args = [syscall_nr, table_nr, x0, x1, x2, x3, x4, x5, x6, x7];
                    let result = hc_mgr.dispatch_nt_syscall(full_args, sp_el0, tid);
                    match result {
                        HypercallResult::Sync(ret) | HypercallResult::Sched(SchedResult::Sync(ret)) => {
                            set_x0(&mut *vcpu, ret);
                            let ctx = save_ctx_el0(&mut *vcpu, &svc_stack_saved);
                            sched.save_ctx(tid, ctx);
                        }
                        HypercallResult::Sched(SchedResult::Block(req)) => {
                            let ctx = save_ctx_el0(&mut *vcpu, &svc_stack_saved);
                            sched.save_ctx(tid, ctx);
                            sched.set_waiting(tid, req);
                            current = None;
                        }
                        HypercallResult::Sched(SchedResult::Yield) => {
                            let ctx = save_ctx_el0(&mut *vcpu, &svc_stack_saved);
                            sched.save_ctx(tid, ctx);
                            sched.push_ready(tid);
                            current = None;
                        }
                        HypercallResult::Sched(SchedResult::Exit(code)) => {
                            let ctx = save_ctx_el0(&mut *vcpu, &svc_stack_saved);
                            sched.save_ctx(tid, ctx);
                            sched.terminate(tid, code);
                            current = None;
                        }
                    }
                    continue 'run;
                }
                let result = hc_mgr.dispatch(nr, args, tid);
                match result {
                    HypercallResult::Sync(ret) | HypercallResult::Sched(SchedResult::Sync(ret)) => {
                        set_x0(&mut *vcpu, ret);
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
                    log::warn!("vcpu{} unhandled vmexit: {:?} pc={:#x} pstate={:#x} sp={:#x}",
                        vcpu_id, exit, r.pc, r.pstate, r.sp);
                } else {
                    log::warn!("vcpu{} unhandled vmexit: {:?}", vcpu_id, exit);
                }
                let _ = vcpu.advance_pc(4);
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
        regs.sp    = ctx.gpr[31];
        regs.pc    = ctx.gpr[32];
        regs.pstate = ctx.pstate;
        vcpu.set_regs(&regs).unwrap();
        // Verify SP was set correctly
        let check = vcpu.regs().unwrap();
        log::debug!("restore_ctx: pc={:#x} sp={:#x} pstate={:#x} (wanted sp={:#x})",
            check.pc, check.sp, check.pstate, ctx.gpr[31]);
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
        ctx.pstate  = regs.pstate as u64;
        // FP 延迟保存：暂不保存（Phase 3 加 fp_dirty 检测）
        ctx.fp_dirty = false;
    }
    ctx
}

fn set_x0(vcpu: &mut dyn Vcpu, val: u64) {
    vcpu.set_return_value(val).unwrap();
}

/// Save EL0 thread context from inside the SVC handler (vCPU is at EL1).
/// ELR_EL1/SPSR_EL1 are read from the SVC stack snapshot (hvc clobbers them).
/// Stack layout: [0]=elr_orig,[1]=spsr_orig,[2]=x11_orig,[3]=x12_orig,[4]=x9_orig,[5]=x10_orig,[6]=x29_orig,[7]=x30_orig
fn save_ctx_el0(vcpu: &mut dyn Vcpu, svc_stack: &[u64; 8]) -> ThreadContext {
    let mut ctx = ThreadContext::default();
    #[cfg(target_arch = "aarch64")]
    {
        let regs = vcpu.regs().unwrap();
        ctx.gpr[..31].copy_from_slice(&regs.x[..31]);
        ctx.gpr[31] = vcpu.sp_el0().unwrap_or(regs.sp);
        // ELR and SPSR saved on stack before hvc (hvc clobbers live ELR_EL1/SPSR_EL1)
        ctx.gpr[32] = svc_stack[0]; // elr_orig = SVC return PC
        ctx.pstate   = svc_stack[1]; // spsr_orig = EL0 pstate
        ctx.fp_dirty = false;
        log::debug!("save_ctx_el0: elr={:#x} spsr={:#x} sp_el0={:#x}",
            ctx.gpr[32], ctx.pstate, ctx.gpr[31]);
        // Restore original x9/x10/x11/x12 from SVC stack snapshot
        ctx.gpr[11] = svc_stack[2];
        ctx.gpr[12] = svc_stack[3];
        ctx.gpr[9]  = svc_stack[4];
        ctx.gpr[10] = svc_stack[5];
        // x29/x30 already correct in regs (SVC handler doesn't modify them)
    }
    ctx
}
