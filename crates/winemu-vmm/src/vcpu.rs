use super::debugger::{DebugController, RunOutcome};
use super::hypercall::{HypercallManager, HypercallResult};
use super::sched::Scheduler;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use winemu_hypervisor::{types::VmExit, Vcpu};

const HOSTCALL_MAIN_BUDGET: usize = 32;
const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(1);

enum RunLoopOutcome {
    VmExit(VmExit),
    Retry,
    Break,
}

pub fn vcpu_thread(
    vcpu_id: u32,
    mut vcpu: Box<dyn Vcpu>,
    hc_mgr: Arc<HypercallManager>,
    sched: Arc<Scheduler>,
    debugger: Option<Arc<DebugController>>,
    main_executor: bool,
) {
    sched.register_vcpu_thread(vcpu_id);
    if let Some(debugger) = debugger.as_ref() {
        debugger.on_vcpu_thread_start(vcpu_id);
        if debugger.debug_caps().debug_exception_trap {
            if let Err(err) = vcpu.set_trap_debug_exceptions(true) {
                log::warn!(
                    "vcpu{} enable trap_debug_exceptions for debugger failed: {}",
                    vcpu_id,
                    err
                );
            }
        }
    }
    let mut external_irq_asserted = false;

    loop {
        pump_hostcall_main_thread(hc_mgr.as_ref(), main_executor);

        if sched.shutdown.load(Ordering::Acquire) {
            notify_debugger_shutdown(debugger.as_deref(), sched.as_ref());
            log::info!("vcpu{} all threads terminated — shutting down", vcpu_id);
            break;
        }

        maybe_assert_external_irq(
            vcpu_id,
            &mut *vcpu,
            sched.as_ref(),
            &mut external_irq_asserted,
        );

        if let Some(debugger) = debugger.as_ref() {
            debugger.maybe_pause_before_run(vcpu_id, &mut *vcpu);
        }

        let exit = match run_vcpu_once(vcpu_id, &mut *vcpu, sched.as_ref(), debugger.as_deref()) {
            RunLoopOutcome::VmExit(exit) => exit,
            RunLoopOutcome::Retry => continue,
            RunLoopOutcome::Break => {
                notify_debugger_shutdown(debugger.as_deref(), sched.as_ref());
                break;
            }
        };

        maybe_clear_external_irq(vcpu_id, &mut *vcpu, &exit, &mut external_irq_asserted);

        if !handle_vmexit(
            vcpu_id,
            &mut *vcpu,
            hc_mgr.as_ref(),
            sched.as_ref(),
            debugger.as_deref(),
            exit,
        ) {
            notify_debugger_shutdown(debugger.as_deref(), sched.as_ref());
            break;
        }
    }
}

fn handle_vmexit(
    vcpu_id: u32,
    vcpu: &mut dyn Vcpu,
    hc_mgr: &HypercallManager,
    sched: &Scheduler,
    debugger: Option<&DebugController>,
    exit: VmExit,
) -> bool {
    match exit {
        VmExit::Wfi => {
            let _ = vcpu.advance_pc(4);
            let wait = bounded_wfi_wait(vcpu).unwrap_or(IDLE_POLL_INTERVAL);
            wait_while_idle(sched, vcpu_id, wait);
            true
        }
        VmExit::Timer => true,
        VmExit::DebugException {
            syndrome,
            virtual_address,
            physical_address,
        } => {
            let ec = (syndrome >> 26) & 0x3f;
            match vcpu.regs() {
                Ok(regs) => {
                    log::debug!(
                        "vcpu{} debug exception: ec={:#x} syndrome={:#x} pc={:#x} sp={:#x} pstate={:#x} va={:#x} pa={:#x}",
                        vcpu_id,
                        ec,
                        syndrome,
                        regs.pc,
                        regs.sp,
                        regs.pstate,
                        virtual_address,
                        physical_address
                    );
                }
                Err(err) => {
                    log::debug!(
                        "vcpu{} debug exception: ec={:#x} syndrome={:#x} va={:#x} pa={:#x} (regs unavailable: {})",
                        vcpu_id,
                        ec,
                        syndrome,
                        virtual_address,
                        physical_address,
                        err
                    );
                }
            }
            if let Err(err) = vcpu.set_guest_single_step(false) {
                log::warn!(
                    "vcpu{} disable guest single-step after debug exception failed: {}",
                    vcpu_id,
                    err
                );
            }
            if let Some(debugger) = debugger {
                if let Err(err) = debugger.request_pause_from_vcpu(
                    vcpu_id,
                    vcpu,
                    super::debugger::StopReason::DebugException {
                        syndrome,
                        virtual_address,
                        physical_address,
                    },
                ) {
                    log::warn!(
                        "vcpu{} debug exception pause failed: {} syndrome={:#x} va={:#x} pa={:#x}",
                        vcpu_id,
                        err,
                        syndrome,
                        virtual_address,
                        physical_address
                    );
                    return false;
                }
                return true;
            }
            log_unhandled_vmexit(
                vcpu_id,
                vcpu,
                &VmExit::DebugException {
                    syndrome,
                    virtual_address,
                    physical_address,
                },
            );
            false
        }
        VmExit::Hypercall { nr, args } => {
            let result = hc_mgr.dispatch(nr, args);
            match result {
                HypercallResult::Sync(ret) => {
                    set_x0(vcpu, ret);
                    true
                }
                HypercallResult::Sync2 { x0, x1 } => {
                    set_x0_x1(vcpu, x0, x1);
                    true
                }
                HypercallResult::DebugTrap { code, arg0, arg1 } => {
                    if let Some(debugger) = debugger {
                        if let Err(err) = debugger.request_pause_from_vcpu(
                            vcpu_id,
                            vcpu,
                            super::debugger::StopReason::GuestDebugTrap { code, arg0, arg1 },
                        ) {
                            log::warn!("vcpu{} guest debug trap pause failed: {}", vcpu_id, err);
                        }
                    }
                    set_x0(vcpu, 0);
                    true
                }
                HypercallResult::Exit(code) => {
                    log::info!("vcpu{} exited: code={}", vcpu_id, code);
                    false
                }
            }
        }
        VmExit::Halt | VmExit::Shutdown => {
            log::info!("vcpu{} halted", vcpu_id);
            false
        }
        other => {
            log_unhandled_vmexit(vcpu_id, vcpu, &other);
            if vcpu_id == 0 {
                return false;
            }
            let _ = vcpu.advance_pc(4);
            true
        }
    }
}

fn run_vcpu_once(
    vcpu_id: u32,
    vcpu: &mut dyn Vcpu,
    sched: &Scheduler,
    debugger: Option<&DebugController>,
) -> RunLoopOutcome {
    let run_result = vcpu.run();
    if let Some(debugger) = debugger {
        match debugger.intercept_run_result(
            vcpu_id,
            vcpu,
            run_result,
            sched.shutdown.load(Ordering::Acquire),
        ) {
            Ok(RunOutcome::VmExit(exit)) => return RunLoopOutcome::VmExit(exit),
            Ok(RunOutcome::Retry) => return RunLoopOutcome::Retry,
            Ok(RunOutcome::Shutdown) => return RunLoopOutcome::Break,
            Err(err) => {
                log::error!("vcpu{} run error: {}", vcpu_id, err);
                return RunLoopOutcome::Break;
            }
        }
    }

    match run_result {
        Ok(exit) => RunLoopOutcome::VmExit(exit),
        Err(err) => {
            let err_text = format!("{:?}", err);
            let canceled = err_text.contains("canceled");
            if sched.shutdown.load(Ordering::Acquire) || canceled {
                log::debug!("vcpu{} run canceled on shutdown: {}", vcpu_id, err_text);
            } else {
                log::error!("vcpu{} run error: {}", vcpu_id, err_text);
            }
            RunLoopOutcome::Break
        }
    }
}

fn pump_hostcall_main_thread(hc_mgr: &HypercallManager, main_executor: bool) {
    if host_ui_main_thread_mode() {
        return;
    }
    if main_executor {
        hc_mgr.pump_hostcall_main_thread(HOSTCALL_MAIN_BUDGET);
    }
}

fn host_ui_main_thread_mode() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| std::env::var("WINEMU_HOST_UI_MAIN_THREAD").ok().as_deref() == Some("1"))
}

fn wait_while_idle(sched: &Scheduler, vcpu_id: u32, timeout: Duration) {
    sched.set_vcpu_idle(vcpu_id, true);
    sched.wait_for_wakeup(timeout);
    sched.set_vcpu_idle(vcpu_id, false);
}

fn maybe_assert_external_irq(
    vcpu_id: u32,
    vcpu: &mut dyn Vcpu,
    sched: &Scheduler,
    external_irq_asserted: &mut bool,
) {
    if !*external_irq_asserted && sched.take_external_irq_request(vcpu_id) {
        if let Err(e) = vcpu.set_pending_irq(true) {
            log::warn!("vcpu{} set_pending_irq(true) failed: {:?}", vcpu_id, e);
        } else {
            *external_irq_asserted = true;
        }
    }
}

fn maybe_clear_external_irq(
    vcpu_id: u32,
    vcpu: &mut dyn Vcpu,
    exit: &VmExit,
    external_irq_asserted: &mut bool,
) {
    let should_clear = *external_irq_asserted
        && matches!(
            exit,
            VmExit::Hypercall { .. } | VmExit::Halt | VmExit::Shutdown
        );
    if should_clear {
        if let Err(e) = vcpu.set_pending_irq(false) {
            log::warn!("vcpu{} set_pending_irq(false) failed: {:?}", vcpu_id, e);
        }
        *external_irq_asserted = false;
    }
}

fn log_unhandled_vmexit(vcpu_id: u32, vcpu: &dyn Vcpu, exit: &VmExit) {
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

fn notify_debugger_shutdown(debugger: Option<&DebugController>, sched: &Scheduler) {
    if sched.shutdown.load(Ordering::Acquire) {
        if let Some(debugger) = debugger {
            debugger.notify_shutdown();
        }
    }
}

fn bounded_wfi_wait(vcpu: &dyn Vcpu) -> Option<Duration> {
    let hint = vcpu.wfi_idle_hint()?;
    let min_wait = Duration::from_micros(20);
    let max_wait = Duration::from_millis(10);
    Some(hint.clamp(min_wait, max_wait))
}
