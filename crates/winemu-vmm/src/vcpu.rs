use super::hypercall::{HypercallManager, HypercallResult};
use super::sched::Scheduler;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use winemu_hypervisor::{types::VmExit, Vcpu};

const HOSTCALL_MAIN_BUDGET: usize = 32;
const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(1);

pub fn vcpu_thread(
    vcpu_id: u32,
    mut vcpu: Box<dyn Vcpu>,
    hc_mgr: Arc<HypercallManager>,
    sched: Arc<Scheduler>,
    main_executor: bool,
) {
    sched.register_vcpu_thread(vcpu_id);
    let mut external_irq_asserted = false;

    loop {
        pump_hostcall_main_thread(hc_mgr.as_ref(), main_executor);

        if sched.shutdown.load(Ordering::Acquire) {
            log::info!("vcpu{} all threads terminated — shutting down", vcpu_id);
            break;
        }

        maybe_assert_external_irq(
            vcpu_id,
            &mut *vcpu,
            sched.as_ref(),
            &mut external_irq_asserted,
        );

        let Some(exit) = run_vcpu_once(vcpu_id, &mut *vcpu, sched.as_ref()) else {
            break;
        };

        maybe_clear_external_irq(vcpu_id, &mut *vcpu, &exit, &mut external_irq_asserted);

        if !handle_vmexit(vcpu_id, &mut *vcpu, hc_mgr.as_ref(), sched.as_ref(), exit) {
            break;
        }
    }
}

fn handle_vmexit(
    vcpu_id: u32,
    vcpu: &mut dyn Vcpu,
    hc_mgr: &HypercallManager,
    sched: &Scheduler,
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
        VmExit::Hypercall { nr, args } => {
            let result = hc_mgr.dispatch(nr, args);
            if let Some(code) = apply_hypercall_result_to_regs(vcpu, result) {
                log::info!("vcpu{} exited: code={}", vcpu_id, code);
                return false;
            }
            true
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

fn run_vcpu_once(vcpu_id: u32, vcpu: &mut dyn Vcpu, sched: &Scheduler) -> Option<VmExit> {
    match vcpu.run() {
        Ok(e) => Some(e),
        Err(e) => {
            let err_text = format!("{:?}", e);
            let canceled = err_text.contains("canceled");
            if sched.shutdown.load(Ordering::Acquire) || canceled {
                log::debug!("vcpu{} run canceled on shutdown: {}", vcpu_id, err_text);
            } else {
                log::error!("vcpu{} run error: {}", vcpu_id, err_text);
            }
            None
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

fn apply_hypercall_result_to_regs(vcpu: &mut dyn Vcpu, result: HypercallResult) -> Option<u32> {
    match result {
        HypercallResult::Sync(ret) => {
            set_x0(vcpu, ret);
            None
        }
        HypercallResult::Sync2 { x0, x1 } => {
            set_x0_x1(vcpu, x0, x1);
            None
        }
        HypercallResult::Exit(code) => Some(code),
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

fn bounded_wfi_wait(vcpu: &dyn Vcpu) -> Option<Duration> {
    let hint = vcpu.wfi_idle_hint()?;
    let min_wait = Duration::from_micros(20);
    let max_wait = Duration::from_millis(10);
    Some(hint.clamp(min_wait, max_wait))
}
