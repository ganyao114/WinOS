use super::snapshot::{apply_snapshot, arm_single_step, capture_snapshot};
use super::{DebugController, ResumeMode, RunOutcome, WaitOutcome, DEFAULT_PAUSE_TIMEOUT};
use crate::debugger::types::{DebugState, StopReason, VcpuSnapshot};
use std::time::{Duration, Instant};
use winemu_core::{Result, WinemuError};
use winemu_hypervisor::Vcpu;

impl DebugController {
    pub fn request_pause_all(&self, reason: StopReason) -> Result<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            match inner.state {
                DebugState::Paused => return Ok(()),
                DebugState::PauseRequested => {}
                DebugState::Running => {
                    inner.state = DebugState::PauseRequested;
                    inner.pause_epoch = inner.pause_epoch.wrapping_add(1);
                    inner.stop_reason = Some(reason);
                    inner.stop_vcpu_id = None;
                    inner.resume_mode = ResumeMode::All;
                }
            }
            self.cv.notify_all();
        }

        self.sched.nudge_all_vcpus();
        self.force_exit_all_vcpus();
        self.wait_until_paused(DEFAULT_PAUSE_TIMEOUT)
    }

    pub fn request_pause_from_vcpu(
        &self,
        vcpu_id: u32,
        vcpu: &mut dyn Vcpu,
        reason: StopReason,
    ) -> Result<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            match inner.state {
                DebugState::Running => {
                    inner.state = DebugState::PauseRequested;
                    inner.pause_epoch = inner.pause_epoch.wrapping_add(1);
                    inner.stop_reason = Some(reason);
                    inner.stop_vcpu_id = Some(vcpu_id);
                    inner.resume_mode = ResumeMode::All;
                }
                DebugState::PauseRequested | DebugState::Paused => {
                    if inner.stop_reason.is_none() {
                        inner.stop_reason = Some(reason);
                    }
                    if inner.stop_vcpu_id.is_none() {
                        inner.stop_vcpu_id = Some(vcpu_id);
                    }
                }
            }
            self.cv.notify_all();
        }

        self.sched.nudge_all_vcpus();
        self.force_exit_all_vcpus();
        self.pause_here_if_requested(vcpu_id, vcpu);
        Ok(())
    }

    pub fn resume_all(&self) {
        let mut inner = self.inner.lock().unwrap();
        let pause_epoch = inner.pause_epoch;
        let registered_len = inner.registered.len();
        for idx in 0..registered_len {
            if inner.registered[idx] {
                inner.resume_apply_epoch[idx] = pause_epoch;
                inner.resume_grace_epoch[idx] = pause_epoch;
            }
        }
        inner.resume_mode = ResumeMode::All;
        inner.state = DebugState::Running;
        inner.stop_reason = None;
        inner.stop_vcpu_id = None;
        self.cv.notify_all();
        drop(inner);
        self.sched.nudge_all_vcpus();
    }

    pub fn step_vcpu(&self, vcpu_id: u32) -> Result<()> {
        self.require_paused()?;
        let mut inner = self.inner.lock().unwrap();
        let Some(snapshot) = inner.snapshots.get(vcpu_id as usize) else {
            return Err(WinemuError::Memory(format!(
                "invalid vcpu {} for single-step",
                vcpu_id
            )));
        };
        if snapshot.is_none() {
            return Err(WinemuError::Memory(format!(
                "no paused snapshot for vcpu {}",
                vcpu_id
            )));
        }
        let pause_epoch = inner.pause_epoch;
        if let Some(slot) = inner.resume_apply_epoch.get_mut(vcpu_id as usize) {
            *slot = pause_epoch;
        }
        if let Some(slot) = inner.resume_grace_epoch.get_mut(vcpu_id as usize) {
            *slot = pause_epoch;
        }
        inner.resume_mode = ResumeMode::SingleStep { vcpu_id };
        inner.state = DebugState::Running;
        inner.stop_reason = None;
        inner.stop_vcpu_id = None;
        self.cv.notify_all();
        drop(inner);
        self.sched.nudge_all_vcpus();
        Ok(())
    }

    pub fn maybe_pause_before_run(&self, vcpu_id: u32, vcpu: &mut dyn Vcpu) {
        self.pause_here_if_requested(vcpu_id, vcpu);
    }

    pub fn intercept_run_result(
        &self,
        vcpu_id: u32,
        vcpu: &mut dyn Vcpu,
        run_result: Result<winemu_hypervisor::types::VmExit>,
        shutting_down: bool,
    ) -> Result<RunOutcome> {
        match run_result {
            Ok(exit) => Ok(RunOutcome::VmExit(exit)),
            Err(err) => {
                if shutting_down {
                    return Ok(RunOutcome::Shutdown);
                }
                if is_canceled_run(&err) {
                    if self.pause_requested() {
                        self.pause_here_if_requested(vcpu_id, vcpu);
                    } else if !self.consume_resume_grace(vcpu_id) {
                        log::debug!(
                            "debugger: retrying unexpected canceled run on vcpu{} while running",
                            vcpu_id
                        );
                    }
                    return Ok(RunOutcome::Retry);
                }
                Err(err)
            }
        }
    }

    pub fn wait_for_pause_or_shutdown(&self, poll_interval: Duration) -> WaitOutcome {
        let mut inner = self.inner.lock().unwrap();
        loop {
            if self
                .sched
                .shutdown
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return WaitOutcome::Shutdown;
            }
            if inner.state == DebugState::Paused {
                return WaitOutcome::Paused;
            }
            let (next_inner, _) = self.cv.wait_timeout(inner, poll_interval).unwrap();
            inner = next_inner;
        }
    }

    pub fn poll_pause_or_shutdown(&self, poll_interval: Duration) -> Option<WaitOutcome> {
        let mut inner = self.inner.lock().unwrap();
        if self
            .sched
            .shutdown
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Some(WaitOutcome::Shutdown);
        }
        if inner.state == DebugState::Paused {
            return Some(WaitOutcome::Paused);
        }
        let (next_inner, _) = self.cv.wait_timeout(inner, poll_interval).unwrap();
        inner = next_inner;
        if self
            .sched
            .shutdown
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Some(WaitOutcome::Shutdown);
        }
        if inner.state == DebugState::Paused {
            return Some(WaitOutcome::Paused);
        }
        None
    }

    pub fn notify_shutdown(&self) {
        self.cv.notify_all();
    }

    fn wait_until_paused(&self, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        while inner.state != DebugState::Paused {
            let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
                return Err(WinemuError::Hypervisor(
                    "debugger pause timed out waiting for all vcpus".to_string(),
                ));
            };
            let (next_inner, result) = self.cv.wait_timeout(inner, remaining).unwrap();
            inner = next_inner;
            if result.timed_out() && inner.state != DebugState::Paused {
                return Err(WinemuError::Hypervisor(
                    "debugger pause timed out waiting for all vcpus".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn pause_requested(&self) -> bool {
        matches!(
            self.inner.lock().unwrap().state,
            DebugState::PauseRequested | DebugState::Paused
        )
    }

    fn consume_resume_grace(&self, vcpu_id: u32) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.state != DebugState::Running {
            return false;
        }
        let pause_epoch = inner.pause_epoch;
        let Some(slot) = inner.resume_grace_epoch.get_mut(vcpu_id as usize) else {
            return false;
        };
        if *slot == pause_epoch && *slot != 0 {
            *slot = 0;
            true
        } else {
            false
        }
    }

    fn pause_here_if_requested(&self, vcpu_id: u32, vcpu: &mut dyn Vcpu) {
        let mut inner = self.inner.lock().unwrap();
        let mut last_acked_epoch = 0u64;
        let mut captured_snapshot: Option<VcpuSnapshot> = None;
        let mut did_capture = false;
        loop {
            match inner.state {
                DebugState::Running => {
                    if !inner.can_resume_vcpu(vcpu_id) {
                        inner = self.cv.wait(inner).unwrap();
                        continue;
                    }
                    let resume_snapshot = if inner.resume_apply_epoch.get(vcpu_id as usize).copied()
                        == Some(inner.pause_epoch)
                    {
                        if let Some(slot) = inner.resume_apply_epoch.get_mut(vcpu_id as usize) {
                            *slot = 0;
                        }
                        inner.snapshots.get(vcpu_id as usize).cloned().flatten()
                    } else {
                        None
                    };
                    let single_step = matches!(
                        inner.resume_mode,
                        ResumeMode::SingleStep { vcpu_id: target } if target == vcpu_id
                    );
                    drop(inner);
                    if let Some(snapshot) = resume_snapshot.as_ref() {
                        apply_snapshot(vcpu_id, vcpu, snapshot);
                    }
                    if single_step {
                        if let Err(err) = arm_single_step(vcpu_id, vcpu) {
                            log::warn!("debugger: vcpu{} arm single-step failed: {}", vcpu_id, err);
                            inner = self.inner.lock().unwrap();
                            inner.state = DebugState::Paused;
                            inner.resume_mode = ResumeMode::All;
                            inner.stop_reason = Some(StopReason::ManualPause);
                            inner.stop_vcpu_id = Some(vcpu_id);
                            self.cv.notify_all();
                            continue;
                        }
                    }
                    return;
                }
                DebugState::PauseRequested | DebugState::Paused => {
                    let pause_epoch = inner.pause_epoch;
                    if last_acked_epoch != pause_epoch {
                        let reason = inner.stop_reason.unwrap_or(StopReason::ManualPause);
                        let snapshot = if did_capture {
                            captured_snapshot.clone().map(|mut snapshot| {
                                snapshot.reason = reason;
                                snapshot
                            })
                        } else {
                            let snapshot = capture_snapshot(vcpu_id, vcpu, reason);
                            captured_snapshot = snapshot.clone();
                            did_capture = true;
                            snapshot
                        };
                        if let Some(slot) = inner.acked_epoch.get_mut(vcpu_id as usize) {
                            *slot = pause_epoch;
                        }
                        if let Some(slot) = inner.snapshots.get_mut(vcpu_id as usize) {
                            *slot = snapshot;
                        }
                        if inner.stop_vcpu_id.is_none() {
                            inner.stop_vcpu_id = Some(vcpu_id);
                        }
                        last_acked_epoch = pause_epoch;
                        if inner.all_registered_acked() {
                            inner.state = DebugState::Paused;
                            self.cv.notify_all();
                        }
                    }
                    inner = self.cv.wait(inner).unwrap();
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn force_exit_all_vcpus(&self) {
        use winemu_hypervisor::hvf::ffi;

        if self.vcpu_count == 0 {
            return;
        }
        let mut ids = Vec::with_capacity(self.vcpu_count as usize);
        for id in 0..self.vcpu_count {
            ids.push(id as ffi::hv_vcpuid_t);
        }
        // SAFETY: IDs are created by this process and the buffer remains valid
        // for the duration of the call.
        let ret = unsafe { ffi::hv_vcpus_exit(ids.as_mut_ptr(), ids.len() as u32) };
        if ret != ffi::HV_SUCCESS && ret != ffi::HV_NO_DEVICE {
            log::warn!("debugger: hv_vcpus_exit failed ret={:#x}", ret);
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn force_exit_all_vcpus(&self) {}
}

fn is_canceled_run(err: &WinemuError) -> bool {
    matches!(err, WinemuError::Hypervisor(msg) if msg.contains("canceled"))
}
