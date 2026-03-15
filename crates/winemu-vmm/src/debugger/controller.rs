use super::breakpoint::{
    is_software_breakpoint_encoding, validate_software_breakpoint_kind, BreakpointKey,
    SoftwareBreakpoint, AARCH64_BRK_0, ESR_EC_BRK64, SOFTWARE_BREAKPOINT_KIND,
};
use super::memory::GuestMemoryAccess;
use super::symbol::KernelSymbolizer;
use super::translate;
use super::translate::{TranslationRoot, TranslationSpace};
use super::types::{DebugState, StopReason, VcpuSnapshot};
use crate::memory::GuestMemory;
use crate::sched::Scheduler;
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};
use winemu_core::{Result, WinemuError};
use winemu_hypervisor::{DebugCaps, Vcpu};

const DEFAULT_PAUSE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResumeMode {
    All,
    SingleStep { vcpu_id: u32 },
}

struct Inner {
    state: DebugState,
    pause_epoch: u64,
    stop_reason: Option<StopReason>,
    stop_vcpu_id: Option<u32>,
    resume_mode: ResumeMode,
    resume_apply_epoch: Vec<u64>,
    registered: Vec<bool>,
    acked_epoch: Vec<u64>,
    resume_grace_epoch: Vec<u64>,
    snapshots: Vec<Option<VcpuSnapshot>>,
    breakpoints: BTreeMap<BreakpointKey, SoftwareBreakpoint>,
}

impl Inner {
    fn new(vcpu_count: u32) -> Self {
        let len = vcpu_count as usize;
        Self {
            state: DebugState::Running,
            pause_epoch: 0,
            stop_reason: None,
            stop_vcpu_id: None,
            resume_mode: ResumeMode::All,
            resume_apply_epoch: vec![0; len],
            registered: vec![false; len],
            acked_epoch: vec![0; len],
            resume_grace_epoch: vec![0; len],
            snapshots: vec![None; len],
            breakpoints: BTreeMap::new(),
        }
    }

    fn all_registered_acked(&self) -> bool {
        self.registered
            .iter()
            .enumerate()
            .filter(|(_, registered)| **registered)
            .all(|(idx, _)| self.acked_epoch[idx] == self.pause_epoch)
    }

    fn snapshot(&self, vcpu_id: u32) -> Option<VcpuSnapshot> {
        self.snapshots
            .get(vcpu_id as usize)
            .and_then(|entry| entry.clone())
    }

    fn can_resume_vcpu(&self, vcpu_id: u32) -> bool {
        match self.resume_mode {
            ResumeMode::All => true,
            ResumeMode::SingleStep { vcpu_id: target } => target == vcpu_id,
        }
    }
}

pub enum RunOutcome {
    VmExit(winemu_hypervisor::types::VmExit),
    Retry,
    Shutdown,
}

pub enum WaitOutcome {
    Paused,
    Shutdown,
}

pub struct DebugController {
    vcpu_count: u32,
    sched: Arc<Scheduler>,
    memory: GuestMemoryAccess,
    symbolizer: Option<KernelSymbolizer>,
    caps: RwLock<DebugCaps>,
    inner: Mutex<Inner>,
    cv: Condvar,
}

impl DebugController {
    pub fn new(
        vcpu_count: u32,
        sched: Arc<Scheduler>,
        memory: Arc<RwLock<GuestMemory>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            vcpu_count,
            sched,
            memory: GuestMemoryAccess::new(memory),
            symbolizer: KernelSymbolizer::load_default(),
            caps: RwLock::new(DebugCaps::default()),
            inner: Mutex::new(Inner::new(vcpu_count)),
            cv: Condvar::new(),
        })
    }

    pub fn set_backend_caps(&self, caps: DebugCaps) {
        *self.caps.write().unwrap() = caps;
    }

    pub fn debug_caps(&self) -> DebugCaps {
        *self.caps.read().unwrap()
    }

    pub fn on_vcpu_thread_start(&self, vcpu_id: u32) {
        let mut inner = self.inner.lock().unwrap();
        let Some(slot) = inner.registered.get_mut(vcpu_id as usize) else {
            return;
        };
        if *slot {
            return;
        }
        *slot = true;
        if inner.state == DebugState::Paused
            && inner.acked_epoch[vcpu_id as usize] != inner.pause_epoch
        {
            inner.state = DebugState::PauseRequested;
        }
        self.cv.notify_all();
    }

    pub fn state(&self) -> DebugState {
        self.inner.lock().unwrap().state
    }

    pub fn snapshot(&self, vcpu_id: u32) -> Option<VcpuSnapshot> {
        self.inner.lock().unwrap().snapshot(vcpu_id)
    }

    pub fn primary_paused_vcpu(&self) -> Option<u32> {
        let inner = self.inner.lock().unwrap();
        if inner.state != DebugState::Paused {
            return None;
        }
        if let Some(vcpu_id) = inner.stop_vcpu_id {
            if inner
                .snapshots
                .get(vcpu_id as usize)
                .and_then(Option::as_ref)
                .is_some()
            {
                return Some(vcpu_id);
            }
        }
        inner
            .registered
            .iter()
            .enumerate()
            .find(|(idx, registered)| **registered && inner.snapshots[*idx].is_some())
            .and_then(|(idx, _)| u32::try_from(idx).ok())
    }

    pub fn thread_ids(&self) -> Vec<u32> {
        let inner = self.inner.lock().unwrap();
        inner
            .registered
            .iter()
            .enumerate()
            .filter_map(|(idx, registered)| {
                if *registered {
                    u32::try_from(idx + 1).ok()
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn stop_vcpu_id(&self) -> Option<u32> {
        let inner = self.inner.lock().unwrap();
        if inner.state != DebugState::Paused {
            return None;
        }
        inner.stop_vcpu_id.filter(|vcpu_id| {
            inner
                .snapshots
                .get(*vcpu_id as usize)
                .and_then(Option::as_ref)
                .is_some()
        })
    }

    pub fn read_guest_phys(&self, gpa: u64, len: usize) -> Result<Vec<u8>> {
        self.require_paused()?;
        self.memory.read_phys(gpa, len)
    }

    pub fn read_guest_virt(&self, vcpu_id: u32, va: u64, len: usize) -> Result<Vec<u8>> {
        self.require_paused()?;
        let snapshot = self.snapshot(vcpu_id).ok_or_else(|| {
            WinemuError::Memory(format!("no paused snapshot for vcpu {}", vcpu_id))
        })?;
        let space = translate::translation_space_for_va(&snapshot, va)?;
        self.read_guest_virt_in_space(space, va, len)
    }

    pub fn write_guest_virt(&self, vcpu_id: u32, va: u64, bytes: &[u8]) -> Result<()> {
        self.require_paused()?;
        let snapshot = self.snapshot(vcpu_id).ok_or_else(|| {
            WinemuError::Memory(format!("no paused snapshot for vcpu {}", vcpu_id))
        })?;
        let space = translate::translation_space_for_va(&snapshot, va)?;
        self.write_guest_virt_in_space(space, va, bytes)
    }

    pub fn read_guest_virt_resolved(
        &self,
        preferred_vcpu_id: Option<u32>,
        va: u64,
        len: usize,
    ) -> Result<Vec<u8>> {
        let (_, space) = self.resolve_virtual_access_space(preferred_vcpu_id, va)?;
        self.read_guest_virt_in_space(space, va, len)
    }

    pub fn write_guest_virt_resolved(
        &self,
        preferred_vcpu_id: Option<u32>,
        va: u64,
        bytes: &[u8],
    ) -> Result<()> {
        let (_, space) = self.resolve_virtual_access_space(preferred_vcpu_id, va)?;
        self.write_guest_virt_in_space(space, va, bytes)
    }

    pub fn insert_software_breakpoint(
        &self,
        preferred_vcpu_id: Option<u32>,
        addr: u64,
        kind: usize,
    ) -> Result<()> {
        self.require_paused()?;
        validate_software_breakpoint_kind(kind)?;
        let (vcpu_id, key) = self.resolve_breakpoint_anchor(preferred_vcpu_id, addr)?;
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(bp) = inner.breakpoints.get_mut(&key) {
                if bp.kind != kind {
                    return Err(WinemuError::Memory(format!(
                        "software breakpoint kind mismatch at {}: existing={} requested={}",
                        format_breakpoint_key(key),
                        bp.kind,
                        kind
                    )));
                }
                bp.refs += 1;
                return Ok(());
            }
        }

        let original = self.read_guest_virt_in_space(key.space, addr, SOFTWARE_BREAKPOINT_KIND)?;
        if is_software_breakpoint_encoding(&original) {
            return Err(WinemuError::Memory(format!(
                "refusing to install software breakpoint over existing BRK at {}",
                format_breakpoint_key(key)
            )));
        }
        self.write_guest_virt_in_space(key.space, addr, &AARCH64_BRK_0)?;

        let mut original_raw = [0u8; SOFTWARE_BREAKPOINT_KIND];
        original_raw.copy_from_slice(&original);
        self.inner.lock().unwrap().breakpoints.insert(
            key,
            SoftwareBreakpoint {
                key,
                kind,
                original: original_raw,
                refs: 1,
            },
        );
        log::debug!(
            "debugger: installed software breakpoint vcpu={} {} original={}",
            vcpu_id,
            format_breakpoint_key(key),
            hex_sample(&original_raw)
        );
        Ok(())
    }

    pub fn remove_software_breakpoint(
        &self,
        preferred_vcpu_id: Option<u32>,
        addr: u64,
        kind: usize,
    ) -> Result<()> {
        self.require_paused()?;
        validate_software_breakpoint_kind(kind)?;
        let (vcpu_id, key) = self.resolve_breakpoint_anchor(preferred_vcpu_id, addr)?;

        let original = {
            let mut inner = self.inner.lock().unwrap();
            let Some(bp) = inner.breakpoints.get_mut(&key) else {
                return Err(WinemuError::Memory(format!(
                    "software breakpoint not found at {}",
                    format_breakpoint_key(key)
                )));
            };
            if bp.kind != kind {
                return Err(WinemuError::Memory(format!(
                    "software breakpoint kind mismatch at {}: existing={} requested={}",
                    format_breakpoint_key(key),
                    bp.kind,
                    kind
                )));
            }
            if bp.refs > 1 {
                bp.refs -= 1;
                return Ok(());
            }
            let original = bp.original;
            inner.breakpoints.remove(&key);
            original
        };

        self.write_guest_virt_in_space(key.space, addr, &original)?;
        log::debug!(
            "debugger: removed software breakpoint vcpu={} {}",
            vcpu_id,
            format_breakpoint_key(key)
        );
        Ok(())
    }

    pub fn paused_software_breakpoint_key(&self, vcpu_id: u32) -> Option<BreakpointKey> {
        let snapshot = {
            let inner = self.inner.lock().unwrap();
            inner.snapshots.get(vcpu_id as usize)?.as_ref()?.clone()
        };
        let StopReason::DebugException { syndrome, .. } = snapshot.reason else {
            return None;
        };
        let ec = (syndrome >> 26) & 0x3f;
        if ec != ESR_EC_BRK64 {
            return None;
        }
        let pc = snapshot.regs.pc;
        let space = translate::translation_space_for_va(&snapshot, pc).ok()?;
        let key = BreakpointKey { space, addr: pc };
        if self.breakpoint_exists(key) {
            return Some(key);
        }
        let gpa = translate::translate_va_in_space(&self.memory, space, pc).ok()?;
        self.find_breakpoint_alias_key(pc, gpa, &[key])
    }

    pub fn temporarily_disable_software_breakpoint(
        &self,
        vcpu_id: u32,
        key: BreakpointKey,
    ) -> Result<()> {
        let original = {
            let inner = self.inner.lock().unwrap();
            let Some(bp) = inner.breakpoints.get(&key) else {
                return Err(WinemuError::Memory(format!(
                    "software breakpoint not found at {}",
                    format_breakpoint_key(key)
                )));
            };
            bp.original
        };
        self.write_guest_virt_in_space(key.space, key.addr, &original)?;
        log::debug!(
            "debugger: temporarily disabled software breakpoint vcpu={} {}",
            vcpu_id,
            format_breakpoint_key(key)
        );
        Ok(())
    }

    pub fn reenable_software_breakpoint(&self, vcpu_id: u32, key: BreakpointKey) -> Result<()> {
        {
            let inner = self.inner.lock().unwrap();
            if !inner.breakpoints.contains_key(&key) {
                return Err(WinemuError::Memory(format!(
                    "software breakpoint not found at {}",
                    format_breakpoint_key(key)
                )));
            }
        }
        self.write_guest_virt_in_space(key.space, key.addr, &AARCH64_BRK_0)?;
        log::debug!(
            "debugger: re-enabled software breakpoint vcpu={} {}",
            vcpu_id,
            format_breakpoint_key(key)
        );
        Ok(())
    }

    pub fn set_gdb_register(&self, vcpu_id: u32, index: usize, raw: &[u8]) -> Result<()> {
        self.with_snapshot_mut(vcpu_id, |snapshot| {
            set_snapshot_register_from_gdb(snapshot, index, raw)
        })
    }

    pub fn replace_gdb_register_file(&self, vcpu_id: u32, raw: &[u8]) -> Result<()> {
        self.with_snapshot_mut(vcpu_id, |snapshot| {
            let mut offset = 0usize;
            for index in 0..gdb_register_count() {
                let Some(size) = gdb_register_size(index) else {
                    break;
                };
                let end = offset
                    .checked_add(size)
                    .ok_or_else(|| WinemuError::Memory("gdb register file overflow".to_string()))?;
                if end > raw.len() {
                    return Err(WinemuError::Memory(
                        "short gdb register file payload".to_string(),
                    ));
                }
                set_snapshot_register_from_gdb(snapshot, index, &raw[offset..end])?;
                offset = end;
            }
            if offset != raw.len() {
                return Err(WinemuError::Memory(
                    "unexpected trailing gdb register bytes".to_string(),
                ));
            }
            Ok(())
        })
    }

    pub fn format_symbol(&self, addr: u64) -> String {
        let Some(symbolizer) = self.symbolizer.as_ref() else {
            return "error: kernel symbolizer not loaded\n".to_string();
        };
        let Some(symbol) = symbolizer.lookup(addr) else {
            return format!(
                "{:#018x}: <unknown> (symbols from {})\n",
                addr,
                symbolizer.path().display()
            );
        };
        format!(
            "{:#018x}: {} + {:#x} (base {:#018x}, symbols from {})\n",
            addr,
            symbol.symbol,
            symbol.offset,
            symbol.symbol_addr,
            symbolizer.path().display()
        )
    }

    pub fn format_backtrace(&self, vcpu_id: u32) -> String {
        if let Err(err) = self.require_paused() {
            return format!("error: {}\n", err);
        }
        let Some(snapshot) = self.snapshot(vcpu_id) else {
            return format!("error: no paused snapshot for vcpu {}\n", vcpu_id);
        };
        let Some(frames) = self.collect_backtrace_frames(vcpu_id, &snapshot) else {
            return "error: backtrace is only implemented for aarch64 snapshots\n".to_string();
        };

        let mut out = String::new();
        for (index, addr, label) in frames {
            out.push_str(&format!("#{} {:<4} {:#018x}", index, label, addr));
            if let Some(symbolizer) = self.symbolizer.as_ref() {
                if let Some(symbol) = symbolizer.lookup(addr) {
                    out.push_str(&format!(" {}+{:#x}", symbol.symbol, symbol.offset));
                }
            }
            out.push('\n');
        }
        out
    }

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

    pub fn format_status(&self) -> String {
        let inner = self.inner.lock().unwrap();
        let registered = inner.registered.iter().filter(|slot| **slot).count();
        let paused = if inner.state == DebugState::Running {
            0
        } else {
            inner
                .registered
                .iter()
                .enumerate()
                .filter(|(idx, registered)| {
                    **registered && inner.acked_epoch[*idx] == inner.pause_epoch
                })
                .count()
        };
        format!(
            "state={:?} pause_epoch={} registered={} paused={} resume_mode={:?} reason={:?} stop_vcpu={:?}\n",
            inner.state,
            inner.pause_epoch,
            registered,
            paused,
            inner.resume_mode,
            inner.stop_reason,
            inner.stop_vcpu_id
        )
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

    fn resolve_breakpoint_anchor(
        &self,
        preferred_vcpu_id: Option<u32>,
        addr: u64,
    ) -> Result<(u32, BreakpointKey)> {
        let (vcpu_id, space) = self.resolve_virtual_access_space(preferred_vcpu_id, addr)?;
        let key = BreakpointKey { space, addr };
        let gpa = translate::translate_va_in_space(&self.memory, space, addr)?;
        if self.breakpoint_exists(key) {
            return Ok((vcpu_id, key));
        }
        if let Some(alias_key) = self.find_breakpoint_alias_key(addr, gpa, &[key]) {
            return Ok((vcpu_id, alias_key));
        }
        Ok((vcpu_id, key))
    }

    fn breakpoint_exists(&self, key: BreakpointKey) -> bool {
        self.inner.lock().unwrap().breakpoints.contains_key(&key)
    }

    fn find_breakpoint_alias_key(
        &self,
        addr: u64,
        gpa: u64,
        skip_keys: &[BreakpointKey],
    ) -> Option<BreakpointKey> {
        let candidate_keys = {
            let inner = self.inner.lock().unwrap();
            inner
                .breakpoints
                .values()
                .map(|bp| bp.key)
                .filter(|key| key.addr == addr && !skip_keys.contains(key))
                .collect::<Vec<_>>()
        };
        for key in candidate_keys {
            let existing_gpa =
                match translate::translate_va_in_space(&self.memory, key.space, key.addr) {
                    Ok(gpa) => gpa,
                    Err(_) => continue,
                };
            if existing_gpa == gpa {
                return Some(key);
            }
        }
        None
    }

    fn candidate_paused_vcpus(&self, preferred_vcpu_id: Option<u32>) -> Vec<u32> {
        let mut candidates = Vec::new();
        let mut push_unique = |vcpu_id: u32| {
            if !candidates.contains(&vcpu_id) {
                candidates.push(vcpu_id);
            }
        };
        if let Some(vcpu_id) = preferred_vcpu_id {
            push_unique(vcpu_id);
        }
        if let Some(vcpu_id) = self.stop_vcpu_id() {
            push_unique(vcpu_id);
        }
        if let Some(vcpu_id) = self.primary_paused_vcpu() {
            push_unique(vcpu_id);
        }
        let inner = self.inner.lock().unwrap();
        for (idx, snapshot) in inner.snapshots.iter().enumerate() {
            if snapshot.is_some() {
                push_unique(idx as u32);
            }
        }
        candidates
    }

    fn resolve_virtual_access_space(
        &self,
        preferred_vcpu_id: Option<u32>,
        va: u64,
    ) -> Result<(u32, TranslationSpace)> {
        self.require_paused()?;

        let mut first_err = None;
        for vcpu_id in self.candidate_paused_vcpus(preferred_vcpu_id) {
            let snapshot = match self.snapshot(vcpu_id) {
                Some(snapshot) => snapshot,
                None => continue,
            };
            match translate::translation_space_for_va(&snapshot, va) {
                Ok(space) => match translate::translate_va_in_space(&self.memory, space, va) {
                    Ok(_) => return Ok((vcpu_id, space)),
                    Err(err) if first_err.is_none() => first_err = Some(err),
                    Err(_) => {}
                },
                Err(err) if first_err.is_none() => first_err = Some(err),
                Err(_) => {}
            }
        }

        Err(first_err.unwrap_or_else(|| {
            WinemuError::Memory(format!(
                "no paused vcpu can resolve virtual address {:#x}",
                va
            ))
        }))
    }

    fn read_guest_virt_in_space(
        &self,
        space: TranslationSpace,
        va: u64,
        len: usize,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        let mut offset = 0usize;
        while offset < len {
            let cur_va = va.checked_add(offset as u64).ok_or_else(|| {
                WinemuError::Memory(format!("virtual address overflow at {:#x}", va))
            })?;
            let gpa = translate::translate_va_in_space(&self.memory, space, cur_va)?;
            let page_remaining = (0x1000 - ((cur_va as usize) & 0xfff)).min(len - offset);
            let chunk = self.memory.read_phys(gpa, page_remaining)?;
            out.extend_from_slice(&chunk);
            offset += page_remaining;
        }
        Ok(out)
    }

    fn write_guest_virt_in_space(
        &self,
        space: TranslationSpace,
        va: u64,
        bytes: &[u8],
    ) -> Result<()> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let cur_va = va.checked_add(offset as u64).ok_or_else(|| {
                WinemuError::Memory(format!("virtual address overflow at {:#x}", va))
            })?;
            let trace = translate::translate_va_in_space_trace(&self.memory, space, cur_va)?;
            let page_remaining = (0x1000 - ((cur_va as usize) & 0xfff)).min(bytes.len() - offset);
            let chunk = &bytes[offset..offset + page_remaining];
            let before = self.memory.read_phys(trace.gpa, page_remaining)?;
            self.memory.write_phys(trace.gpa, chunk)?;
            let after = self.memory.read_phys(trace.gpa, page_remaining)?;
            log::debug!(
                "debugger: write_guest_virt space={} va={:#x} -> gpa={:#x} len={} before={} after={} requested={} l0e={:#x} l1e={:#x} l2e={:#x} l3e={:#x}",
                format_translation_space(space),
                cur_va,
                trace.gpa,
                page_remaining,
                hex_sample(&before),
                hex_sample(&after),
                hex_sample(chunk),
                trace.l0e,
                trace.l1e,
                trace.l2e,
                trace.l3e
            );
            offset += page_remaining;
        }
        Ok(())
    }

    fn with_snapshot_mut<T>(
        &self,
        vcpu_id: u32,
        update: impl FnOnce(&mut VcpuSnapshot) -> Result<T>,
    ) -> Result<T> {
        self.require_paused()?;
        let mut inner = self.inner.lock().unwrap();
        let snapshot = inner
            .snapshots
            .get_mut(vcpu_id as usize)
            .and_then(Option::as_mut)
            .ok_or_else(|| {
                WinemuError::Memory(format!("no paused snapshot for vcpu {}", vcpu_id))
            })?;
        update(snapshot)
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

    fn require_paused(&self) -> Result<()> {
        if self.state() != DebugState::Paused {
            return Err(WinemuError::Memory("debugger is not paused".to_string()));
        }
        Ok(())
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

    fn collect_backtrace_frames(
        &self,
        vcpu_id: u32,
        snapshot: &VcpuSnapshot,
    ) -> Option<Vec<(usize, u64, &'static str)>> {
        #[cfg(target_arch = "aarch64")]
        {
            let mut frames = Vec::new();
            frames.push((0, snapshot.regs.pc, "pc"));
            if snapshot.regs.x[30] != 0 {
                frames.push((1, snapshot.regs.x[30], "lr"));
            }

            let mut fp = snapshot.regs.x[29];
            let mut frame_index = frames.len();
            for _ in 0..16 {
                if fp == 0 {
                    break;
                }
                let raw = match self.read_guest_virt(vcpu_id, fp, 16) {
                    Ok(raw) if raw.len() == 16 => raw,
                    _ => break,
                };
                let mut prev_fp_raw = [0u8; 8];
                let mut ret_raw = [0u8; 8];
                prev_fp_raw.copy_from_slice(&raw[..8]);
                ret_raw.copy_from_slice(&raw[8..16]);
                let prev_fp = u64::from_le_bytes(prev_fp_raw);
                let ret = u64::from_le_bytes(ret_raw);
                if ret == 0 || prev_fp <= fp {
                    break;
                }
                frames.push((frame_index, ret, "fp"));
                frame_index += 1;
                fp = prev_fp;
            }
            Some(frames)
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = vcpu_id;
            let _ = snapshot;
            None
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

fn capture_snapshot(vcpu_id: u32, vcpu: &mut dyn Vcpu, reason: StopReason) -> Option<VcpuSnapshot> {
    let regs = match vcpu.regs() {
        Ok(regs) => regs,
        Err(err) => {
            log::warn!("debugger: vcpu{} regs snapshot failed: {}", vcpu_id, err);
            return None;
        }
    };
    let special_regs = match vcpu.special_regs() {
        Ok(regs) => regs,
        Err(err) => {
            log::warn!(
                "debugger: vcpu{} special regs snapshot failed: {}",
                vcpu_id,
                err
            );
            return None;
        }
    };
    Some(VcpuSnapshot {
        vcpu_id,
        regs,
        special_regs,
        reason,
    })
}

fn apply_snapshot(vcpu_id: u32, vcpu: &mut dyn Vcpu, snapshot: &VcpuSnapshot) {
    if let Err(err) = vcpu.set_regs(&snapshot.regs) {
        log::warn!("debugger: vcpu{} restore regs failed: {}", vcpu_id, err);
        return;
    }
    if let Err(err) = vcpu.set_special_regs(&snapshot.special_regs) {
        log::warn!(
            "debugger: vcpu{} restore special regs failed: {}",
            vcpu_id,
            err
        );
    }
}

fn arm_single_step(vcpu_id: u32, vcpu: &mut dyn Vcpu) -> Result<()> {
    vcpu.set_trap_debug_exceptions(true).map_err(|err| {
        WinemuError::Hypervisor(format!(
            "vcpu{} enable debug exception trap failed: {}",
            vcpu_id, err
        ))
    })?;
    vcpu.set_guest_single_step(true).map_err(|err| {
        WinemuError::Hypervisor(format!(
            "vcpu{} enable guest single-step failed: {}",
            vcpu_id, err
        ))
    })
}

fn gdb_register_count() -> usize {
    34
}

fn gdb_register_size(index: usize) -> Option<usize> {
    match index {
        0..=32 => Some(core::mem::size_of::<u64>()),
        33 => Some(core::mem::size_of::<u32>()),
        _ => None,
    }
}

fn set_snapshot_register_from_gdb(
    snapshot: &mut VcpuSnapshot,
    index: usize,
    raw: &[u8],
) -> Result<()> {
    #[cfg(target_arch = "aarch64")]
    {
        match index {
            0..=30 => snapshot.regs.x[index] = decode_u64(raw)?,
            31 => snapshot.regs.sp = decode_u64(raw)?,
            32 => snapshot.regs.pc = decode_u64(raw)?,
            33 => snapshot.regs.pstate = decode_u32(raw)? as u64,
            _ => {
                return Err(WinemuError::Memory(format!(
                    "unsupported gdb register index {}",
                    index
                )));
            }
        }
        Ok(())
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = snapshot;
        let _ = index;
        let _ = raw;
        Err(WinemuError::Memory(
            "gdb register writes are only implemented for aarch64".to_string(),
        ))
    }
}

fn decode_u64(raw: &[u8]) -> Result<u64> {
    if raw.len() != core::mem::size_of::<u64>() {
        return Err(WinemuError::Memory(format!(
            "invalid 64-bit register payload size {}",
            raw.len()
        )));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(raw);
    Ok(u64::from_le_bytes(bytes))
}

fn decode_u32(raw: &[u8]) -> Result<u32> {
    if raw.len() != core::mem::size_of::<u32>() {
        return Err(WinemuError::Memory(format!(
            "invalid 32-bit register payload size {}",
            raw.len()
        )));
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(raw);
    Ok(u32::from_le_bytes(bytes))
}

fn is_canceled_run(err: &WinemuError) -> bool {
    matches!(err, WinemuError::Hypervisor(msg) if msg.contains("canceled"))
}

fn format_breakpoint_key(key: BreakpointKey) -> String {
    format!("{} va={:#x}", format_translation_space(key.space), key.addr)
}

fn format_translation_space(space: TranslationSpace) -> String {
    format!(
        "{} root_base={:#x}",
        translation_root_name(space.root),
        space.root_base
    )
}

fn translation_root_name(root: TranslationRoot) -> &'static str {
    match root {
        TranslationRoot::Ttbr0 => "ttbr0",
        TranslationRoot::Ttbr1 => "ttbr1",
    }
}

fn hex_sample(bytes: &[u8]) -> String {
    const LIMIT: usize = 16;
    let mut out = String::new();
    for (index, byte) in bytes.iter().take(LIMIT).enumerate() {
        if index != 0 {
            out.push(' ');
        }
        use std::fmt::Write as _;
        let _ = write!(out, "{:02x}", byte);
    }
    if bytes.len() > LIMIT {
        out.push_str(" ...");
    }
    out
}
