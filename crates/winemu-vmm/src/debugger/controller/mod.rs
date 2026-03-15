use super::breakpoint::{BreakpointKey, SoftwareBreakpoint};
use super::memory::GuestMemoryAccess;
use super::symbol::KernelSymbolizer;
use super::types::{DebugState, StopReason, VcpuSnapshot};
use crate::memory::GuestMemory;
use crate::sched::Scheduler;
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Duration;
use winemu_hypervisor::DebugCaps;

mod access;
mod breakpoints;
mod formatting;
mod pause;
mod registers;
mod snapshot;

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
}
