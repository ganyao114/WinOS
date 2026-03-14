use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    Arc, Condvar, Mutex,
};
use std::time::Duration;

const MAX_TRACKED_VCPUS: usize = 256;
type CpuMask =
    winemu_shared::CpuMask<{ (MAX_TRACKED_VCPUS + (u64::BITS as usize) - 1) / (u64::BITS as usize) }>;

#[derive(Clone, Copy, Debug, Default)]
struct MaskState {
    idle_vcpu_mask: CpuMask,
    kick_armed_mask: CpuMask,
    external_irq_pending_mask: CpuMask,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SchedulerWakeStats {
    pub kick_requests: u64,
    pub kick_coalesced: u64,
    pub external_irq_requests: u64,
    pub external_irq_coalesced: u64,
    pub external_irq_taken: u64,
    pub unpark_mask_calls: u64,
    pub unpark_any_calls: u64,
    pub unpark_thread_wakes: u64,
    pub pending_external_irq_mask: u64,
    pub idle_vcpu_mask: u64,
}

pub struct Scheduler {
    pub vcpu_count: u32,
    vcpu_threads: Mutex<Vec<(u32, std::thread::Thread)>>,
    masks: Mutex<MaskState>,
    wake_cursor: AtomicU32,
    kick_requests: AtomicU64,
    kick_coalesced: AtomicU64,
    external_irq_requests: AtomicU64,
    external_irq_coalesced: AtomicU64,
    external_irq_taken: AtomicU64,
    unpark_mask_calls: AtomicU64,
    unpark_any_calls: AtomicU64,
    unpark_thread_wakes: AtomicU64,
    idle_wait_epoch: Mutex<u64>,
    idle_wait_cv: Condvar,
    pub shutdown: AtomicBool,
}

impl Scheduler {
    pub fn new(vcpu_count: u32) -> Arc<Self> {
        assert!(
            (vcpu_count as usize) <= MAX_TRACKED_VCPUS,
            "vcpu_count {} exceeds MAX_TRACKED_VCPUS {}",
            vcpu_count,
            MAX_TRACKED_VCPUS
        );
        Arc::new(Self {
            vcpu_count,
            vcpu_threads: Mutex::new(Vec::new()),
            masks: Mutex::new(MaskState::default()),
            wake_cursor: AtomicU32::new(0),
            kick_requests: AtomicU64::new(0),
            kick_coalesced: AtomicU64::new(0),
            external_irq_requests: AtomicU64::new(0),
            external_irq_coalesced: AtomicU64::new(0),
            external_irq_taken: AtomicU64::new(0),
            unpark_mask_calls: AtomicU64::new(0),
            unpark_any_calls: AtomicU64::new(0),
            unpark_thread_wakes: AtomicU64::new(0),
            idle_wait_epoch: Mutex::new(0),
            idle_wait_cv: Condvar::new(),
            shutdown: AtomicBool::new(false),
        })
    }

    #[inline]
    fn valid_vcpu_mask(&self) -> CpuMask {
        CpuMask::prefix(self.vcpu_count as usize)
    }

    fn notify_idle_waiters(&self) {
        let mut epoch = self.idle_wait_epoch.lock().unwrap();
        *epoch = epoch.wrapping_add(1);
        self.idle_wait_cv.notify_all();
    }

    pub fn wait_for_wakeup(&self, timeout: Duration) {
        let epoch = self.idle_wait_epoch.lock().unwrap();
        let observed = *epoch;
        let _ = self
            .idle_wait_cv
            .wait_timeout_while(epoch, timeout, |cur| *cur == observed);
    }

    pub fn register_vcpu_thread(&self, vcpu_id: u32) {
        self.vcpu_threads
            .lock()
            .unwrap()
            .push((vcpu_id, std::thread::current()));
    }

    pub fn set_vcpu_idle(&self, vcpu_id: u32, idle: bool) {
        if vcpu_id as usize >= MAX_TRACKED_VCPUS {
            return;
        }
        let mut masks = self.masks.lock().unwrap();
        if idle {
            masks.idle_vcpu_mask.insert(vcpu_id as usize);
        } else {
            masks.idle_vcpu_mask.remove(vcpu_id as usize);
            masks.kick_armed_mask.remove(vcpu_id as usize);
        }
    }

    fn unpark_vcpu_mask(&self, mask: CpuMask) {
        let valid = mask.intersection(self.valid_vcpu_mask());
        if valid.is_empty() {
            return;
        }
        self.unpark_mask_calls.fetch_add(1, Ordering::Relaxed);
        let mut woke_threads = 0u64;
        for (id, thread) in self.vcpu_threads.lock().unwrap().iter() {
            if valid.contains(*id as usize) {
                thread.unpark();
                woke_threads = woke_threads.saturating_add(1);
            }
        }
        if woke_threads != 0 {
            self.unpark_thread_wakes
                .fetch_add(woke_threads, Ordering::Relaxed);
            self.notify_idle_waiters();
        }
    }

    fn unpark_any_vcpu(&self) {
        let threads = self.vcpu_threads.lock().unwrap();
        let len = threads.len();
        if len == 0 {
            return;
        }
        self.unpark_any_calls.fetch_add(1, Ordering::Relaxed);
        let idx = (self.wake_cursor.fetch_add(1, Ordering::Relaxed) as usize) % len;
        threads[idx].1.unpark();
        self.unpark_thread_wakes.fetch_add(1, Ordering::Relaxed);
        self.notify_idle_waiters();
    }

    fn choose_vcpu_from_mask(&self, mask: CpuMask) -> Option<u32> {
        let valid = mask.intersection(self.valid_vcpu_mask());
        if valid.is_empty() {
            return None;
        }
        let count = self.vcpu_count as usize;
        if count == 0 {
            return None;
        }
        let start = (self.wake_cursor.fetch_add(1, Ordering::Relaxed) as usize) % count;
        for off in 0..count {
            let vid = (start + off) % count;
            if valid.contains(vid) {
                return Some(vid as u32);
            }
        }
        None
    }

    fn choose_external_irq_target(&self) -> Option<u32> {
        let valid = self.valid_vcpu_mask();
        if valid.is_empty() {
            return None;
        }
        let idle_mask = {
            let masks = self.masks.lock().unwrap();
            masks.idle_vcpu_mask.intersection(valid)
        };
        if let Some(vid) = self.choose_vcpu_from_mask(idle_mask) {
            return Some(vid);
        }
        self.choose_vcpu_from_mask(valid)
    }

    pub fn unpark_one_vcpu(&self) {
        if let Some(vid) = self.choose_external_irq_target() {
            self.unpark_vcpu_mask(CpuMask::from_cpu(vid as usize));
            return;
        }
        let idle_mask = {
            let masks = self.masks.lock().unwrap();
            masks.idle_vcpu_mask.intersection(self.valid_vcpu_mask())
        };
        if let Some(vid) = self.choose_vcpu_from_mask(idle_mask) {
            self.unpark_vcpu_mask(CpuMask::from_cpu(vid as usize));
            return;
        }
        self.unpark_any_vcpu();
    }

    fn request_external_irq_cpumask(&self, mask: CpuMask) {
        let valid = mask.intersection(self.valid_vcpu_mask());
        if valid.is_empty() {
            return;
        }
        self.external_irq_requests.fetch_add(1, Ordering::Relaxed);
        let newly_armed = {
            let mut masks = self.masks.lock().unwrap();
            let newly_armed = valid.difference(masks.external_irq_pending_mask);
            masks.external_irq_pending_mask = masks.external_irq_pending_mask.union(valid);
            newly_armed
        };
        if newly_armed.is_empty() {
            self.external_irq_coalesced.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.unpark_vcpu_mask(newly_armed);
    }

    pub fn request_external_irq_mask(&self, mask: u32) {
        self.request_external_irq_cpumask(CpuMask::from_low_u64(mask as u64));
    }

    fn kick_vcpu_cpumask(&self, mask: CpuMask) {
        let valid = mask.intersection(self.valid_vcpu_mask());
        if valid.is_empty() {
            return;
        }
        self.kick_requests.fetch_add(1, Ordering::Relaxed);
        let newly_armed = {
            let mut masks = self.masks.lock().unwrap();
            let idle_targets = masks.idle_vcpu_mask.intersection(valid);
            if idle_targets.is_empty() {
                CpuMask::empty()
            } else {
                let newly_armed = idle_targets.difference(masks.kick_armed_mask);
                masks.kick_armed_mask = masks.kick_armed_mask.union(idle_targets);
                newly_armed
            }
        };
        if newly_armed.is_empty() {
            self.kick_coalesced.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.unpark_vcpu_mask(newly_armed);
    }

    pub fn kick_vcpu_mask(&self, mask: u32) {
        self.kick_vcpu_cpumask(CpuMask::from_low_u64(mask as u64));
    }

    pub fn kick_vcpu(&self, vcpu_id: u32) {
        if vcpu_id as usize >= MAX_TRACKED_VCPUS {
            return;
        }
        self.kick_vcpu_cpumask(CpuMask::from_cpu(vcpu_id as usize));
    }

    pub fn request_external_irq(&self) {
        if let Some(target) = self.choose_external_irq_target() {
            self.request_external_irq_cpumask(CpuMask::from_cpu(target as usize));
            return;
        }
        let valid = self.valid_vcpu_mask();
        if !valid.is_empty() {
            self.request_external_irq_cpumask(valid);
            return;
        }
        self.unpark_any_vcpu();
    }

    pub fn take_external_irq_request(&self, vcpu_id: u32) -> bool {
        if vcpu_id as usize >= MAX_TRACKED_VCPUS {
            return false;
        }
        let took = {
            let mut masks = self.masks.lock().unwrap();
            if masks.external_irq_pending_mask.contains(vcpu_id as usize) {
                masks.external_irq_pending_mask.remove(vcpu_id as usize);
                true
            } else {
                false
            }
        };
        if took {
            self.external_irq_taken.fetch_add(1, Ordering::Relaxed);
        }
        took
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.masks.lock().unwrap().external_irq_pending_mask = self.valid_vcpu_mask();
        for (_, thread) in self.vcpu_threads.lock().unwrap().iter() {
            thread.unpark();
        }
        self.notify_idle_waiters();
    }

    pub fn wake_stats_snapshot(&self) -> SchedulerWakeStats {
        let masks = *self.masks.lock().unwrap();
        SchedulerWakeStats {
            kick_requests: self.kick_requests.load(Ordering::Relaxed),
            kick_coalesced: self.kick_coalesced.load(Ordering::Relaxed),
            external_irq_requests: self.external_irq_requests.load(Ordering::Relaxed),
            external_irq_coalesced: self.external_irq_coalesced.load(Ordering::Relaxed),
            external_irq_taken: self.external_irq_taken.load(Ordering::Relaxed),
            unpark_mask_calls: self.unpark_mask_calls.load(Ordering::Relaxed),
            unpark_any_calls: self.unpark_any_calls.load(Ordering::Relaxed),
            unpark_thread_wakes: self.unpark_thread_wakes.load(Ordering::Relaxed),
            pending_external_irq_mask: masks.external_irq_pending_mask.to_low_u64(),
            idle_vcpu_mask: masks.idle_vcpu_mask.to_low_u64(),
        }
    }

    pub fn reset_wake_stats(&self) {
        self.kick_requests.store(0, Ordering::Relaxed);
        self.kick_coalesced.store(0, Ordering::Relaxed);
        self.external_irq_requests.store(0, Ordering::Relaxed);
        self.external_irq_coalesced.store(0, Ordering::Relaxed);
        self.external_irq_taken.store(0, Ordering::Relaxed);
        self.unpark_mask_calls.store(0, Ordering::Relaxed);
        self.unpark_any_calls.store(0, Ordering::Relaxed);
        self.unpark_thread_wakes.store(0, Ordering::Relaxed);
    }
}
