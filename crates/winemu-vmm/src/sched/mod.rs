use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    Arc, Condvar, Mutex,
};
use std::time::Duration;

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
    pub pending_external_irq_mask: u32,
    pub idle_vcpu_mask: u32,
}

pub struct Scheduler {
    pub vcpu_count: u32,
    vcpu_threads: Mutex<Vec<(u32, std::thread::Thread)>>,
    idle_vcpu_mask: AtomicU32,
    kick_armed_mask: AtomicU32,
    wake_cursor: AtomicU32,
    external_irq_pending_mask: AtomicU32,
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
    #[inline(always)]
    fn vcpu_bit(vcpu_id: u32) -> Option<u32> {
        if vcpu_id < 32 {
            Some(1u32 << vcpu_id)
        } else {
            None
        }
    }

    pub fn new(vcpu_count: u32) -> Arc<Self> {
        Arc::new(Self {
            vcpu_count,
            vcpu_threads: Mutex::new(Vec::new()),
            idle_vcpu_mask: AtomicU32::new(0),
            kick_armed_mask: AtomicU32::new(0),
            wake_cursor: AtomicU32::new(0),
            external_irq_pending_mask: AtomicU32::new(0),
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

    #[inline(always)]
    fn valid_vcpu_mask(&self) -> u32 {
        if self.vcpu_count == 0 {
            return 0;
        }
        if self.vcpu_count >= 32 {
            return u32::MAX;
        }
        (1u32 << self.vcpu_count) - 1
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
        let Some(bit) = Self::vcpu_bit(vcpu_id) else {
            return;
        };
        if idle {
            self.idle_vcpu_mask.fetch_or(bit, Ordering::Release);
        } else {
            self.idle_vcpu_mask.fetch_and(!bit, Ordering::Release);
            self.kick_armed_mask.fetch_and(!bit, Ordering::Release);
        }
    }

    pub fn unpark_vcpu_mask(&self, mask: u32) {
        let valid = mask & self.valid_vcpu_mask();
        if valid == 0 {
            return;
        }
        self.unpark_mask_calls.fetch_add(1, Ordering::Relaxed);
        let mut woke_threads = 0u64;
        for (id, thread) in self.vcpu_threads.lock().unwrap().iter() {
            if let Some(bit) = Self::vcpu_bit(*id) {
                if (valid & bit) != 0 {
                    thread.unpark();
                    woke_threads = woke_threads.saturating_add(1);
                }
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

    fn choose_vcpu_from_mask(&self, mask: u32) -> Option<u32> {
        if mask == 0 {
            return None;
        }
        let valid = mask & self.valid_vcpu_mask();
        if valid == 0 {
            return None;
        }
        let count = self.vcpu_count.min(32);
        let start = self.wake_cursor.fetch_add(1, Ordering::Relaxed) % count;
        for off in 0..count {
            let vid = (start + off) % count;
            let bit = 1u32 << vid;
            if (valid & bit) != 0 {
                return Some(vid);
            }
        }
        None
    }

    fn choose_external_irq_target(&self) -> Option<u32> {
        let valid = self.valid_vcpu_mask();
        if valid == 0 {
            return None;
        }
        let idle_mask = self.idle_vcpu_mask.load(Ordering::Acquire) & valid;
        if let Some(vid) = self.choose_vcpu_from_mask(idle_mask) {
            return Some(vid);
        }
        self.choose_vcpu_from_mask(valid)
    }

    pub fn unpark_one_vcpu(&self) {
        if let Some(vid) = self.choose_external_irq_target() {
            if let Some(bit) = Self::vcpu_bit(vid) {
                self.unpark_vcpu_mask(bit);
                return;
            }
        }
        let idle_mask = self.idle_vcpu_mask.load(Ordering::Acquire) & self.valid_vcpu_mask();
        if let Some(vid) = self.choose_vcpu_from_mask(idle_mask) {
            if let Some(bit) = Self::vcpu_bit(vid) {
                self.unpark_vcpu_mask(bit);
                return;
            }
            return;
        }
        self.unpark_any_vcpu();
    }

    pub fn request_external_irq_mask(&self, mask: u32) {
        let valid = mask & self.valid_vcpu_mask();
        if valid == 0 {
            return;
        }
        self.external_irq_requests.fetch_add(1, Ordering::Relaxed);
        let prev = self
            .external_irq_pending_mask
            .fetch_or(valid, Ordering::AcqRel);
        let newly_armed = valid & !prev;
        if newly_armed == 0 {
            self.external_irq_coalesced.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.unpark_vcpu_mask(newly_armed);
    }

    pub fn kick_vcpu_mask(&self, mask: u32) {
        let valid = mask & self.valid_vcpu_mask();
        if valid == 0 {
            return;
        }
        self.kick_requests.fetch_add(1, Ordering::Relaxed);
        let idle_targets = self.idle_vcpu_mask.load(Ordering::Acquire) & valid;
        if idle_targets == 0 {
            self.kick_coalesced.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let prev = self
            .kick_armed_mask
            .fetch_or(idle_targets, Ordering::AcqRel);
        let newly_armed = idle_targets & !prev;
        if newly_armed == 0 {
            self.kick_coalesced.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.unpark_vcpu_mask(newly_armed);
    }

    pub fn request_external_irq(&self) {
        if let Some(target) = self.choose_external_irq_target() {
            if let Some(bit) = Self::vcpu_bit(target) {
                self.request_external_irq_mask(bit);
                return;
            }
        }
        let valid = self.valid_vcpu_mask();
        if valid != 0 {
            self.request_external_irq_mask(valid);
            return;
        }
        self.unpark_any_vcpu();
    }

    pub fn take_external_irq_request(&self, vcpu_id: u32) -> bool {
        let Some(bit) = Self::vcpu_bit(vcpu_id) else {
            return false;
        };
        self.external_irq_pending_mask
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                if (pending & bit) != 0 {
                    Some(pending & !bit)
                } else {
                    None
                }
            })
            .map(|_| {
                self.external_irq_taken.fetch_add(1, Ordering::Relaxed);
            })
            .is_ok()
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.external_irq_pending_mask
            .store(self.valid_vcpu_mask(), Ordering::Release);
        for (_, thread) in self.vcpu_threads.lock().unwrap().iter() {
            thread.unpark();
        }
        self.notify_idle_waiters();
    }

    pub fn wake_stats_snapshot(&self) -> SchedulerWakeStats {
        SchedulerWakeStats {
            kick_requests: self.kick_requests.load(Ordering::Relaxed),
            kick_coalesced: self.kick_coalesced.load(Ordering::Relaxed),
            external_irq_requests: self.external_irq_requests.load(Ordering::Relaxed),
            external_irq_coalesced: self.external_irq_coalesced.load(Ordering::Relaxed),
            external_irq_taken: self.external_irq_taken.load(Ordering::Relaxed),
            unpark_mask_calls: self.unpark_mask_calls.load(Ordering::Relaxed),
            unpark_any_calls: self.unpark_any_calls.load(Ordering::Relaxed),
            unpark_thread_wakes: self.unpark_thread_wakes.load(Ordering::Relaxed),
            pending_external_irq_mask: self.external_irq_pending_mask.load(Ordering::Acquire),
            idle_vcpu_mask: self.idle_vcpu_mask.load(Ordering::Acquire),
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
