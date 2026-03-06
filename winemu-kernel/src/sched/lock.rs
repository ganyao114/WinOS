// sched/lock.rs — KSchedulerLock RAII + 可重入自旋锁
// unlock edge 在 Drop 时触发：commit deferred scheduling + kernel switch

use super::global::SCHED;
use super::cpu::{vcpu_id};

fn spinlock_acquire() {
    crate::arch::spin::lock_word(SCHED.spinlock.get());
}

fn spinlock_release() {
    crate::arch::spin::unlock_word(SCHED.spinlock.get());
}

// ── RAII guard ────────────────────────────────────────────────

pub struct KSchedulerLock {
    held: bool,
}

impl KSchedulerLock {
    #[inline(always)]
    pub fn acquire() -> Self {
        sched_lock_acquire();
        Self { held: true }
    }

    /// 提前手动释放（消耗 self，不触发 Drop 的二次释放）
    #[inline(always)]
    pub fn unlock(mut self) {
        if self.held {
            self.held = false;
            sched_lock_release();
        }
    }
}

impl Drop for KSchedulerLock {
    fn drop(&mut self) {
        if self.held {
            self.held = false;
            sched_lock_release();
        }
    }
}

// 旧名称兼容别名
pub type ScopedSchedulerLock = KSchedulerLock;

impl KSchedulerLock {
    /// 旧接口兼容：ScopedSchedulerLock::new()
    #[inline(always)]
    pub fn new() -> Self {
        Self::acquire()
    }
}

// ── 底层 acquire / release ────────────────────────────────────

pub fn sched_lock_acquire() {
    let vid = vcpu_id();
    let owner_key = (vid as u32) + 1;
    unsafe {
        let owner = SCHED.lock_owner.get();
        let count = SCHED.lock_count.get();
        if *owner == owner_key && *count > 0 {
            *count += 1;
            return;
        }
        debug_assert!(
            !crate::timer::timer_lock_held_by_current_vcpu(),
            "lock order violation: acquire sched lock before timer lock"
        );
        spinlock_acquire();
        *owner = owner_key;
        *count = 1;
    }
}

pub fn sched_lock_release() {
    let mut wake_idle_mask = 0u32;
    let mut unlock_switch = None;
    unsafe {
        let vid = vcpu_id();
        let owner_key = (vid as u32) + 1;
        let owner = SCHED.lock_owner.get();
        let count = SCHED.lock_count.get();
        if *owner != owner_key {
            debug_assert!(
                *owner == owner_key,
                "sched_lock_release by non-owner vcpu={} owner={}",
                vid,
                *owner
            );
            return;
        }
        if *count == 0 {
            debug_assert!(*count != 0, "sched_lock_release with zero depth");
            return;
        }
        *count -= 1;
        if *count == 0 {
            let decision =
                super::topology::commit_and_collect_unlock_edge_decision_locked(vid);
            unlock_switch = decision.unlock_kernel_switch;
            wake_idle_mask = decision.wake_idle_mask;
            *SCHED.lock_owner.get() = 0;
            spinlock_release();
        }
    }
    if wake_idle_mask != 0 {
        crate::hypercall::kick_vcpu_mask(wake_idle_mask);
    }
    if let Some(sw) = unlock_switch {
        super::topology::record_schedule_event_unlock_edge();
        super::context::execute_kernel_continuation_switch(
            sw.from_tid,
            sw.to_tid,
            sw.now_100ns,
            sw.next_deadline_100ns,
            sw.slice_remaining_100ns,
            "unlock-edge",
        );
    }
}

#[inline(always)]
pub fn sched_lock_held_by_current_vcpu() -> bool {
    let owner_key = (vcpu_id() as u32) + 1;
    unsafe { *SCHED.lock_owner.get() == owner_key && *SCHED.lock_count.get() != 0 }
}
