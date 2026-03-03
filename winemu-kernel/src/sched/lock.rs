use super::{
    commit_deferred_scheduling_locked, prepare_unlock_edge_kernel_switch_locked,
    switch_kernel_continuation, vcpu_id, SCHED,
};

// 可重入；底层用原子自旋锁保护多 vCPU 并发。
// lock_owner 存 vcpu_id+1（0 = 未持有）。

fn spinlock_acquire() {
    crate::arch::spin::lock_word(SCHED.spinlock.get());
}

fn spinlock_release() {
    crate::arch::spin::unlock_word(SCHED.spinlock.get());
}

pub struct ScopedSchedulerLock {
    held: bool,
}

impl ScopedSchedulerLock {
    #[inline(always)]
    pub fn new() -> Self {
        sched_lock_acquire();
        Self { held: true }
    }

    #[inline(always)]
    pub fn unlock(mut self) {
        if self.held {
            self.held = false;
            sched_lock_release();
        }
    }
}

impl Drop for ScopedSchedulerLock {
    fn drop(&mut self) {
        if self.held {
            self.held = false;
            sched_lock_release();
        }
    }
}

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
    sched_lock_release_impl();
}

fn sched_lock_release_impl() {
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
            commit_deferred_scheduling_locked();
            unlock_switch = prepare_unlock_edge_kernel_switch_locked(vid);
            wake_idle_mask = super::consume_idle_wakeup_mask_locked();
            *SCHED.lock_owner.get() = 0;
            spinlock_release();
        }
    }
    if wake_idle_mask != 0 {
        crate::hypercall::kick_vcpu_mask(wake_idle_mask);
    }
    if let Some(sw) = unlock_switch {
        crate::process::switch_to_thread_process(sw.to_tid);
        crate::timer::schedule_running_slice_100ns(
            sw.now_100ns,
            sw.next_deadline_100ns,
            sw.slice_remaining_100ns,
        );
        let switched = unsafe { switch_kernel_continuation(sw.from_tid, sw.to_tid) };
        if !switched {
            panic!(
                "sched: unlock-edge kernel continuation switch failed from={} to={}",
                sw.from_tid, sw.to_tid
            );
        }
    }
}

#[inline(always)]
pub fn sched_lock_held_by_current_vcpu() -> bool {
    let owner_key = (vcpu_id() as u32) + 1;
    unsafe { *SCHED.lock_owner.get() == owner_key && *SCHED.lock_count.get() != 0 }
}
