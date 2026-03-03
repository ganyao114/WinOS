use super::{commit_deferred_scheduling_locked, vcpu_id, SCHED};

// 可重入；底层用原子自旋锁保护多 vCPU 并发。
// lock_owner 存 vcpu_id+1（0 = 未持有）。

fn spinlock_acquire() {
    crate::arch::spin::lock_word(SCHED.spinlock.get());
}

fn spinlock_release() {
    crate::arch::spin::unlock_word(SCHED.spinlock.get());
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
    let mut try_immediate_resched = false;
    unsafe {
        let count = SCHED.lock_count.get();
        if *count == 0 {
            return;
        }
        *count -= 1;
        if *count == 0 {
            let owner_vid = vcpu_id();
            commit_deferred_scheduling_locked();
            let owner_bit = 1u32 << owner_vid;
            let cur = super::current_tid();
            if cur != 0
                && super::thread_exists(cur)
                && (*SCHED.pending_reschedule_mask.get() & owner_bit) != 0
                && super::with_thread(cur, |t| t.state == super::ThreadState::Waiting)
                && super::has_dispatch_continuation(cur)
            {
                try_immediate_resched = true;
            }
            *SCHED.lock_owner.get() = 0;
            spinlock_release();
        }
    }
    // Mesosphere-like unlock edge: when current kernel thread just entered
    // waiting state, immediately jump back to dispatch continuation so
    // scheduler can run without waiting for later trap-exit opportunities.
    if try_immediate_resched {
        let _ = super::reschedule_current_via_dispatch_continuation();
    }
}

#[inline(always)]
pub fn sched_lock_held_by_current_vcpu() -> bool {
    let owner_key = (vcpu_id() as u32) + 1;
    unsafe { *SCHED.lock_owner.get() == owner_key && *SCHED.lock_count.get() != 0 }
}
