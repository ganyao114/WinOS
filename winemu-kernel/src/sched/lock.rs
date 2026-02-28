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
        spinlock_acquire();
        *owner = owner_key;
        *count = 1;
    }
}

pub fn sched_lock_release() {
    unsafe {
        let count = SCHED.lock_count.get();
        if *count == 0 {
            return;
        }
        *count -= 1;
        if *count == 0 {
            let _owner_vid = vcpu_id();
            commit_deferred_scheduling_locked();
            *SCHED.lock_owner.get() = 0;
            spinlock_release();
        }
    }
}
