use super::{commit_deferred_scheduling_locked, vcpu_id, SCHED};

// 可重入；底层用原子自旋锁保护多 vCPU 并发。
// lock_owner 存 vcpu_id+1（0 = 未持有）。

fn spinlock_acquire() {
    unsafe {
        let p = SCHED.spinlock.get();
        loop {
            // STXR/LDXR 自旋
            core::arch::asm!(
                "1: ldaxr {old:w}, [{p}]",
                "   cbnz  {old:w}, 1b",
                "   stxr  {old:w}, {one:w}, [{p}]",
                "   cbnz  {old:w}, 1b",
                p   = in(reg) p,
                old = out(reg) _,
                one = in(reg) 1u32,
                options(nostack)
            );
            break;
        }
    }
}

fn spinlock_release() {
    unsafe {
        core::arch::asm!(
            "stlr wzr, [{}]",
            in(reg) SCHED.spinlock.get(),
            options(nostack)
        );
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
