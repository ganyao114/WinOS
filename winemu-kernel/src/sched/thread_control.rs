use winemu_shared::status;
use crate::nt::constants::{PSEUDO_CURRENT_THREAD, PSEUDO_CURRENT_THREAD_ALT};
use super::types::ThreadState;
use super::thread_store::{thread_exists, with_thread, with_thread_mut};
use super::cpu::{current_tid, set_current_cpu_thread};
use super::lock::{sched_lock_acquire, sched_lock_release};
use super::topology::{
    set_thread_state_locked, ready_remove_tid_locked, ready_push_tid_locked,
    ready_target_vcpu_hint, mark_reschedule_targeted_locked,
};
use super::global::SCHED;
use super::sync;

// ── 优先级辅助（调用者必须持有 sched lock）──────────────────────

pub(crate) fn set_thread_priority_locked(tid: u32, new_priority: u8) {
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    let clamped = if new_priority > 31 { 31 } else { new_priority };
    let state = with_thread(tid, |t| t.state);
    if state == ThreadState::Ready {
        ready_remove_tid_locked(tid);
    }
    with_thread_mut(tid, |t| {
        t.priority = clamped;
        t.transient_boost = 0;
    });
    if state == ThreadState::Ready {
        ready_push_tid_locked(tid);
    }
    let (ready_prio, ready_hint) = if state == ThreadState::Ready {
        (Some(clamped), ready_target_vcpu_hint(tid))
    } else {
        (None, None)
    };
    mark_reschedule_targeted_locked(tid, ready_prio, ready_hint);
}

pub(crate) fn boost_thread_priority_locked(tid: u32, min_priority: u8) {
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    let cur = with_thread(tid, |t| t.priority);
    if min_priority > cur {
        set_thread_priority_locked(tid, min_priority);
    }
}

pub fn set_thread_base_priority(tid: u32, new_priority: u8) -> bool {
    if tid == 0 || !thread_exists(tid) {
        return false;
    }
    sched_lock_acquire();
    let valid = with_thread(tid, |t| t.state != ThreadState::Free);
    if valid {
        let clamped = if new_priority > 31 { 31 } else { new_priority };
        with_thread_mut(tid, |t| t.base_priority = clamped);
        set_thread_priority_locked(tid, clamped);
    }
    sched_lock_release();
    valid
}

pub fn resolve_thread_tid_from_handle(thread_handle: u64) -> Option<u32> {
    if thread_handle == 0
        || thread_handle == PSEUDO_CURRENT_THREAD
        || thread_handle == PSEUDO_CURRENT_THREAD_ALT
    {
        return Some(current_tid());
    }
    if sync::handle_type(thread_handle) != sync::HANDLE_TYPE_THREAD {
        return None;
    }
    let tid = sync::handle_idx(thread_handle);
    if tid == 0 || !thread_exists(tid) {
        return None;
    }
    if !with_thread(tid, |t| t.state != ThreadState::Free) {
        return None;
    }
    Some(tid)
}

pub fn suspend_thread_by_tid(tid: u32) -> Result<u32, u32> {
    if tid == 0 || !thread_exists(tid) {
        return Err(status::INVALID_HANDLE);
    }

    sched_lock_acquire();
    let (state, prev_count) = with_thread(tid, |t| (t.state, t.suspend_count));
    if state == ThreadState::Free || state == ThreadState::Terminated {
        sched_lock_release();
        return Err(status::INVALID_HANDLE);
    }
    if prev_count == u8::MAX {
        sched_lock_release();
        return Err(status::INVALID_PARAMETER);
    }

    with_thread_mut(tid, |t| {
        t.suspend_count = t.suspend_count.saturating_add(1);
    });
    if prev_count == 0 {
        match state {
            ThreadState::Running | ThreadState::Ready => {
                set_thread_state_locked(tid, ThreadState::Suspended);
            }
            _ => {}
        }
    }

    sched_lock_release();
    Ok(prev_count as u32)
}

pub fn suspend_thread_by_handle(thread_handle: u64) -> Result<u32, u32> {
    let Some(tid) = resolve_thread_tid_from_handle(thread_handle) else {
        return Err(status::INVALID_HANDLE);
    };
    suspend_thread_by_tid(tid)
}

pub fn resume_thread_by_tid(tid: u32) -> Result<u32, u32> {
    if tid == 0 || !thread_exists(tid) {
        return Err(status::INVALID_HANDLE);
    }

    sched_lock_acquire();
    let (state, prev_count) = with_thread(tid, |t| (t.state, t.suspend_count));
    if state == ThreadState::Free || state == ThreadState::Terminated {
        sched_lock_release();
        return Err(status::INVALID_HANDLE);
    }

    if prev_count != 0 {
        with_thread_mut(tid, |t| {
            t.suspend_count -= 1;
        });
        if prev_count == 1 && state == ThreadState::Suspended {
            set_thread_state_locked(tid, ThreadState::Ready);
        }
    }

    sched_lock_release();
    Ok(prev_count as u32)
}

pub fn resume_thread_by_handle(thread_handle: u64) -> Result<u32, u32> {
    let Some(tid) = resolve_thread_tid_from_handle(thread_handle) else {
        return Err(status::INVALID_HANDLE);
    };
    resume_thread_by_tid(tid)
}

pub fn set_thread_base_priority_by_handle(thread_handle: u64, new_priority: i32) -> u32 {
    if new_priority < 0 {
        return status::INVALID_PARAMETER;
    }
    let Some(target_tid) = resolve_thread_tid_from_handle(thread_handle) else {
        return status::INVALID_HANDLE;
    };
    if !set_thread_base_priority(target_tid, new_priority as u8) {
        return status::INVALID_HANDLE;
    }
    status::SUCCESS
}

// ── 时间片记账（调用者必须持有 sched lock）──────────────────────

pub fn charge_current_runtime_locked(vcpu_id: usize, now_100ns: u64, quantum_100ns: u64) -> bool {
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let cur_tid = vcpu.current_tid;
        if cur_tid == 0 {
            return false;
        }
        if !thread_exists(cur_tid) {
            vcpu.current_tid = 0;
            set_current_cpu_thread(vcpu_id, 0);
            return false;
        }
        let mut expired = false;
        with_thread_mut(cur_tid, |t| {
            if t.state != ThreadState::Running {
                return;
            }
            if t.slice_remaining_100ns == 0 {
                t.slice_remaining_100ns = quantum_100ns.max(1);
            }
            if t.last_start_100ns == 0 {
                t.last_start_100ns = now_100ns;
                return;
            }
            let elapsed = now_100ns.saturating_sub(t.last_start_100ns);
            t.last_start_100ns = now_100ns;
            if elapsed >= t.slice_remaining_100ns {
                t.slice_remaining_100ns = 0;
                expired = true;
            } else {
                t.slice_remaining_100ns -= elapsed;
            }
        });
        expired
    }
}

pub fn rotate_current_on_quantum_expire_locked(vcpu_id: usize, quantum_100ns: u64) {
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let cur_tid = vcpu.current_tid;
        if cur_tid == 0 {
            return;
        }
        if !thread_exists(cur_tid) {
            vcpu.current_tid = 0;
            set_current_cpu_thread(vcpu_id, 0);
            return;
        }
        let is_running = with_thread(cur_tid, |t| t.state == ThreadState::Running);
        if !is_running {
            return;
        }
        with_thread_mut(cur_tid, |t| {
            t.slice_remaining_100ns = quantum_100ns.max(1);
            t.last_start_100ns = 0;
            if t.transient_boost > 0 {
                t.transient_boost -= 1;
                let target = t.base_priority.saturating_add(t.transient_boost);
                if t.priority > target {
                    t.priority = target;
                }
            }
        });
        set_thread_state_locked(cur_tid, ThreadState::Ready);
    }
}

pub fn current_slice_remaining_100ns(vcpu_id: usize, default_100ns: u64) -> u64 {
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let cur_tid = vcpu.current_tid;
        if cur_tid == 0 {
            return default_100ns.max(1);
        }
        if !thread_exists(cur_tid) {
            vcpu.current_tid = 0;
            set_current_cpu_thread(vcpu_id, 0);
            return default_100ns.max(1);
        }
        with_thread(cur_tid, |t| {
            if t.state != ThreadState::Running || t.slice_remaining_100ns == 0 {
                default_100ns.max(1)
            } else {
                t.slice_remaining_100ns
            }
        })
    }
}
