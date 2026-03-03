#[inline(always)]
fn vcpu_bit(vid: usize) -> u32 {
    if vid >= 32 {
        0
    } else {
        1u32 << vid
    }
}

#[inline(always)]
fn ready_target_vcpu_hint(tid: u32) -> Option<usize> {
    let hint = with_thread(tid, |t| t.last_vcpu_hint as usize);
    if hint < MAX_VCPUS {
        Some(hint)
    } else {
        None
    }
}

fn ready_push_tid_locked(tid: u32) {
    unsafe {
        if let Some(vid) = ready_target_vcpu_hint(tid) {
            with_thread_mut(tid, |t| (*SCHED.ready_local.get())[vid].push(t));
        } else {
            with_thread_mut(tid, |t| (*SCHED.ready_global.get()).push(t));
        }
    }
}

fn ready_remove_tid_locked(tid: u32) {
    unsafe {
        (*SCHED.ready_global.get()).remove(tid);
        for vid in 0..MAX_VCPUS {
            (*SCHED.ready_local.get())[vid].remove(tid);
        }
    }
}

fn ready_highest_priority_locked() -> Option<u8> {
    unsafe {
        let mut highest = (*SCHED.ready_global.get()).highest_priority();
        for vid in 0..MAX_VCPUS {
            let cand = (*SCHED.ready_local.get())[vid].highest_priority();
            if cand.is_some() && (highest.is_none() || cand > highest) {
                highest = cand;
            }
        }
        highest
    }
}

fn ready_pop_for_vcpu_locked(vcpu_id: usize) -> u32 {
    unsafe {
        let local = &mut (*SCHED.ready_local.get())[vcpu_id];
        let local_prio = local.highest_priority();
        let global_prio = (*SCHED.ready_global.get()).highest_priority();
        let mut donor_vid = None;
        let mut donor_prio = None;
        for off in 1..=MAX_VCPUS {
            let vid = (vcpu_id + off) % MAX_VCPUS;
            let p = (*SCHED.ready_local.get())[vid].highest_priority();
            if p.is_some() && (donor_prio.is_none() || p > donor_prio) {
                donor_prio = p;
                donor_vid = Some(vid);
            }
        }

        let mut best = local_prio;
        if global_prio.is_some() && (best.is_none() || global_prio > best) {
            best = global_prio;
        }
        if donor_prio.is_some() && (best.is_none() || donor_prio > best) {
            best = donor_prio;
        }
        let Some(best_prio) = best else {
            return 0;
        };

        if local_prio == Some(best_prio) {
            return local.pop_highest_prefer_vcpu(vcpu_id);
        }
        if global_prio == Some(best_prio) {
            return (*SCHED.ready_global.get()).pop_highest_prefer_vcpu(vcpu_id);
        }
        if let Some(vid) = donor_vid {
            return (*SCHED.ready_local.get())[vid].pop_highest_prefer_vcpu(vcpu_id);
        }
        0
    }
}

pub(crate) fn mark_vcpu_needs_scheduling_locked(vid: usize) {
    if vid >= MAX_VCPUS {
        return;
    }
    unsafe {
        (*SCHED.vcpus.get())[vid].needs_scheduling = true;
    }
}

pub(crate) fn mark_all_vcpus_needs_scheduling_locked() {
    unsafe {
        for vid in 0..MAX_VCPUS {
            let bit = vcpu_bit(vid);
            if (*SCHED.vcpus.get())[vid].current_tid != 0
                || (*SCHED.idle_vcpu_mask.get() & bit) != 0
                || vid == 0
            {
                (*SCHED.vcpus.get())[vid].needs_scheduling = true;
            }
        }
    }
}

pub(crate) fn commit_deferred_scheduling_locked() {
    unsafe {
        let mut pending = *SCHED.pending_reschedule_mask.get();
        let mut mask = *SCHED.reschedule_mask.get();
        for vid in 0..MAX_VCPUS {
            if (*SCHED.vcpus.get())[vid].needs_scheduling {
                let bit = vcpu_bit(vid);
                pending |= bit;
                mask |= bit;
                if (*SCHED.idle_vcpu_mask.get() & bit) != 0 {
                    // Preserve in reschedule mask for idle-vCPU wakeup path.
                    *SCHED.reschedule_mask.get() |= bit;
                }
                (*SCHED.vcpus.get())[vid].needs_scheduling = false;
            }
        }
        *SCHED.pending_reschedule_mask.get() = pending;
        *SCHED.reschedule_mask.get() = mask;
    }
}

fn mark_reschedule_targeted_locked(changed_tid: u32, ready_prio: Option<u8>, ready_hint: Option<usize>) {
    let local_vid = vcpu_id().min(MAX_VCPUS - 1);
    let mut marked = vcpu_bit(local_vid);
    mark_vcpu_needs_scheduling_locked(local_vid);

    unsafe {
        if let Some(hint) = ready_hint {
            if hint < MAX_VCPUS && hint != local_vid {
                mark_vcpu_needs_scheduling_locked(hint);
                marked |= vcpu_bit(hint);
            }
        }
        let mut idle_target = None;
        let mut preempt_target = None;
        let mut preempt_prio = u8::MAX;
        let idle_mask = *SCHED.idle_vcpu_mask.get();
        for vid in 0..MAX_VCPUS {
            let bit = vcpu_bit(vid);
            if (marked & bit) != 0 {
                continue;
            }
            if (idle_mask & bit) != 0 {
                if idle_target.is_none() {
                    idle_target = Some(vid);
                }
                continue;
            }

            let running_tid = (*SCHED.vcpus.get())[vid].current_tid;
            if running_tid == changed_tid {
                mark_vcpu_needs_scheduling_locked(vid);
                continue;
            }

            if let Some(prio) = ready_prio {
                if running_tid != 0 && thread_exists(running_tid) {
                    let running_prio = with_thread(running_tid, |t| t.priority);
                    if running_prio < prio && running_prio < preempt_prio {
                        preempt_prio = running_prio;
                        preempt_target = Some(vid);
                    }
                }
            }
        }
        if let Some(vid) = idle_target {
            mark_vcpu_needs_scheduling_locked(vid);
        } else if let Some(vid) = preempt_target {
            mark_vcpu_needs_scheduling_locked(vid);
        }
    }
}

pub(crate) fn consume_pending_reschedule_locked(vid: usize) -> bool {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "consume_pending_reschedule_locked requires sched lock"
    );
    unsafe {
        let bit = vcpu_bit(vid);
        let pending = SCHED.pending_reschedule_mask.get();
        let hinted = SCHED.reschedule_mask.get();
        let had = ((*pending | *hinted) & bit) != 0;
        if !had {
            return false;
        }
        *pending &= !bit;
        *hinted &= !bit;
        true
    }
}

pub(crate) fn consume_idle_wakeup_mask_locked() -> u32 {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "consume_idle_wakeup_mask_locked requires sched lock"
    );
    unsafe {
        let hinted = SCHED.reschedule_mask.get();
        let idle = *SCHED.idle_vcpu_mask.get();
        let wake_mask = *hinted & idle;
        if wake_mask != 0 {
            *hinted &= !wake_mask;
        }
        wake_mask
    }
}

pub(crate) struct UnlockEdgeKernelSwitch {
    pub from_tid: u32,
    pub to_tid: u32,
    pub now_100ns: u64,
    pub next_deadline_100ns: u64,
    pub slice_remaining_100ns: u64,
}

fn local_reschedule_pending_locked(vid: usize) -> bool {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "local_reschedule_pending_locked requires sched lock"
    );
    unsafe {
        let bit = vcpu_bit(vid);
        ((*SCHED.pending_reschedule_mask.get() | *SCHED.reschedule_mask.get()) & bit) != 0
    }
}

fn pick_ready_kernel_continuation_locked(vcpu_id: usize) -> u32 {
    let mut skipped = Vec::new();
    let mut picked = 0u32;
    loop {
        let tid = ready_pop_for_vcpu_locked(vcpu_id);
        if tid == 0 {
            break;
        }
        if has_kernel_continuation(tid) {
            picked = tid;
            break;
        }
        let _ = skipped.try_reserve(1);
        skipped.push(tid);
    }
    for tid in skipped {
        ready_push_tid_locked(tid);
    }
    picked
}

pub(crate) fn prepare_unlock_edge_kernel_switch_locked(
    vid: usize,
) -> Option<UnlockEdgeKernelSwitch> {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "prepare_unlock_edge_kernel_switch_locked requires sched lock"
    );
    if vid >= MAX_VCPUS || !local_reschedule_pending_locked(vid) {
        return None;
    }

    let from_tid = current_tid();
    if from_tid == 0 || !thread_exists(from_tid) {
        return None;
    }
    // Unlock-edge direct kctx switch is only valid when current thread already
    // left Running state (e.g. entered Waiting in the same critical section).
    if with_thread(from_tid, |t| t.state == ThreadState::Running) {
        return None;
    }

    let now = now_ticks();
    let quantum_100ns = timer::DEFAULT_TIMESLICE_100NS.max(1);
    let to_tid = pick_ready_kernel_continuation_locked(vid);
    if to_tid == 0 {
        return None;
    }

    let _ = consume_pending_reschedule_locked(vid);
    set_thread_state_locked(to_tid, ThreadState::Running);
    with_thread_mut(to_tid, |t| {
        if t.slice_remaining_100ns == 0 {
            t.slice_remaining_100ns = quantum_100ns;
        }
        t.last_start_100ns = now;
        t.last_vcpu_hint = vid as u8;
    });
    unsafe {
        (*SCHED.vcpus.get())[vid].current_tid = to_tid;
    }
    set_current_cpu_thread(vid, to_tid);
    set_vcpu_kernel_sp_for_tid(vid, to_tid);

    Some(UnlockEdgeKernelSwitch {
        from_tid,
        to_tid,
        now_100ns: now,
        next_deadline_100ns: next_wait_deadline_locked(),
        slice_remaining_100ns: current_slice_remaining_100ns(vid, quantum_100ns),
    })
}

pub(crate) fn set_vcpu_idle_locked(vid: usize, idle: bool) {
    unsafe {
        let bit = vcpu_bit(vid);
        let mask = SCHED.idle_vcpu_mask.get();
        if idle {
            *mask |= bit;
        } else {
            *mask &= !bit;
        }
    }
}

#[inline(always)]
pub(crate) fn sched_lock_held_by_current_vcpu() -> bool {
    lock::sched_lock_held_by_current_vcpu()
}

// 调度状态变迁的唯一入口（调用者必须持有 sched lock）。
pub(crate) fn set_thread_state_locked(tid: u32, new_state: ThreadState) {
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    let old_state = with_thread(tid, |t| t.state);
    if old_state == new_state {
        return;
    }

    if old_state == ThreadState::Ready {
        ready_remove_tid_locked(tid);
    }

    with_thread_mut(tid, |t| {
        t.state = new_state;
        if new_state != ThreadState::Running {
            t.last_start_100ns = 0;
        }
        if new_state != ThreadState::Ready {
            t.sched_next = 0;
        }
    });

    if new_state == ThreadState::Ready {
        ready_push_tid_locked(tid);
    }
    let (ready_prio, ready_hint) = if new_state == ThreadState::Ready {
        (
            Some(with_thread(tid, |t| t.priority)),
            ready_target_vcpu_hint(tid),
        )
    } else {
        (None, None)
    };
    mark_reschedule_targeted_locked(tid, ready_prio, ready_hint);
}
