// ── 调度核心 ──────────────────────────────────────────────────

#[inline(always)]
fn running_on_other_vcpu_locked(tid: u32, self_vcpu: usize) -> bool {
    unsafe {
        for vid in 0..MAX_VCPUS {
            if vid != self_vcpu && (*SCHED.vcpus.get())[vid].current_tid == tid {
                return true;
            }
        }
    }
    false
}

#[inline(always)]
fn next_ready_priority_for_vcpu_locked(vcpu_id: usize) -> Option<u8> {
    if let Some(p) = ready_highest_priority_scheduled_locked(vcpu_id) {
        return Some(p);
    }
    ready_highest_priority_suggested_locked(vcpu_id)
}

#[inline(always)]
pub(crate) fn record_schedule_event_unlock_edge() {
    unsafe {
        *SCHED.schedule_unlock_edge_count.get() =
            (*SCHED.schedule_unlock_edge_count.get()).saturating_add(1);
    }
}

#[inline(always)]
pub(crate) fn record_schedule_event_trap() {
    unsafe {
        *SCHED.schedule_trap_count.get() = (*SCHED.schedule_trap_count.get()).saturating_add(1);
    }
}

pub(crate) fn execute_kernel_continuation_switch(
    from_tid: u32,
    to_tid: u32,
    now_100ns: u64,
    next_deadline_100ns: u64,
    slice_remaining_100ns: u64,
    source: &'static str,
) {
    crate::process::switch_to_thread_process(to_tid);
    crate::timer::schedule_running_slice_100ns(now_100ns, next_deadline_100ns, slice_remaining_100ns);
    let switched = unsafe { switch_kernel_continuation(from_tid, to_tid) };
    if !switched {
        panic!(
            "sched: {} kernel continuation switch failed from={} to={}",
            source,
            from_tid,
            to_tid
        );
    }
}

fn run_selected_thread_noreturn(
    to_tid: u32,
    now_100ns: u64,
    next_deadline_100ns: u64,
    slice_remaining_100ns: u64,
) -> ! {
    crate::process::switch_to_thread_process(to_tid);
    timer::schedule_running_slice_100ns(now_100ns, next_deadline_100ns, slice_remaining_100ns);
    if has_kernel_continuation(to_tid) {
        unsafe { enter_kernel_continuation_noreturn(to_tid) }
    }
    set_thread_in_kernel(to_tid, false);
    unsafe { enter_user_thread_noreturn(to_tid) }
}

pub(crate) enum SchedulerRoundAction {
    ContinueCurrent {
        now_100ns: u64,
        next_deadline_100ns: u64,
        slice_remaining_100ns: u64,
    },
    RunThread {
        now_100ns: u64,
        next_deadline_100ns: u64,
        slice_remaining_100ns: u64,
        from_tid: u32,
        to_tid: u32,
        pending_resched: bool,
        timeout_woke: bool,
        cur_not_running: bool,
    },
    IdleWait {
        now_100ns: u64,
        next_deadline_100ns: u64,
        from_tid: u32,
    },
}

pub(crate) fn scheduler_round_locked(
    vcpu_id: usize,
    from_tid: u32,
    quantum_100ns: u64,
) -> SchedulerRoundAction {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "scheduler_round_locked requires sched lock"
    );
    let now = now_ticks();
    set_vcpu_idle_locked(vcpu_id, false);
    let pending_resched = consume_pending_reschedule_locked(vcpu_id);
    let quantum_expired = charge_current_runtime_locked(vcpu_id, now, quantum_100ns);
    if quantum_expired {
        rotate_current_on_quantum_expire_locked(vcpu_id, quantum_100ns);
    }
    let cur_not_running = from_tid != 0
        && thread_exists(from_tid)
        && with_thread(from_tid, |t| t.state != ThreadState::Running);
    let timeout_woke = check_timeouts(now);
    let next_deadline = next_wait_deadline_locked();

    if pending_resched || quantum_expired || timeout_woke || from_tid == 0 || cur_not_running {
        let (from_sched, to) = schedule(vcpu_id, now, quantum_100ns);
        if to != 0 {
            set_vcpu_idle_locked(vcpu_id, false);
            let slice_remaining = current_slice_remaining_100ns(vcpu_id, quantum_100ns);
            return SchedulerRoundAction::RunThread {
                now_100ns: now,
                next_deadline_100ns: next_deadline,
                slice_remaining_100ns: slice_remaining,
                from_tid: from_sched,
                to_tid: to,
                pending_resched,
                timeout_woke,
                cur_not_running,
            };
        }
        return SchedulerRoundAction::IdleWait {
            now_100ns: now,
            next_deadline_100ns: next_deadline,
            from_tid: from_sched,
        };
    }

    let slice_remaining = current_slice_remaining_100ns(vcpu_id, quantum_100ns);
    SchedulerRoundAction::ContinueCurrent {
        now_100ns: now,
        next_deadline_100ns: next_deadline,
        slice_remaining_100ns: slice_remaining,
    }
}

/// 选取下一个线程并切换（在 trap 路径持锁调用）
/// 返回 (from_tid, to_tid)；若无需切换则 from == to；to == 0 表示 WFI idle
pub fn schedule(vcpu_id: usize, now_100ns: u64, quantum_100ns: u64) -> (u32, u32) {
    unsafe {
        mark_vcpu_online_locked(vcpu_id);
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let mut cur_tid = vcpu.current_tid;
        if cur_tid != 0 && !thread_exists(cur_tid) {
            vcpu.current_tid = 0;
            set_current_cpu_thread(vcpu_id, 0);
            cur_tid = 0;
        }
        let cur_running = cur_tid != 0 && with_thread(cur_tid, |t| t.state == ThreadState::Running);

        // Strict priority preemption:
        // keep current running thread unless there exists a higher-priority ready thread
        // in this core's scheduled front, or (when empty) in suggested migration view.
        if cur_running {
            let cur_prio = with_thread(cur_tid, |t| t.priority);
            match next_ready_priority_for_vcpu_locked(vcpu_id) {
                None => return (cur_tid, cur_tid),
                Some(ready_prio) if ready_prio <= cur_prio => return (cur_tid, cur_tid),
                _ => {}
            }
        }

        let mut next_tid = ready_pop_for_vcpu_locked(vcpu_id);
        while next_tid != 0 {
            if !thread_exists(next_tid) {
                next_tid = ready_pop_for_vcpu_locked(vcpu_id);
                continue;
            }
            let state = with_thread(next_tid, |t| t.state);
            if state != ThreadState::Ready {
                next_tid = ready_pop_for_vcpu_locked(vcpu_id);
                continue;
            }
            if running_on_other_vcpu_locked(next_tid, vcpu_id) {
                // Stale ready node: this thread is already bound to another vCPU.
                if with_thread(next_tid, |t| t.state == ThreadState::Ready) {
                    set_thread_state_locked(next_tid, ThreadState::Running);
                } else {
                    with_thread_mut(next_tid, |t| t.sched_next = 0);
                }
                next_tid = ready_pop_for_vcpu_locked(vcpu_id);
                continue;
            }
            break;
        }

        if next_tid == 0 {
            // No ready threads — if current thread is still Running, keep it
            if cur_running {
                return (cur_tid, cur_tid);
            }
            // No runnable threads at all → WFI
            vcpu.current_tid = 0;
            set_current_cpu_thread(vcpu_id, 0);
            set_vcpu_kernel_sp(vcpu_id, default_kernel_stack_top());
            return (cur_tid, 0);
        }

        if cur_running {
            if next_tid == cur_tid {
                set_thread_state_locked(cur_tid, ThreadState::Running);
                with_thread_mut(cur_tid, |t| {
                    if t.slice_remaining_100ns == 0 {
                        t.slice_remaining_100ns = quantum_100ns.max(1);
                    }
                    t.last_start_100ns = now_100ns;
                    t.last_vcpu_hint = vcpu_id as u8;
                });
                return (cur_tid, cur_tid);
            }
            let cur_state = with_thread(cur_tid, |t| t.state);
            if cur_state == ThreadState::Running {
                set_thread_state_locked(cur_tid, ThreadState::Ready);
            }
        }

        set_thread_state_locked(next_tid, ThreadState::Running);
        with_thread_mut(next_tid, |t| {
            if t.slice_remaining_100ns == 0 {
                t.slice_remaining_100ns = quantum_100ns.max(1);
            }
            t.last_start_100ns = now_100ns;
            t.last_vcpu_hint = vcpu_id as u8;
        });
        vcpu.current_tid = next_tid;
        set_current_cpu_thread(vcpu_id, next_tid);
        set_vcpu_kernel_sp_for_tid(vcpu_id, next_tid);

        (cur_tid, next_tid)
    }
}

/// 唤醒指定线程
pub fn wake(tid: u32, result: u32) {
    sched_lock_acquire();
    let _ = end_wait_locked(tid, result);
    sched_lock_release();
}

/// Put the current running thread back to ready queue.
pub fn yield_current_thread() {
    sched_lock_acquire();
    let cur = current_tid();
    if cur == 0 || !thread_exists(cur) {
        sched_lock_release();
        return;
    }
    let cur_state = with_thread(cur, |t| t.state);
    if cur_state == ThreadState::Running {
        set_thread_state_locked(cur, ThreadState::Ready);
    }
    sched_lock_release();
}

pub fn terminate_current_thread() {
    let cur = current_tid();
    if cur != 0 {
        let _ = terminate_thread_by_tid(cur);
    }
}

/// Initialize the first thread on a vCPU (called from kernel_main).
pub fn set_initial_thread(vcpu_id: usize, tid: u32) {
    sched_lock_acquire();
    unsafe {
        mark_vcpu_online_locked(vcpu_id);
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        vcpu.current_tid = tid;
        set_thread_state_locked(tid, ThreadState::Running);
        with_thread_mut(tid, |t| t.last_vcpu_hint = vcpu_id as u8);
        set_current_cpu_thread(vcpu_id, tid);
        set_vcpu_kernel_sp_for_tid(vcpu_id, tid);
        if let Some(pid) = thread_pid(tid) {
            crate::process::set_current_vcpu_pid(vcpu_id, pid);
        }
    }
    sched_lock_release();
}

/// Lazily register Thread 0 on first SVC entry.
/// Called at the top of svc_dispatch when current_tid() == 0.
pub fn register_thread0(teb_va: u64) -> bool {
    let pid = crate::process::boot_pid();
    let Some((kstack_base, kstack_size)) = alloc_kernel_stack() else {
        return false;
    };
    let tid = thread_store_mut().alloc_with(|id| {
        let mut t = KThread::zeroed();
        t.init_thread0(id, pid, teb_va, kstack_base, kstack_size);
        t
    });
    let Some(tid) = tid else {
        free_kernel_stack(kstack_base);
        return false;
    };
    crate::process::on_thread_created(pid, tid);
    unsafe {
        let vid = vcpu_id().min(MAX_VCPUS - 1);
        mark_vcpu_online_locked(vid);
        let vcpu = &mut (*SCHED.vcpus.get())[vid];
        vcpu.current_tid = tid;
        with_thread_mut(tid, |t| t.last_vcpu_hint = vid as u8);
        set_current_cpu_thread(vid, tid);
        set_vcpu_kernel_sp_for_tid(vid, tid);
        crate::process::set_current_vcpu_pid(vid, pid);
    }
    true
}

pub fn set_current_thread_teb(teb_va: u64) {
    if teb_va == 0 {
        return;
    }
    let tid = current_tid();
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    sched_lock_acquire();
    with_thread_mut(tid, |t| {
        t.teb_va = teb_va;
        t.ctx.tpidr = teb_va;
        t.ctx.x[18] = teb_va;
    });
    sched_lock_release();
}

fn enter_bootstrap_thread_dispatch(vcpu_id: usize) -> ! {
    let vid = vcpu_id.min(MAX_VCPUS - 1);
    let quantum_100ns = timer::DEFAULT_TIMESLICE_100NS.max(1);
    let tid = current_tid();
    if tid == 0 || !thread_exists(tid) {
        panic!("sched: bootstrap current tid is invalid");
    }

    let now_100ns = now_ticks();
    let next_deadline_100ns;
    let slice_remaining_100ns;

    sched_lock_acquire();
    set_vcpu_idle_locked(vid, false);
    next_deadline_100ns = next_wait_deadline_locked();
    slice_remaining_100ns = current_slice_remaining_100ns(vid, quantum_100ns);
    sched_lock_release();

    run_selected_thread_noreturn(tid, now_100ns, next_deadline_100ns, slice_remaining_100ns)
}

fn enter_secondary_idle_loop(vcpu_id: usize) -> ! {
    if cfg!(feature = "sched-secondary-round") {
        enter_core_scheduler_round_loop(vcpu_id, 0, false);
    }

    let vid = vcpu_id.min(MAX_VCPUS - 1);

    set_current_cpu_thread(vid, 0);
    set_vcpu_kernel_sp(vid, default_kernel_stack_top());

    loop {
        let now_100ns = now_ticks();
        let next_deadline_100ns;

        sched_lock_acquire();
        set_vcpu_idle_locked(vid, true);
        next_deadline_100ns = next_wait_deadline_locked();
        sched_lock_release();
        crate::hostcall::pump_completions();
        timer::idle_wait_until_deadline_100ns(now_100ns, next_deadline_100ns);
    }
}

fn enter_core_scheduler_round_loop(
    vcpu_id: usize,
    from_tid_hint: u32,
    allow_user_entry_fallback: bool,
) -> ! {
    let vid = vcpu_id.min(MAX_VCPUS - 1);
    let quantum_100ns = timer::DEFAULT_TIMESLICE_100NS.max(1);

    // Stage alignment: secondary-style round loop keeps old invariant and
    // only consumes runnable kernel continuations.
    if !allow_user_entry_fallback {
        set_current_cpu_thread(vid, 0);
        set_vcpu_kernel_sp(vid, default_kernel_stack_top());

        loop {
            let now_100ns;
            let next_deadline_100ns;
            let mut to_tid = 0u32;
            let mut slice_remaining_100ns = quantum_100ns;

            crate::hostcall::pump_completions();
            sched_lock_acquire();
            now_100ns = now_ticks();
            set_vcpu_idle_locked(vid, false);
            let _ = consume_pending_reschedule_locked(vid);
            let _ = check_timeouts(now_100ns);
            next_deadline_100ns = next_wait_deadline_locked();

            if ready_highest_priority_kernel_continuation_locked(vid).is_some() {
                let picked = pick_ready_kernel_continuation_locked(vid);
                if picked != 0 {
                    set_thread_state_locked(picked, ThreadState::Running);
                    with_thread_mut(picked, |t| {
                        if t.slice_remaining_100ns == 0 {
                            t.slice_remaining_100ns = quantum_100ns;
                        }
                        t.last_start_100ns = now_100ns;
                        t.last_vcpu_hint = vid as u8;
                    });
                    unsafe {
                        (*SCHED.vcpus.get())[vid].current_tid = picked;
                    }
                    set_current_cpu_thread(vid, picked);
                    set_vcpu_kernel_sp_for_tid(vid, picked);
                    slice_remaining_100ns = current_slice_remaining_100ns(vid, quantum_100ns);
                    to_tid = picked;
                }
            }

            if to_tid == 0 {
                set_vcpu_idle_locked(vid, true);
                sched_lock_release();
                timer::idle_wait_until_deadline_100ns(now_100ns, next_deadline_100ns);
                continue;
            }

            sched_lock_release();
            run_selected_thread_noreturn(
                to_tid,
                now_100ns,
                next_deadline_100ns,
                slice_remaining_100ns,
            )
        }
    }

    let mut from_tid = from_tid_hint;

    if from_tid != 0 && thread_exists(from_tid) {
        set_current_cpu_thread(vid, from_tid);
        set_vcpu_kernel_sp_for_tid(vid, from_tid);
    } else {
        from_tid = 0;
        set_current_cpu_thread(vid, 0);
        set_vcpu_kernel_sp(vid, default_kernel_stack_top());
    }

    loop {
        crate::hostcall::pump_completions();
        sched_lock_acquire();
        match scheduler_round_locked(vid, from_tid, quantum_100ns) {
            SchedulerRoundAction::RunThread {
                now_100ns,
                next_deadline_100ns,
                slice_remaining_100ns,
                to_tid,
                ..
            } => {
                sched_lock_release();
                run_selected_thread_noreturn(
                    to_tid,
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns,
                )
            }
            SchedulerRoundAction::ContinueCurrent {
                now_100ns,
                next_deadline_100ns,
                slice_remaining_100ns,
            } => {
                let to_tid = if from_tid != 0 && thread_exists(from_tid) {
                    from_tid
                } else {
                    current_tid()
                };
                if to_tid == 0 || !thread_exists(to_tid) {
                    from_tid = 0;
                    set_vcpu_idle_locked(vid, true);
                    sched_lock_release();
                    timer::idle_wait_until_deadline_100ns(now_100ns, next_deadline_100ns);
                    continue;
                }
                sched_lock_release();
                run_selected_thread_noreturn(
                    to_tid,
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns,
                )
            }
            SchedulerRoundAction::IdleWait {
                now_100ns,
                next_deadline_100ns,
                ..
            } => {
                from_tid = 0;
                set_vcpu_idle_locked(vid, true);
                sched_lock_release();
                timer::idle_wait_until_deadline_100ns(now_100ns, next_deadline_100ns);
                continue;
            }
        }
    }
}

pub fn enter_core_scheduler_entry(vcpu_id: usize) -> ! {
    if cfg!(feature = "sched-secondary-round") {
        let cur = current_tid();
        if cur != 0 && thread_exists(cur) {
            enter_core_scheduler_round_loop(vcpu_id, cur, true);
        }
        enter_core_scheduler_round_loop(vcpu_id, 0, false);
    }

    let cur = current_tid();
    if cur != 0 && thread_exists(cur) {
        enter_bootstrap_thread_dispatch(vcpu_id)
    }
    enter_secondary_idle_loop(vcpu_id)
}

/// Returns true if all allocated threads are Terminated or Free (process can exit).
pub fn all_threads_done() -> bool {
    unsafe {
        let Some(store) = (&*SCHED.threads.get()).as_ref() else {
            return true;
        };
        let mut all_done = true;
        store.for_each_live_ptr(|_tid, ptr| {
            if !all_done {
                return;
            }
            if (*ptr).is_idle_thread {
                return;
            }
            let state = (*ptr).state;
            if state != ThreadState::Terminated && state != ThreadState::Free {
                all_done = false;
            }
        });
        all_done
    }
}
