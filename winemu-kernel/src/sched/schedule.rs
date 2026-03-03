// ── 调度核心 ──────────────────────────────────────────────────

/// 选取下一个线程并切换（在 trap 路径持锁调用）
/// 返回 (from_tid, to_tid)；若无需切换则 from == to；to == 0 表示 WFI idle
pub fn schedule(vcpu_id: usize, now_100ns: u64, quantum_100ns: u64) -> (u32, u32) {
    unsafe {
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        let mut cur_tid = vcpu.current_tid;
        if cur_tid != 0 && !thread_exists(cur_tid) {
            vcpu.current_tid = 0;
            set_current_cpu_thread(vcpu_id, 0);
            cur_tid = 0;
        }
        let cur_running = cur_tid != 0 && with_thread(cur_tid, |t| t.state == ThreadState::Running);

        // Strict priority preemption:
        // keep current running thread unless there exists a higher-priority ready thread.
        if cur_running {
            let cur_prio = with_thread(cur_tid, |t| t.priority);
            match ready_highest_priority_locked() {
                None => return (cur_tid, cur_tid),
                Some(ready_prio) if ready_prio <= cur_prio => return (cur_tid, cur_tid),
                _ => {}
            }
        }

        let next_tid = ready_pop_for_vcpu_locked(vcpu_id);

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
        let vcpu = &mut (*SCHED.vcpus.get())[vcpu_id];
        vcpu.current_tid = tid;
        set_thread_state_locked(tid, ThreadState::Running);
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
        let vcpu = &mut (*SCHED.vcpus.get())[vid];
        vcpu.current_tid = tid;
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
            let state = (*ptr).state;
            if state != ThreadState::Terminated && state != ThreadState::Free {
                all_done = false;
            }
        });
        all_done
    }
}
