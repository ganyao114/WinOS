// svc_dispatch — EL1 SVC 分发器
// 由 vectors.rs 的 SVC handler 汇编调用，处理所有来自 EL0 的 syscall。
// 若需要线程切换，直接修改 SvcFrame 中的寄存器，ERET 后进入新线程。

use crate::hypercall;
use crate::sched::{
    current_tid, has_kernel_continuation, record_schedule_event_trap, register_thread0,
    sched_lock_acquire, sched_lock_release, set_current_in_kernel, set_thread_in_kernel,
    set_vcpu_idle_locked, vcpu_id, with_thread, with_thread_mut, ThreadState,
};
use crate::timer;
use core::sync::atomic::{AtomicU32, Ordering};

use super::constants::{
    EL0_FAULT_ELR_TAG, EL0_FAULT_ESR_TAG, EL0_FAULT_FAR_TAG, EL0_FAULT_SPSR_TAG, EL1_FAULT_ELR_TAG,
    EL1_FAULT_ESR_TAG, EL1_FAULT_FAR_TAG, EL1_FAULT_SPSR_TAG, SVC_TAG_NR_MASK, SVC_TAG_TABLE_MASK,
    SVC_TAG_TABLE_SHIFT,
};
use super::sysno;
use super::{
    file, memory, object, process, registry, section, sync, system, thread, token, win32k, SvcFrame,
};

static SYSCALL_ERR_TRACE_BUDGET: AtomicU32 = AtomicU32::new(512);

#[no_mangle]
pub extern "C" fn svc_migrate_frame_to_thread_stack(frame_ptr: u64, frame_size: u64) -> u64 {
    crate::sched::migrate_svc_frame_to_current_kstack(frame_ptr as *mut u8, frame_size as usize)
        as u64
}

#[no_mangle]
pub extern "C" fn svc_dispatch(frame: &mut SvcFrame) {
    if current_tid() == 0 {
        let _ = register_thread0(frame.tpidr);
    }
    set_current_in_kernel(true);
    crate::sched::reclaim_deferred_kernel_stacks();

    let tag = frame.x8_orig;
    let nr = (tag & SVC_TAG_NR_MASK) as u16;
    let table = ((tag >> SVC_TAG_TABLE_SHIFT) & SVC_TAG_TABLE_MASK) as u8;
    crate::log::debug_u64(0xE200_0000 | ((table as u64) << 12) | nr as u64);

    if table != 0 {
        if table == 1 {
            match nr {
                0x127 => {
                    // NtUserInitializeClientPfnArrays
                    win32k::handle_user_initialize_client_pfn_arrays(frame);
                    schedule_from_trap(frame, true, true);
                    return;
                }
                _ => {}
            }
        }

        // Non-NT tables still need normal trap-exit scheduling so timer slice /
        // deadline programming remains consistent on this path.
        forward_to_vmm(frame, nr, table);
        schedule_from_trap(frame, true, true);
        return;
    }

    match nr {
        sysno::CREATE_FILE => file::handle_create_file(frame),
        sysno::OPEN_FILE => file::handle_open_file(frame),
        sysno::READ_FILE => file::handle_read_file(frame),
        sysno::DEVICE_IO_CONTROL_FILE => file::handle_device_io_control_file(frame),
        sysno::WRITE_FILE => file::handle_write_file(frame),
        sysno::QUERY_INFORMATION_FILE => file::handle_query_information_file(frame),
        sysno::QUERY_ATTRIBUTES_FILE => file::handle_query_attributes_file(frame),
        sysno::QUERY_VOLUME_INFORMATION_FILE => file::handle_query_volume_information_file(frame),
        sysno::SET_INFORMATION_FILE => file::handle_set_information_file(frame),
        sysno::FS_CONTROL_FILE => file::handle_fs_control_file(frame),
        sysno::QUERY_DIRECTORY_FILE => file::handle_query_directory_file(frame),
        sysno::NOTIFY_CHANGE_DIRECTORY_FILE => file::handle_notify_change_directory_file(frame),
        sysno::QUERY_SYSTEM_INFORMATION => system::handle_query_system_information(frame),
        sysno::QUERY_SYSTEM_TIME => system::handle_query_system_time(frame),
        sysno::QUERY_PERFORMANCE_COUNTER => system::handle_query_performance_counter(frame),

        sysno::CREATE_EVENT => sync::handle_create_event(frame),
        sysno::SET_EVENT => sync::handle_set_event(frame),
        sysno::RESET_EVENT => sync::handle_reset_event_or_delay(frame),
        sysno::WAIT_SINGLE => sync::handle_wait_single(frame),
        sysno::WAIT_MULTIPLE => sync::handle_wait_multiple(frame),
        sysno::CREATE_MUTEX => sync::handle_create_mutex(frame),
        sysno::RELEASE_MUTANT => sync::handle_release_mutant_or_set_information_process(frame),
        sysno::CREATE_SEMAPHORE => sync::handle_create_semaphore(frame),
        sysno::RELEASE_SEMAPHORE => sync::handle_release_semaphore(frame),

        sysno::OPEN_KEY => registry::handle_open_key(frame),
        sysno::CREATE_KEY => registry::handle_create_key(frame),
        sysno::QUERY_KEY => registry::handle_query_key(frame),
        sysno::QUERY_VALUE_KEY => registry::handle_query_value_key(frame),
        sysno::SET_VALUE_KEY => registry::handle_set_value_key(frame),
        sysno::DELETE_KEY => registry::handle_delete_key(frame),
        sysno::DELETE_VALUE_KEY => registry::handle_delete_value_key(frame),
        sysno::ENUMERATE_KEY => registry::handle_enumerate_key(frame),
        sysno::ENUMERATE_VALUE_KEY => registry::handle_enumerate_value_key(frame),

        sysno::ALLOCATE_VIRTUAL_MEMORY => memory::handle_allocate_virtual_memory(frame),
        sysno::FREE_VIRTUAL_MEMORY => memory::handle_free_virtual_memory(frame),
        sysno::QUERY_VIRTUAL_MEMORY => memory::handle_query_virtual_memory(frame),
        sysno::PROTECT_VIRTUAL_MEMORY => memory::handle_protect_virtual_memory(frame),
        sysno::READ_VIRTUAL_MEMORY => memory::handle_read_virtual_memory(frame),
        sysno::WRITE_VIRTUAL_MEMORY => memory::handle_write_virtual_memory(frame),

        sysno::CREATE_SECTION => section::handle_create_section(frame),
        sysno::OPEN_SECTION => section::handle_open_section(frame),
        sysno::MAP_VIEW_OF_SECTION => section::handle_map_view_of_section(frame),
        sysno::UNMAP_VIEW_OF_SECTION => section::handle_unmap_view_of_section(frame),

        sysno::QUERY_INFORMATION_PROCESS => process::handle_query_information_process(frame),
        sysno::OPEN_PROCESS => process::handle_open_process(frame),
        sysno::CREATE_PROCESS_EX => process::handle_create_process(frame),
        sysno::TERMINATE_PROCESS => process::handle_terminate_process(frame),
        sysno::OPEN_PROCESS_TOKEN => token::handle_open_process_token(frame),
        sysno::QUERY_INFORMATION_TOKEN => token::handle_query_information_token(frame),

        sysno::QUERY_INFORMATION_THREAD => thread::handle_query_information_thread(frame),
        sysno::SET_INFORMATION_THREAD => thread::handle_set_information_thread(frame),
        sysno::CREATE_THREAD_EX => thread::handle_create_thread(frame),
        sysno::SUSPEND_THREAD => thread::handle_suspend_thread(frame),
        sysno::RESUME_THREAD => thread::handle_resume_thread(frame),
        sysno::YIELD_EXECUTION => thread::handle_yield(frame),
        sysno::TERMINATE_THREAD => thread::handle_terminate_thread(frame),

        sysno::DUPLICATE_OBJECT => object::handle_duplicate_object(frame),
        sysno::QUERY_OBJECT => object::handle_query_object(frame),
        sysno::CLOSE => {
            if !object::handle_close(frame) {
                forward_to_vmm(frame, sysno::CLOSE, 0);
            }
        }

        _ => forward_to_vmm(frame, nr, table),
    }

    trace_syscall_error(nr, table, frame);
    schedule_from_trap(frame, true, true);
}

fn trace_syscall_error(nr: u16, table: u8, frame: &SvcFrame) {
    if table != 0 {
        return;
    }
    let status = frame.x[0] as u32;
    if status < 0xC000_0000 {
        return;
    }
    let remain = SYSCALL_ERR_TRACE_BUDGET.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        if v == 0 {
            None
        } else {
            Some(v - 1)
        }
    });
    if remain.is_err() {
        return;
    }
    crate::kerror!(
        "nt: syscall error nr={:#x} st={:#x} elr={:#x} lr={:#x}",
        nr,
        status,
        frame.elr,
        frame.x[30]
    );
}

fn save_ctx_for(tid: u32, frame: &SvcFrame) {
    if tid == 0 || !crate::sched::thread_exists(tid) {
        return;
    }
    with_thread_mut(tid, |t| {
        t.ctx.x.copy_from_slice(&frame.x);
        t.ctx.sp = frame.sp_el0;
        t.ctx.pc = frame.elr;
        t.ctx.pstate = frame.spsr;
        t.ctx.tpidr = frame.tpidr;
    });
}

fn restore_ctx_to_frame(tid: u32, frame: &mut SvcFrame) {
    if tid == 0 || !crate::sched::thread_exists(tid) {
        return;
    }
    with_thread_mut(tid, |t| {
        frame.x.copy_from_slice(&t.ctx.x);
        frame.sp_el0 = t.ctx.sp;
        frame.elr = t.ctx.pc;
        frame.spsr = t.ctx.pstate;
        frame.tpidr = t.ctx.tpidr;
    });
}

fn schedule_from_trap(frame: &mut SvcFrame, allow_idle_wait: bool, drain_hostcall: bool) -> bool {
    let vid = vcpu_id();
    let quantum_100ns = timer::DEFAULT_TIMESLICE_100NS;
    let mut from = current_tid();
    if from != 0 {
        save_ctx_for(from, frame);
    }
    loop {
        if drain_hostcall {
            crate::hostcall::pump_completions();
        }
        sched_lock_acquire();
        match crate::sched::scheduler_round_locked(vid, from, quantum_100ns) {
            crate::sched::SchedulerRoundAction::ContinueCurrent {
                now_100ns,
                next_deadline_100ns,
                slice_remaining_100ns,
            } => {
                sched_lock_release();
                let cur = current_tid();
                if cur != 0 {
                    set_thread_in_kernel(cur, false);
                }
                timer::schedule_running_slice_100ns(
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns,
                );
                return false;
            }
            crate::sched::SchedulerRoundAction::RunThread {
                now_100ns,
                next_deadline_100ns,
                slice_remaining_100ns,
                from_tid: from_sched,
                to_tid: to,
                pending_resched,
                timeout_woke,
                cur_not_running,
            } => {
                record_schedule_event_trap();
                if from_sched != 0 && from_sched != to {
                    let to_has_kctx = has_kernel_continuation(to);
                    let mut to_in_kernel = with_thread(to, |t| t.in_kernel);
                    // Tighten direct-kctx only for true kernel-thread targets:
                    // first-run/user-resume targets still use EL0 frame restore.
                    if cur_not_running && to_in_kernel && !to_has_kctx {
                        // No kernel continuation means this target can only be resumed
                        // through EL0 frame restore; normalize stale in-kernel marker.
                        crate::sched::set_thread_in_kernel_locked(to, false);
                        to_in_kernel = false;
                    }
                    if cur_not_running
                        && with_thread(from_sched, |t| t.state == ThreadState::Terminated)
                    {
                        crate::sched::set_thread_in_kernel_locked(from_sched, false);
                    }
                    if to_has_kctx {
                        save_ctx_for(from_sched, frame);
                        sched_lock_release();
                        crate::sched::execute_kernel_continuation_switch(
                            from_sched,
                            to,
                            now_100ns,
                            next_deadline_100ns,
                            slice_remaining_100ns,
                            "trap",
                        );
                        from = current_tid();
                        continue;
                    }
                    if to_in_kernel {
                        panic!(
                            "sched: in-kernel target missing continuation from={} to={}",
                            from_sched, to
                        );
                    }
                    // Fallback is limited to EL0 frame restore scheduling
                    // (new thread first run or user-mode resume).
                    crate::process::switch_to_thread_process(to);
                    save_ctx_for(from_sched, frame);
                    restore_ctx_to_frame(to, frame);
                    sched_lock_release();
                    // If trap-exit chooses EL0 frame-restore (instead of direct-kctx),
                    // the preempted running thread will resume from EL0 next time.
                    // Clear its in-kernel marker to avoid stale "in_kernel=true but
                    // no continuation" state.
                    if !cur_not_running {
                        set_thread_in_kernel(from_sched, false);
                    }
                    set_thread_in_kernel(to, false);
                    timer::schedule_running_slice_100ns(
                        now_100ns,
                        next_deadline_100ns,
                        slice_remaining_100ns,
                    );
                    return true;
                }
                crate::process::switch_to_thread_process(to);
                if from_sched == 0 {
                    // We were idling; current frame no longer belongs to a runnable thread.
                    restore_ctx_to_frame(to, frame);
                } else if from_sched == to && (cur_not_running || pending_resched || timeout_woke) {
                    // Same-thread continuation may still need frame refresh when wait/completion
                    // updated thread context x0 under scheduler lock but we did not context-switch.
                    restore_ctx_to_frame(to, frame);
                }
                sched_lock_release();
                set_thread_in_kernel(to, false);
                timer::schedule_running_slice_100ns(
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns,
                );
                return from_sched != to;
            }
            crate::sched::SchedulerRoundAction::IdleWait {
                now_100ns,
                next_deadline_100ns,
                from_tid: from_sched,
            } => {
                record_schedule_event_trap();
                if !allow_idle_wait {
                    sched_lock_release();
                    timer::schedule_running_slice_100ns(
                        now_100ns,
                        next_deadline_100ns,
                        quantum_100ns,
                    );
                    return false;
                }

                // No runnable thread. Persist current frame once before sleeping.
                if from_sched != 0 {
                    save_ctx_for(from_sched, frame);
                    from = 0;
                }
                set_vcpu_idle_locked(vid, true);
                sched_lock_release();

                if crate::sched::all_threads_done() {
                    let code =
                        crate::process::process_exit_status(crate::process::current_pid()).unwrap_or(0);
                    hypercall::process_exit(code);
                }
                timer::idle_wait_until_deadline_100ns(now_100ns, next_deadline_100ns);
                continue;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn timer_irq_dispatch(frame: &mut SvcFrame) {
    set_current_in_kernel(true);
    crate::sched::reclaim_deferred_kernel_stacks();
    let _ = schedule_from_trap(frame, false, true);
}

#[no_mangle]
pub extern "C" fn el1_fault_dispatch(frame: &mut SvcFrame) {
    let esr = crate::arch::cpu::current_fault_syndrome();
    let far = crate::arch::cpu::current_fault_address();
    crate::log::debug_u64(EL1_FAULT_ESR_TAG | esr);
    crate::log::debug_u64(EL1_FAULT_FAR_TAG | far);
    crate::log::debug_u64(EL1_FAULT_ELR_TAG | frame.elr);
    crate::log::debug_u64(EL1_FAULT_SPSR_TAG | frame.spsr);
    hypercall::process_exit(0xE1);
}

#[no_mangle]
pub extern "C" fn el0_fault_dispatch(frame: &mut SvcFrame) {
    let esr = crate::arch::cpu::current_fault_syndrome();
    let far = crate::arch::cpu::current_fault_address();
    crate::log::debug_u64(EL0_FAULT_ESR_TAG | esr);
    crate::log::debug_u64(EL0_FAULT_FAR_TAG | far);
    crate::log::debug_u64(EL0_FAULT_ELR_TAG | frame.elr);
    crate::log::debug_u64(EL0_FAULT_SPSR_TAG | frame.spsr);
    hypercall::process_exit(0xFF);
}

fn forward_to_vmm(frame: &mut SvcFrame, nr: u16, table: u8) {
    let ret = crate::arch::hypercall::forward_nt_syscall(frame, nr, table);
    frame.x[0] = ret;
}
