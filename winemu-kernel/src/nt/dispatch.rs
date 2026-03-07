// svc_dispatch — EL1 SVC 分发器
// 由 vectors.rs 的 SVC handler 汇编调用，处理所有来自 EL0 的 syscall。
// 若需要线程切换，直接修改 SvcFrame 中的寄存器，ERET 后进入新线程。

use crate::hypercall;
use crate::sched::{
    current_tid, drain_deferred_kstacks, set_thread_in_kernel_locked,
    vcpu_id, with_thread, with_thread_mut, ThreadState,
    KSchedulerLock, SCHED_LOCK, SchedulerRoundAction, scheduler_round_locked,
    execute_kernel_continuation_switch, enter_kernel_continuation_noreturn,
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
pub extern "C" fn svc_migrate_frame_to_thread_stack(_frame_ptr: u64, _frame_size: u64) -> u64 {
    // Frame migration is handled by the kernel stack setup; no-op here.
    _frame_ptr
}

#[no_mangle]
pub extern "C" fn svc_dispatch(frame: &mut SvcFrame) {
    let cur = current_tid();
    if cur != 0 {
        set_thread_in_kernel_locked(cur, true);
    }
    drain_deferred_kstacks();

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
        SCHED_LOCK.acquire();
        match scheduler_round_locked(vid, from, quantum_100ns) {
            SchedulerRoundAction::ContinueCurrent {
                now_100ns,
                next_deadline_100ns,
                slice_remaining_100ns,
            } => {
                crate::sched::lock::KSchedulerLock::release_raw(vid as usize);
                let cur = current_tid();
                if cur != 0 {
                    set_thread_in_kernel_locked(cur, false);
                }
                timer::schedule_running_slice_100ns(
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns,
                );
                return false;
            }
            SchedulerRoundAction::RunThread {
                now_100ns,
                next_deadline_100ns,
                slice_remaining_100ns,
                from_tid: from_sched,
                to_tid: to,
                pending_resched,
                timeout_woke,
                cur_not_running,
            } => {
                if from_sched != 0 && from_sched != to {
                    let to_has_kctx = with_thread(to, |t| t.kctx.has_continuation()).unwrap_or(false);
                    let mut to_in_kernel = with_thread(to, |t| t.in_kernel).unwrap_or(false);
                    if cur_not_running && to_in_kernel && !to_has_kctx {
                        set_thread_in_kernel_locked(to, false);
                        to_in_kernel = false;
                    }
                    if cur_not_running
                        && with_thread(from_sched, |t| t.state == ThreadState::Terminated).unwrap_or(false)
                    {
                        set_thread_in_kernel_locked(from_sched, false);
                    }
                    if to_has_kctx {
                        save_ctx_for(from_sched, frame);
                        execute_kernel_continuation_switch(
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
                    crate::process::switch_to_thread_process(to);
                    save_ctx_for(from_sched, frame);
                    restore_ctx_to_frame(to, frame);
                    crate::sched::lock::KSchedulerLock::release_raw(vid as usize);
                    if !cur_not_running {
                        set_thread_in_kernel_locked(from_sched, false);
                    }
                    set_thread_in_kernel_locked(to, false);
                    timer::schedule_running_slice_100ns(
                        now_100ns,
                        next_deadline_100ns,
                        slice_remaining_100ns,
                    );
                    return true;
                }
                crate::process::switch_to_thread_process(to);
                if from_sched == 0 {
                    if with_thread(to, |t| t.is_idle_thread).unwrap_or(false) {
                        unsafe { enter_kernel_continuation_noreturn(to) }
                    }
                    restore_ctx_to_frame(to, frame);
                } else if from_sched == to && (cur_not_running || pending_resched || timeout_woke) {
                    restore_ctx_to_frame(to, frame);
                }
                crate::sched::lock::KSchedulerLock::release_raw(vid as usize);
                set_thread_in_kernel_locked(to, false);
                timer::schedule_running_slice_100ns(
                    now_100ns,
                    next_deadline_100ns,
                    slice_remaining_100ns,
                );
                return from_sched != to;
            }
            SchedulerRoundAction::IdleWait {
                now_100ns,
                next_deadline_100ns,
                from_tid: from_sched,
            } => {
                if !allow_idle_wait {
                    crate::sched::lock::KSchedulerLock::release_raw(vid as usize);
                    timer::schedule_running_slice_100ns(
                        now_100ns,
                        next_deadline_100ns,
                        quantum_100ns,
                    );
                    return false;
                }
                if from_sched != 0 {
                    save_ctx_for(from_sched, frame);
                    from = 0;
                }
                crate::sched::lock::KSchedulerLock::release_raw(vid as usize);
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
    let cur = current_tid();
    if cur != 0 {
        set_thread_in_kernel_locked(cur, true);
    }
    drain_deferred_kstacks();
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
