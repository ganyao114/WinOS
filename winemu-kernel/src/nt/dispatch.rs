// svc_dispatch — EL1 SVC 分发器
// 由 vectors.rs 的 SVC handler 汇编调用，处理所有来自 EL0 的 syscall。
// 若需要线程切换，直接修改 SvcFrame 中的寄存器，ERET 后进入新线程。

use crate::hypercall;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::sched::{
    charge_current_runtime_locked, check_timeouts, consume_pending_reschedule_locked,
    current_slice_remaining_100ns, current_tid, has_kernel_continuation, next_wait_deadline_locked,
    now_ticks, register_thread0, rotate_current_on_quantum_expire_locked, sched_lock_acquire,
    sched_lock_release, save_current_dispatch_continuation, schedule, set_current_in_kernel, set_thread_in_kernel,
    set_vcpu_idle_locked, switch_kernel_continuation, thread_exists, vcpu_id, with_thread, with_thread_mut,
    ThreadState,
};
use crate::timer;

use super::constants::{
    EL0_FAULT_ELR_TAG, EL0_FAULT_ESR_TAG, EL0_FAULT_FAR_TAG, EL0_FAULT_SPSR_TAG, EL1_FAULT_ELR_TAG,
    EL1_FAULT_ESR_TAG, EL1_FAULT_FAR_TAG, EL1_FAULT_SPSR_TAG, SVC_TAG_NR_MASK, SVC_TAG_TABLE_MASK,
    SVC_TAG_TABLE_SHIFT,
};
use super::sysno;
use super::{
    file, memory, object, process, registry, section, sync, system, thread, token, win32k,
    SvcFrame,
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
        register_thread0(frame.tpidr);
    }
    set_current_in_kernel(true);
    let resumed_dispatch = unsafe { save_current_dispatch_continuation() };
    if resumed_dispatch != 0 {
        schedule_from_trap(frame, true);
        return;
    }

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
                    schedule_from_trap(frame, true);
                    return;
                }
                _ => {}
            }
        }

        // Non-NT tables still need normal trap-exit scheduling so timer slice /
        // deadline programming remains consistent on this path.
        forward_to_vmm(frame, nr, table);
        schedule_from_trap(frame, true);
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
    schedule_from_trap(frame, true);
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

fn schedule_from_trap(frame: &mut SvcFrame, allow_idle_wait: bool) -> bool {
    let vid = vcpu_id();
    let quantum_100ns = timer::DEFAULT_TIMESLICE_100NS;
    let mut from = current_tid();
    if from != 0 {
        save_ctx_for(from, frame);
    }
    loop {
        crate::hostcall::pump_completions();
        file::poll_async_file_completions();

        let now = now_ticks();
        sched_lock_acquire();
        set_vcpu_idle_locked(vid, false);
        let pending_resched = consume_pending_reschedule_locked(vid);
        let quantum_expired = charge_current_runtime_locked(vid, now, quantum_100ns);
        if quantum_expired {
            rotate_current_on_quantum_expire_locked(vid, quantum_100ns);
        }
        let cur_not_running = from != 0
            && thread_exists(from)
            && with_thread(from, |t| t.state != ThreadState::Running);
        let timeout_woke = check_timeouts(now);
        let next_deadline = next_wait_deadline_locked();

        // Defer scheduling decision to the unlock boundary:
        // only run schedule() when a committed reschedule request exists, or
        // timer logic produced runnable-state change.
        if pending_resched || quantum_expired || timeout_woke || from == 0 || cur_not_running {
            let (from_sched, to) = schedule(vid, now, quantum_100ns);
            if to != 0 {
                set_vcpu_idle_locked(vid, false);
                crate::process::switch_to_thread_process(to);
                if from_sched != 0 && from_sched != to && has_kernel_continuation(to) {
                    let (from_sp, from_lr, from_x30) = with_thread(from_sched, |t| {
                        (t.kctx.sp_el1, t.kctx.lr_el1, t.kctx.x19_x30[11])
                    });
                    let (to_sp, to_lr, to_x30) =
                        with_thread(to, |t| (t.kctx.sp_el1, t.kctx.lr_el1, t.kctx.x19_x30[11]));
                    let (to_ret_slot, to_saved_x19) = if to_sp >= 0x4000_0000 && (to_sp & 0x7) == 0 {
                        unsafe {
                            (
                                (to_sp as *const u64).read_volatile(),
                                ((to_sp + 8) as *const u64).read_volatile(),
                            )
                        }
                    } else {
                        (0, 0)
                    };
                    crate::log::debug_u64(0xD203_0001);
                    crate::log::debug_u64(from_sched as u64);
                    crate::log::debug_u64(to as u64);
                    crate::log::debug_u64(0xD203_0002);
                    crate::log::debug_u64(from_sp);
                    crate::log::debug_u64(from_lr);
                    crate::log::debug_u64(from_x30);
                    crate::log::debug_u64(0xD203_0003);
                    crate::log::debug_u64(to_sp);
                    crate::log::debug_u64(to_lr);
                    crate::log::debug_u64(to_x30);
                    crate::log::debug_u64(to_ret_slot);
                    crate::log::debug_u64(to_saved_x19);
                    crate::kdebug!(
                        "sched: kctx to tid={} sp={:#x} x30={:#x} ret_slot={:#x} saved_x19={:#x}",
                        to,
                        to_sp,
                        to_x30,
                        to_ret_slot,
                        to_saved_x19
                    );
                    crate::kdebug!(
                        "sched: kctx from tid={} sp={:#x} lr={:#x} x30={:#x}",
                        from_sched,
                        from_sp,
                        from_lr,
                        from_x30,
                    );
                    save_ctx_for(from_sched, frame);
                    sched_lock_release();
                    let switched = unsafe { switch_kernel_continuation(from_sched, to) };
                    if !switched {
                        restore_ctx_to_frame(to, frame);
                        let slice_remaining = current_slice_remaining_100ns(vid, quantum_100ns);
                        set_thread_in_kernel(to, false);
                        timer::schedule_running_slice_100ns(now, next_deadline, slice_remaining);
                        return from_sched != to;
                    }
                    // Returned by a later kernel-continuation switch back into
                    // this thread; restart scheduling decision with fresh state.
                    from = current_tid();
                    continue;
                }
                if from_sched != 0 && from_sched != to {
                    save_ctx_for(from_sched, frame);
                    restore_ctx_to_frame(to, frame);
                } else if from_sched == 0 {
                    // We were idling; current frame no longer belongs to a runnable thread.
                    restore_ctx_to_frame(to, frame);
                }
                let slice_remaining = current_slice_remaining_100ns(vid, quantum_100ns);
                sched_lock_release();
                set_thread_in_kernel(to, false);
                timer::schedule_running_slice_100ns(now, next_deadline, slice_remaining);
                return from_sched != to;
            }

            if !allow_idle_wait {
                sched_lock_release();
                timer::schedule_running_slice_100ns(now, next_deadline, quantum_100ns);
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
                let code = crate::process::process_exit_status(crate::process::current_pid())
                    .unwrap_or(0);
                hypercall::process_exit(code);
            }
            timer::idle_wait_until_deadline_100ns(now, next_deadline);
            continue;
        }

        let slice_remaining = current_slice_remaining_100ns(vid, quantum_100ns);
        sched_lock_release();
        let cur = current_tid();
        if cur != 0 {
            set_thread_in_kernel(cur, false);
        }
        timer::schedule_running_slice_100ns(now, next_deadline, slice_remaining);
        return false;
    }
}

#[no_mangle]
pub extern "C" fn timer_irq_dispatch(frame: &mut SvcFrame) {
    set_current_in_kernel(true);
    let _ = schedule_from_trap(frame, false);
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
