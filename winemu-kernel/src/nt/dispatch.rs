// Trap/syscall dispatch glue used by arch trap entry code.
// This layer owns generic syscall dispatch and post-trap scheduling policy.

use crate::hypercall;
use crate::sched::{
    current_tid, drain_deferred_kstacks, enter_kernel_continuation_noreturn,
    execute_kernel_continuation_switch, scheduler_round_locked, set_current_tid,
    set_needs_reschedule, set_thread_in_kernel_locked, set_vcpu_current_thread, vcpu_id,
    with_thread, with_thread_mut, ScheduleReason, SchedulerRoundAction, ThreadState, SCHED_LOCK,
};
use crate::timer;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::constants::{
    KERNEL_FAULT_ADDRESS_TAG, KERNEL_FAULT_PC_TAG, KERNEL_FAULT_STATE_TAG,
    KERNEL_FAULT_SYNDROME_TAG, SVC_TAG_NR_MASK, SVC_TAG_TABLE_MASK, SVC_TAG_TABLE_SHIFT,
    USER_FAULT_ADDRESS_TAG, USER_FAULT_PC_TAG, USER_FAULT_STATE_TAG, USER_FAULT_SYNDROME_TAG,
};
use super::sysno;
use super::sysno_table::{lookup, NtHandlerId, HANDLER_NONE};
use super::{
    file, memory, object, process, registry, section, sync, system, thread, token, win32k, SvcFrame,
};

static SYSCALL_ERR_TRACE_BUDGET: AtomicU32 = AtomicU32::new(512);
const DEFERRED_RESCHED_RETRY_100NS: u64 = 10_000; // 1ms
static TRAP_SCHED_ACTIVE: [AtomicU32; 8] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
static USER_IRQ_LAST_PC: [AtomicU64; 8] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static USER_IRQ_REPEAT_COUNT: [AtomicU32; 8] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

#[inline]
fn trace_repeated_user_irq_pc(vid: usize, tid: u32, frame: &SvcFrame) {
    if tid == 0 || vid >= TRAP_SCHED_ACTIVE.len() {
        return;
    }
    if with_thread(tid, |t| t.is_idle_thread).unwrap_or(true) {
        return;
    }

    let last_pc = USER_IRQ_LAST_PC[vid].load(Ordering::Acquire);
    let repeat = if last_pc == frame.program_counter() {
        USER_IRQ_REPEAT_COUNT[vid].fetch_add(1, Ordering::AcqRel) + 1
    } else {
        USER_IRQ_LAST_PC[vid].store(frame.program_counter(), Ordering::Release);
        USER_IRQ_REPEAT_COUNT[vid].store(1, Ordering::Release);
        1
    };

    if repeat < 64 || (repeat & (repeat - 1)) != 0 {
        return;
    }

    crate::kwarn!(
        "user_irq_repeat: vid={} repeat={} tid={} pid={} pc={:#x} user_sp={:#x} x0={:#x} x1={:#x} user_root={:#x}",
        vid,
        repeat,
        tid,
        crate::sched::thread_pid(tid),
        frame.program_counter(),
        frame.user_sp(),
        frame.x[0],
        frame.x[1],
        crate::arch::mmu::current_user_table_root(),
    );
}

struct TrapSchedGuard {
    vid: usize,
    active: bool,
}

impl TrapSchedGuard {
    #[inline]
    fn enter(vid: usize) -> Self {
        TRAP_SCHED_ACTIVE[vid].fetch_add(1, Ordering::AcqRel);
        Self { vid, active: true }
    }

    #[inline]
    fn suspend(&mut self) {
        if self.active {
            TRAP_SCHED_ACTIVE[self.vid].fetch_sub(1, Ordering::AcqRel);
            self.active = false;
        }
    }

    #[inline]
    fn resume(&mut self) {
        if !self.active {
            TRAP_SCHED_ACTIVE[self.vid].fetch_add(1, Ordering::AcqRel);
            self.active = true;
        }
    }
}

impl Drop for TrapSchedGuard {
    #[inline]
    fn drop(&mut self) {
        if self.active {
            TRAP_SCHED_ACTIVE[self.vid].fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[no_mangle]
pub extern "C" fn svc_migrate_frame_to_thread_stack(_frame_ptr: u64, _frame_size: u64) -> u64 {
    // Frame migration is handled by the kernel stack setup; no-op here.
    _frame_ptr
}

#[no_mangle]
pub extern "C" fn syscall_dispatch(frame: &mut SvcFrame) {
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
            win32k::handle_win32k_syscall(frame, nr, table);
        } else {
            forward_to_vmm(frame, nr, table);
        }
        schedule_from_trap(frame, true, true, 0, ScheduleReason::UnlockEdge);
        return;
    }

    let handler_id = lookup(nr);
    let is_delay_execution = handler_id == NtHandlerId::DelayExecution as u8
        || (handler_id == NtHandlerId::ResetEvent as u8
            && system::should_dispatch_delay_execution(frame));
    if handler_id == HANDLER_NONE {
        forward_to_vmm(frame, nr, table);
    } else {
        dispatch_nt_handler(frame, handler_id);
    }

    trace_syscall_error(nr, table, frame);
    let sched_reason = schedule_reason_for_handler(handler_id, frame, cur, is_delay_execution);
    schedule_from_trap(frame, true, true, 0, sched_reason);
}

fn dispatch_nt_handler(frame: &mut SvcFrame, handler_id: u8) {
    use NtHandlerId::*;
    match handler_id {
        x if x == CreateFile as u8 => file::handle_create_file(frame),
        x if x == OpenFile as u8 => file::handle_open_file(frame),
        x if x == ReadFile as u8 => file::handle_read_file(frame),
        x if x == DeviceIoControlFile as u8 => file::handle_device_io_control_file(frame),
        x if x == WriteFile as u8 => file::handle_write_file(frame),
        x if x == QueryInformationFile as u8 => file::handle_query_information_file(frame),
        x if x == QueryAttributesFile as u8 => file::handle_query_attributes_file(frame),
        x if x == QueryFullAttributesFile as u8 => file::handle_query_full_attributes_file(frame),
        x if x == QueryVolumeInformationFile as u8 => {
            file::handle_query_volume_information_file(frame)
        }
        x if x == SetInformationFile as u8 => file::handle_set_information_file(frame),
        x if x == FsControlFile as u8 => file::handle_fs_control_file(frame),
        x if x == QueryDirectoryFile as u8 => file::handle_query_directory_file(frame),
        x if x == NotifyChangeDirectoryFile as u8 => {
            file::handle_notify_change_directory_file(frame)
        }
        x if x == FlushBuffersFile as u8 => file::handle_flush_buffers_file(frame),
        x if x == CancelIoFile as u8 => file::handle_cancel_io_file(frame),
        x if x == LockFile as u8 => file::handle_lock_file(frame),
        x if x == UnlockFile as u8 => file::handle_unlock_file(frame),
        x if x == QuerySystemInformation as u8 => system::handle_query_system_information(frame),
        x if x == QuerySystemTime as u8 => system::handle_query_system_time(frame),
        x if x == QueryPerformanceCounter as u8 => system::handle_query_performance_counter(frame),
        x if x == CreateEvent as u8 => sync::handle_create_event(frame),
        x if x == SetEvent as u8 => sync::handle_set_event(frame),
        x if x == ResetEvent as u8 => sync::handle_reset_event_or_delay(frame),
        x if x == ClearEvent as u8 => sync::handle_clear_event(frame),
        x if x == OpenEvent as u8 => sync::handle_open_event(frame),
        x if x == WaitForSingleObject as u8 => sync::handle_wait_single(frame),
        x if x == WaitForMultipleObjects as u8 => sync::handle_wait_multiple(frame),
        x if x == CreateMutant as u8 => sync::handle_create_mutex(frame),
        x if x == ReleaseMutant as u8 || x == SetInformationProcess as u8 => {
            sync::handle_release_mutant_or_set_information_process(frame)
        }
        x if x == OpenMutant as u8 => sync::handle_open_mutex(frame),
        x if x == CreateSemaphore as u8 => sync::handle_create_semaphore(frame),
        x if x == ReleaseSemaphore as u8 => sync::handle_release_semaphore(frame),
        x if x == OpenSemaphore as u8 => sync::handle_open_semaphore(frame),
        x if x == OpenKey as u8 => registry::handle_open_key(frame),
        x if x == OpenKeyEx as u8 => registry::handle_open_key_ex(frame),
        x if x == CreateKey as u8 => registry::handle_create_key(frame),
        x if x == QueryKey as u8 => registry::handle_query_key(frame),
        x if x == QueryValueKey as u8 => registry::handle_query_value_key(frame),
        x if x == SetValueKey as u8 => registry::handle_set_value_key(frame),
        x if x == DeleteKey as u8 => registry::handle_delete_key(frame),
        x if x == DeleteValueKey as u8 => registry::handle_delete_value_key(frame),
        x if x == EnumerateKey as u8 => registry::handle_enumerate_key(frame),
        x if x == EnumerateValueKey as u8 => registry::handle_enumerate_value_key(frame),
        x if x == AllocateVirtualMemory as u8 => memory::handle_allocate_virtual_memory(frame),
        x if x == FreeVirtualMemory as u8 => memory::handle_free_virtual_memory(frame),
        x if x == QueryVirtualMemory as u8 => memory::handle_query_virtual_memory(frame),
        x if x == ProtectVirtualMemory as u8 => memory::handle_protect_virtual_memory(frame),
        x if x == ReadVirtualMemory as u8 => memory::handle_read_virtual_memory(frame),
        x if x == WriteVirtualMemory as u8 => memory::handle_write_virtual_memory(frame),
        x if x == CreateSection as u8 => section::handle_create_section(frame),
        x if x == OpenSection as u8 => section::handle_open_section(frame),
        x if x == MapViewOfSection as u8 => section::handle_map_view_of_section(frame),
        x if x == UnmapViewOfSection as u8 => section::handle_unmap_view_of_section(frame),
        x if x == QuerySection as u8 => section::handle_query_section(frame),
        x if x == QueryInformationProcess as u8 => process::handle_query_information_process(frame),
        x if x == OpenProcess as u8 => process::handle_open_process(frame),
        x if x == CreateProcessEx as u8 => process::handle_create_process(frame),
        x if x == TerminateProcess as u8 => process::handle_terminate_process(frame),
        x if x == OpenProcessToken as u8 => token::handle_open_process_token(frame),
        x if x == OpenProcessTokenEx as u8 => token::handle_open_process_token_ex(frame),
        x if x == OpenThreadToken as u8 => token::handle_open_thread_token(frame),
        x if x == OpenThreadTokenEx as u8 => token::handle_open_thread_token_ex(frame),
        x if x == AdjustPrivilegesToken as u8 => token::handle_adjust_privileges_token(frame),
        x if x == QueryInformationToken as u8 => token::handle_query_information_token(frame),
        x if x == QueryInformationThread as u8 => thread::handle_query_information_thread(frame),
        x if x == SetInformationThread as u8 => thread::handle_set_information_thread(frame),
        x if x == CreateThreadEx as u8 => thread::handle_create_thread(frame),
        x if x == SuspendThread as u8 => thread::handle_suspend_thread(frame),
        x if x == ResumeThread as u8 => thread::handle_resume_thread(frame),
        x if x == YieldExecution as u8 => thread::handle_yield(frame),
        x if x == TerminateThread as u8 => thread::handle_terminate_thread(frame),
        x if x == AlertThreadByThreadId as u8 => thread::handle_alert_thread_by_thread_id(frame),
        x if x == WaitForAlertByThreadId as u8 => thread::handle_wait_for_alert_by_thread_id(frame),
        x if x == Continue as u8 => thread::handle_continue(frame),
        x if x == RaiseException as u8 => thread::handle_raise_exception(frame),
        x if x == DuplicateObject as u8 => object::handle_duplicate_object(frame),
        x if x == QueryObject as u8 => object::handle_query_object(frame),
        x if x == Close as u8 => {
            if !object::handle_close(frame) {
                forward_to_vmm(frame, sysno::CLOSE, 0);
            }
        }
        x if x == DelayExecution as u8 => sync::handle_reset_event_or_delay(frame),
        x if x == SetInformationObject as u8 => {
            let nr = frame.x8_orig as u16;
            forward_to_vmm(frame, nr, 0);
        }
        _ => {
            // handler_id is valid but has no dispatch arm — forward to VMM
            let nr = frame.x8_orig as u16;
            forward_to_vmm(frame, nr, 0);
        }
    }
}

fn schedule_reason_for_handler(
    handler_id: u8,
    frame: &SvcFrame,
    current: u32,
    is_delay_execution: bool,
) -> ScheduleReason {
    use NtHandlerId::*;
    if handler_id == YieldExecution as u8 {
        return ScheduleReason::Yield;
    }
    if handler_id == WaitForSingleObject as u8
        || handler_id == WaitForMultipleObjects as u8
        || handler_id == WaitForAlertByThreadId as u8
    {
        return if current != 0
            && with_thread(current, |t| t.state == ThreadState::Waiting).unwrap_or(false)
        {
            ScheduleReason::Timeout
        } else {
            ScheduleReason::UnlockEdge
        };
    }
    if handler_id == SetEvent as u8
        || handler_id == ReleaseMutant as u8
        || handler_id == ReleaseSemaphore as u8
        || handler_id == ResumeThread as u8
        || handler_id == CreateThreadEx as u8
    {
        return if frame.x[0] as u32 == crate::sched::STATUS_SUCCESS {
            ScheduleReason::Wakeup
        } else {
            ScheduleReason::UnlockEdge
        };
    }
    if handler_id == ResetEvent as u8 || handler_id == DelayExecution as u8 {
        return if is_delay_execution {
            ScheduleReason::Timeout
        } else {
            ScheduleReason::UnlockEdge
        };
    }
    ScheduleReason::UnlockEdge
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
        "nt: syscall error nr={:#x} st={:#x} pc={:#x} lr={:#x}",
        nr,
        status,
        frame.program_counter(),
        frame.x[30]
    );
}

fn save_ctx_for(tid: u32, frame: &SvcFrame) {
    if tid == 0 || !crate::sched::thread_exists(tid) {
        return;
    }
    with_thread_mut(tid, |t| {
        t.ctx.copy_general_registers_from(&frame.x);
        t.ctx.set_user_sp(frame.user_sp());
        t.ctx.set_program_counter(frame.program_counter());
        t.ctx.set_processor_state(frame.processor_state());
        t.ctx.set_thread_pointer(frame.thread_pointer());
    });
}

fn restore_ctx_to_frame(tid: u32, frame: &mut SvcFrame) {
    if tid == 0 || !crate::sched::thread_exists(tid) {
        return;
    }
    with_thread_mut(tid, |t| {
        frame.x.copy_from_slice(t.ctx.general_registers());
        frame.set_user_sp(t.ctx.user_sp());
        frame.set_program_counter(t.ctx.program_counter());
        frame.set_processor_state(t.ctx.processor_state());
        frame.set_thread_pointer(t.ctx.thread_pointer());
    });
}

fn schedule_from_trap(
    frame: &mut SvcFrame,
    allow_idle_wait: bool,
    drain_hostcall: bool,
    quantum_100ns: u64,
    reason: ScheduleReason,
) -> bool {
    let vid = vcpu_id();
    let vid_u8 = vid as u8;
    let mut active_guard = TrapSchedGuard::enter(vid as usize);
    let mut from = current_tid();
    if from != 0 {
        save_ctx_for(from, frame);
    }
    loop {
        if drain_hostcall {
            crate::hostcall::pump_completions();
        }
        SCHED_LOCK.acquire();
        match scheduler_round_locked(vid, from, quantum_100ns, reason) {
            SchedulerRoundAction::ContinueCurrent {
                now_100ns,
                next_deadline_100ns,
                slice_remaining_100ns,
            } => {
                let cur = current_tid();
                if cur != 0 {
                    crate::process::switch_to_thread_process(cur);
                    with_thread_mut(cur, |t| {
                        t.state = ThreadState::Running;
                        t.last_vcpu_hint = vid_u8;
                    });
                    set_thread_in_kernel_locked(cur, false);
                }
                crate::sched::lock::unlock_after_raw_or_scoped(vid as usize);
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
                    let to_has_kctx =
                        with_thread(to, |t| t.kctx.has_continuation()).unwrap_or(false);
                    let mut to_in_kernel = with_thread(to, |t| t.in_kernel).unwrap_or(false);
                    if cur_not_running && to_in_kernel && !to_has_kctx {
                        set_thread_in_kernel_locked(to, false);
                        to_in_kernel = false;
                    }
                    if cur_not_running
                        && with_thread(from_sched, |t| t.state == ThreadState::Terminated)
                            .unwrap_or(false)
                    {
                        set_thread_in_kernel_locked(from_sched, false);
                    }
                    if to_has_kctx {
                        save_ctx_for(from_sched, frame);
                        active_guard.suspend();
                        execute_kernel_continuation_switch(
                            from_sched,
                            to,
                            now_100ns,
                            next_deadline_100ns,
                            slice_remaining_100ns,
                            "trap",
                        );
                        active_guard.resume();
                        let cur = current_tid();
                        if cur != 0 {
                            set_vcpu_current_thread(vid as usize, cur);
                            set_current_tid(cur);
                            with_thread_mut(cur, |t| {
                                t.state = ThreadState::Running;
                                t.last_vcpu_hint = vid_u8;
                            });
                            crate::process::switch_to_thread_process(cur);
                            restore_ctx_to_frame(cur, frame);
                            set_thread_in_kernel_locked(cur, false);
                        }
                        timer::schedule_running_slice_100ns(
                            now_100ns,
                            next_deadline_100ns,
                            slice_remaining_100ns,
                        );
                        return cur != from_sched;
                    }
                    if to_in_kernel {
                        panic!(
                            "sched: in-kernel target missing continuation from={} to={}",
                            from_sched, to
                        );
                    }
                    set_vcpu_current_thread(vid as usize, to);
                    set_current_tid(to);
                    with_thread_mut(to, |t| {
                        t.state = ThreadState::Running;
                        t.last_vcpu_hint = vid_u8;
                    });
                    crate::process::switch_to_thread_process(to);
                    save_ctx_for(from_sched, frame);
                    restore_ctx_to_frame(to, frame);
                    crate::sched::lock::unlock_after_raw_or_scoped(vid as usize);
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
                        active_guard.suspend();
                        unsafe { enter_kernel_continuation_noreturn(to) }
                    }
                    set_vcpu_current_thread(vid as usize, to);
                    set_current_tid(to);
                    with_thread_mut(to, |t| {
                        t.state = ThreadState::Running;
                        t.last_vcpu_hint = vid_u8;
                    });
                    restore_ctx_to_frame(to, frame);
                } else if from_sched == to && (cur_not_running || pending_resched || timeout_woke) {
                    set_vcpu_current_thread(vid as usize, to);
                    set_current_tid(to);
                    with_thread_mut(to, |t| {
                        t.state = ThreadState::Running;
                        t.last_vcpu_hint = vid_u8;
                    });
                    restore_ctx_to_frame(to, frame);
                }
                set_thread_in_kernel_locked(to, false);
                crate::sched::lock::unlock_after_raw_or_scoped(vid as usize);
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
                    crate::sched::lock::unlock_after_raw_or_scoped(vid as usize);
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
                crate::sched::lock::unlock_after_raw_or_scoped(vid as usize);
                crate::sched::schedule::idle_wait_or_exit(
                    vid as usize,
                    now_100ns,
                    next_deadline_100ns,
                );
                continue;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn user_irq_dispatch(frame: &mut SvcFrame) {
    let vid = vcpu_id() as usize;
    let cur = current_tid();
    let in_nested_trap_sched = TRAP_SCHED_ACTIVE[vid].load(Ordering::Acquire) != 0;
    let interrupted_user = crate::arch::trap::interrupted_user_mode(frame);
    if interrupted_user {
        trace_repeated_user_irq_pc(vid, cur, frame);
    }
    if in_nested_trap_sched || !interrupted_user {
        set_needs_reschedule();
        let now = crate::sched::wait::current_ticks();
        // Nested-trap / in-kernel IRQ path cannot switch immediately.
        // Re-arm a short retry slice so deferred preemption is observed before
        // CPU-bound user code can run to completion.
        timer::schedule_running_slice_100ns(now, u64::MAX, DEFERRED_RESCHED_RETRY_100NS);
        return;
    }
    if cur != 0 {
        set_thread_in_kernel_locked(cur, true);
    }
    drain_deferred_kstacks();
    let reason = if crate::sched::cpu::cpu_local().needs_reschedule {
        ScheduleReason::Ipi
    } else {
        ScheduleReason::TimerPreempt
    };
    schedule_from_trap(frame, false, true, timer::DEFAULT_TIMESLICE_100NS, reason);
}

#[no_mangle]
pub extern "C" fn kernel_fault_dispatch(frame: &mut SvcFrame) {
    let fault = crate::arch::trap::current_fault_info();
    crate::log::debug_u64(KERNEL_FAULT_SYNDROME_TAG | fault.syndrome);
    crate::log::debug_u64(KERNEL_FAULT_ADDRESS_TAG | fault.address);
    crate::log::debug_u64(KERNEL_FAULT_PC_TAG | frame.program_counter());
    crate::log::debug_u64(KERNEL_FAULT_STATE_TAG | frame.processor_state());
    hypercall::process_exit(0xE1);
}

#[no_mangle]
pub extern "C" fn user_fault_dispatch(frame: &mut SvcFrame) {
    let fault = crate::arch::trap::current_fault_info();
    crate::log::debug_u64(USER_FAULT_SYNDROME_TAG | fault.syndrome);
    crate::log::debug_u64(USER_FAULT_ADDRESS_TAG | fault.address);
    crate::log::debug_u64(USER_FAULT_PC_TAG | frame.program_counter());
    crate::log::debug_u64(USER_FAULT_STATE_TAG | frame.processor_state());
    hypercall::process_exit(0xFF);
}

fn forward_to_vmm(frame: &mut SvcFrame, nr: u16, table: u8) {
    let ret = crate::arch::hypercall::forward_nt_syscall(frame, nr, table);
    frame.x[0] = ret;
}
