// svc_dispatch — EL1 SVC 分发器
// 由 vectors.rs 的 SVC handler 汇编调用，处理所有来自 EL0 的 syscall。
// 若需要线程切换，直接修改 SvcFrame 中的寄存器，ERET 后进入新线程。

use crate::hypercall;
use crate::sched::{
    charge_current_runtime_locked, check_timeouts, consume_pending_reschedule_locked,
    current_slice_remaining_100ns, current_tid, next_wait_deadline_locked, now_ticks,
    register_thread0, rotate_current_on_quantum_expire_locked, sched_lock_acquire,
    sched_lock_release, schedule, set_vcpu_idle_locked, vcpu_id, with_thread_mut,
};
use crate::timer;

use super::constants::{
    EL0_FAULT_ELR_TAG, EL0_FAULT_ESR_TAG, EL0_FAULT_FAR_TAG, EL0_FAULT_SPSR_TAG,
    EL1_FAULT_ELR_TAG, EL1_FAULT_ESR_TAG, EL1_FAULT_FAR_TAG, EL1_FAULT_SPSR_TAG, SVC_TAG_NR_MASK,
    SVC_TAG_TABLE_MASK, SVC_TAG_TABLE_SHIFT,
};
use super::{file, memory, object, process, registry, section, sync, thread, SvcFrame};
use super::sysno;

#[no_mangle]
pub extern "C" fn svc_dispatch(frame: &mut SvcFrame) {
    if current_tid() == 0 {
        register_thread0(frame.tpidr);
    }

    let tag = frame.x8_orig;
    let nr = (tag & SVC_TAG_NR_MASK) as u16;
    let table = ((tag >> SVC_TAG_TABLE_SHIFT) & SVC_TAG_TABLE_MASK) as u8;

    if table != 0 {
        forward_to_vmm(frame, nr, table);
        return;
    }

    match nr {
        sysno::CREATE_FILE => file::handle_create_file(frame),
        sysno::OPEN_FILE => file::handle_open_file(frame),
        sysno::READ_FILE => file::handle_read_file(frame),
        sysno::WRITE_FILE => file::handle_write_file(frame),
        sysno::QUERY_INFORMATION_FILE => file::handle_query_information_file(frame),
        sysno::SET_INFORMATION_FILE => file::handle_set_information_file(frame),
        sysno::QUERY_DIRECTORY_FILE => file::handle_query_directory_file(frame),

        sysno::CREATE_EVENT => sync::handle_create_event(frame),
        sysno::SET_EVENT => sync::handle_set_event(frame),
        sysno::RESET_EVENT => sync::handle_reset_event(frame),
        sysno::WAIT_SINGLE => sync::handle_wait_single(frame),
        sysno::WAIT_MULTIPLE => sync::handle_wait_multiple(frame),
        sysno::CREATE_MUTEX => sync::handle_create_mutex(frame),
        sysno::RELEASE_MUTANT => sync::handle_release_mutant(frame),
        sysno::CREATE_SEMAPHORE => sync::handle_create_semaphore(frame),
        sysno::RELEASE_SEMAPHORE => sync::handle_release_semaphore(frame),

        sysno::OPEN_KEY => registry::handle_open_key(frame),
        sysno::CREATE_KEY => registry::handle_create_key(frame),
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

        sysno::CREATE_SECTION => section::handle_create_section(frame),
        sysno::MAP_VIEW_OF_SECTION => section::handle_map_view_of_section(frame),
        sysno::UNMAP_VIEW_OF_SECTION => section::handle_unmap_view_of_section(frame),

        sysno::QUERY_INFORMATION_PROCESS => process::handle_query_information_process(frame),
        sysno::CREATE_PROCESS_EX => process::handle_create_process(frame),
        sysno::TERMINATE_PROCESS => process::handle_terminate_process(frame),

        sysno::QUERY_INFORMATION_THREAD => thread::handle_query_information_thread(frame),
        sysno::SET_INFORMATION_THREAD => thread::handle_set_information_thread(frame),
        sysno::CREATE_THREAD_EX => thread::handle_create_thread(frame),
        sysno::YIELD_EXECUTION => thread::handle_yield(frame),
        sysno::TERMINATE_THREAD => thread::handle_terminate_thread(frame),

        sysno::DUPLICATE_OBJECT => object::handle_duplicate_object(frame),
        sysno::CLOSE => {
            if !object::handle_close(frame) {
                forward_to_vmm(frame, sysno::CLOSE, 0);
            }
        }

        _ => forward_to_vmm(frame, nr, table),
    }

    schedule_from_trap(frame, true);
}

fn save_ctx_for(tid: u32, frame: &SvcFrame) {
    with_thread_mut(tid, |t| {
        t.ctx.x.copy_from_slice(&frame.x);
        t.ctx.sp = frame.sp_el0;
        t.ctx.pc = frame.elr;
        t.ctx.pstate = frame.spsr;
        t.ctx.tpidr = frame.tpidr;
    });
}

fn restore_ctx_to_frame(tid: u32, frame: &mut SvcFrame) {
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
    loop {
        sched_lock_acquire();
        set_vcpu_idle_locked(vid, false);
        let now = now_ticks();
        let pending_resched = consume_pending_reschedule_locked(vid);
        let quantum_expired = charge_current_runtime_locked(vid, now, quantum_100ns);
        if quantum_expired {
            rotate_current_on_quantum_expire_locked(vid, quantum_100ns);
        }
        let timeout_woke = check_timeouts(now);
        let next_deadline = next_wait_deadline_locked();

        // Defer scheduling decision to the unlock boundary:
        // only run schedule() when a committed reschedule request exists, or
        // timer logic produced runnable-state change.
        if pending_resched || quantum_expired || timeout_woke || from == 0 {
            let (from_sched, to) = schedule(vid, now, quantum_100ns);
            if to != 0 {
                set_vcpu_idle_locked(vid, false);
                crate::process::switch_to_thread_process(to);
                if from_sched != 0 && from_sched != to {
                    save_ctx_for(from_sched, frame);
                    restore_ctx_to_frame(to, frame);
                } else if from_sched == 0 {
                    // We were idling; current frame no longer belongs to a runnable thread.
                    restore_ctx_to_frame(to, frame);
                }
                let slice_remaining = current_slice_remaining_100ns(vid, quantum_100ns);
                sched_lock_release();
                timer::arm_running_slice_100ns(now, next_deadline, slice_remaining);
                return from_sched != to;
            }

            if !allow_idle_wait {
                sched_lock_release();
                timer::arm_running_slice_100ns(now, next_deadline, quantum_100ns);
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
                hypercall::process_exit(0);
            }
            timer::idle_wait_until_deadline_100ns(now, next_deadline);
            continue;
        }

        let slice_remaining = current_slice_remaining_100ns(vid, quantum_100ns);
        sched_lock_release();
        timer::arm_running_slice_100ns(now, next_deadline, slice_remaining);
        return false;
    }
}

#[no_mangle]
pub extern "C" fn timer_irq_dispatch(frame: &mut SvcFrame) {
    let _ = schedule_from_trap(frame, false);
}

#[no_mangle]
pub extern "C" fn el1_fault_dispatch(frame: &mut SvcFrame) {
    let esr = crate::arch::cpu::read_esr_el1();
    let far = crate::arch::cpu::read_far_el1();
    hypercall::debug_u64(EL1_FAULT_ESR_TAG | esr);
    hypercall::debug_u64(EL1_FAULT_FAR_TAG | far);
    hypercall::debug_u64(EL1_FAULT_ELR_TAG | frame.elr);
    hypercall::debug_u64(EL1_FAULT_SPSR_TAG | frame.spsr);
    hypercall::process_exit(0xE1);
}

#[no_mangle]
pub extern "C" fn el0_fault_dispatch(frame: &mut SvcFrame) {
    let esr = crate::arch::cpu::read_esr_el1();
    let far = crate::arch::cpu::read_far_el1();
    hypercall::debug_u64(EL0_FAULT_ESR_TAG | esr);
    hypercall::debug_u64(EL0_FAULT_FAR_TAG | far);
    hypercall::debug_u64(EL0_FAULT_ELR_TAG | frame.elr);
    hypercall::debug_u64(EL0_FAULT_SPSR_TAG | frame.spsr);
    hypercall::process_exit(0xFF);
}

fn forward_to_vmm(frame: &mut SvcFrame, nr: u16, table: u8) {
    let ret = crate::arch::hypercall::forward_nt_syscall(frame, nr, table);
    frame.x[0] = ret;
}
