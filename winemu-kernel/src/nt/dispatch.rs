// Trap/syscall dispatch glue used by arch trap entry code.
// This layer owns generic syscall dispatch and post-trap scheduling policy.

use crate::hypercall;

use super::constants::{
    KERNEL_FAULT_ADDRESS_TAG, KERNEL_FAULT_PC_TAG, KERNEL_FAULT_STATE_TAG,
    KERNEL_FAULT_SYNDROME_TAG, SVC_TAG_NR_MASK, SVC_TAG_TABLE_MASK, SVC_TAG_TABLE_SHIFT,
    USER_FAULT_ADDRESS_TAG, USER_FAULT_PC_TAG, USER_FAULT_STATE_TAG, USER_FAULT_SYNDROME_TAG,
};
use super::sysno;
use super::sysno_table::{lookup, NtHandlerId, HANDLER_NONE};
use super::trap_schedule::{
    begin_syscall_trap, finish_nt_syscall_trap, schedule_syscall_unlock_edge,
};
use super::{
    file, loader, memory, object, process, registry, section, sync, system, thread, token, win32k,
    SvcFrame,
};

#[no_mangle]
pub extern "C" fn svc_migrate_frame_to_thread_stack(_frame_ptr: u64, _frame_size: u64) -> u64 {
    // Frame migration is handled by the kernel stack setup; no-op here.
    _frame_ptr
}

#[no_mangle]
pub extern "C" fn syscall_dispatch(frame: &mut SvcFrame) {
    let cur = begin_syscall_trap();

    let tag = frame.x8_orig;
    let table = ((tag >> SVC_TAG_TABLE_SHIFT) & SVC_TAG_TABLE_MASK) as u8;
    let nr = (tag & SVC_TAG_NR_MASK) as u16;

    if table != 0 {
        if table == 1 {
            win32k::handle_win32k_syscall(frame, nr, table);
        } else {
            forward_to_vmm(frame, nr, table);
        }
        schedule_syscall_unlock_edge(frame);
        return;
    }

    if nr == sysno::WINEMU_LOAD_DLL {
        loader::handle_load_dll(frame);
        schedule_syscall_unlock_edge(frame);
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

    finish_nt_syscall_trap(frame, handler_id, cur, is_delay_execution);
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
