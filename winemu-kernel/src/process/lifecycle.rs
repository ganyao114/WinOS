use winemu_shared::status;
use core::sync::atomic::{AtomicU32, Ordering};

use super::{
    alloc_process, boot_pid, free_process, set_boot_pid, set_current_vcpu_pid, with_process,
    with_process_mut, ProcessAddressSpace, ProcessState,
};

// 0 = no shutdown request; otherwise stores (exit_code + 1).
static KERNEL_SHUTDOWN_EXIT_CODE_PLUS1: AtomicU32 = AtomicU32::new(0);

fn has_live_processes() -> bool {
    let mut live = false;
    super::for_each_process(|_, p| {
        if p.state != ProcessState::Terminated {
            live = true;
        }
    });
    live
}

fn compute_shutdown_exit_code() -> u32 {
    let bpid = boot_pid();
    if bpid != 0 {
        if let Some(code) = process_exit_status(bpid) {
            return code;
        }
    }
    let mut code = 0u32;
    super::for_each_process(|_, p| {
        if p.state == ProcessState::Terminated {
            code = p.exit_status;
        }
    });
    code
}

fn maybe_request_kernel_shutdown() {
    if has_live_processes() {
        return;
    }
    let encoded = compute_shutdown_exit_code().wrapping_add(1);
    let _ = KERNEL_SHUTDOWN_EXIT_CODE_PLUS1.compare_exchange(
        0,
        encoded,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

pub fn take_kernel_shutdown_exit_code(current_vid: usize) -> Option<u32> {
    if current_vid != 0 {
        return None;
    }
    let encoded = KERNEL_SHUTDOWN_EXIT_CODE_PLUS1.swap(0, Ordering::AcqRel);
    if encoded == 0 {
        None
    } else {
        Some(encoded.wrapping_sub(1))
    }
}

pub fn process_exists(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    !super::process_ptr(pid).is_null()
}

pub fn process_accepts_new_threads(pid: u32) -> bool {
    with_process(pid, |p| {
        p.state == ProcessState::Running || p.state == ProcessState::Creating
    })
    .unwrap_or(false)
}

pub fn process_signaled(pid: u32) -> bool {
    with_process(pid, |p| p.state == ProcessState::Terminated).unwrap_or(false)
}

pub fn init_boot_process(image_base: u64, peb_va: u64) -> bool {
    let existing = boot_pid();
    if existing != 0 && process_exists(existing) {
        let _ = with_process_mut(existing, |p| {
            p.image_base = image_base;
            p.peb_va = peb_va;
            p.state = ProcessState::Running;
        });
        set_current_vcpu_pid(0, existing);
        return true;
    }

    let Some(address_space) = ProcessAddressSpace::new_bootstrap_clone() else {
        return false;
    };
    let Some(pid) = alloc_process(0, image_base, peb_va, address_space) else {
        return false;
    };
    let _ = with_process_mut(pid, |p| p.state = ProcessState::Running);
    set_boot_pid(pid);
    set_current_vcpu_pid(0, pid);

    let ttbr0 = with_process(pid, |p| p.address_space.ttbr0()).unwrap_or(0);
    if ttbr0 != 0 {
        crate::mm::switch_process_ttbr0(ttbr0);
    }

    true
}

pub fn create_process(parent_handle: u64, section_handle: u64, _flags: u32) -> Result<u64, u32> {
    crate::log::debug_u64(0xC502_0001);
    let Some(parent_pid) = super::resolve_process_handle(parent_handle) else {
        crate::log::debug_u64(0xC502_E001);
        return Err(status::INVALID_HANDLE);
    };
    crate::log::debug_u64(0xC502_0002);

    if section_handle != 0 {
        use crate::process::{KObjectKind, with_process_mut};
        let ppid = super::resolve_process_handle(parent_handle).unwrap_or(0);
        let ok = with_process_mut(ppid, |p| {
            p.handle_table.get(section_handle as u32)
                .map(|o| o.kind == KObjectKind::Section)
                .unwrap_or(false)
        }).unwrap_or(false);
        if !ok {
            crate::log::debug_u64(0xC502_E002);
            return Err(status::INVALID_HANDLE);
        }
    }

    let Some((state, image_base, peb_va, child_as)) = with_process(parent_pid, |parent| {
        let child_as = ProcessAddressSpace::clone_from(&parent.address_space);
        (parent.state, parent.image_base, parent.peb_va, child_as)
    }) else {
        crate::log::debug_u64(0xC502_E003);
        return Err(status::INVALID_HANDLE);
    };
    crate::log::debug_u64(0xC502_0003);

    if state == ProcessState::Terminated || state == ProcessState::Terminating {
        crate::log::debug_u64(0xC502_E004);
        return Err(status::INVALID_HANDLE);
    }

    let Some(address_space) = child_as else {
        crate::log::debug_u64(0xC502_E005);
        return Err(status::NO_MEMORY);
    };
    crate::log::debug_u64(0xC502_0004);

    let Some(pid) = alloc_process(parent_pid, image_base, peb_va, address_space) else {
        crate::log::debug_u64(0xC502_E006);
        return Err(status::NO_MEMORY);
    };
    crate::log::debug_u64(0xC502_0005);

    let _ = with_process_mut(pid, |p| p.state = ProcessState::Running);
    if !crate::nt::state::vm_clone_external_mappings(parent_pid, pid) {
        crate::log::debug_u64(0xC502_E008);
        let _ = free_process(pid);
        return Err(status::NO_MEMORY);
    }

    let Some(handle) = crate::nt::kobject::add_handle_for_pid(
        parent_pid,
        crate::process::KObjectRef::process(pid),
    ) else {
        crate::log::debug_u64(0xC502_E007);
        let _ = free_process(pid);
        return Err(status::NO_MEMORY);
    };
    crate::log::debug_u64(0xC502_0006);

    Ok(handle)
}

pub fn open_process(pid: u32, _desired_access: u32) -> Result<u64, u32> {
    if pid == 0 || !process_exists(pid) {
        return Err(status::INVALID_PARAMETER);
    }
    let cur_pid = super::handle::current_pid();
    crate::nt::kobject::add_handle_for_pid(cur_pid, crate::process::KObjectRef::process(pid))
        .ok_or(status::NO_MEMORY)
}

pub fn on_thread_created(pid: u32, tid: u32) {
    let _ = with_process_mut(pid, |p| {
        p.thread_count = p.thread_count.saturating_add(1);
        if p.main_thread_tid == 0 {
            p.main_thread_tid = tid;
        }
        if p.state == ProcessState::Creating {
            p.state = ProcessState::Running;
        }
    });
}

pub fn on_thread_terminated(pid: u32, tid: u32) {
    let _ = with_process_mut(pid, |p| {
        if p.thread_count > 0 {
            p.thread_count -= 1;
        }
        if p.main_thread_tid == tid {
            p.main_thread_tid = 0;
        }
        if p.thread_count == 0 {
            p.state = ProcessState::Terminated;
        }
    });
    finalize_process_if_no_threads(pid);
}

pub fn terminate_process(pid: u32, exit_status: u32) -> u32 {
    if !process_exists(pid) {
        return status::INVALID_HANDLE;
    }

    let _ = with_process_mut(pid, |p| {
        p.exit_status = exit_status;
        if p.state != ProcessState::Terminated {
            p.state = ProcessState::Terminating;
        }
    });

    crate::nt::file::cancel_pending_dir_notify_for_pid(pid);
    crate::nt::state::cleanup_process_owned_resources(pid);

    let tids = crate::sched::thread_ids_by_pid(pid);
    for tid in tids {
        let _ = crate::sched::terminate_thread_by_tid(tid);
    }

    crate::nt::kobject::drain_handles_for_pid(pid);
    finalize_process_if_no_threads(pid);
    status::SUCCESS
}

pub fn last_handle_closed(pid: u32) {
    finalize_process_if_no_threads(pid);
}

pub fn switch_to_thread_process(tid: u32) {
    let pid = crate::sched::thread_pid(tid);
    if pid == 0 {
        return;
    }
    let Some(ttbr0) = with_process(pid, |p| p.address_space.ttbr0()) else {
        return;
    };

    let vid = (crate::sched::vcpu_id() as usize).min(crate::sched::MAX_VCPUS - 1);
    let cur_pid = super::current_vcpu_pid(vid);
    if cur_pid == pid {
        return;
    }

    crate::mm::switch_process_ttbr0(ttbr0);
    set_current_vcpu_pid(vid, pid);
}

pub fn process_exit_status(pid: u32) -> Option<u32> {
    with_process(pid, |p| p.exit_status)
}

fn finalize_process_if_no_threads(pid: u32) {
    if pid == 0 {
        return;
    }
    let Some(thread_count) = with_process(pid, |p| p.thread_count) else {
        return;
    };
    if thread_count != 0 {
        return;
    }

    let _ = with_process_mut(pid, |p| p.state = ProcessState::Terminated);
    crate::nt::file::cancel_pending_dir_notify_for_pid(pid);
    crate::nt::state::cleanup_process_owned_resources(pid);
    let _ = crate::hostcall::cancel_requests_for_owner_pid(pid);
    maybe_free_if_unreferenced(pid);
    maybe_request_kernel_shutdown();
}

fn maybe_free_if_unreferenced(pid: u32) {
    if pid == 0 || pid == boot_pid() {
        return;
    }
    let Some(thread_count) = with_process(pid, |p| p.thread_count) else {
        return;
    };
    if thread_count != 0 {
        return;
    }
    let _ = free_process(pid);
}
