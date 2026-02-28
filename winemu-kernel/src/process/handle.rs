use crate::sched::sync::{self, HANDLE_TYPE_PROCESS};

use super::{boot_pid, current_vcpu_pid, process_exists};

pub const PSEUDO_CURRENT_PROCESS: u64 = u64::MAX;

pub fn current_pid() -> u32 {
    let tid = crate::sched::current_tid();
    if tid != 0 {
        if let Some(pid) = crate::sched::thread_pid(tid) {
            return pid;
        }
    }
    let vid = crate::sched::vcpu_id().min(crate::sched::MAX_VCPUS - 1);
    let pid = current_vcpu_pid(vid);
    if pid != 0 {
        pid
    } else {
        boot_pid()
    }
}

pub fn resolve_process_handle(process_handle: u64) -> Option<u32> {
    if process_handle == 0 || process_handle == PSEUDO_CURRENT_PROCESS {
        let pid = current_pid();
        return if pid != 0 { Some(pid) } else { None };
    }

    if sync::handle_type(process_handle) != HANDLE_TYPE_PROCESS {
        return None;
    }
    let pid = sync::handle_idx(process_handle);
    if pid == 0 || !process_exists(pid) {
        return None;
    }
    Some(pid)
}
