use super::{boot_pid, current_vcpu_pid, process_exists};

pub const PSEUDO_CURRENT_PROCESS: u64 = u64::MAX;

pub fn current_pid() -> u32 {
    let tid = crate::sched::current_tid();
    if tid != 0 {
        let pid = crate::sched::thread_pid(tid);
        if pid != 0 {
            return pid;
        }
    }
    let vid = (crate::sched::vcpu_id() as usize).min(crate::sched::MAX_VCPUS - 1);
    let pid = current_vcpu_pid(vid);
    if pid != 0 { pid } else { boot_pid() }
}

pub fn resolve_process_handle(process_handle: u64) -> Option<u32> {
    if process_handle == 0 || process_handle == PSEUDO_CURRENT_PROCESS {
        let pid = current_pid();
        return if pid != 0 { Some(pid) } else { None };
    }

    use crate::process::{KObjectKind, with_process_mut};
    let pid = current_pid();
    let obj = with_process_mut(pid, |p| p.handle_table.get(process_handle as u32)).flatten()?;
    if obj.kind != KObjectKind::Process {
        return None;
    }
    let target_pid = obj.obj_idx;
    if target_pid == 0 || !process_exists(target_pid) {
        return None;
    }
    Some(target_pid)
}
