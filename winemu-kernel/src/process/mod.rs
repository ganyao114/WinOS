mod address_space;
mod handle;
mod lifecycle;
mod query;

use crate::kobj::ObjectStore;
use core::cell::UnsafeCell;

pub use handle::{current_pid, resolve_process_handle};
pub use lifecycle::{
    create_process, init_boot_process, last_handle_closed, on_thread_created, on_thread_terminated,
    open_process, process_accepts_new_threads, process_exists, process_signaled, switch_to_thread_process,
    terminate_process,
};
pub use query::query_information_process;

pub(crate) use address_space::{ProcessAddressSpace, USER_VA_BASE, USER_VA_LIMIT};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ProcessState {
    Creating = 0,
    Running = 1,
    Terminating = 2,
    Terminated = 3,
}

pub struct KProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub state: ProcessState,
    pub exit_status: u32,
    pub image_base: u64,
    pub peb_va: u64,
    pub main_thread_tid: u32,
    pub thread_count: u32,
    pub create_time_100ns: u64,
    pub address_space: ProcessAddressSpace,
}

impl KProcess {
    fn new(
        pid: u32,
        parent_pid: u32,
        image_base: u64,
        peb_va: u64,
        address_space: ProcessAddressSpace,
        create_time_100ns: u64,
    ) -> Self {
        Self {
            pid,
            parent_pid,
            state: ProcessState::Creating,
            exit_status: 0,
            image_base,
            peb_va,
            main_thread_tid: 0,
            thread_count: 0,
            create_time_100ns,
            address_space,
        }
    }
}

struct ProcessRuntime {
    processes: UnsafeCell<Option<ObjectStore<KProcess>>>,
    boot_pid: UnsafeCell<u32>,
    current_pid_by_vcpu: UnsafeCell<[u32; crate::sched::MAX_VCPUS]>,
}

unsafe impl Sync for ProcessRuntime {}

static PROCESS_RUNTIME: ProcessRuntime = ProcessRuntime {
    processes: UnsafeCell::new(None),
    boot_pid: UnsafeCell::new(0),
    current_pid_by_vcpu: UnsafeCell::new([0; crate::sched::MAX_VCPUS]),
};

fn process_store_mut() -> &'static mut ObjectStore<KProcess> {
    unsafe {
        let slot = &mut *PROCESS_RUNTIME.processes.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

pub(crate) fn process_ptr(pid: u32) -> *mut KProcess {
    if pid == 0 {
        return core::ptr::null_mut();
    }
    process_store_mut().get_ptr(pid)
}

pub(crate) fn with_process<R>(pid: u32, f: impl FnOnce(&KProcess) -> R) -> Option<R> {
    let ptr = process_ptr(pid);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { f(&*ptr) })
    }
}

pub(crate) fn with_process_mut<R>(pid: u32, f: impl FnOnce(&mut KProcess) -> R) -> Option<R> {
    let ptr = process_ptr(pid);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { f(&mut *ptr) })
    }
}

pub(crate) fn alloc_process(
    parent_pid: u32,
    image_base: u64,
    peb_va: u64,
    address_space: ProcessAddressSpace,
) -> Option<u32> {
    let create_time = crate::hypercall::query_mono_time_100ns();
    let store = process_store_mut();
    let (pid, ptr) = store.alloc_slot_with_id()?;
    unsafe {
        ptr.write(KProcess::new(
            pid,
            parent_pid,
            image_base,
            peb_va,
            address_space,
            create_time,
        ));
    }
    Some(pid)
}

pub(crate) fn free_process(pid: u32) -> bool {
    process_store_mut().free(pid)
}

pub(crate) fn set_boot_pid(pid: u32) {
    unsafe {
        *PROCESS_RUNTIME.boot_pid.get() = pid;
    }
}

pub(crate) fn boot_pid() -> u32 {
    unsafe { *PROCESS_RUNTIME.boot_pid.get() }
}

pub(crate) fn set_current_vcpu_pid(vcpu_id: usize, pid: u32) {
    if vcpu_id >= crate::sched::MAX_VCPUS {
        return;
    }
    unsafe {
        (*PROCESS_RUNTIME.current_pid_by_vcpu.get())[vcpu_id] = pid;
    }
}

pub(crate) fn current_vcpu_pid(vcpu_id: usize) -> u32 {
    if vcpu_id >= crate::sched::MAX_VCPUS {
        return boot_pid();
    }
    unsafe {
        let pid = (*PROCESS_RUNTIME.current_pid_by_vcpu.get())[vcpu_id];
        if pid != 0 {
            pid
        } else {
            boot_pid()
        }
    }
}

pub(crate) fn for_each_process(mut f: impl FnMut(u32, &KProcess)) {
    unsafe {
        let Some(store) = (&*PROCESS_RUNTIME.processes.get()).as_ref() else {
            return;
        };
        store.for_each_live_ptr(|pid, ptr| {
            let proc_ref = &*ptr;
            f(pid, proc_ref);
        });
    }
}
