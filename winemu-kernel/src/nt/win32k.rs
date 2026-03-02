use core::cell::UnsafeCell;

use crate::kobj::ObjectStore;
use winemu_shared::status;

use super::state::VM_ACCESS_READ;
use super::SvcFrame;

#[derive(Clone, Copy)]
pub(crate) struct ClientPfnArrays {
    pub(crate) pid: u32,
    pub(crate) procs_a: u64,
    pub(crate) procs_w: u64,
    pub(crate) workers: u64,
    pub(crate) user_module: u64,
}

struct Win32kRuntime {
    entries: UnsafeCell<Option<ObjectStore<ClientPfnArrays>>>,
    lock: UnsafeCell<u32>,
}

unsafe impl Sync for Win32kRuntime {}

static WIN32K_RUNTIME: Win32kRuntime = Win32kRuntime {
    entries: UnsafeCell::new(None),
    lock: UnsafeCell::new(0),
};

#[inline(always)]
fn lock() {
    crate::arch::spin::lock_word(WIN32K_RUNTIME.lock.get());
}

#[inline(always)]
fn unlock() {
    crate::arch::spin::unlock_word(WIN32K_RUNTIME.lock.get());
}

fn entries_mut() -> &'static mut ObjectStore<ClientPfnArrays> {
    unsafe {
        let slot = &mut *WIN32K_RUNTIME.entries.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn validate_user_ptr(pid: u32, va: u64) -> bool {
    if va < crate::process::USER_ACCESS_BASE || va >= crate::process::USER_VA_LIMIT {
        return false;
    }
    crate::process::with_process(pid, |p| p.address_space.translate_user_va_for_access(va, VM_ACCESS_READ))
        .flatten()
        .is_some()
}

fn set_client_pfn_arrays(
    pid: u32,
    procs_a: u64,
    procs_w: u64,
    workers: u64,
    user_module: u64,
) -> bool {
    lock();
    let store = entries_mut();

    let mut updated = false;
    store.for_each_live_ptr(|_, ptr| unsafe {
        if (*ptr).pid == pid {
            (*ptr).procs_a = procs_a;
            (*ptr).procs_w = procs_w;
            (*ptr).workers = workers;
            (*ptr).user_module = user_module;
            updated = true;
        }
    });

    let ok = if updated {
        true
    } else {
        store
            .alloc_with(|_| ClientPfnArrays {
                pid,
                procs_a,
                procs_w,
                workers,
                user_module,
            })
            .is_some()
    };
    unlock();
    ok
}

pub(crate) fn handle_user_initialize_client_pfn_arrays(frame: &mut SvcFrame) {
    let pid = crate::process::current_pid();
    if pid == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let procs_a = frame.x[0];
    let procs_w = frame.x[1];
    let workers = frame.x[2];
    let user_module = frame.x[3];

    if procs_a == 0 || procs_w == 0 || workers == 0 || user_module == 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    if !validate_user_ptr(pid, procs_a)
        || !validate_user_ptr(pid, procs_w)
        || !validate_user_ptr(pid, workers)
        || !validate_user_ptr(pid, user_module)
    {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    if !set_client_pfn_arrays(pid, procs_a, procs_w, workers, user_module) {
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    }

    frame.x[0] = status::SUCCESS as u64;
}
