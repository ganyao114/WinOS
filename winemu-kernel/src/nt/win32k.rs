use core::cell::UnsafeCell;

use crate::hostcall;
use crate::kobj::ObjectStore;
use winemu_shared::hostcall as hc;
use winemu_shared::status;
use winemu_shared::win32k_sysno;

use super::user_args::SyscallArgs;
use super::SvcFrame;
use crate::mm::usercopy::ensure_user_range_access;
use crate::mm::UserVa;
use crate::mm::VM_ACCESS_READ;

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
    ensure_user_range_access(pid, UserVa::new(va), 1, VM_ACCESS_READ)
}

fn collect_win32k_args(frame: &SvcFrame) -> [u64; hc::WIN32K_CALL_MAX_ARGS] {
    let mut out = [0u64; hc::WIN32K_CALL_MAX_ARGS];
    let reg_count = core::cmp::min(8, hc::WIN32K_CALL_MAX_ARGS);
    out[..reg_count].copy_from_slice(&frame.x[..reg_count]);
    if hc::WIN32K_CALL_MAX_ARGS <= 8 {
        return out;
    }

    let spill = hc::WIN32K_CALL_MAX_ARGS - 8;
    let mut i = 0usize;
    let args = SyscallArgs::new(frame);
    while i < spill {
        out[8 + i] = args.spill_u64(i).unwrap_or(0);
        i += 1;
    }
    out
}

fn dispatch_win32k_hostcall(frame: &SvcFrame, nr: u16, table: u8) -> u32 {
    let owner_pid = crate::process::current_pid();
    if owner_pid == 0 {
        return status::INVALID_PARAMETER;
    }
    let mut packet = hc::Win32kCallPacket::new();
    packet.table = table as u32;
    packet.syscall_nr = nr as u32;
    packet.arg_count = hc::WIN32K_CALL_MAX_ARGS as u32;
    packet.owner_pid = owner_pid;
    packet.owner_tid = crate::sched::current_tid();
    packet.args = collect_win32k_args(frame);

    let submit = hostcall::call_sync(
        owner_pid,
        hostcall::SubmitArgs {
            opcode: hc::OP_WIN32K_CALL,
            flags: hc::FLAG_MAIN_THREAD,
            arg0: (&packet as *const hc::Win32kCallPacket) as u64,
            arg1: hc::WIN32K_CALL_PACKET_SIZE as u64,
            arg2: 0,
            arg3: 0,
            user_tag: 0,
        },
    );
    match submit {
        Ok(done) => {
            if done.host_result != hc::HC_OK {
                return hostcall::map_host_result_to_status(done.host_result);
            }
            done.value0 as u32
        }
        Err(st) => st,
    }
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

pub(crate) fn handle_win32k_syscall(frame: &mut SvcFrame, nr: u16, table: u8) {
    match nr {
        // NtUserInitializeClientPfnArrays
        win32k_sysno::NT_USER_INITIALIZE_CLIENT_PFN_ARRAYS => {
            handle_user_initialize_client_pfn_arrays(frame)
        }
        _ => {
            let st = dispatch_win32k_hostcall(frame, nr, table);
            frame.x[0] = st as u64;
        }
    }
}
