use core::cell::UnsafeCell;

use crate::hostcall;
use crate::kobj::ObjectStore;
use crate::rust_alloc::vec::Vec;
use winemu_shared::hostcall as hc;
use winemu_shared::status;
use winemu_shared::win32k_sysno;

use super::user_args::SyscallArgs;
use super::SvcFrame;
use crate::mm::usercopy::{
    copy_to_process_user, ensure_user_range_access, read_current_user_bytes, read_user_value,
};
use crate::mm::{UserVa, VM_ACCESS_READ};

#[derive(Clone, Copy)]
pub(crate) struct ClientPfnArrays {
    pub(crate) pid: u32,
    pub(crate) procs_a: u64,
    pub(crate) procs_w: u64,
    pub(crate) workers: u64,
    pub(crate) user_module: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawUnicodeString64 {
    length: u16,
    maximum_length: u16,
    pad: u32,
    buffer: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawClientMenuName64 {
    name_a: u64,
    name_w: u64,
    name_us: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawWndClassEx64 {
    cb_size: u32,
    style: u32,
    lpfn_wnd_proc: u64,
    cb_cls_extra: i32,
    cb_wnd_extra: i32,
    h_instance: u64,
    h_icon: u64,
    h_cursor: u64,
    hbr_background: u64,
    lpsz_menu_name: u64,
    lpsz_class_name: u64,
    h_icon_sm: u64,
}

struct CopyBackRange {
    user_va: u64,
    payload_offset: usize,
    size: usize,
}

struct MarshalledWin32kCall {
    packet: hc::Win32kCallPacket,
    storage: Vec<u8>,
    copybacks: Vec<CopyBackRange>,
}

impl MarshalledWin32kCall {
    fn new(packet: hc::Win32kCallPacket, extra: usize, copybacks: usize) -> Option<Self> {
        let total = hc::WIN32K_CALL_PACKET_SIZE.checked_add(extra)?;
        let mut storage = Vec::new();
        storage.try_reserve(total).ok()?;
        storage.resize(hc::WIN32K_CALL_PACKET_SIZE, 0);
        let mut pending = Vec::new();
        pending.try_reserve(copybacks).ok()?;
        Some(Self {
            packet,
            storage,
            copybacks: pending,
        })
    }

    fn payload_ptr(&self, payload_offset: usize) -> u64 {
        (self.storage.as_ptr() as u64)
            + (hc::WIN32K_CALL_PACKET_SIZE as u64)
            + (payload_offset as u64)
    }

    fn append_bytes(&mut self, bytes: &[u8]) -> Option<(u64, usize)> {
        let payload_offset = self
            .storage
            .len()
            .checked_sub(hc::WIN32K_CALL_PACKET_SIZE)?;
        self.storage.try_reserve(bytes.len()).ok()?;
        self.storage.extend_from_slice(bytes);
        Some((self.payload_ptr(payload_offset), payload_offset))
    }

    fn append_zeroed(&mut self, size: usize) -> Option<(u64, usize)> {
        let payload_offset = self
            .storage
            .len()
            .checked_sub(hc::WIN32K_CALL_PACKET_SIZE)?;
        self.storage.try_reserve(size).ok()?;
        self.storage
            .resize(self.storage.len().checked_add(size)?, 0);
        Some((self.payload_ptr(payload_offset), payload_offset))
    }

    fn append_plain<T: Copy>(&mut self, value: &T) -> Option<(u64, usize)> {
        let size = core::mem::size_of::<T>();
        let (ptr, payload_offset) = self.append_zeroed(size)?;
        let start = hc::WIN32K_CALL_PACKET_SIZE.checked_add(payload_offset)?;
        let end = start.checked_add(size)?;
        let dst = self.storage.get_mut(start..end)?;
        // SAFETY: `value` is a plain `Copy` POD-like struct, and `dst` is a
        // valid, non-overlapping byte slice of the same size.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (value as *const T).cast::<u8>(),
                dst.as_mut_ptr(),
                size,
            );
        }
        Some((ptr, payload_offset))
    }

    fn append_name_shadow(&mut self, name: &RawUnicodeString64) -> Option<u64> {
        let mut shadow = *name;
        if shadow.buffer > 0xffff && shadow.length != 0 {
            if shadow.length > shadow.maximum_length || (shadow.length & 1) != 0 {
                return None;
            }
            let bytes =
                read_current_user_bytes(shadow.buffer as *const u8, shadow.length as usize)?;
            let (buf_ptr, _) = self.append_bytes(&bytes)?;
            shadow.buffer = buf_ptr;
        }
        let (name_ptr, _) = self.append_plain(&shadow)?;
        Some(name_ptr)
    }

    fn add_copyback(&mut self, user_va: u64, payload_offset: usize, size: usize) -> bool {
        if self.copybacks.try_reserve(1).is_err() {
            return false;
        }
        self.copybacks.push(CopyBackRange {
            user_va,
            payload_offset,
            size,
        });
        true
    }

    fn finalize(&mut self) {
        let dst = &mut self.storage[..hc::WIN32K_CALL_PACKET_SIZE];
        // SAFETY: `dst` points to the packet-sized prefix of the backing
        // storage, and the source is a properly initialized `Win32kCallPacket`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (&self.packet as *const hc::Win32kCallPacket).cast::<u8>(),
                dst.as_mut_ptr(),
                hc::WIN32K_CALL_PACKET_SIZE,
            );
        }
    }

    fn packet_ptr(&self) -> u64 {
        self.storage.as_ptr() as u64
    }

    fn packet_len(&self) -> u64 {
        self.storage.len() as u64
    }

    fn copy_back_outputs(&self, owner_pid: u32, result: u32) {
        if result == 0 {
            return;
        }
        for copyback in &self.copybacks {
            let start = match hc::WIN32K_CALL_PACKET_SIZE.checked_add(copyback.payload_offset) {
                Some(v) => v,
                None => continue,
            };
            let end = match start.checked_add(copyback.size) {
                Some(v) => v,
                None => continue,
            };
            let Some(src) = self.storage.get(start..end) else {
                continue;
            };
            let _ = copy_to_process_user(
                owner_pid,
                UserVa::new(copyback.user_va),
                src.as_ptr(),
                src.len(),
            );
        }
    }
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

fn marshal_register_class_ex_wow(
    owner_pid: u32,
    mut packet: hc::Win32kCallPacket,
) -> Option<MarshalledWin32kCall> {
    let wc_user = packet.args[0];
    let name_user = packet.args[1];
    let menu_user = packet.args[3];
    let wow_user = packet.args[6];

    let raw_name = read_user_value(owner_pid, name_user as *const RawUnicodeString64)?;
    let name_extra = if raw_name.buffer > 0xffff {
        raw_name.length as usize
    } else {
        0
    };
    let extra = core::mem::size_of::<RawWndClassEx64>()
        .checked_add(core::mem::size_of::<RawUnicodeString64>())?
        .checked_add(name_extra)?
        .checked_add(if menu_user != 0 {
            core::mem::size_of::<RawClientMenuName64>()
        } else {
            0
        })?
        .checked_add(if wow_user != 0 {
            core::mem::size_of::<u32>()
        } else {
            0
        })?;
    let copybacks = if wow_user != 0 { 1 } else { 0 };
    let mut marshalled = MarshalledWin32kCall::new(packet, extra, copybacks)?;

    let wc = read_user_value(owner_pid, wc_user as *const RawWndClassEx64)?;
    let (wc_ptr, _) = marshalled.append_plain(&wc)?;
    marshalled.packet.args[0] = wc_ptr;
    marshalled.packet.args[1] = marshalled.append_name_shadow(&raw_name)?;

    if menu_user != 0 {
        let menu = read_user_value(owner_pid, menu_user as *const RawClientMenuName64)?;
        let (menu_ptr, _) = marshalled.append_plain(&menu)?;
        marshalled.packet.args[3] = menu_ptr;
    } else {
        marshalled.packet.args[3] = 0;
    }

    if wow_user != 0 {
        let (wow_ptr, wow_off) = marshalled.append_zeroed(core::mem::size_of::<u32>())?;
        marshalled.packet.args[6] = wow_ptr;
        if !marshalled.add_copyback(wow_user, wow_off, core::mem::size_of::<u32>()) {
            return None;
        }
    } else {
        marshalled.packet.args[6] = 0;
    }

    marshalled.finalize();
    Some(marshalled)
}

fn marshal_get_class_info_ex(
    owner_pid: u32,
    mut packet: hc::Win32kCallPacket,
) -> Option<MarshalledWin32kCall> {
    let name_user = packet.args[1];
    let wc_user = packet.args[2];
    let menu_user = packet.args[3];

    let raw_name = read_user_value(owner_pid, name_user as *const RawUnicodeString64)?;
    let name_extra = if raw_name.buffer > 0xffff {
        raw_name.length as usize
    } else {
        0
    };
    let extra = core::mem::size_of::<RawUnicodeString64>()
        .checked_add(name_extra)?
        .checked_add(if wc_user != 0 {
            core::mem::size_of::<RawWndClassEx64>()
        } else {
            0
        })?
        .checked_add(if menu_user != 0 {
            core::mem::size_of::<RawClientMenuName64>()
        } else {
            0
        })?;
    let copybacks = usize::from(wc_user != 0) + usize::from(menu_user != 0);
    let mut marshalled = MarshalledWin32kCall::new(packet, extra, copybacks)?;

    marshalled.packet.args[1] = marshalled.append_name_shadow(&raw_name)?;

    if wc_user != 0 {
        let (wc_ptr, wc_off) = marshalled.append_zeroed(core::mem::size_of::<RawWndClassEx64>())?;
        marshalled.packet.args[2] = wc_ptr;
        if !marshalled.add_copyback(wc_user, wc_off, core::mem::size_of::<RawWndClassEx64>()) {
            return None;
        }
    } else {
        marshalled.packet.args[2] = 0;
    }

    if menu_user != 0 {
        let (menu_ptr, menu_off) =
            marshalled.append_zeroed(core::mem::size_of::<RawClientMenuName64>())?;
        marshalled.packet.args[3] = menu_ptr;
        if !marshalled.add_copyback(
            menu_user,
            menu_off,
            core::mem::size_of::<RawClientMenuName64>(),
        ) {
            return None;
        }
    } else {
        marshalled.packet.args[3] = 0;
    }

    marshalled.finalize();
    Some(marshalled)
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

    let mut marshalled = match nr {
        win32k_sysno::NT_USER_REGISTER_CLASS_EX_WOW => {
            marshal_register_class_ex_wow(owner_pid, packet)
        }
        win32k_sysno::NT_USER_GET_CLASS_INFO_EX => marshal_get_class_info_ex(owner_pid, packet),
        _ => None,
    };
    let (packet_ptr, packet_len) = if let Some(shadow) = marshalled.as_ref() {
        (shadow.packet_ptr(), shadow.packet_len())
    } else {
        (
            (&packet as *const hc::Win32kCallPacket) as u64,
            hc::WIN32K_CALL_PACKET_SIZE as u64,
        )
    };

    let submit = hostcall::call_sync(
        owner_pid,
        hostcall::SubmitArgs {
            opcode: hc::OP_WIN32K_CALL,
            flags: hc::FLAG_MAIN_THREAD,
            arg0: packet_ptr,
            arg1: packet_len,
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
            if let Some(shadow) = marshalled.as_ref() {
                shadow.copy_back_outputs(owner_pid, done.value0 as u32);
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
