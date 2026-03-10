use core::mem::size_of;

use winemu_shared::hostcall as hc;
use winemu_shared::status;

use crate::sched::types::WaitDeadline;

use super::constants::PAGE_SIZE_4K;
use crate::mm::usercopy::{
    copy_to_current_user, read_current_user_value, write_current_user_value,
};
use super::SvcFrame;

const SYSTEM_INFO_CLASS_BASIC: u32 = 0;
const SYSTEM_INFO_CLASS_TIME_OF_DAY: u32 = 3;
// Test-only class: force async hostcall through call_sync pending path.
const SYSTEM_INFO_CLASS_HOSTCALL_FORCE_ASYNC: u32 = 0x8000_1001;
// Test-only class: query VMM scheduler wake statistics.
const SYSTEM_INFO_CLASS_VMM_SCHED_WAKE_STATS: u32 = 0x8000_1002;

const PERF_COUNTER_FREQUENCY_100NS: u64 = 10_000_000;
const ALLOCATION_GRANULARITY: u32 = 0x10000;

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemBasicInformation {
    reserved: u32,
    timer_resolution_100ns: u32,
    page_size: u32,
    number_of_physical_pages: u32,
    lowest_physical_page_number: u32,
    highest_physical_page_number: u32,
    allocation_granularity: u32,
    minimum_user_mode_address: u64,
    maximum_user_mode_address: u64,
    active_processors_affinity_mask: u64,
    number_of_processors: u8,
    pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemTimeOfDayInformation {
    boot_time: i64,
    current_time: i64,
    time_zone_bias: i64,
    time_zone_id: u32,
    reserved: u32,
    boot_time_bias: u64,
    sleep_time_bias: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VmmSchedWakeStatsInformation {
    version: u64,
    kick_requests: u64,
    kick_coalesced: u64,
    external_irq_requests: u64,
    external_irq_coalesced: u64,
    external_irq_taken: u64,
    unpark_mask_calls: u64,
    unpark_any_calls: u64,
    unpark_thread_wakes: u64,
    pending_external_irq_mask: u64,
    idle_vcpu_mask: u64,
}

#[inline(always)]
fn write_ret_len(ret_len: *mut u32, value: u32) {
    if !ret_len.is_null() {
        let _ = write_current_user_value(ret_len, value);
    }
}

fn write_info_struct<T: Copy>(buf: *mut u8, buf_len: usize, ret_len: *mut u32, info: &T) -> u32 {
    let need = size_of::<T>();
    if buf.is_null() || buf_len < need {
        write_ret_len(ret_len, need as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    if !copy_to_current_user(buf, (info as *const T).cast::<u8>(), need) {
        write_ret_len(ret_len, need as u32);
        return status::INVALID_PARAMETER;
    }
    write_ret_len(ret_len, need as u32);
    status::SUCCESS
}

fn query_system_basic_information(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    let (active_mask, processor_count) = {
        let _lock = crate::sched::KSchedulerLock::lock();
        let mut mask = 0u64;
        for vid in 0..crate::sched::MAX_VCPUS {
            if unsafe { crate::sched::SCHED.vcpu_raw(vid) }.idle_tid != 0 {
                mask |= 1u64 << vid;
            }
        }
        if mask == 0 {
            (1u64, 1u8)
        } else {
            (mask, mask.count_ones() as u8)
        }
    };

    let mut pages = crate::mm::phys::free_page_count() as u32;
    if pages < 0x2000 {
        pages = 0x2000;
    }

    let max_user = crate::process::USER_VA_LIMIT.saturating_sub(1);
    let info = SystemBasicInformation {
        reserved: 0,
        timer_resolution_100ns: 10_000, // 1ms
        page_size: PAGE_SIZE_4K as u32,
        number_of_physical_pages: pages,
        lowest_physical_page_number: 0,
        highest_physical_page_number: pages.saturating_sub(1),
        allocation_granularity: ALLOCATION_GRANULARITY,
        minimum_user_mode_address: crate::process::USER_VA_BASE,
        maximum_user_mode_address: max_user,
        active_processors_affinity_mask: active_mask,
        number_of_processors: processor_count,
        pad: [0; 3],
    };
    write_info_struct(buf, buf_len, ret_len, &info)
}

fn query_system_time_of_day_information(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    let current = crate::hypercall::query_system_time_100ns();
    let mono = crate::hypercall::query_mono_time_100ns();
    let boot = current.saturating_sub(mono);

    let info = SystemTimeOfDayInformation {
        boot_time: boot as i64,
        current_time: current as i64,
        time_zone_bias: 0,
        time_zone_id: 0,
        reserved: 0,
        boot_time_bias: 0,
        sleep_time_bias: 0,
    };
    write_info_struct(buf, buf_len, ret_len, &info)
}

fn query_hostcall_force_async_information(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    let owner_pid = crate::process::current_pid();
    let path = "guest/sysroot/syscall_sysinfo_test.exe";
    let open = crate::hostcall::call_sync(
        owner_pid,
        crate::hostcall::SubmitArgs {
            opcode: hc::OP_OPEN,
            flags: hc::FLAG_FORCE_ASYNC,
            arg0: path.as_ptr() as u64,
            arg1: path.len() as u64,
            arg2: 0,
            arg3: 0,
            user_tag: 0,
        },
    );
    let Ok(open_done) = open else {
        return status::INVALID_PARAMETER;
    };
    let fd = open_done.value0;
    if fd == 0 || fd == u64::MAX {
        return status::INVALID_PARAMETER;
    }
    let _ = crate::hostcall::call_sync(
        owner_pid,
        crate::hostcall::SubmitArgs {
            opcode: hc::OP_CLOSE,
            flags: 0,
            arg0: fd,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            user_tag: 0,
        },
    );
    write_info_struct(buf, buf_len, ret_len, &fd)
}

fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(core::mem::size_of::<u64>())?;
    let slice = bytes.get(off..end)?;
    Some(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn query_vmm_sched_wake_stats_information(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    let mut raw = [0u8; hc::SCHED_WAKE_STATS_SIZE];
    let wrote = crate::hypercall::hostcall_query_sched_wake_stats(raw.as_mut_ptr(), raw.len(), 0);
    if wrote < hc::SCHED_WAKE_STATS_SIZE {
        write_ret_len(ret_len, size_of::<VmmSchedWakeStatsInformation>() as u32);
        return status::NOT_IMPLEMENTED;
    }

    let info = VmmSchedWakeStatsInformation {
        version: read_u64_le(&raw, 0).unwrap_or(0),
        kick_requests: read_u64_le(&raw, 8).unwrap_or(0),
        kick_coalesced: read_u64_le(&raw, 16).unwrap_or(0),
        external_irq_requests: read_u64_le(&raw, 24).unwrap_or(0),
        external_irq_coalesced: read_u64_le(&raw, 32).unwrap_or(0),
        external_irq_taken: read_u64_le(&raw, 40).unwrap_or(0),
        unpark_mask_calls: read_u64_le(&raw, 48).unwrap_or(0),
        unpark_any_calls: read_u64_le(&raw, 56).unwrap_or(0),
        unpark_thread_wakes: read_u64_le(&raw, 64).unwrap_or(0),
        pending_external_irq_mask: read_u64_le(&raw, 72).unwrap_or(0),
        idle_vcpu_mask: read_u64_le(&raw, 80).unwrap_or(0),
    };
    if info.version != hc::SCHED_WAKE_STATS_VERSION {
        write_ret_len(ret_len, size_of::<VmmSchedWakeStatsInformation>() as u32);
        return status::NOT_IMPLEMENTED;
    }
    write_info_struct(buf, buf_len, ret_len, &info)
}

pub(crate) fn handle_query_system_information(frame: &mut SvcFrame) {
    let info_class = frame.x[0] as u32;
    let buf = frame.x[1] as *mut u8;
    let buf_len = frame.x[2] as usize;
    let ret_len = frame.x[3] as *mut u32;

    let st = match info_class {
        SYSTEM_INFO_CLASS_BASIC => query_system_basic_information(buf, buf_len, ret_len),
        SYSTEM_INFO_CLASS_TIME_OF_DAY => {
            query_system_time_of_day_information(buf, buf_len, ret_len)
        }
        SYSTEM_INFO_CLASS_HOSTCALL_FORCE_ASYNC => {
            query_hostcall_force_async_information(buf, buf_len, ret_len)
        }
        SYSTEM_INFO_CLASS_VMM_SCHED_WAKE_STATS => {
            query_vmm_sched_wake_stats_information(buf, buf_len, ret_len)
        }
        _ => status::INVALID_PARAMETER,
    };
    frame.x[0] = st as u64;
}

pub(crate) fn handle_query_system_time(frame: &mut SvcFrame) {
    let out = frame.x[0] as *mut i64;
    if out.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let now = crate::hypercall::query_system_time_100ns() as i64;
    if !write_current_user_value(out, now) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_query_performance_counter(frame: &mut SvcFrame) {
    let counter_ptr = frame.x[0] as *mut i64;
    let freq_ptr = frame.x[1] as *mut i64;
    if counter_ptr.is_null() && freq_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let counter = crate::hypercall::query_mono_time_100ns() as i64;
    if !counter_ptr.is_null() && !write_current_user_value(counter_ptr, counter) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if !freq_ptr.is_null()
        && !write_current_user_value(freq_ptr, PERF_COUNTER_FREQUENCY_100NS as i64)
    {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn should_dispatch_delay_execution(frame: &SvcFrame) -> bool {
    // `NtDelayExecution(alertable, timeout*)` uses x0 in [0,1].
    // `NtResetEvent(handle, previous_state*)` uses an object handle in x0.
    frame.x[0] <= 1 && frame.x[1] != 0
}

pub(crate) fn handle_delay_execution(frame: &mut SvcFrame) {
    let _alertable = frame.x[0] != 0;
    let timeout_ptr = frame.x[1] as *const i64;
    crate::log::debug_u64(0xD100_0001);
    crate::log::debug_u64(timeout_ptr as u64);
    if timeout_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Some(raw) = read_current_user_value(timeout_ptr) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    crate::log::debug_u64(0xD100_0002);
    crate::log::debug_u64(raw as u64);
    let timeout = parse_delay_timeout(raw);
    let deadline_dbg = match timeout {
        WaitDeadline::Infinite => 0,
        WaitDeadline::Immediate => 1,
        WaitDeadline::DeadlineTicks(t) => t,
    };
    crate::log::debug_u64(0xD100_0003);
    crate::log::debug_u64(deadline_dbg);
    let st = crate::sched::sync::delay_current_thread_sync(timeout);
    crate::log::debug_u64(0xD100_0004);
    crate::log::debug_u64(st as u64);
    frame.x[0] = st as u64;
}

fn parse_delay_timeout(raw: i64) -> WaitDeadline {
    if raw == 0 {
        return WaitDeadline::Immediate;
    }
    if raw < 0 {
        return crate::sched::deadline_after_100ns(raw);
    }

    let now = crate::hypercall::query_system_time_100ns() as i64;
    if raw <= now {
        return WaitDeadline::Immediate;
    }
    crate::sched::deadline_after_100ns(raw - now)
}
