use core::mem::size_of;

use winemu_shared::status;

use crate::sched::sync::WaitDeadline;

use super::constants::PAGE_SIZE_4K;
use super::SvcFrame;

const SYSTEM_INFO_CLASS_BASIC: u32 = 0;
const SYSTEM_INFO_CLASS_TIME_OF_DAY: u32 = 3;

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

#[inline(always)]
fn write_ret_len(ret_len: *mut u32, value: u32) {
    if !ret_len.is_null() {
        unsafe { ret_len.write_volatile(value) };
    }
}

fn write_info_struct<T: Copy>(buf: *mut u8, buf_len: usize, ret_len: *mut u32, info: &T) -> u32 {
    let need = size_of::<T>();
    if buf.is_null() || buf_len < need {
        write_ret_len(ret_len, need as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(info as *const T as *const u8, buf, need);
    }
    write_ret_len(ret_len, need as u32);
    status::SUCCESS
}

fn query_system_basic_information(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
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
        active_processors_affinity_mask: 1,
        number_of_processors: 1,
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

pub(crate) fn handle_query_system_information(frame: &mut SvcFrame) {
    let info_class = frame.x[0] as u32;
    let buf = frame.x[1] as *mut u8;
    let buf_len = frame.x[2] as usize;
    let ret_len = frame.x[3] as *mut u32;

    frame.x[0] = match info_class {
        SYSTEM_INFO_CLASS_BASIC => query_system_basic_information(buf, buf_len, ret_len),
        SYSTEM_INFO_CLASS_TIME_OF_DAY => {
            query_system_time_of_day_information(buf, buf_len, ret_len)
        }
        _ => status::INVALID_PARAMETER,
    } as u64;
}

pub(crate) fn handle_query_system_time(frame: &mut SvcFrame) {
    let out = frame.x[0] as *mut i64;
    if out.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let now = crate::hypercall::query_system_time_100ns() as i64;
    unsafe { out.write_volatile(now) };
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
    unsafe {
        if !counter_ptr.is_null() {
            counter_ptr.write_volatile(counter);
        }
        if !freq_ptr.is_null() {
            freq_ptr.write_volatile(PERF_COUNTER_FREQUENCY_100NS as i64);
        }
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

    let raw = unsafe { timeout_ptr.read_volatile() };
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
    let st = crate::sched::sync::delay_current_thread(timeout);
    crate::log::debug_u64(0xD100_0004);
    crate::log::debug_u64(st as u64);
    frame.x[0] = st as u64;
}

fn parse_delay_timeout(raw: i64) -> WaitDeadline {
    if raw == 0 {
        return WaitDeadline::Immediate;
    }
    if raw < 0 {
        return WaitDeadline::DeadlineTicks(crate::sched::deadline_after_100ns(raw.unsigned_abs()));
    }

    let now = crate::hypercall::query_system_time_100ns() as i64;
    if raw <= now {
        return WaitDeadline::Immediate;
    }
    WaitDeadline::DeadlineTicks(crate::sched::deadline_after_100ns((raw - now) as u64))
}
