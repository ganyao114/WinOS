use core::mem::size_of;

use winemu_shared::hostcall as hc;
use winemu_shared::status;

use crate::rust_alloc::vec::Vec;
use crate::sched::types::WaitDeadline;

use super::common::GuestWriter;
use super::constants::PAGE_SIZE_4K;
use super::user_args::{UserInPtr, UserOutPtr};
use super::SvcFrame;
const SYSTEM_INFO_CLASS_BASIC: u32 = 0;
const SYSTEM_INFO_CLASS_CPU: u32 = 1;
const SYSTEM_INFO_CLASS_PERFORMANCE: u32 = 2;
const SYSTEM_INFO_CLASS_TIME_OF_DAY: u32 = 3;
const SYSTEM_INFO_CLASS_FIRMWARE_TABLE: u32 = 76;
// Test-only class: force async hostcall through call_sync pending path.
const SYSTEM_INFO_CLASS_HOSTCALL_FORCE_ASYNC: u32 = 0x8000_1001;
// Test-only class: query VMM scheduler wake statistics.
const SYSTEM_INFO_CLASS_VMM_SCHED_WAKE_STATS: u32 = 0x8000_1002;

const PERF_COUNTER_FREQUENCY_100NS: u64 = 10_000_000;
const ALLOCATION_GRANULARITY: u32 = 0x10000;
const PROCESSOR_ARCHITECTURE_ARM64: u16 = 12;
const FIRMWARE_PROVIDER_RSMB: u32 = 0x5253_4d42;
const SYSTEM_FIRMWARE_TABLE_ENUMERATE: u32 = 0;
const SYSTEM_FIRMWARE_TABLE_GET: u32 = 1;
const SMBIOS_MAJOR_VERSION: u8 = 3;
const SMBIOS_MINOR_VERSION: u8 = 0;
const SMBIOS_UNKNOWN_U8: u8 = 0xff;
const TOTAL_PHYS_PAGES: u32 = ((crate::arch::mmu::GUEST_PHYS_LIMIT
    - crate::arch::mmu::GUEST_PHYS_BASE)
    / PAGE_SIZE_4K) as u32;

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
struct SystemCpuInformation {
    processor_architecture: u16,
    processor_level: u16,
    processor_revision: u16,
    maximum_processors: u16,
    processor_feature_bits: u32,
}

const _: [(); 12] = [(); size_of::<SystemCpuInformation>()];

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemPerformanceInformation {
    idle_time: i64,
    read_transfer_count: i64,
    write_transfer_count: i64,
    other_transfer_count: i64,
    read_operation_count: u32,
    write_operation_count: u32,
    other_operation_count: u32,
    available_pages: u32,
    total_committed_pages: u32,
    total_commit_limit: u32,
    peak_commitment: u32,
    page_faults: u32,
    write_copy_faults: u32,
    transition_faults: u32,
    reserved1: u32,
    demand_zero_faults: u32,
    pages_read: u32,
    page_read_ios: u32,
    reserved2: [u32; 2],
    pagefile_pages_written: u32,
    pagefile_page_write_ios: u32,
    mapped_file_pages_written: u32,
    mapped_file_page_write_ios: u32,
    paged_pool_usage: u32,
    non_paged_pool_usage: u32,
    paged_pool_allocs: u32,
    paged_pool_frees: u32,
    non_paged_pool_allocs: u32,
    non_paged_pool_frees: u32,
    total_free_system_ptes: u32,
    system_code_page: u32,
    total_system_driver_pages: u32,
    total_system_code_pages: u32,
    small_non_paged_lookaside_list_allocate_hits: u32,
    small_paged_lookaside_list_allocate_hits: u32,
    reserved3: u32,
    mm_system_cache_page: u32,
    paged_pool_page: u32,
    system_driver_page: u32,
    fast_read_no_wait: u32,
    fast_read_wait: u32,
    fast_read_resource_miss: u32,
    fast_read_not_possible: u32,
    fast_mdl_read_no_wait: u32,
    fast_mdl_read_wait: u32,
    fast_mdl_read_resource_miss: u32,
    fast_mdl_read_not_possible: u32,
    map_data_no_wait: u32,
    map_data_wait: u32,
    map_data_no_wait_miss: u32,
    map_data_wait_miss: u32,
    pin_mapped_data_count: u32,
    pin_read_no_wait: u32,
    pin_read_wait: u32,
    pin_read_no_wait_miss: u32,
    pin_read_wait_miss: u32,
    copy_read_no_wait: u32,
    copy_read_wait: u32,
    copy_read_no_wait_miss: u32,
    copy_read_wait_miss: u32,
    mdl_read_no_wait: u32,
    mdl_read_wait: u32,
    mdl_read_no_wait_miss: u32,
    mdl_read_wait_miss: u32,
    read_ahead_ios: u32,
    lazy_write_ios: u32,
    lazy_write_pages: u32,
    data_flushes: u32,
    data_pages: u32,
    context_switches: u32,
    first_level_tb_fills: u32,
    second_level_tb_fills: u32,
    system_calls: u32,
}

const _: [(); 0x138] = [(); size_of::<SystemPerformanceInformation>()];

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

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemFirmwareTableInformation {
    provider_signature: u32,
    action: u32,
    table_id: u32,
    table_buffer_length: u32,
}

const _: [(); 16] = [(); size_of::<SystemFirmwareTableInformation>()];

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSmbiosDataHeader {
    calling_method: u8,
    major_version: u8,
    minor_version: u8,
    revision: u8,
    length: u32,
}

const _: [(); 8] = [(); size_of::<RawSmbiosDataHeader>()];

#[inline(always)]
fn write_ret_len(ret_len: *mut u32, value: u32) {
    let _ = UserOutPtr::from_raw(ret_len).write_current_if_present(value);
}

fn write_info_struct<T: Copy>(buf: *mut u8, buf_len: usize, ret_len: *mut u32, info: &T) -> u32 {
    let need = size_of::<T>();
    if buf.is_null() || buf_len < need {
        write_ret_len(ret_len, need as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    let Some(mut w) = GuestWriter::new(buf, buf_len, need) else {
        write_ret_len(ret_len, need as u32);
        return status::INVALID_PARAMETER;
    };
    w.write_struct(*info);
    write_ret_len(ret_len, need as u32);
    status::SUCCESS
}

fn active_processor_mask_and_count() -> (u64, u8) {
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
}

fn physical_page_stats() -> (u32, u32, u32) {
    let free_pages = crate::mm::phys::free_page_count() as u32;
    let total_pages = TOTAL_PHYS_PAGES.max(0x2000);
    let used_pages = total_pages.saturating_sub(free_pages.min(total_pages));
    (free_pages, total_pages, used_pages)
}

fn query_system_basic_information(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    let (active_mask, processor_count) = active_processor_mask_and_count();
    let (_free_pages, total_pages, _used_pages) = physical_page_stats();

    let max_user = crate::process::USER_VA_LIMIT.saturating_sub(1);
    let info = SystemBasicInformation {
        reserved: 0,
        timer_resolution_100ns: 10_000, // 1ms
        page_size: PAGE_SIZE_4K as u32,
        number_of_physical_pages: total_pages,
        lowest_physical_page_number: 0,
        highest_physical_page_number: total_pages.saturating_sub(1),
        allocation_granularity: ALLOCATION_GRANULARITY,
        minimum_user_mode_address: crate::process::USER_VA_BASE,
        maximum_user_mode_address: max_user,
        active_processors_affinity_mask: active_mask,
        number_of_processors: processor_count,
        pad: [0; 3],
    };
    write_info_struct(buf, buf_len, ret_len, &info)
}

fn query_system_cpu_information(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    let (_active_mask, processor_count) = active_processor_mask_and_count();
    let info = SystemCpuInformation {
        processor_architecture: PROCESSOR_ARCHITECTURE_ARM64,
        processor_level: 1,
        processor_revision: 0,
        maximum_processors: processor_count.max(1) as u16,
        processor_feature_bits: 0,
    };
    write_info_struct(buf, buf_len, ret_len, &info)
}

fn query_system_performance_information(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    let (free_pages, total_pages, used_pages) = physical_page_stats();
    let info = SystemPerformanceInformation {
        idle_time: 0,
        read_transfer_count: 0,
        write_transfer_count: 0,
        other_transfer_count: 0,
        read_operation_count: 0,
        write_operation_count: 0,
        other_operation_count: 0,
        available_pages: free_pages,
        total_committed_pages: used_pages,
        total_commit_limit: total_pages,
        peak_commitment: used_pages,
        page_faults: 0,
        write_copy_faults: 0,
        transition_faults: 0,
        reserved1: 0,
        demand_zero_faults: 0,
        pages_read: 0,
        page_read_ios: 0,
        reserved2: [0; 2],
        pagefile_pages_written: 0,
        pagefile_page_write_ios: 0,
        mapped_file_pages_written: 0,
        mapped_file_page_write_ios: 0,
        paged_pool_usage: 0,
        non_paged_pool_usage: 0,
        paged_pool_allocs: 0,
        paged_pool_frees: 0,
        non_paged_pool_allocs: 0,
        non_paged_pool_frees: 0,
        total_free_system_ptes: free_pages,
        system_code_page: 0,
        total_system_driver_pages: 0,
        total_system_code_pages: 0,
        small_non_paged_lookaside_list_allocate_hits: 0,
        small_paged_lookaside_list_allocate_hits: 0,
        reserved3: 0,
        mm_system_cache_page: 0,
        paged_pool_page: 0,
        system_driver_page: 0,
        fast_read_no_wait: 0,
        fast_read_wait: 0,
        fast_read_resource_miss: 0,
        fast_read_not_possible: 0,
        fast_mdl_read_no_wait: 0,
        fast_mdl_read_wait: 0,
        fast_mdl_read_resource_miss: 0,
        fast_mdl_read_not_possible: 0,
        map_data_no_wait: 0,
        map_data_wait: 0,
        map_data_no_wait_miss: 0,
        map_data_wait_miss: 0,
        pin_mapped_data_count: 0,
        pin_read_no_wait: 0,
        pin_read_wait: 0,
        pin_read_no_wait_miss: 0,
        pin_read_wait_miss: 0,
        copy_read_no_wait: 0,
        copy_read_wait: 0,
        copy_read_no_wait_miss: 0,
        copy_read_wait_miss: 0,
        mdl_read_no_wait: 0,
        mdl_read_wait: 0,
        mdl_read_no_wait_miss: 0,
        mdl_read_wait_miss: 0,
        read_ahead_ios: 0,
        lazy_write_ios: 0,
        lazy_write_pages: 0,
        data_flushes: 0,
        data_pages: 0,
        context_switches: 0,
        first_level_tb_fills: 0,
        second_level_tb_fills: 0,
        system_calls: 0,
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

#[inline]
fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[inline]
fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[inline]
fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_smbios_strings(bytes: &mut Vec<u8>, strings: &[&[u8]]) {
    for string in strings {
        bytes.extend_from_slice(string);
        bytes.push(0);
    }
    if strings.is_empty() {
        bytes.push(0);
    }
    bytes.push(0);
}

fn next_smbios_handle(next_handle: &mut u16) -> u16 {
    let handle = *next_handle;
    *next_handle = next_handle.wrapping_add(1);
    handle
}

fn append_smbios_bios(bytes: &mut Vec<u8>, next_handle: &mut u16) {
    let handle = next_smbios_handle(next_handle);
    let vendor = b"WinEmu";
    let version = b"1.0";
    let date = b"01/01/2021";

    bytes.push(0);
    bytes.push(24);
    push_u16(bytes, handle);
    bytes.push(1);
    bytes.push(2);
    push_u16(bytes, 0xe000);
    bytes.push(3);
    bytes.push(0);
    push_u64(bytes, 0x8);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&[
        SMBIOS_UNKNOWN_U8,
        SMBIOS_UNKNOWN_U8,
        SMBIOS_UNKNOWN_U8,
        SMBIOS_UNKNOWN_U8,
    ]);
    append_smbios_strings(bytes, &[vendor, version, date]);
}

fn append_smbios_system(bytes: &mut Vec<u8>, next_handle: &mut u16) {
    let handle = next_smbios_handle(next_handle);
    let vendor = b"WinEmu";
    let product = b"Virtual ARM64 Machine";
    let version = b"1.0";
    let serial = b"0";

    bytes.push(1);
    bytes.push(27);
    push_u16(bytes, handle);
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    bytes.extend_from_slice(&[0; 16]);
    bytes.push(0x06);
    bytes.extend_from_slice(&[0, 0]);
    append_smbios_strings(bytes, &[vendor, product, version, serial]);
}

fn append_smbios_chassis(bytes: &mut Vec<u8>, next_handle: &mut u16) -> u16 {
    let handle = next_smbios_handle(next_handle);
    let vendor = b"WinEmu";
    let version = b"1.0";
    let serial = b"0";

    bytes.push(3);
    bytes.push(21);
    push_u16(bytes, handle);
    bytes.extend_from_slice(&[1, 2, 2, 3, 0]);
    bytes.extend_from_slice(&[0x02, 0x02, 0x02, 0x02]);
    push_u32(bytes, 0);
    bytes.extend_from_slice(&[0, 0, 0, 3]);
    append_smbios_strings(bytes, &[vendor, version, serial]);
    handle
}

fn append_smbios_board(bytes: &mut Vec<u8>, next_handle: &mut u16, chassis_handle: u16) {
    let handle = next_smbios_handle(next_handle);
    let vendor = b"WinEmu";
    let product = b"Virtual ARM64 Board";
    let version = b"1.0";
    let serial = b"0";

    bytes.push(2);
    bytes.push(15);
    push_u16(bytes, handle);
    bytes.extend_from_slice(&[1, 2, 3, 4, 0, 0x05, 0]);
    push_u16(bytes, chassis_handle);
    bytes.extend_from_slice(&[0x0a, 0]);
    append_smbios_strings(bytes, &[vendor, product, version, serial]);
}

fn append_smbios_processor(bytes: &mut Vec<u8>, next_handle: &mut u16, processor_count: u16) {
    let handle = next_smbios_handle(next_handle);
    let socket = b"Socket #0";
    let vendor = b"WinEmu";
    let version = b"Virtual ARM64 CPU";
    let core_count = core::cmp::min(processor_count.max(1), u16::from(u8::MAX));
    let mut characteristics = 1u16 << 2;
    if core_count > 1 {
        characteristics |= 1u16 << 3;
    }

    bytes.push(4);
    bytes.push(42);
    push_u16(bytes, handle);
    bytes.extend_from_slice(&[1, 3, 2, 2]);
    push_u64(bytes, 0);
    bytes.extend_from_slice(&[3, 0]);
    push_u16(bytes, 100);
    push_u16(bytes, 3000);
    push_u16(bytes, 3000);
    bytes.extend_from_slice(&[0x41, 2]);
    push_u16(bytes, 0xffff);
    push_u16(bytes, 0xffff);
    push_u16(bytes, 0xffff);
    bytes.extend_from_slice(&[
        0,
        0,
        0,
        core_count as u8,
        core_count as u8,
        core_count as u8,
    ]);
    push_u16(bytes, characteristics);
    push_u16(bytes, 2);
    push_u16(bytes, core_count);
    push_u16(bytes, core_count);
    push_u16(bytes, core_count);
    append_smbios_strings(bytes, &[socket, vendor, version]);
}

fn append_smbios_boot_info(bytes: &mut Vec<u8>, next_handle: &mut u16) {
    let handle = next_smbios_handle(next_handle);
    bytes.push(32);
    bytes.push(20);
    push_u16(bytes, handle);
    bytes.extend_from_slice(&[0; 16]);
    append_smbios_strings(bytes, &[]);
}

fn append_smbios_end(bytes: &mut Vec<u8>, next_handle: &mut u16) {
    let handle = next_smbios_handle(next_handle);
    bytes.push(127);
    bytes.push(4);
    push_u16(bytes, handle);
    append_smbios_strings(bytes, &[]);
}

fn build_fake_raw_smbios_data() -> Vec<u8> {
    let (_active_mask, processor_count) = active_processor_mask_and_count();
    let mut table = Vec::with_capacity(256);
    let mut next_handle = 0u16;

    append_smbios_bios(&mut table, &mut next_handle);
    append_smbios_system(&mut table, &mut next_handle);
    let chassis_handle = append_smbios_chassis(&mut table, &mut next_handle);
    append_smbios_board(&mut table, &mut next_handle, chassis_handle);
    append_smbios_processor(&mut table, &mut next_handle, processor_count.max(1) as u16);
    append_smbios_boot_info(&mut table, &mut next_handle);
    append_smbios_end(&mut table, &mut next_handle);

    let mut raw = Vec::with_capacity(size_of::<RawSmbiosDataHeader>() + table.len());
    raw.extend_from_slice(&[0, SMBIOS_MAJOR_VERSION, SMBIOS_MINOR_VERSION, 0]);
    push_u32(&mut raw, table.len() as u32);
    raw.extend_from_slice(&table);
    raw
}

fn write_firmware_response(
    req: &SystemFirmwareTableInformation,
    table_buffer_length: u32,
    table_buffer: &[u8],
    buf: *mut u8,
    buf_len: usize,
    ret_len: *mut u32,
) -> u32 {
    let total_len = size_of::<SystemFirmwareTableInformation>() + table_buffer.len();
    let out = SystemFirmwareTableInformation {
        provider_signature: req.provider_signature,
        action: req.action,
        table_id: req.table_id,
        table_buffer_length,
    };

    if buf.is_null() || buf_len < size_of::<SystemFirmwareTableInformation>() {
        write_ret_len(ret_len, size_of::<SystemFirmwareTableInformation>() as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    if buf_len < total_len {
        let Some(mut w) =
            GuestWriter::new(buf, buf_len, size_of::<SystemFirmwareTableInformation>())
        else {
            write_ret_len(ret_len, total_len as u32);
            return status::INVALID_PARAMETER;
        };
        w.write_struct(out);
        write_ret_len(ret_len, total_len as u32);
        return status::BUFFER_TOO_SMALL;
    }

    let Some(mut w) = GuestWriter::new(buf, buf_len, total_len) else {
        write_ret_len(ret_len, total_len as u32);
        return status::INVALID_PARAMETER;
    };
    w.write_struct(out);
    w.bytes(table_buffer);
    write_ret_len(ret_len, total_len as u32);
    status::SUCCESS
}

fn query_system_firmware_table_information(buf: *mut u8, buf_len: usize, ret_len: *mut u32) -> u32 {
    let req_len = size_of::<SystemFirmwareTableInformation>();
    if buf.is_null() || buf_len < req_len {
        write_ret_len(ret_len, req_len as u32);
        return status::INFO_LENGTH_MISMATCH;
    }

    let req_ptr = UserInPtr::from_raw(buf as *const SystemFirmwareTableInformation);
    let Some(req) = req_ptr.read_current() else {
        write_ret_len(ret_len, req_len as u32);
        return status::INVALID_PARAMETER;
    };

    crate::ktrace!(
        "nt: SystemFirmwareTableInformation provider={:#x} action={} table_id={:#x} len={:#x}",
        req.provider_signature,
        req.action,
        req.table_id,
        buf_len
    );

    match (req.provider_signature, req.action) {
        (FIRMWARE_PROVIDER_RSMB, SYSTEM_FIRMWARE_TABLE_ENUMERATE) => write_firmware_response(
            &req,
            size_of::<u32>() as u32,
            &0u32.to_le_bytes(),
            buf,
            buf_len,
            ret_len,
        ),
        (FIRMWARE_PROVIDER_RSMB, SYSTEM_FIRMWARE_TABLE_GET) => {
            let raw = build_fake_raw_smbios_data();
            write_firmware_response(&req, raw.len() as u32, &raw, buf, buf_len, ret_len)
        }
        (_, SYSTEM_FIRMWARE_TABLE_ENUMERATE | SYSTEM_FIRMWARE_TABLE_GET) => {
            write_ret_len(ret_len, 0);
            crate::kdebug!(
                "nt: SystemFirmwareTableInformation unsupported provider={:#x}",
                req.provider_signature
            );
            status::NOT_IMPLEMENTED
        }
        _ => {
            write_ret_len(ret_len, 0);
            crate::kdebug!(
                "nt: SystemFirmwareTableInformation unsupported action={}",
                req.action
            );
            status::NOT_IMPLEMENTED
        }
    }
}

pub(crate) fn handle_query_system_information(frame: &mut SvcFrame) {
    let info_class = frame.x[0] as u32;
    let buf = frame.x[1] as *mut u8;
    let buf_len = frame.x[2] as usize;
    let ret_len = frame.x[3] as *mut u32;

    let st = match info_class {
        SYSTEM_INFO_CLASS_BASIC => query_system_basic_information(buf, buf_len, ret_len),
        SYSTEM_INFO_CLASS_CPU => query_system_cpu_information(buf, buf_len, ret_len),
        SYSTEM_INFO_CLASS_PERFORMANCE => {
            query_system_performance_information(buf, buf_len, ret_len)
        }
        SYSTEM_INFO_CLASS_TIME_OF_DAY => {
            query_system_time_of_day_information(buf, buf_len, ret_len)
        }
        SYSTEM_INFO_CLASS_FIRMWARE_TABLE => {
            query_system_firmware_table_information(buf, buf_len, ret_len)
        }
        SYSTEM_INFO_CLASS_HOSTCALL_FORCE_ASYNC => {
            query_hostcall_force_async_information(buf, buf_len, ret_len)
        }
        SYSTEM_INFO_CLASS_VMM_SCHED_WAKE_STATS => {
            query_vmm_sched_wake_stats_information(buf, buf_len, ret_len)
        }
        _ => {
            crate::kdebug!(
                "nt: NtQuerySystemInformation unsupported class={} buf={:#x} len={:#x}",
                info_class,
                buf as u64,
                buf_len
            );
            status::INVALID_PARAMETER
        }
    };
    frame.x[0] = st as u64;
}

pub(crate) fn handle_query_system_time(frame: &mut SvcFrame) {
    let out = UserOutPtr::from_raw(frame.x[0] as *mut i64);
    if out.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let now = crate::hypercall::query_system_time_100ns() as i64;
    if !out.write_current(now) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_query_performance_counter(frame: &mut SvcFrame) {
    let counter_ptr = UserOutPtr::from_raw(frame.x[0] as *mut i64);
    let freq_ptr = UserOutPtr::from_raw(frame.x[1] as *mut i64);
    if counter_ptr.is_null() && freq_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let counter = crate::hypercall::query_mono_time_100ns() as i64;
    if !counter_ptr.write_current_if_present(counter) {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if !freq_ptr.write_current_if_present(PERF_COUNTER_FREQUENCY_100NS as i64) {
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
    let timeout_ptr = UserInPtr::from_raw(frame.x[1] as *const i64);
    let trace_enabled = crate::log::log_enabled(crate::log::LogLevel::Trace);
    if trace_enabled {
        crate::log::debug_u64(0xD100_0001);
        crate::log::debug_u64(timeout_ptr.as_raw() as u64);
    }
    if timeout_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Some(raw) = timeout_ptr.read_current() else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    if trace_enabled {
        crate::log::debug_u64(0xD100_0002);
        crate::log::debug_u64(raw as u64);
    }
    let timeout = parse_delay_timeout(raw);
    let deadline_dbg = match timeout {
        WaitDeadline::Infinite => 0,
        WaitDeadline::Immediate => 1,
        WaitDeadline::DeadlineTicks(t) => t,
    };
    if trace_enabled {
        crate::log::debug_u64(0xD100_0003);
        crate::log::debug_u64(deadline_dbg);
    }
    let st = crate::sched::sync::delay_current_thread_sync(timeout);
    if trace_enabled {
        crate::log::debug_u64(0xD100_0004);
        crate::log::debug_u64(st as u64);
    }
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
