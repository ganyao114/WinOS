// svc_dispatch — EL1 SVC 分发器
// 由 vectors.rs 的 SVC handler 汇编调用，处理所有来自 EL0 的 syscall。
// 若需要线程切换，直接修改 SvcFrame 中的寄存器，ERET 后进入新线程。

use crate::hypercall;
use crate::sched::{current_tid, register_thread0, schedule, vcpu_id, with_thread_mut};

use super::{file, memory, object, process, registry, section, sync, thread, SvcFrame};

// Table 0 = Nt*, Table 1 = Win32k (ignored here)
const NR_CREATE_EVENT: u16 = 0x0048;
const NR_SET_INFORMATION_THREAD: u16 = 0x000D;
const NR_DELETE_KEY: u16 = 0x000C;
const NR_ENUMERATE_VALUE_KEY: u16 = 0x0010;
const NR_OPEN_KEY: u16 = 0x0012;
const NR_QUERY_VALUE_KEY: u16 = 0x0016;
const NR_CREATE_KEY: u16 = 0x001D;
const NR_ENUMERATE_KEY: u16 = 0x0032;
const NR_SET_VALUE_KEY: u16 = 0x003D;
const NR_READ_FILE: u16 = 0x0006;
const NR_WRITE_FILE: u16 = 0x0008;
const NR_SET_EVENT: u16 = 0x000E;
const NR_QUERY_INFORMATION_FILE: u16 = 0x0011;
const NR_OPEN_FILE: u16 = 0x0030;
const NR_QUERY_INFORMATION_PROCESS: u16 = 0x0019;
const NR_QUERY_INFORMATION_THREAD: u16 = 0x0025;
const NR_SET_INFORMATION_FILE: u16 = 0x0027;
const NR_FREE_VIRTUAL_MEMORY: u16 = 0x001E;
const NR_QUERY_VIRTUAL_MEMORY: u16 = 0x0023;
const NR_PROTECT_VIRTUAL_MEMORY: u16 = 0x004D;
const NR_MAP_VIEW_OF_SECTION: u16 = 0x0028;
const NR_UNMAP_VIEW_OF_SECTION: u16 = 0x002A;
const NR_CREATE_FILE: u16 = 0x0055;
const NR_RESET_EVENT: u16 = 0x0034;
const NR_DUPLICATE_OBJECT: u16 = 0x003C;
const NR_ALLOCATE_VIRTUAL_MEMORY: u16 = 0x0015;
const NR_WAIT_SINGLE: u16 = 0x0004;
const NR_WAIT_MULTIPLE: u16 = 0x0040;
const NR_CREATE_SECTION: u16 = 0x004A;
const NR_CREATE_PROCESS_EX: u16 = 0x004B;
const NR_QUERY_DIRECTORY_FILE: u16 = 0x004E;
const NR_CREATE_MUTEX: u16 = 0x00A9;
const NR_RELEASE_MUTANT: u16 = 0x001C;
const NR_CREATE_SEMAPHORE: u16 = 0x00C3;
const NR_RELEASE_SEMAPHORE: u16 = 0x0033;
const NR_CLOSE: u16 = 0x000F;
const NR_YIELD_EXECUTION: u16 = 0x0046;
const NR_CREATE_THREAD_EX: u16 = 0x00C1;
const NR_TERMINATE_THREAD: u16 = 0x0053;
const NR_TERMINATE_PROCESS: u16 = 0x002C;

#[no_mangle]
pub extern "C" fn svc_dispatch(frame: &mut SvcFrame) {
    if current_tid() == 0 {
        register_thread0(frame.tpidr);
    }

    let tag = frame.x8_orig;
    let nr = (tag & 0xFFF) as u16;
    let table = ((tag >> 12) & 0x3) as u8;

    if table != 0 {
        forward_to_vmm(frame, nr, table);
        return;
    }

    match nr {
        NR_CREATE_FILE => file::handle_create_file(frame),
        NR_OPEN_FILE => file::handle_open_file(frame),
        NR_READ_FILE => file::handle_read_file(frame),
        NR_WRITE_FILE => file::handle_write_file(frame),
        NR_QUERY_INFORMATION_FILE => file::handle_query_information_file(frame),
        NR_SET_INFORMATION_FILE => file::handle_set_information_file(frame),
        NR_QUERY_DIRECTORY_FILE => file::handle_query_directory_file(frame),

        NR_CREATE_EVENT => sync::handle_create_event(frame),
        NR_SET_EVENT => sync::handle_set_event(frame),
        NR_RESET_EVENT => sync::handle_reset_event(frame),
        NR_WAIT_SINGLE => sync::handle_wait_single(frame),
        NR_WAIT_MULTIPLE => sync::handle_wait_multiple(frame),
        NR_CREATE_MUTEX => sync::handle_create_mutex(frame),
        NR_RELEASE_MUTANT => sync::handle_release_mutant(frame),
        NR_CREATE_SEMAPHORE => sync::handle_create_semaphore(frame),
        NR_RELEASE_SEMAPHORE => sync::handle_release_semaphore(frame),

        NR_OPEN_KEY => registry::handle_open_key(frame),
        NR_CREATE_KEY => registry::handle_create_key(frame),
        NR_QUERY_VALUE_KEY => registry::handle_query_value_key(frame),
        NR_SET_VALUE_KEY => registry::handle_set_value_key(frame),
        NR_DELETE_KEY => registry::handle_delete_key(frame),
        NR_ENUMERATE_KEY => registry::handle_enumerate_key(frame),
        NR_ENUMERATE_VALUE_KEY => registry::handle_enumerate_value_key(frame),

        NR_ALLOCATE_VIRTUAL_MEMORY => memory::handle_allocate_virtual_memory(frame),
        NR_FREE_VIRTUAL_MEMORY => memory::handle_free_virtual_memory(frame),
        NR_QUERY_VIRTUAL_MEMORY => memory::handle_query_virtual_memory(frame),
        NR_PROTECT_VIRTUAL_MEMORY => memory::handle_protect_virtual_memory(frame),

        NR_CREATE_SECTION => section::handle_create_section(frame),
        NR_MAP_VIEW_OF_SECTION => section::handle_map_view_of_section(frame),
        NR_UNMAP_VIEW_OF_SECTION => section::handle_unmap_view_of_section(frame),

        NR_QUERY_INFORMATION_PROCESS => process::handle_query_information_process(frame),
        NR_CREATE_PROCESS_EX => process::handle_create_process(frame),
        NR_TERMINATE_PROCESS => process::handle_terminate_process(frame),

        NR_QUERY_INFORMATION_THREAD => thread::handle_query_information_thread(frame),
        NR_SET_INFORMATION_THREAD => thread::handle_set_information_thread(frame),
        NR_CREATE_THREAD_EX => thread::handle_create_thread(frame),
        NR_YIELD_EXECUTION => thread::handle_yield(frame),
        NR_TERMINATE_THREAD => thread::handle_terminate_thread(frame),

        NR_DUPLICATE_OBJECT => object::handle_duplicate_object(frame),
        NR_CLOSE => {
            if !object::handle_close(frame) {
                forward_to_vmm(frame, NR_CLOSE, 0);
            }
        }

        _ => forward_to_vmm(frame, nr, table),
    }

    maybe_preempt(frame);
}

fn save_ctx_for(tid: u32, frame: &SvcFrame) {
    with_thread_mut(tid, |t| {
        t.ctx.x.copy_from_slice(&frame.x);
        t.ctx.sp = frame.sp_el0;
        t.ctx.pc = frame.elr;
        t.ctx.pstate = frame.spsr;
        t.ctx.tpidr = frame.tpidr;
    });
}

fn restore_ctx_to_frame(tid: u32, frame: &mut SvcFrame) {
    with_thread_mut(tid, |t| {
        frame.x.copy_from_slice(&t.ctx.x);
        frame.sp_el0 = t.ctx.sp;
        frame.elr = t.ctx.pc;
        frame.spsr = t.ctx.pstate;
        frame.tpidr = t.ctx.tpidr;
    });
}

fn maybe_preempt(frame: &mut SvcFrame) {
    let vid = vcpu_id();
    let from = current_tid();
    let (_, to) = schedule(vid);
    if to == 0 {
        if crate::sched::all_threads_done() {
            hypercall::process_exit(0);
        }
        unsafe { core::arch::asm!("wfi", options(nostack, nomem)) };
        return;
    }
    if from != to {
        save_ctx_for(from, frame);
        restore_ctx_to_frame(to, frame);
    }
}

#[no_mangle]
pub extern "C" fn el1_fault_dispatch(frame: &mut SvcFrame) {
    let esr: u64;
    let far: u64;
    unsafe {
        core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nostack, nomem));
        core::arch::asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
    }
    hypercall::debug_u64(0xE100_0000_0000_0000 | esr);
    hypercall::debug_u64(0xE102_0000_0000_0000 | far);
    hypercall::debug_u64(0xE103_0000_0000_0000 | frame.elr);
    hypercall::debug_u64(0xE104_0000_0000_0000 | frame.spsr);
    hypercall::process_exit(0xE1);
}

#[no_mangle]
pub extern "C" fn el0_fault_dispatch(frame: &mut SvcFrame) {
    let esr: u64;
    let far: u64;
    unsafe {
        core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nostack, nomem));
        core::arch::asm!("mrs {}, far_el1", out(reg) far, options(nostack, nomem));
    }
    hypercall::debug_u64(0xFA01_0000_0000_0000 | esr);
    hypercall::debug_u64(0xFA02_0000_0000_0000 | far);
    hypercall::debug_u64(0xFA03_0000_0000_0000 | frame.elr);
    hypercall::debug_u64(0xFA04_0000_0000_0000 | frame.spsr);
    hypercall::process_exit(0xFF);
}

fn forward_to_vmm(frame: &mut SvcFrame, nr: u16, table: u8) {
    let ret = unsafe {
        let mut r: u64;
        core::arch::asm!(
            "hvc #0",
            inout("x0") winemu_shared::nr::NT_SYSCALL => r,
            in("x1") frame.x[1],
            in("x2") frame.x[2],
            in("x3") frame.x[3],
            in("x4") frame.x[4],
            in("x5") frame.x[5],
            in("x6") frame.x[6],
            in("x7") frame.x[7],
            in("x9") nr as u64,
            in("x10") table as u64,
            in("x11") frame.x[0],
            in("x12") frame as *const SvcFrame as u64,
            options(nostack)
        );
        r
    };
    frame.x[0] = ret;
}
