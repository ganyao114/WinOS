use winemu_core::addr::Gpa;
use winemu_shared::status;

use crate::sched::sync::SyncObject;
use crate::sched::{SchedResult, ThreadContext};

use super::{DispatchContext, DispatchResult, SyscallArgs};

pub(super) fn nt_query_information_thread(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // a[0]=ThreadHandle, a[1]=ThreadInformationClass
    // a[2]=ThreadInformation GPA, a[3]=ThreadInformationLength
    // a[4]=ReturnLength GPA
    let info_class = call.get(1) as u32;
    let buf_gpa = Gpa(call.get(2));
    let buf_len = call.get(3) as usize;
    let ret_gpa = call.get(4);

    match info_class {
        // ThreadBasicInformation = 0
        0 => {
            if buf_len < 48 {
                if ret_gpa != 0 {
                    ctx.memory
                        .write()
                        .unwrap()
                        .write_bytes(Gpa(ret_gpa), &48u32.to_le_bytes());
                }
                return DispatchResult::Sync(status::INFO_LENGTH_MISMATCH as u64);
            }
            let teb_gpa = ctx.sched.get_teb(ctx.tid).unwrap_or(0);
            let thread_id = ctx.tid.0 as u64;
            let mut tbi = [0u8; 48];
            tbi[8..16].copy_from_slice(&teb_gpa.to_le_bytes());
            tbi[16..24].copy_from_slice(&1u64.to_le_bytes()); // pid
            tbi[24..32].copy_from_slice(&thread_id.to_le_bytes());
            tbi[32..40].copy_from_slice(&1u64.to_le_bytes()); // AffinityMask
            tbi[40..44].copy_from_slice(&8i32.to_le_bytes()); // Priority
            tbi[44..48].copy_from_slice(&8i32.to_le_bytes()); // BasePriority
            ctx.memory.write().unwrap().write_bytes(buf_gpa, &tbi);
            if ret_gpa != 0 {
                ctx.memory
                    .write()
                    .unwrap()
                    .write_bytes(Gpa(ret_gpa), &48u32.to_le_bytes());
            }
            DispatchResult::Sync(status::SUCCESS as u64)
        }
        _ => {
            log::debug!("NtQueryInformationThread: unhandled class {}", info_class);
            DispatchResult::Sync(status::INVALID_PARAMETER as u64)
        }
    }
}

pub(super) fn nt_set_information_thread(call: &SyscallArgs<'_>) -> DispatchResult {
    // Most classes are no-ops in emulation (ThreadHideFromDebugger, etc.)
    let info_class = call.get(1) as u32;
    log::debug!("NtSetInformationThread: class={}", info_class);
    DispatchResult::Sync(status::SUCCESS as u64)
}

pub(super) fn nt_terminate_thread(call: &SyscallArgs<'_>) -> DispatchResult {
    // a[0]=ThreadHandle (-1 or -2 = current thread), a[1]=ExitStatus
    let handle = call.get(0);
    let code = call.get(1) as u32;
    let is_self = handle == 0xFFFF_FFFF_FFFF_FFFF || handle == 0xFFFF_FFFF_FFFF_FFFE || handle == 0;
    if is_self {
        // Terminate calling thread only.
        DispatchResult::Sched(SchedResult::Exit(code))
    } else {
        // TODO: terminate other thread by handle.
        log::warn!("NtTerminateThread: remote thread termination not implemented");
        DispatchResult::Sync(status::SUCCESS as u64)
    }
}

pub(super) fn nt_yield_execution() -> DispatchResult {
    DispatchResult::Sched(SchedResult::Yield)
}

pub(super) fn nt_create_thread(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // NtCreateThreadEx(OUT PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE ProcessHandle,
    //   PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits,
    //   SIZE_T StackSize, SIZE_T MaxStackSize, PPS_ATTRIBUTE_LIST)
    // x0=ThreadHandle out, x1=DesiredAccess, x2=ObjAttrs, x3=ProcessHandle
    // x4=StartRoutine, x5=Argument, x6=CreateFlags, x7=ZeroBits
    // stack[0]=StackSize, stack[1]=MaxStackSize, stack[2]=AttrList
    let handle_gpa = call.get(0);
    let start_routine = call.get(4);
    let argument = call.get(5);
    let create_flags = call.get(6) as u32;
    let stack_size = {
        let s = call.get(8);
        if s == 0 {
            0x10000u64
        } else {
            (s + 0xFFFF) & !0xFFFF
        }
    };

    if start_routine == 0 {
        return DispatchResult::Sync(status::INVALID_PARAMETER as u64);
    }

    let stack_base = match ctx
        .vaspace
        .lock()
        .unwrap()
        .alloc(0, stack_size, 0x04 /* PAGE_READWRITE */)
    {
        Some(va) => va,
        None => return DispatchResult::Sync(status::NO_MEMORY as u64),
    };
    let zero = vec![0u8; stack_size as usize];
    ctx.memory
        .write()
        .unwrap()
        .write_bytes(Gpa(stack_base), &zero);
    let stack_top = stack_base + stack_size;

    let teb_va = match ctx.vaspace.lock().unwrap().alloc(0, 0x1000, 0x04) {
        Some(va) => va,
        None => return DispatchResult::Sync(status::NO_MEMORY as u64),
    };

    let caller_teb = ctx.sched.get_teb(ctx.tid).unwrap_or(0);
    let peb_va = if caller_teb != 0 {
        let mem = ctx.memory.read().unwrap();
        let b = mem.read_bytes(Gpa(caller_teb + winemu_shared::teb::PEB as u64), 8);
        u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
    } else {
        0
    };

    let new_tid = ctx.sched.alloc_tid();
    {
        let mut mem = ctx.memory.write().unwrap();
        let teb_buf = vec![0u8; winemu_shared::teb::SIZE];
        mem.write_bytes(Gpa(teb_va), &teb_buf);
        mem.write_bytes(
            Gpa(teb_va + winemu_shared::teb::EXCEPTION_LIST as u64),
            &u64::MAX.to_le_bytes(),
        );
        mem.write_bytes(
            Gpa(teb_va + winemu_shared::teb::STACK_BASE as u64),
            &stack_top.to_le_bytes(),
        );
        mem.write_bytes(
            Gpa(teb_va + winemu_shared::teb::STACK_LIMIT as u64),
            &stack_base.to_le_bytes(),
        );
        mem.write_bytes(
            Gpa(teb_va + winemu_shared::teb::SELF as u64),
            &teb_va.to_le_bytes(),
        );
        mem.write_bytes(
            Gpa(teb_va + winemu_shared::teb::PEB as u64),
            &peb_va.to_le_bytes(),
        );
        // CLIENT_ID: pid=1, tid=new_tid
        mem.write_bytes(
            Gpa(teb_va + winemu_shared::teb::CLIENT_ID as u64),
            &1u64.to_le_bytes(),
        );
        mem.write_bytes(
            Gpa(teb_va + winemu_shared::teb::CLIENT_ID as u64 + 8),
            &(new_tid.0 as u64).to_le_bytes(),
        );
    }

    let mut thread_ctx = ThreadContext::default();
    thread_ctx.gpr[32] = start_routine; // pc
    thread_ctx.gpr[31] = stack_top; // sp
    thread_ctx.gpr[0] = argument; // x0 = arg
    thread_ctx.gpr[18] = teb_va; // x18 = TEB (ARM64 thread register)
    thread_ctx.pstate = 0x0; // EL0t

    // CREATE_SUSPENDED (0x1) — don't push to ready queue yet.
    let _suspended = (create_flags & 1) != 0;

    let thread_handle = ctx.sched.alloc_handle();
    ctx.sched
        .insert_object(thread_handle, SyncObject::Thread(new_tid));
    ctx.sched.spawn(new_tid, thread_ctx, teb_va);

    log::info!(
        "NtCreateThreadEx: tid={} entry={:#x} stack=[{:#x},{:#x}) teb={:#x} handle={}",
        new_tid.0,
        start_routine,
        stack_base,
        stack_top,
        teb_va,
        thread_handle.0
    );

    if handle_gpa != 0 {
        ctx.memory
            .write()
            .unwrap()
            .write_bytes(Gpa(handle_gpa), &(thread_handle.0 as u64).to_le_bytes());
    }
    DispatchResult::Sync(status::SUCCESS as u64)
}
