use winemu_core::addr::Gpa;
use winemu_shared::status;

use crate::sched::SchedResult;

use super::{DispatchContext, DispatchResult, SyscallArgs};

pub(super) fn nt_query_information_process(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // a[0]=ProcessHandle, a[1]=ProcessInformationClass
    // a[2]=ProcessInformation GPA, a[3]=ProcessInformationLength
    // a[4]=ReturnLength GPA
    let info_class = call.get(1) as u32;
    let buf_gpa = Gpa(call.get(2));
    let buf_len = call.get(3) as usize;
    let ret_gpa = call.get(4);

    match info_class {
        // ProcessBasicInformation = 0
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
            // Read PEB pointer from TEB (TEB+0x60).
            let teb_gpa = ctx.sched.get_teb(ctx.tid).unwrap_or(0);
            let peb_base = if teb_gpa != 0 {
                let mem = ctx.memory.read().unwrap();
                let b = mem.read_bytes(Gpa(teb_gpa + 0x60), 8);
                u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
            } else {
                0
            };
            let mut pbi = [0u8; 48];
            pbi[8..16].copy_from_slice(&peb_base.to_le_bytes());
            pbi[16..24].copy_from_slice(&1u64.to_le_bytes()); // AffinityMask
            pbi[24..28].copy_from_slice(&8i32.to_le_bytes()); // BasePriority
            pbi[32..40].copy_from_slice(&1u64.to_le_bytes()); // UniqueProcessId
            pbi[40..48].copy_from_slice(&0u64.to_le_bytes()); // InheritedFrom
            ctx.memory.write().unwrap().write_bytes(buf_gpa, &pbi);
            if ret_gpa != 0 {
                ctx.memory
                    .write()
                    .unwrap()
                    .write_bytes(Gpa(ret_gpa), &48u32.to_le_bytes());
            }
            DispatchResult::Sync(status::SUCCESS as u64)
        }
        // ProcessImageFileName = 27
        27 => {
            if buf_len < 16 {
                if ret_gpa != 0 {
                    ctx.memory
                        .write()
                        .unwrap()
                        .write_bytes(Gpa(ret_gpa), &16u32.to_le_bytes());
                }
                return DispatchResult::Sync(status::INFO_LENGTH_MISMATCH as u64);
            }
            let us = [0u8; 16];
            ctx.memory.write().unwrap().write_bytes(buf_gpa, &us);
            if ret_gpa != 0 {
                ctx.memory
                    .write()
                    .unwrap()
                    .write_bytes(Gpa(ret_gpa), &16u32.to_le_bytes());
            }
            DispatchResult::Sync(status::SUCCESS as u64)
        }
        _ => {
            log::debug!("NtQueryInformationProcess: unhandled class {}", info_class);
            DispatchResult::Sync(status::INVALID_PARAMETER as u64)
        }
    }
}

pub(super) fn nt_terminate_process(call: &SyscallArgs<'_>) -> DispatchResult {
    let code = call.get(1) as u32;
    DispatchResult::Sched(SchedResult::Exit(code))
}

pub(super) fn nt_create_process() -> DispatchResult {
    log::warn!("NtCreateProcessEx: not supported");
    DispatchResult::Sync(status::NOT_IMPLEMENTED as u64)
}
