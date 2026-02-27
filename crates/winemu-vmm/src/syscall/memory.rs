use winemu_core::addr::Gpa;
use winemu_shared::status;

use super::{DispatchContext, DispatchResult, SyscallArgs};

pub(super) fn nt_allocate_virtual_memory(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // a[0]=ProcessHandle(-1=self), a[1]=*BaseAddress GPA, a[2]=ZeroBits
    // a[3]=*RegionSize GPA, a[4]=AllocationType, a[5]=Protect
    let base_ptr_gpa = call.get(1);
    let size_ptr_gpa = call.get(3);
    let prot = call.get(5) as u32;

    let hint = if base_ptr_gpa != 0 {
        let mem = ctx.memory.read().unwrap();
        let b = mem.read_bytes(Gpa(base_ptr_gpa), 8);
        u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
    } else {
        0
    };
    let size = if size_ptr_gpa != 0 {
        let mem = ctx.memory.read().unwrap();
        let b = mem.read_bytes(Gpa(size_ptr_gpa), 8);
        u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
    } else {
        0
    };

    if size == 0 {
        return DispatchResult::Sync(status::INVALID_PARAMETER as u64);
    }
    match ctx.vaspace.lock().unwrap().alloc(hint, size, prot) {
        Some(va) => {
            // Zero-initialize committed memory (Windows guarantee)
            let aligned = (size + 0xFFFF) & !0xFFFF;
            let zero = vec![0u8; aligned as usize];
            ctx.memory.write().unwrap().write_bytes(Gpa(va), &zero);
            if base_ptr_gpa != 0 {
                ctx.memory
                    .write()
                    .unwrap()
                    .write_bytes(Gpa(base_ptr_gpa), &va.to_le_bytes());
            }
            if size_ptr_gpa != 0 {
                ctx.memory
                    .write()
                    .unwrap()
                    .write_bytes(Gpa(size_ptr_gpa), &aligned.to_le_bytes());
            }
            DispatchResult::Sync(status::SUCCESS as u64)
        }
        None => DispatchResult::Sync(status::NO_MEMORY as u64),
    }
}

pub(super) fn nt_free_virtual_memory(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // a[0]=ProcessHandle, a[1]=*BaseAddress GPA, a[2]=*RegionSize GPA, a[3]=FreeType
    let base_ptr_gpa = call.get(1);
    let base = if base_ptr_gpa != 0 {
        let mem = ctx.memory.read().unwrap();
        let b = mem.read_bytes(Gpa(base_ptr_gpa), 8);
        u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
    } else {
        0
    };
    ctx.vaspace.lock().unwrap().free(base);
    DispatchResult::Sync(status::SUCCESS as u64)
}

pub(super) fn nt_query_virtual_memory(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // a[0]=ProcessHandle, a[1]=BaseAddress, a[2]=InfoClass
    // a[3]=Buffer GPA, a[4]=BufferSize, a[5]=*ReturnLength GPA
    let addr = call.get(1);
    let buf_gpa = Gpa(call.get(3));
    let buf_size = call.get(4) as usize;
    let ret_gpa = call.get(5);
    // MEMORY_BASIC_INFORMATION64 size = 48
    if buf_size < 48 {
        return DispatchResult::Sync(status::INFO_LENGTH_MISMATCH as u64);
    }
    let (base, size, state, prot) = {
        let va = ctx.vaspace.lock().unwrap();
        match va.query(addr) {
            Some(r) => (r.base, r.size, r.state as u32, r.prot),
            None => (addr & !0xFFFF, 0x10000, 0u32, 0u32),
        }
    };
    let mut mbi = [0u8; 48];
    mbi[0..8].copy_from_slice(&base.to_le_bytes());
    mbi[8..16].copy_from_slice(&base.to_le_bytes()); // AllocationBase
    mbi[16..20].copy_from_slice(&prot.to_le_bytes()); // AllocationProtect
    mbi[24..32].copy_from_slice(&size.to_le_bytes()); // RegionSize
    mbi[32..36].copy_from_slice(&state.to_le_bytes()); // State
    mbi[36..40].copy_from_slice(&prot.to_le_bytes()); // Protect
    ctx.memory.write().unwrap().write_bytes(buf_gpa, &mbi);
    if ret_gpa != 0 {
        ctx.memory
            .write()
            .unwrap()
            .write_bytes(Gpa(ret_gpa), &48u64.to_le_bytes());
    }
    DispatchResult::Sync(status::SUCCESS as u64)
}

pub(super) fn nt_protect_virtual_memory(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // a[0]=ProcessHandle, a[1]=*BaseAddress, a[2]=*RegionSize
    // a[3]=NewProtect, a[4]=*OldProtect
    // Stub: write OldProtect=PAGE_READWRITE, return SUCCESS.
    let old_protect_gpa = call.get(4);
    if old_protect_gpa != 0 {
        ctx.memory
            .write()
            .unwrap()
            .write_bytes(Gpa(old_protect_gpa), &4u32.to_le_bytes()); // PAGE_READWRITE
    }
    DispatchResult::Sync(status::SUCCESS as u64)
}
