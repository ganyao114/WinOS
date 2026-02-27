use winemu_core::addr::Gpa;
use winemu_shared::status;

use super::{DispatchContext, DispatchResult, SyscallArgs};

pub(super) fn nt_create_section(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    let handle_out_gpa = call.get(0);
    let prot = call.get(4) as u32;
    let file_handle = call.get(6);
    log::debug!(
        "NtCreateSection args: handle_out_gpa={:#x} prot={:#x} file={:#x}",
        handle_out_gpa,
        prot,
        file_handle
    );
    let size = if call.get(3) != 0 {
        let mem = ctx.memory.read().unwrap();
        let b = mem.read_bytes(Gpa(call.get(3)), 8);
        u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
    } else {
        0
    };
    let (st, h) = ctx.sections.create(file_handle, size, prot, ctx.files);
    if st == status::SUCCESS as u64 && handle_out_gpa != 0 {
        ctx.memory
            .write()
            .unwrap()
            .write_bytes(Gpa(handle_out_gpa), &h.to_le_bytes());
    }
    log::debug!("NtCreateSection: status={:#x} handle={:#x}", st, h);
    DispatchResult::Sync(st)
}

pub(super) fn nt_map_view_of_section(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // a[0]=SectionHandle, a[1]=ProcessHandle, a[2]=*BaseAddress
    // a[3]=ZeroBits, a[4]=CommitSize, a[5]=SectionOffset*
    // a[6]=ViewSize*, a[7]=InheritDisposition, a[8]=AllocationType
    // a[9]=Win32Protect
    let section_handle = call.get(0);
    let base_ptr_gpa = call.get(2);
    let offset_ptr_gpa = call.get(5);
    let size_ptr_gpa = call.get(6);
    let prot = call.get(9) as u32;

    let base_hint = if base_ptr_gpa != 0 {
        let mem = ctx.memory.read().unwrap();
        let b = mem.read_bytes(Gpa(base_ptr_gpa), 8);
        u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
    } else {
        0
    };
    let offset = if offset_ptr_gpa != 0 {
        let mem = ctx.memory.read().unwrap();
        let b = mem.read_bytes(Gpa(offset_ptr_gpa), 8);
        u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
    } else {
        0
    };
    let map_size = if size_ptr_gpa != 0 {
        let mem = ctx.memory.read().unwrap();
        let b = mem.read_bytes(Gpa(size_ptr_gpa), 8);
        u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
    } else {
        0
    };

    let mut vs = ctx.vaspace.lock().unwrap();
    let mut mem = ctx.memory.write().unwrap();
    let (st, va) = ctx.sections.map_view(
        section_handle,
        base_hint,
        map_size,
        offset,
        prot,
        &mut vs,
        &mut mem,
    );
    drop(vs);
    drop(mem);

    if st == status::SUCCESS as u64 && base_ptr_gpa != 0 {
        ctx.memory
            .write()
            .unwrap()
            .write_bytes(Gpa(base_ptr_gpa), &va.to_le_bytes());
    }

    log::debug!("NtMapViewOfSection: status={:#x} va={:#x}", st, va);
    DispatchResult::Sync(st)
}

pub(super) fn nt_unmap_view_of_section(
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    // a[0]=ProcessHandle, a[1]=BaseAddress
    let base_va = call.get(1);
    let st = ctx
        .sections
        .unmap_view(base_va, &mut ctx.vaspace.lock().unwrap());
    log::debug!("NtUnmapViewOfSection: status={:#x} va={:#x}", st, base_va);
    DispatchResult::Sync(st)
}
