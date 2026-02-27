use winemu_core::addr::Gpa;
use winemu_shared::status;
use winereg::RegistryValue;

use super::{
    decode_reg_value, encode_key_basic_info, encode_key_value_full, read_unicode_string,
    read_unicode_string_direct, DispatchContext, DispatchResult, SyscallArgs, SyscallDispatcher,
};

pub(super) fn nt_open_key(
    disp: &SyscallDispatcher,
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    let oa_gpa = call.get(2);
    let path = read_unicode_string(ctx.memory, oa_gpa);
    log::debug!("NtOpenKey: {}", path);
    let mut reg = disp.reg.lock().unwrap();
    let node = reg.db.open_key(&path);
    match node {
        Some(n) => {
            let h = reg.alloc_handle(n);
            DispatchResult::Sync(h)
        }
        None => DispatchResult::Sync(status::OBJECT_NAME_NOT_FOUND as u64),
    }
}

pub(super) fn nt_create_key(
    disp: &SyscallDispatcher,
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    let oa_gpa = call.get(2);
    let path = read_unicode_string(ctx.memory, oa_gpa);
    log::debug!("NtCreateKey: {}", path);
    let mut reg = disp.reg.lock().unwrap();
    let node = reg.db.create_key(&path);
    let h = reg.alloc_handle(node);
    DispatchResult::Sync(h)
}

pub(super) fn nt_query_value_key(
    disp: &SyscallDispatcher,
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    let handle = call.get(0);
    let vn_gpa = call.get(1);
    let buf_gpa = Gpa(call.get(3));
    let buf_len = call.get(4) as usize;
    let ret_gpa = call.get(5);
    let val_name = read_unicode_string_direct(ctx.memory, vn_gpa);
    let node = disp.reg.lock().unwrap().key_handles.get(&handle).cloned();
    match node {
        None => DispatchResult::Sync(status::INVALID_HANDLE as u64),
        Some(n) => {
            let guard = n.borrow();
            match guard.get_value(&val_name) {
                None => DispatchResult::Sync(status::OBJECT_NAME_NOT_FOUND as u64),
                Some(val) => {
                    let data = encode_key_value_full(&val_name, val);
                    if buf_len < data.len() {
                        if ret_gpa != 0 {
                            ctx.memory
                                .write()
                                .unwrap()
                                .write_bytes(Gpa(ret_gpa), &(data.len() as u32).to_le_bytes());
                        }
                        return DispatchResult::Sync(status::BUFFER_TOO_SMALL as u64);
                    }
                    ctx.memory.write().unwrap().write_bytes(buf_gpa, &data);
                    if ret_gpa != 0 {
                        ctx.memory
                            .write()
                            .unwrap()
                            .write_bytes(Gpa(ret_gpa), &(data.len() as u32).to_le_bytes());
                    }
                    DispatchResult::Sync(status::SUCCESS as u64)
                }
            }
        }
    }
}

pub(super) fn nt_enumerate_key(
    disp: &SyscallDispatcher,
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    let handle = call.get(0);
    let index = call.get(1) as usize;
    let buf_gpa = Gpa(call.get(3));
    let buf_len = call.get(4) as usize;
    let ret_gpa = call.get(5);
    let node = disp.reg.lock().unwrap().key_handles.get(&handle).cloned();
    match node {
        None => DispatchResult::Sync(status::INVALID_HANDLE as u64),
        Some(n) => {
            let guard = n.borrow();
            let subkeys: Vec<_> = guard.subkeys().keys().cloned().collect();
            if index >= subkeys.len() {
                return DispatchResult::Sync(status::NO_MORE_ENTRIES as u64);
            }
            let name = &subkeys[index];
            let data = encode_key_basic_info(name);
            if buf_len < data.len() {
                if ret_gpa != 0 {
                    ctx.memory
                        .write()
                        .unwrap()
                        .write_bytes(Gpa(ret_gpa), &(data.len() as u32).to_le_bytes());
                }
                return DispatchResult::Sync(status::BUFFER_TOO_SMALL as u64);
            }
            ctx.memory.write().unwrap().write_bytes(buf_gpa, &data);
            if ret_gpa != 0 {
                ctx.memory
                    .write()
                    .unwrap()
                    .write_bytes(Gpa(ret_gpa), &(data.len() as u32).to_le_bytes());
            }
            DispatchResult::Sync(status::SUCCESS as u64)
        }
    }
}

pub(super) fn nt_enumerate_value_key(
    disp: &SyscallDispatcher,
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    let handle = call.get(0);
    let index = call.get(1) as usize;
    let buf_gpa = Gpa(call.get(3));
    let buf_len = call.get(4) as usize;
    let ret_gpa = call.get(5);
    let node = disp.reg.lock().unwrap().key_handles.get(&handle).cloned();
    match node {
        None => DispatchResult::Sync(status::INVALID_HANDLE as u64),
        Some(n) => {
            let guard = n.borrow();
            let vals: Vec<_> = guard.values().values().cloned().collect();
            if index >= vals.len() {
                return DispatchResult::Sync(status::NO_MORE_ENTRIES as u64);
            }
            let val = &vals[index];
            let data = encode_key_value_full(&val.name, val);
            if buf_len < data.len() {
                if ret_gpa != 0 {
                    ctx.memory
                        .write()
                        .unwrap()
                        .write_bytes(Gpa(ret_gpa), &(data.len() as u32).to_le_bytes());
                }
                return DispatchResult::Sync(status::BUFFER_TOO_SMALL as u64);
            }
            ctx.memory.write().unwrap().write_bytes(buf_gpa, &data);
            if ret_gpa != 0 {
                ctx.memory
                    .write()
                    .unwrap()
                    .write_bytes(Gpa(ret_gpa), &(data.len() as u32).to_le_bytes());
            }
            DispatchResult::Sync(status::SUCCESS as u64)
        }
    }
}

pub(super) fn nt_set_value_key(
    disp: &SyscallDispatcher,
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    let handle = call.get(0);
    let vn_gpa = call.get(1);
    let val_type = call.get(3) as u32;
    let data_gpa = call.get(4);
    let data_len = call.get(5) as usize;
    let val_name = read_unicode_string_direct(ctx.memory, vn_gpa);
    let raw = if data_len > 0 && data_len <= 65536 {
        ctx.memory
            .read()
            .unwrap()
            .read_bytes(Gpa(data_gpa), data_len)
            .to_vec()
    } else {
        vec![]
    };
    let node = disp.reg.lock().unwrap().key_handles.get(&handle).cloned();
    if let Some(n) = node {
        let val = RegistryValue::new(val_name.clone(), decode_reg_value(val_type, &raw));
        n.borrow_mut().set_value(val_name, val);
    }
    DispatchResult::Sync(status::SUCCESS as u64)
}

pub(super) fn nt_delete_key(disp: &SyscallDispatcher, call: &SyscallArgs<'_>) -> DispatchResult {
    let handle = call.get(0);
    disp.reg.lock().unwrap().key_handles.remove(&handle);
    DispatchResult::Sync(status::SUCCESS as u64)
}

pub(super) fn nt_delete_value_key(
    disp: &SyscallDispatcher,
    call: &SyscallArgs<'_>,
    ctx: &DispatchContext<'_>,
) -> DispatchResult {
    let handle = call.get(0);
    let vn_gpa = call.get(1);
    let val_name = read_unicode_string_direct(ctx.memory, vn_gpa);
    let node = disp.reg.lock().unwrap().key_handles.get(&handle).cloned();
    if let Some(n) = node {
        n.borrow_mut().delete_value(&val_name);
    }
    DispatchResult::Sync(status::SUCCESS as u64)
}

pub(super) fn nt_flush_key() -> DispatchResult {
    DispatchResult::Sync(status::SUCCESS as u64)
}
