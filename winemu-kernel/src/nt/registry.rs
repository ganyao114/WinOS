use core::cell::UnsafeCell;

use crate::kobj::ObjectStore;
use crate::process::{with_process_mut, KObjectKind, KObjectRef};
use crate::rust_alloc::{
    string::{String, ToString},
    vec::Vec,
};
use winemu_shared::status;
use winereg::{
    KeyNode, RegistryKey, RegistryValue, RegistryValueData, REG_BINARY, REG_DWORD, REG_EXPAND_SZ,
    REG_MULTI_SZ, REG_QWORD, REG_SZ,
};

use super::path::{
    bytes_path_to_registry, normalize_registry_path, ObjectAttributesView, UnicodeStringView,
};
use super::user_args::UserOutPtr;
use super::SvcFrame;
use crate::mm::usercopy::read_current_user_bytes;
use crate::nt::common::GuestWriter;

const MAX_PATH: usize = 256;
const MAX_NAME_BYTES: usize = 256;
const MAX_VALUE_NAME_UTF16: usize = 256;
const KEY_INFORMATION_BASIC: u32 = 0;
const KEY_INFORMATION_FULL: u32 = 2;
const KEY_INFORMATION_NAME: u32 = 3;
const KEY_BASIC_INFORMATION_SIZE: usize = 16;
const KEY_FULL_INFORMATION_SIZE: usize = 44;
const KEY_NAME_INFORMATION_SIZE: usize = 4;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
const KEY_WOW64_FLAGS: u32 = 0x0000_0300;

struct RegistryState {
    root: KeyNode,
    handles: ObjectStore<KeyNode>,
}

struct RegistryStateCell(UnsafeCell<Option<RegistryState>>);

unsafe impl Sync for RegistryStateCell {}

static REG_STATE: RegistryStateCell = RegistryStateCell(UnsafeCell::new(None));

const WBEM_LOCATOR_CLSID: &str = "{4590F811-1D3A-11D0-891F-00AA004B2E24}";
const WBEM_REFRESHER_CLSID: &str = "{C71566F2-561E-11D1-AD87-00C04FD8FDFF}";
const WBEMPROX_DLL_PATH: &str = "C:\\windows\\system32\\wbem\\wbemprox.dll";
const FASTPROX_DLL_PATH: &str = "C:\\windows\\system32\\wbem\\fastprox.dll";

fn ensure_state() -> &'static mut RegistryState {
    // SAFETY: Registry state is process-global and accessed through the
    // existing serialized kernel paths. UnsafeCell here removes `static mut`
    // references but keeps the same runtime discipline.
    unsafe {
        let slot = &mut *REG_STATE.0.get();
        if slot.is_none() {
            let root = RegistryKey::create_root();
            seed_registry_defaults(&root);
            *slot = Some(RegistryState {
                root,
                handles: ObjectStore::new(),
            });
        }
        slot.as_mut().unwrap()
    }
}

fn set_string_value(node: &KeyNode, name: &str, value: &str) {
    node.borrow_mut().set_value(
        name.to_string(),
        RegistryValue::new(
            name.to_string(),
            RegistryValueData::String(value.to_string()),
        ),
    );
}

fn seed_inproc_clsid(root: &KeyNode, clsid_text: &str, display_name: &str, dll_path: &str) {
    let base_path = "Software\\Classes\\CLSID\\";
    let clsid_path = {
        let mut s = String::with_capacity(base_path.len() + clsid_text.len());
        s.push_str(base_path);
        s.push_str(clsid_text);
        s
    };
    let inproc_path = {
        let mut s = String::with_capacity(clsid_path.len() + "\\InprocServer32".len());
        s.push_str(&clsid_path);
        s.push_str("\\InprocServer32");
        s
    };

    let clsid = RegistryKey::create_key_recursive(root, &clsid_path);
    set_string_value(&clsid, "", display_name);

    let inproc = RegistryKey::create_key_recursive(root, &inproc_path);
    set_string_value(&inproc, "", dll_path);
    set_string_value(&inproc, "ThreadingModel", "Both");
}

fn seed_registry_defaults(root: &KeyNode) {
    seed_inproc_clsid(root, WBEM_LOCATOR_CLSID, "WBEM Locator", WBEMPROX_DLL_PATH);
    seed_inproc_clsid(
        root,
        WBEM_REFRESHER_CLSID,
        "WBEM Refresher",
        FASTPROX_DLL_PATH,
    );
}

fn read_value_name(us_ptr: u64) -> String {
    let mut raw = [0u8; MAX_NAME_BYTES];
    let len = UnicodeStringView::from_ptr(us_ptr).map_or(0, |us| us.read_ascii(&mut raw));
    let mut out = String::new();
    for &b in raw.iter().take(len) {
        out.push(b as char);
    }
    out
}

fn alloc_key_handle(state: &mut RegistryState, node: KeyNode) -> Option<u32> {
    state.handles.alloc_with(|_| node)
}

fn key_node_from_handle(state: &RegistryState, handle: u64) -> Option<KeyNode> {
    let pid = crate::process::current_pid();
    let obj = with_process_mut(pid, |p| p.handle_table.get(handle as u32)).flatten()?;
    if obj.kind != KObjectKind::Key {
        return None;
    }
    let idx = obj.obj_idx;
    let ptr = state.handles.get_ptr(idx);
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { (*ptr).clone() })
}

fn join_registry_path(base: &str, rel: &str) -> String {
    if base.is_empty() {
        return rel.to_string();
    }
    if rel.is_empty() {
        return base.to_string();
    }
    let mut s = String::with_capacity(base.len() + 1 + rel.len());
    s.push_str(base);
    s.push('\\');
    s.push_str(rel);
    s
}

fn oa_full_path(oa: ObjectAttributesView, state: &RegistryState) -> Option<String> {
    let root_handle = oa.root_directory();
    let mut rel = [0u8; MAX_PATH];
    let rel_len_raw = oa.read_path(&mut rel);
    let (rel_len, abs) = normalize_registry_path(&mut rel, rel_len_raw);
    let rel_path = bytes_path_to_registry(&rel[..rel_len]);

    if abs {
        return Some(rel_path);
    }

    let Some(root) = key_node_from_handle(state, root_handle) else {
        return Some(rel_path);
    };

    let base = RegistryKey::get_full_path(&root);
    Some(join_registry_path(&base, &rel_path))
}

fn parse_utf16le_string(data: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let ch = u16::from_le_bytes([data[i], data[i + 1]]);
        i += 2;
        if ch == 0 {
            break;
        }
        out.push(core::char::from_u32(ch as u32).unwrap_or('?'));
    }
    out
}

fn parse_utf16le_multisz(data: &[u8]) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = Vec::<u16>::new();
    let mut i = 0usize;

    while i + 1 < data.len() {
        let ch = u16::from_le_bytes([data[i], data[i + 1]]);
        i += 2;

        if ch == 0 {
            if cur.is_empty() {
                break;
            }
            let s: String = cur
                .iter()
                .map(|u| core::char::from_u32(*u as u32).unwrap_or('?'))
                .collect();
            parts.push(s);
            cur.clear();
            continue;
        }

        cur.push(ch);
    }

    parts
}

fn decode_registry_value(name: &str, ty: u32, data: &[u8]) -> RegistryValue {
    let parsed = match ty {
        REG_SZ => RegistryValueData::String(parse_utf16le_string(data)),
        REG_EXPAND_SZ => RegistryValueData::ExpandString(parse_utf16le_string(data)),
        REG_MULTI_SZ => RegistryValueData::MultiString(parse_utf16le_multisz(data)),
        REG_DWORD if data.len() >= 4 => {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&data[..4]);
            RegistryValueData::Dword(u32::from_le_bytes(arr))
        }
        REG_QWORD if data.len() >= 8 => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&data[..8]);
            RegistryValueData::Qword(u64::from_le_bytes(arr))
        }
        _ => RegistryValueData::Binary(data.to_vec(), if ty == 0 { REG_BINARY } else { ty }),
    };
    RegistryValue::new(name.to_string(), parsed)
}

fn encode_utf16_bytes(s: &str, out: &mut [u8]) -> usize {
    let mut w = 0usize;
    for ch in s.encode_utf16() {
        if w + 2 > out.len() {
            break;
        }
        let b = ch.to_le_bytes();
        out[w] = b[0];
        out[w + 1] = b[1];
        w += 2;
    }
    w
}

fn utf16_bytes(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::<u8>::new();
    let units = s.encode_utf16().count();
    if out.try_reserve(units.saturating_mul(2)).is_err() {
        return None;
    }
    for ch in s.encode_utf16() {
        let b = ch.to_le_bytes();
        out.push(b[0]);
        out.push(b[1]);
    }
    Some(out)
}

fn utf16_byte_len(s: &str) -> usize {
    s.encode_utf16().count().saturating_mul(2)
}

fn write_ret_len(ptr: u64, len: usize) {
    let _ = UserOutPtr::from_raw(ptr as *mut u32).write_current_if_present(len as u32);
}

#[inline(always)]
fn validate_key_desired_access(desired_access: u32) -> bool {
    let meta = super::kobject::object_type_meta_for_kind(KObjectKind::Key);
    let allowed =
        meta.valid_access_mask | MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY | KEY_WOW64_FLAGS;
    (desired_access & !allowed) == 0
}

fn gc_key_handles(state: &mut RegistryState) {
    let mut stale = Vec::<u32>::new();
    state.handles.for_each_live_ptr(|id, ptr| {
        let path = RegistryKey::get_full_path(unsafe { &*ptr });
        if path.is_empty() {
            return;
        }
        if RegistryKey::find_key(&state.root, &path).is_none() {
            stale.push(id);
        }
    });
    for id in stale {
        let _ = state.handles.free(id);
    }
}

pub(crate) fn close_key_idx(idx: u32) -> bool {
    let state = ensure_state();
    state.handles.free(idx)
}

pub(crate) fn key_name_utf16(idx: u32) -> Option<Vec<u16>> {
    let state = ensure_state();
    let ptr = state.handles.get_ptr(idx);
    if ptr.is_null() {
        return None;
    }
    let node = unsafe { &*ptr };
    let full_name = RegistryKey::get_full_path(node);
    if full_name.is_empty() {
        return None;
    }
    let mut out = Vec::<u16>::new();
    let units = full_name.encode_utf16().count();
    if out.try_reserve(units).is_err() {
        return None;
    }
    for ch in full_name.encode_utf16() {
        out.push(ch);
    }
    Some(out)
}

pub(crate) fn handle_open_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    let Some(oa) = ObjectAttributesView::from_ptr(frame.x[2]) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if !validate_key_desired_access(desired_access) {
        let path = oa_full_path(oa, state).unwrap_or_else(|| "<invalid>".to_string());
        crate::kdebug!(
            "reg: open key denied access={:#x} path={}",
            desired_access,
            path
        );
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }

    let Some(path) = oa_full_path(oa, state) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };

    let Some(node) = RegistryKey::find_key(&state.root, &path) else {
        crate::ktrace!("reg: open key miss path={}", path);
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    };
    if path.contains(WBEM_LOCATOR_CLSID) {
        crate::ktrace!("reg: open key hit path={}", path);
    }

    let Some(handle_idx) = alloc_key_handle(state, node) else {
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };

    let pid = crate::process::current_pid();
    let Some(h) = with_process_mut(pid, |p| {
        p.handle_table
            .add(KObjectRef::key(handle_idx))
            .map(|v| v as u64)
    })
    .flatten() else {
        let _ = state.handles.free(handle_idx);
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };
    if !out_ptr.write_current(h) {
        let _ = state.handles.free(handle_idx);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    frame.x[0] = status::SUCCESS as u64;
}

// x0=*KeyHandle, x1=DesiredAccess, x2=ObjectAttributes, x3=OpenOptions
pub(crate) fn handle_open_key_ex(frame: &mut SvcFrame) {
    // OpenOptions (x3) is ignored — delegate to standard open logic.
    handle_open_key(frame);
}

pub(crate) fn handle_create_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let out_ptr = UserOutPtr::from_raw(frame.x[0] as *mut u64);
    let desired_access = frame.x[1] as u32;
    let Some(oa) = ObjectAttributesView::from_ptr(frame.x[2]) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    let disp_ptr = UserOutPtr::from_raw(frame.x[6] as *mut u32);
    if out_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    if !validate_key_desired_access(desired_access) {
        let path = oa_full_path(oa, state).unwrap_or_else(|| "<invalid>".to_string());
        crate::kdebug!(
            "reg: create key denied access={:#x} path={}",
            desired_access,
            path
        );
        frame.x[0] = status::ACCESS_DENIED as u64;
        return;
    }

    let Some(path) = oa_full_path(oa, state) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };

    let existing = RegistryKey::find_key(&state.root, &path);
    let (node, disp) = if let Some(node) = existing {
        (node, 2u32)
    } else {
        (RegistryKey::create_key_recursive(&state.root, &path), 1u32)
    };

    let Some(handle_idx) = alloc_key_handle(state, node) else {
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };

    if !disp_ptr.write_current_if_present(disp) {
        let _ = state.handles.free(handle_idx);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    let pid = crate::process::current_pid();
    let Some(h) = with_process_mut(pid, |p| {
        p.handle_table
            .add(KObjectRef::key(handle_idx))
            .map(|v| v as u64)
    })
    .flatten() else {
        let _ = state.handles.free(handle_idx);
        frame.x[0] = status::NO_MEMORY as u64;
        return;
    };
    if !out_ptr.write_current(h) {
        let _ = state.handles.free(handle_idx);
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_delete_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let path = RegistryKey::get_full_path(&node);
    if path.is_empty() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let (parent_path, name) = match path.rsplit_once('\\') {
        Some((p, n)) => (p, n),
        None => ("", path.as_str()),
    };

    let parent = if parent_path.is_empty() {
        Some(state.root.clone())
    } else {
        RegistryKey::find_key(&state.root, parent_path)
    };

    let Some(parent) = parent else {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    };

    if !RegistryKey::delete_subkey(&parent, name, true) {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    }

    gc_key_handles(state);
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_set_value_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];
    let value_name_us = frame.x[1];
    let value_type = frame.x[3] as u32;
    let data_ptr = frame.x[4] as *const u8;
    let data_len = frame.x[5] as usize;

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    if data_len != 0 && data_ptr.is_null() {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let value_name = read_value_name(value_name_us);
    let raw_data = if data_len == 0 {
        Vec::new()
    } else {
        let Some(bytes) = read_current_user_bytes(data_ptr, data_len) else {
            frame.x[0] = status::INVALID_PARAMETER as u64;
            return;
        };
        bytes
    };

    let value = decode_registry_value(&value_name, value_type, &raw_data);
    node.borrow_mut().set_value(value_name, value);
    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_query_value_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];
    let value_name_us = frame.x[1];
    let info_class = frame.x[2] as u32;
    let out_ptr = frame.x[3] as *mut u8;
    let out_len = frame.x[4] as usize;
    let ret_len_ptr = frame.x[5];

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let value_name = read_value_name(value_name_us);
    let full_path = RegistryKey::get_full_path(&node);
    if full_path.contains(WBEM_LOCATOR_CLSID) {
        crate::ktrace!("reg: query value path={} value={}", full_path, value_name);
    }
    let guard = node.borrow();
    let Some(value) = guard.get_value(&value_name).cloned() else {
        if full_path.contains(WBEM_LOCATOR_CLSID) {
            crate::ktrace!(
                "reg: query value miss path={} value={}",
                full_path,
                value_name
            );
        }
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
        return;
    };

    let mut value_name_w = [0u8; MAX_VALUE_NAME_UTF16 * 2];
    let value_name_wlen = encode_utf16_bytes(&value.name, &mut value_name_w);
    let value_data = value.raw_bytes();
    let value_ty = value.reg_type();
    let value_data_len = value_data.len();

    match info_class {
        0 => {
            let need = 12 + value_name_wlen;
            write_ret_len(ret_len_ptr, need);
            if out_ptr.is_null() || out_len < need {
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            }
            let Some(mut w) = GuestWriter::new(out_ptr, out_len, need) else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.u32(0)
                .u32(value_ty)
                .u32(value_name_wlen as u32)
                .bytes(&value_name_w[..value_name_wlen]);
            frame.x[0] = status::SUCCESS as u64;
        }
        1 => {
            let need = 20 + value_name_wlen + value_data_len;
            write_ret_len(ret_len_ptr, need);
            if out_ptr.is_null() || out_len < need {
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            }
            let Some(mut w) = GuestWriter::new(out_ptr, out_len, need) else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.u32(0)
                .u32(value_ty)
                .u32((20 + value_name_wlen) as u32)
                .u32(value_data_len as u32)
                .u32(value_name_wlen as u32)
                .bytes(&value_name_w[..value_name_wlen])
                .bytes(&value_data);
            frame.x[0] = status::SUCCESS as u64;
        }
        2 => {
            let need = 12 + value_data_len;
            write_ret_len(ret_len_ptr, need);
            if out_ptr.is_null() || out_len < need {
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            }
            let Some(mut w) = GuestWriter::new(out_ptr, out_len, need) else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.u32(0)
                .u32(value_ty)
                .u32(value_data_len as u32)
                .bytes(&value_data);
            frame.x[0] = status::SUCCESS as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

pub(crate) fn handle_query_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];
    let info_class = frame.x[1] as u32;
    let out_ptr = frame.x[2] as *mut u8;
    let out_len = frame.x[3] as usize;
    let ret_len_ptr = frame.x[4];

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    match info_class {
        KEY_INFORMATION_BASIC => {
            let name = node.borrow().name.clone();
            let Some(name_w) = utf16_bytes(&name) else {
                frame.x[0] = status::NO_MEMORY as u64;
                return;
            };
            let need = KEY_BASIC_INFORMATION_SIZE + name_w.len();
            write_ret_len(ret_len_ptr, need);
            if out_ptr.is_null() || out_len < need {
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            }

            let Some(mut w) = GuestWriter::new(out_ptr, out_len, need) else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.u64(0).u32(0).u32(name_w.len() as u32).bytes(&name_w);
            frame.x[0] = status::SUCCESS as u64;
        }
        KEY_INFORMATION_NAME => {
            let full_name = RegistryKey::get_full_path(&node);
            let Some(name_w) = utf16_bytes(&full_name) else {
                frame.x[0] = status::NO_MEMORY as u64;
                return;
            };
            let need = KEY_NAME_INFORMATION_SIZE + name_w.len();
            write_ret_len(ret_len_ptr, need);
            if out_ptr.is_null() || out_len < need {
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            }

            let Some(mut w) = GuestWriter::new(out_ptr, out_len, need) else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.u32(name_w.len() as u32).bytes(&name_w);
            frame.x[0] = status::SUCCESS as u64;
        }
        KEY_INFORMATION_FULL => {
            let (subkeys, max_name_len, values, max_value_name_len, max_value_data_len) = {
                let guard = node.borrow();
                let subkeys = guard.subkeys().len() as u32;
                let values = guard.values().len() as u32;

                let mut max_name_len = 0usize;
                for name in guard.subkeys().keys() {
                    max_name_len = core::cmp::max(max_name_len, utf16_byte_len(name));
                }

                let mut max_value_name_len = 0usize;
                let mut max_value_data_len = 0usize;
                for value in guard.values().values() {
                    max_value_name_len =
                        core::cmp::max(max_value_name_len, utf16_byte_len(&value.name));
                    max_value_data_len =
                        core::cmp::max(max_value_data_len, value.raw_bytes().len());
                }

                (
                    subkeys,
                    max_name_len as u32,
                    values,
                    max_value_name_len as u32,
                    max_value_data_len as u32,
                )
            };

            write_ret_len(ret_len_ptr, KEY_FULL_INFORMATION_SIZE);
            if out_ptr.is_null() || out_len < KEY_FULL_INFORMATION_SIZE {
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            }

            let Some(mut w) = GuestWriter::new(out_ptr, out_len, KEY_FULL_INFORMATION_SIZE) else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.u64(0)
                .u32(0)
                .u32(KEY_FULL_INFORMATION_SIZE as u32)
                .u32(0)
                .u32(subkeys)
                .u32(max_name_len)
                .u32(0)
                .u32(values)
                .u32(max_value_name_len)
                .u32(max_value_data_len);
            frame.x[0] = status::SUCCESS as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

pub(crate) fn handle_enumerate_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];
    let index = frame.x[1] as usize;
    let info_class = frame.x[2] as u32;
    let out_ptr = frame.x[3] as *mut u8;
    let out_len = frame.x[4] as usize;
    let ret_len_ptr = frame.x[5];

    if info_class != 0 {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    }

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let child = {
        let guard = node.borrow();
        guard.subkeys().values().nth(index).cloned()
    };
    let Some(child) = child else {
        frame.x[0] = status::NO_MORE_ENTRIES as u64;
        return;
    };

    let child_name = child.borrow().name.clone();
    let mut child_name_w = [0u8; MAX_VALUE_NAME_UTF16 * 2];
    let child_name_wlen = encode_utf16_bytes(&child_name, &mut child_name_w);

    let need = 16 + child_name_wlen;
    write_ret_len(ret_len_ptr, need);
    if out_ptr.is_null() || out_len < need {
        frame.x[0] = status::BUFFER_TOO_SMALL as u64;
        return;
    }

    let Some(mut w) = GuestWriter::new(out_ptr, out_len, need) else {
        frame.x[0] = status::INVALID_PARAMETER as u64;
        return;
    };
    w.u64(0)
        .u32(0)
        .u32(child_name_wlen as u32)
        .bytes(&child_name_w[..child_name_wlen]);

    frame.x[0] = status::SUCCESS as u64;
}

pub(crate) fn handle_enumerate_value_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];
    let index = frame.x[1] as usize;
    let info_class = frame.x[2] as u32;
    let out_ptr = frame.x[3] as *mut u8;
    let out_len = frame.x[4] as usize;
    let ret_len_ptr = frame.x[5];

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let value = {
        let guard = node.borrow();
        guard.values().values().nth(index).cloned()
    };
    let Some(value) = value else {
        frame.x[0] = status::NO_MORE_ENTRIES as u64;
        return;
    };

    let mut value_name_w = [0u8; MAX_VALUE_NAME_UTF16 * 2];
    let value_name_wlen = encode_utf16_bytes(&value.name, &mut value_name_w);
    let value_data = value.raw_bytes();
    let value_ty = value.reg_type();
    let value_data_len = value_data.len();

    match info_class {
        0 => {
            let need = 12 + value_name_wlen;
            write_ret_len(ret_len_ptr, need);
            if out_ptr.is_null() || out_len < need {
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            }
            let Some(mut w) = GuestWriter::new(out_ptr, out_len, need) else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.u32(0)
                .u32(value_ty)
                .u32(value_name_wlen as u32)
                .bytes(&value_name_w[..value_name_wlen]);
            frame.x[0] = status::SUCCESS as u64;
        }
        1 => {
            let need = 20 + value_name_wlen + value_data_len;
            write_ret_len(ret_len_ptr, need);
            if out_ptr.is_null() || out_len < need {
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            }
            let Some(mut w) = GuestWriter::new(out_ptr, out_len, need) else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.u32(0)
                .u32(value_ty)
                .u32((20 + value_name_wlen) as u32)
                .u32(value_data_len as u32)
                .u32(value_name_wlen as u32)
                .bytes(&value_name_w[..value_name_wlen])
                .bytes(&value_data);
            frame.x[0] = status::SUCCESS as u64;
        }
        2 => {
            let need = 12 + value_data_len;
            write_ret_len(ret_len_ptr, need);
            if out_ptr.is_null() || out_len < need {
                frame.x[0] = status::BUFFER_TOO_SMALL as u64;
                return;
            }
            let Some(mut w) = GuestWriter::new(out_ptr, out_len, need) else {
                frame.x[0] = status::INVALID_PARAMETER as u64;
                return;
            };
            w.u32(0)
                .u32(value_ty)
                .u32(value_data_len as u32)
                .bytes(&value_data);
            frame.x[0] = status::SUCCESS as u64;
        }
        _ => {
            frame.x[0] = status::INVALID_PARAMETER as u64;
        }
    }
}

pub(crate) fn handle_delete_value_key(frame: &mut SvcFrame) {
    let state = ensure_state();
    let handle = frame.x[0];
    let value_name_us = frame.x[1];

    let Some(node) = key_node_from_handle(state, handle) else {
        frame.x[0] = status::INVALID_HANDLE as u64;
        return;
    };

    let value_name = read_value_name(value_name_us);
    if node.borrow_mut().delete_value(&value_name) {
        frame.x[0] = status::SUCCESS as u64;
    } else {
        frame.x[0] = status::OBJECT_NAME_NOT_FOUND as u64;
    }
}
