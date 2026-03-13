// handlers.rs — Concrete hostcall implementations
//
// All execute_* functions live here. broker.rs keeps only the scheduling
// framework (queues, workers, stats, routing).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use winemu_core::addr::Gpa;
use winemu_shared::hostcall as hc;
use winemu_shared::status;

use crate::host_file::HostFileTable;
use crate::hostcall::modules::win32k::state::{
    ClassLookupKey, GuestClientMenuName, GuestMsg, GuestWndClassEx,
};
use crate::hostcall::modules::win32k::Win32kState;
use crate::memory::GuestMemory;
use crate::vaspace::VaSpace;

pub(super) const MAX_HOST_PATH: usize = 1024;
pub(super) const MAX_IO_SIZE: usize = 64 * 1024 * 1024;
pub(super) const MAX_DIR_BUF: usize = 4096;
pub(super) const NOTIFY_OPT_WATCH_TREE: u64 = 1u64 << 63;
pub(super) const NOTIFY_OPT_FILTER_MASK: u64 = 0xFFFF_FFFF;
const GUEST_UNICODE_STRING_SIZE: usize = 16;
const GUEST_WNDCLASSEXW_SIZE: usize = 80;
const GUEST_CLIENT_MENU_NAME_SIZE: usize = 24;
const GUEST_GUITHREADINFO_SIZE: usize = 72;
const GUEST_WIN_PROC_PARAMS_SIZE: usize = 72;
static WIN32K_CLASS_TRACE_BUDGET: AtomicU32 = AtomicU32::new(64);

const NT_USER_MESSAGE_CALL_WINDOW_PROC: u64 = 0x02ab;
const NT_USER_MESSAGE_GET_DISPATCH_PARAMS: u64 = 0x3001;
const NT_USER_MESSAGE_SPY_GET_MSG_NAME: u64 = 0x3002;
const NT_USER_MESSAGE_SPY_ENTER: u64 = 0x0303;
const NT_USER_MESSAGE_SPY_EXIT: u64 = 0x0304;

const WMCHAR_MAP_CALLWINDOWPROC: u32 = 5;

const NT_USER_CALL_TWO_PARAM_GET_DIALOG_PROC: u64 = 0;
const NT_USER_CALL_TWO_PARAM_ALLOC_WIN_PROC: u64 = 12;

#[derive(Clone, Copy, Debug, Default)]
struct GuestUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: u64,
}

fn trace_win32k_class(msg: impl FnOnce()) {
    if WIN32K_CLASS_TRACE_BUDGET.load(Ordering::Relaxed) == 0 {
        return;
    }
    WIN32K_CLASS_TRACE_BUDGET.fetch_sub(1, Ordering::Relaxed);
    msg();
}

// ── Shared context passed to every handler ────────────────────────────────────
pub(super) struct HandlerCtx<'a> {
    pub memory: &'a Arc<RwLock<GuestMemory>>,
    pub host_files: &'a Arc<HostFileTable>,
    pub vaspace: &'a Arc<Mutex<VaSpace>>,
    pub win32k: &'a Mutex<Win32kState>,
}

// ── Path helpers ──────────────────────────────────────────────────────────────
pub(super) fn decode_guest_path(
    memory: &Arc<RwLock<GuestMemory>>,
    path_gpa: u64,
    path_len: usize,
) -> Result<String, (u64, u64)> {
    if path_len == 0 || path_len > MAX_HOST_PATH {
        return Err((hc::HC_INVALID, 0));
    }
    let mem = memory.read().unwrap();
    let bytes = mem.read_bytes(Gpa(path_gpa), path_len);
    let path = std::str::from_utf8(bytes).map_err(|_| (hc::HC_INVALID, 0))?;
    Ok(path.to_owned())
}

pub(super) fn execute_mkdir(
    ctx: &HandlerCtx<'_>,
    _args: [u64; 4],
    path: Option<&str>,
) -> (u64, u64) {
    let Some(path) = path else {
        return (hc::HC_INVALID, 0);
    };
    log::debug!("hostcall mkdir path={}", path);
    match ctx.host_files.create_dir(path) {
        Ok(()) => (hc::HC_OK, 0),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            log::debug!("hostcall mkdir already exists path={}", path);
            (hc::HC_IO_ERROR, 1)
        }
        Err(err) => {
            log::debug!("hostcall mkdir failed path={} err={}", path, err);
            (hc::HC_IO_ERROR, 0)
        }
    }
}

// ── Packet helpers ────────────────────────────────────────────────────────────
pub(super) fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let src = bytes.get(off..end)?;
    Some(u32::from_le_bytes([src[0], src[1], src[2], src[3]]))
}

pub(super) fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let src = bytes.get(off..end)?;
    Some(u16::from_le_bytes([src[0], src[1]]))
}

pub(super) fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let src = bytes.get(off..end)?;
    Some(u64::from_le_bytes([
        src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
    ]))
}

fn read_i32_le(bytes: &[u8], off: usize) -> Option<i32> {
    let end = off.checked_add(4)?;
    let src = bytes.get(off..end)?;
    Some(i32::from_le_bytes([src[0], src[1], src[2], src[3]]))
}

fn read_guest_bytes(memory: &Arc<RwLock<GuestMemory>>, gpa: u64, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    if gpa == 0 {
        return None;
    }
    let mem = memory.read().unwrap();
    let bytes = mem.read_bytes(Gpa(gpa), len);
    if bytes.len() != len {
        return None;
    }
    Some(bytes.to_vec())
}

fn write_guest_bytes(memory: &Arc<RwLock<GuestMemory>>, gpa: u64, bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    if gpa == 0 {
        return false;
    }
    let mut mem = memory.write().unwrap();
    mem.write_bytes(Gpa(gpa), bytes);
    true
}

fn read_guest_unicode_string(
    memory: &Arc<RwLock<GuestMemory>>,
    gpa: u64,
) -> Option<GuestUnicodeString> {
    let bytes = read_guest_bytes(memory, gpa, GUEST_UNICODE_STRING_SIZE)?;
    Some(GuestUnicodeString {
        length: read_u16_le(&bytes, 0)?,
        maximum_length: read_u16_le(&bytes, 2)?,
        buffer: read_u64_le(&bytes, 8)?,
    })
}

fn read_guest_utf16(
    memory: &Arc<RwLock<GuestMemory>>,
    gpa: u64,
    byte_len: usize,
) -> Option<String> {
    let bytes = read_guest_bytes(memory, gpa, byte_len)?;
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    Some(String::from_utf16_lossy(&units))
}

fn parse_hash_atom(name: &str) -> Option<u16> {
    let digits = name.strip_prefix('#')?;
    digits.parse::<u16>().ok()
}

fn decode_class_lookup_key(
    memory: &Arc<RwLock<GuestMemory>>,
    name_gpa: u64,
) -> Option<(ClassLookupKey, GuestUnicodeString)> {
    let name = read_guest_unicode_string(memory, name_gpa)?;
    if name.length > name.maximum_length || (name.length & 1) != 0 {
        return None;
    }
    if name.buffer == 0 {
        return None;
    }
    if name.buffer <= 0xffff {
        return Some((ClassLookupKey::Atom(name.buffer as u16), name));
    }
    let text = read_guest_utf16(memory, name.buffer, usize::from(name.length))?;
    let key = match parse_hash_atom(&text) {
        Some(atom) => ClassLookupKey::Atom(atom),
        None => ClassLookupKey::from_name(&text),
    };
    Some((key, name))
}

fn read_guest_wndclass(
    memory: &Arc<RwLock<GuestMemory>>,
    gpa: u64,
) -> Option<(u32, GuestWndClassEx)> {
    let bytes = read_guest_bytes(memory, gpa, GUEST_WNDCLASSEXW_SIZE)?;
    Some((
        read_u32_le(&bytes, 0)?,
        GuestWndClassEx {
            style: read_u32_le(&bytes, 4)?,
            lpfn_wnd_proc: read_u64_le(&bytes, 8)?,
            cb_cls_extra: read_i32_le(&bytes, 16)?,
            cb_wnd_extra: read_i32_le(&bytes, 20)?,
            h_instance: read_u64_le(&bytes, 24)?,
            h_icon: read_u64_le(&bytes, 32)?,
            h_cursor: read_u64_le(&bytes, 40)?,
            hbr_background: read_u64_le(&bytes, 48)?,
            lpsz_menu_name: read_u64_le(&bytes, 56)?,
            lpsz_class_name: read_u64_le(&bytes, 64)?,
            h_icon_sm: read_u64_le(&bytes, 72)?,
        },
    ))
}

fn encode_guest_wndclass(info: GuestWndClassEx) -> [u8; GUEST_WNDCLASSEXW_SIZE] {
    let mut buf = [0u8; GUEST_WNDCLASSEXW_SIZE];
    buf[0..4].copy_from_slice(&(GUEST_WNDCLASSEXW_SIZE as u32).to_le_bytes());
    buf[4..8].copy_from_slice(&info.style.to_le_bytes());
    buf[8..16].copy_from_slice(&info.lpfn_wnd_proc.to_le_bytes());
    buf[16..20].copy_from_slice(&info.cb_cls_extra.to_le_bytes());
    buf[20..24].copy_from_slice(&info.cb_wnd_extra.to_le_bytes());
    buf[24..32].copy_from_slice(&info.h_instance.to_le_bytes());
    buf[32..40].copy_from_slice(&info.h_icon.to_le_bytes());
    buf[40..48].copy_from_slice(&info.h_cursor.to_le_bytes());
    buf[48..56].copy_from_slice(&info.hbr_background.to_le_bytes());
    buf[56..64].copy_from_slice(&info.lpsz_menu_name.to_le_bytes());
    buf[64..72].copy_from_slice(&info.lpsz_class_name.to_le_bytes());
    buf[72..80].copy_from_slice(&info.h_icon_sm.to_le_bytes());
    buf
}

fn read_guest_client_menu_name(
    memory: &Arc<RwLock<GuestMemory>>,
    gpa: u64,
) -> Option<GuestClientMenuName> {
    let bytes = read_guest_bytes(memory, gpa, GUEST_CLIENT_MENU_NAME_SIZE)?;
    Some(GuestClientMenuName {
        name_a: read_u64_le(&bytes, 0)?,
        name_w: read_u64_le(&bytes, 8)?,
        name_us: read_u64_le(&bytes, 16)?,
    })
}

fn encode_guest_client_menu_name(
    menu_name: GuestClientMenuName,
) -> [u8; GUEST_CLIENT_MENU_NAME_SIZE] {
    let mut buf = [0u8; GUEST_CLIENT_MENU_NAME_SIZE];
    buf[0..8].copy_from_slice(&menu_name.name_a.to_le_bytes());
    buf[8..16].copy_from_slice(&menu_name.name_w.to_le_bytes());
    buf[16..24].copy_from_slice(&menu_name.name_us.to_le_bytes());
    buf
}

fn encode_guest_win_proc_params(
    func: u64,
    hwnd: u64,
    msg: u32,
    wparam: u64,
    lparam: u64,
    ansi: bool,
    ansi_dst: bool,
    mapping: u32,
    dpi_context: u32,
    proc_a: u64,
    proc_w: u64,
) -> [u8; GUEST_WIN_PROC_PARAMS_SIZE] {
    let mut buf = [0u8; GUEST_WIN_PROC_PARAMS_SIZE];
    buf[0..8].copy_from_slice(&func.to_le_bytes());
    buf[8..16].copy_from_slice(&hwnd.to_le_bytes());
    buf[16..20].copy_from_slice(&msg.to_le_bytes());
    buf[24..32].copy_from_slice(&wparam.to_le_bytes());
    buf[32..40].copy_from_slice(&lparam.to_le_bytes());
    buf[40..44].copy_from_slice(&(u32::from(ansi)).to_le_bytes());
    buf[44..48].copy_from_slice(&(u32::from(ansi_dst)).to_le_bytes());
    buf[48..52].copy_from_slice(&mapping.to_le_bytes());
    buf[52..56].copy_from_slice(&dpi_context.to_le_bytes());
    buf[56..64].copy_from_slice(&proc_a.to_le_bytes());
    buf[64..72].copy_from_slice(&proc_w.to_le_bytes());
    buf
}

fn handle_nt_user_message_call(
    ctx: &HandlerCtx<'_>,
    w32: &mut Win32kState,
    call_args: [u64; hc::WIN32K_CALL_MAX_ARGS],
) -> u64 {
    let hwnd = call_args[0];
    let msg = call_args[1] as u32;
    let wparam = call_args[2];
    let lparam = call_args[3];
    let result_info_gpa = call_args[4];
    let call_type = call_args[5];
    let ansi = call_args[6] != 0;

    match call_type {
        NT_USER_MESSAGE_CALL_WINDOW_PROC => {
            if result_info_gpa == 0 {
                return 0;
            }
            let func = match read_guest_bytes(ctx.memory, result_info_gpa, 8)
                .and_then(|bytes| read_u64_le(&bytes, 0))
            {
                Some(func) if func != 0 => func,
                _ => return 0,
            };
            let dpi_context = if hwnd == 0 {
                0
            } else {
                w32.get_window_dpi_awareness_context(hwnd as u32) as u32
            };
            let params = encode_guest_win_proc_params(
                func,
                hwnd,
                msg,
                wparam,
                lparam,
                ansi,
                ansi,
                WMCHAR_MAP_CALLWINDOWPROC,
                dpi_context,
                func,
                func,
            );
            if write_guest_bytes(ctx.memory, result_info_gpa, &params) {
                1
            } else {
                0
            }
        }
        NT_USER_MESSAGE_GET_DISPATCH_PARAMS => 0,
        NT_USER_MESSAGE_SPY_GET_MSG_NAME => {
            if result_info_gpa != 0 && wparam != 0 {
                let mut name = format!("msg_{msg:04x}").into_bytes();
                name.push(0);
                let max_len = (wparam as usize).min(name.len());
                let _ = write_guest_bytes(ctx.memory, result_info_gpa, &name[..max_len]);
            }
            0
        }
        NT_USER_MESSAGE_SPY_ENTER | NT_USER_MESSAGE_SPY_EXIT => 0,
        _ => 0,
    }
}

fn handle_nt_user_register_class_ex_wow(
    ctx: &HandlerCtx<'_>,
    w32: &mut Win32kState,
    owner_pid: u32,
    call_args: [u64; hc::WIN32K_CALL_MAX_ARGS],
) -> u64 {
    let wc_gpa = call_args[0];
    let name_gpa = call_args[1];
    let client_menu_name_gpa = call_args[3];
    let flags = call_args[5] as u32;
    let wow_gpa = call_args[6];

    let (key, _) = match decode_class_lookup_key(ctx.memory, name_gpa) {
        Some(v) => v,
        None => {
            trace_win32k_class(|| {
                log::debug!(
                    "win32k: register_class decode_name failed wc={:#x} name={:#x} wc_head={:x?} name_head={:x?}",
                    wc_gpa,
                    name_gpa,
                    read_guest_bytes(ctx.memory, wc_gpa, 16),
                    read_guest_bytes(ctx.memory, name_gpa, 16),
                );
            });
            return 0;
        }
    };
    let (cb_size, info) = match read_guest_wndclass(ctx.memory, wc_gpa) {
        Some(v) => v,
        None => {
            trace_win32k_class(|| {
                log::debug!(
                    "win32k: register_class read_wndclass failed wc={:#x} head={:x?}",
                    wc_gpa,
                    read_guest_bytes(ctx.memory, wc_gpa, 32),
                );
            });
            return 0;
        }
    };
    if cb_size != GUEST_WNDCLASSEXW_SIZE as u32 || info.cb_cls_extra < 0 || info.cb_wnd_extra < 0 {
        trace_win32k_class(|| {
            log::debug!(
                "win32k: register_class invalid_wndclass wc={:#x} cb_size={:#x} cls_extra={} wnd_extra={}",
                wc_gpa,
                cb_size,
                info.cb_cls_extra,
                info.cb_wnd_extra,
            );
        });
        return 0;
    }

    let menu_name = if client_menu_name_gpa != 0 {
        match read_guest_client_menu_name(ctx.memory, client_menu_name_gpa) {
            Some(menu) => Some(menu),
            None => {
                trace_win32k_class(|| {
                    log::debug!(
                        "win32k: register_class read_menu failed menu={:#x} head={:x?}",
                        client_menu_name_gpa,
                        read_guest_bytes(ctx.memory, client_menu_name_gpa, 24),
                    );
                });
                return 0;
            }
        }
    } else {
        None
    };
    let log_key = key.clone();

    if wow_gpa != 0 {
        let wow = 0u32.to_le_bytes();
        if !write_guest_bytes(ctx.memory, wow_gpa, &wow) {
            return 0;
        }
    }

    let atom = w32.register_class(owner_pid, key, info, menu_name, (flags & 1) != 0);
    log::trace!(
        "win32k: register_class pid={} atom={:#x} hinst={:#x} key={:?} menuW={:#x} menuA={:#x}",
        owner_pid,
        atom,
        info.h_instance,
        log_key,
        menu_name.unwrap_or_default().name_w,
        menu_name.unwrap_or_default().name_a,
    );
    u64::from(atom)
}

fn handle_nt_user_get_class_info_ex(
    ctx: &HandlerCtx<'_>,
    w32: &mut Win32kState,
    owner_pid: u32,
    call_args: [u64; hc::WIN32K_CALL_MAX_ARGS],
) -> u64 {
    let instance = call_args[0];
    let name_gpa = call_args[1];
    let wc_gpa = call_args[2];
    let menu_name_gpa = call_args[3];
    let ansi = call_args[4] != 0;

    let (key, name) = match decode_class_lookup_key(ctx.memory, name_gpa) {
        Some(v) => v,
        None => {
            trace_win32k_class(|| {
                log::debug!(
                    "win32k: get_class_info decode_name failed name={:#x} head={:x?}",
                    name_gpa,
                    read_guest_bytes(ctx.memory, name_gpa, 16),
                );
            });
            return 0;
        }
    };
    let Some((atom, mut info, menu_name)) = w32.get_class_info(owner_pid, instance, &key) else {
        trace_win32k_class(|| {
            log::trace!(
                "win32k: get_class_info miss pid={} hinst={:#x} key={:?}",
                owner_pid,
                instance,
                key,
            );
        });
        return 0;
    };

    info.lpsz_class_name = name.buffer;
    info.lpsz_menu_name = if ansi {
        menu_name.name_a
    } else {
        menu_name.name_w
    };

    if wc_gpa != 0 {
        let wc = encode_guest_wndclass(info);
        if !write_guest_bytes(ctx.memory, wc_gpa, &wc) {
            return 0;
        }
    }
    if menu_name_gpa != 0 {
        let menu = encode_guest_client_menu_name(menu_name);
        if !write_guest_bytes(ctx.memory, menu_name_gpa, &menu) {
            return 0;
        }
    }

    log::trace!(
        "win32k: get_class_info pid={} atom={:#x} hinst={:#x} menu={:#x}",
        owner_pid,
        atom,
        instance,
        info.lpsz_menu_name,
    );
    u64::from(atom)
}

fn win32k_call_name(table: u32, syscall_nr: u16) -> &'static str {
    use winemu_shared::win32k_sysno as w;

    match (table, syscall_nr) {
        (1, w::NT_GDI_CREATE_BITMAP) => "NtGdiCreateBitmap",
        (1, w::NT_GDI_CREATE_COMPATIBLE_BITMAP) => "NtGdiCreateCompatibleBitmap",
        (1, w::NT_GDI_CREATE_COMPATIBLE_DC) => "NtGdiCreateCompatibleDC",
        (1, w::NT_GDI_CREATE_PEN) => "NtGdiCreatePen",
        (1, w::NT_GDI_CREATE_SOLID_BRUSH) => "NtGdiCreateSolidBrush",
        (1, w::NT_GDI_CREATE_DIBITMAP_INTERNAL) => "NtGdiCreateDIBitmapInternal",
        (1, w::NT_GDI_CREATE_PATTERN_BRUSH_INTERNAL) => "NtGdiCreatePatternBrushInternal",
        (1, w::NT_GDI_DELETE_OBJECT_APP) => "NtGdiDeleteObjectApp",
        (1, w::NT_GDI_EXT_GET_OBJECT_W) => "NtGdiExtGetObjectW",
        (1, w::NT_GDI_GET_DEVICE_CAPS) => "NtGdiGetDeviceCaps",
        (1, w::NT_GDI_GET_TEXT_CHARSET_INFO) => "NtGdiGetTextCharsetInfo",
        (1, w::NT_GDI_GET_TEXT_METRICS_W) => "NtGdiGetTextMetricsW",
        (1, w::NT_GDI_HFONT_CREATE) => "NtGdiHfontCreate",
        (1, w::NT_GDI_ENUM_FONTS) => "NtGdiEnumFonts",
        (1, w::NT_GDI_OPEN_DCW) => "NtGdiOpenDCW",
        (1, w::NT_GDI_SELECT_BITMAP) => "NtGdiSelectBitmap",
        (1, w::NT_GDI_SELECT_BRUSH) => "NtGdiSelectBrush",
        (1, w::NT_GDI_SELECT_FONT) => "NtGdiSelectFont",
        (1, w::NT_GDI_SELECT_PEN) => "NtGdiSelectPen",
        (1, w::NT_USER_CALL_ONE_PARAM) => "NtUserCallOneParam",
        (1, w::NT_USER_CALL_NO_PARAM) => "NtUserCallNoParam",
        (1, w::NT_USER_CALL_TWO_PARAM) => "NtUserCallTwoParam",
        (1, w::NT_USER_CALL_HWND) => "NtUserCallHwnd",
        (1, w::NT_USER_CALL_HWND_PARAM) => "NtUserCallHwndParam",
        (1, w::NT_USER_CREATE_WINDOW_EX) => "NtUserCreateWindowEx",
        (1, w::NT_USER_ENUM_DISPLAY_MONITORS) => "NtUserEnumDisplayMonitors",
        (1, w::NT_USER_GET_CLASS_INFO_EX) => "NtUserGetClassInfoEx",
        (1, w::NT_USER_GET_GUITHREAD_INFO) => "NtUserGetGUIThreadInfo",
        (1, w::NT_USER_GET_MESSAGE) => "NtUserGetMessage",
        (1, w::NT_USER_PEEK_MESSAGE) => "NtUserPeekMessage",
        (1, w::NT_USER_REGISTER_CLASS_EX_WOW) => "NtUserRegisterClassExWOW",
        (1, w::NT_USER_SET_WINDOW_POS) => "NtUserSetWindowPos",
        (1, w::NT_USER_SYSTEM_PARAMETERS_INFO) => "NtUserSystemParametersInfo",
        (1, w::NT_USER_DESTROY_WINDOW) => "NtUserDestroyWindow",
        (1, w::NT_USER_SHOW_WINDOW) => "NtUserShowWindow",
        (1, w::NT_USER_SHOW_WINDOW_ASYNC) => "NtUserShowWindowAsync",
        (1, w::NT_USER_GET_DC) => "NtUserGetDC",
        (1, w::NT_USER_GET_PROCESS_DPI_AWARENESS_CONTEXT) => "NtUserGetProcessDpiAwarenessContext",
        (1, w::NT_USER_GET_SYSTEM_DPI_FOR_PROCESS) => "NtUserGetSystemDpiForProcess",
        (1, w::NT_USER_GET_WINDOW_DC) => "NtUserGetWindowDC",
        (1, w::NT_USER_RELEASE_DC) => "NtUserReleaseDC",
        (1, w::NT_USER_SET_PROCESS_DPI_AWARENESS_CONTEXT) => "NtUserSetProcessDpiAwarenessContext",
        (1, w::NT_USER_SET_WINDOWS_HOOK_EX) => "NtUserSetWindowsHookEx",
        (1, w::NT_USER_BEGIN_PAINT) => "NtUserBeginPaint",
        (1, w::NT_USER_END_PAINT) => "NtUserEndPaint",
        (1, w::NT_USER_UNHOOK_WINDOWS_HOOK_EX) => "NtUserUnhookWindowsHookEx",
        _ => "unknown",
    }
}

fn nt_user_call_one_param_name(code: u64) -> &'static str {
    match code {
        4 => "GetClipCursor",
        5 => "GetCursorPos",
        7 => "GetMenuItemCount",
        8 => "GetPrimaryMonitorRect",
        9 => "GetSysColor",
        10 => "GetSysColorBrush",
        11 => "GetSysColorPen",
        12 => "GetSystemMetrics",
        13 => "GetVirtualScreenRect",
        14 => "RealizePalette",
        15 => "ReplyMessage",
        16 => "SetCaretBlinkTime",
        17 => "SetProcessDefaultLayout",
        18 => "SetKeyboardAutoRepeat",
        19 => "SetThreadDpiAwarenessContext",
        21 => "GetAsyncKeyboardState",
        _ => "unknown",
    }
}

// ── File I/O ──────────────────────────────────────────────────────────────────
pub(super) fn execute_open(
    ctx: &HandlerCtx<'_>,
    args: [u64; 4],
    path_payload: Option<&str>,
) -> (u64, u64) {
    let flags = args[2];
    let fd = match path_payload {
        Some(path) => ctx.host_files.open(path, flags),
        None => match decode_guest_path(ctx.memory, args[0], args[1] as usize) {
            Ok(path) => ctx.host_files.open(&path, flags),
            Err(e) => return e,
        },
    };
    if fd == u64::MAX {
        (hc::HC_IO_ERROR, 0)
    } else {
        (hc::HC_OK, fd)
    }
}

pub(super) fn execute_read(ctx: &HandlerCtx<'_>, args: [u64; 4]) -> (u64, u64) {
    let fd = args[0];
    let dst_gpa = args[1];
    let len = args[2] as usize;
    let offset = args[3];
    if len == 0 {
        return (hc::HC_OK, 0);
    }
    if len > MAX_IO_SIZE {
        return (hc::HC_INVALID, 0);
    }
    let mut buf = vec![0u8; len];
    let got = ctx.host_files.read(fd, &mut buf, offset);
    if got > 0 {
        let mut mem = ctx.memory.write().unwrap();
        mem.write_bytes(Gpa(dst_gpa), &buf[..got]);
    }
    (hc::HC_OK, got as u64)
}

pub(super) fn execute_write(
    ctx: &HandlerCtx<'_>,
    args: [u64; 4],
    bytes_payload: Option<&[u8]>,
) -> (u64, u64) {
    let fd = args[0];
    let src_gpa = args[1];
    let len = args[2] as usize;
    let offset = args[3];
    if len == 0 {
        return (hc::HC_OK, 0);
    }
    if len > MAX_IO_SIZE {
        return (hc::HC_INVALID, 0);
    }
    let written = match bytes_payload {
        Some(bytes) if bytes.len() == len => ctx.host_files.write(fd, bytes, offset),
        _ => {
            let buf = {
                let mem = ctx.memory.read().unwrap();
                mem.read_bytes(Gpa(src_gpa), len).to_vec()
            };
            ctx.host_files.write(fd, &buf, offset)
        }
    };
    (hc::HC_OK, written as u64)
}

pub(super) fn execute_close(ctx: &HandlerCtx<'_>, args: [u64; 4]) -> (u64, u64) {
    ctx.host_files.close(args[0]);
    (hc::HC_OK, 0)
}

pub(super) fn execute_stat(ctx: &HandlerCtx<'_>, args: [u64; 4]) -> (u64, u64) {
    (hc::HC_OK, ctx.host_files.stat(args[0]))
}

pub(super) fn execute_seek(ctx: &HandlerCtx<'_>, args: [u64; 4]) -> (u64, u64) {
    let offset = args[1] as i64;
    let whence = args[2] as u32;
    match ctx.host_files.seek(args[0], offset, whence) {
        Some(pos) => (hc::HC_OK, pos),
        None => (hc::HC_IO_ERROR, 0),
    }
}

pub(super) fn execute_set_len(ctx: &HandlerCtx<'_>, args: [u64; 4]) -> (u64, u64) {
    if ctx.host_files.set_len(args[0], args[1]) {
        (hc::HC_OK, 0)
    } else {
        (hc::HC_IO_ERROR, 0)
    }
}

pub(super) fn execute_readdir(ctx: &HandlerCtx<'_>, args: [u64; 4]) -> (u64, u64) {
    let fd = args[0];
    let dst_gpa = args[1];
    let len = args[2] as usize;
    let restart = args[3] != 0;
    if len == 0 || len > MAX_DIR_BUF {
        return (hc::HC_INVALID, 0);
    }
    let mut buf = vec![0u8; len];
    let ret = ctx.host_files.readdir(fd, &mut buf, restart);
    if ret == u64::MAX {
        return (hc::HC_IO_ERROR, 0);
    }
    if ret != 0 {
        let copied = (ret & 0xFFFF_FFFF) as usize;
        if copied != 0 {
            let copied = copied.min(len);
            let mut mem = ctx.memory.write().unwrap();
            mem.write_bytes(Gpa(dst_gpa), &buf[..copied]);
        }
    }
    (hc::HC_OK, ret)
}

pub(super) fn execute_notify_dir(ctx: &HandlerCtx<'_>, args: [u64; 4]) -> (u64, u64) {
    let fd = args[0];
    let dst_gpa = args[1];
    let len = args[2] as usize;
    let opts = args[3];
    if len == 0 || len > MAX_DIR_BUF {
        return (hc::HC_INVALID, 0);
    }
    let watch_tree = (opts & NOTIFY_OPT_WATCH_TREE) != 0;
    let completion_filter = (opts & NOTIFY_OPT_FILTER_MASK) as u32;
    let mut buf = vec![0u8; len];
    let ret = ctx
        .host_files
        .notify_dir_change(fd, &mut buf, watch_tree, completion_filter);
    if ret == u64::MAX {
        return (hc::HC_IO_ERROR, 0);
    }
    if ret != 0 {
        let copied = (ret & 0xFFFF_FFFF) as usize;
        if copied != 0 {
            let copied = copied.min(len);
            let mut mem = ctx.memory.write().unwrap();
            mem.write_bytes(Gpa(dst_gpa), &buf[..copied]);
        }
    }
    (hc::HC_OK, ret)
}

pub(super) fn execute_mmap(ctx: &HandlerCtx<'_>, args: [u64; 4]) -> (u64, u64) {
    let fd = args[0];
    let offset = args[1];
    let size = args[2] as usize;
    let prot = args[3] as u32;
    if size == 0 || size > MAX_IO_SIZE {
        return (hc::HC_INVALID, 0);
    }
    let va = ctx.vaspace.lock().unwrap().alloc(0, size as u64, prot);
    match va {
        Some(gpa) => {
            let mut buf = vec![0u8; size];
            let got = ctx.host_files.read(fd, &mut buf, offset);
            if got > 0 {
                let mut mem = ctx.memory.write().unwrap();
                mem.write_bytes(Gpa(gpa), &buf[..got]);
            }
            log::debug!(
                "HOSTCALL_MMAP: fd={} off={:#x} size={:#x} -> gpa={:#x}",
                fd,
                offset,
                size,
                gpa
            );
            (hc::HC_OK, gpa)
        }
        None => {
            log::warn!("HOSTCALL_MMAP: VA alloc failed size={:#x}", size);
            (hc::HC_NO_MEMORY, 0)
        }
    }
}

pub(super) fn execute_munmap(ctx: &HandlerCtx<'_>, args: [u64; 4]) -> (u64, u64) {
    let base = args[0];
    let ok = ctx.vaspace.lock().unwrap().free(base);
    if ok {
        (hc::HC_OK, 0)
    } else {
        (hc::HC_IO_ERROR, 0)
    }
}

// ── Notify dir async loop ─────────────────────────────────────────────────────
// Returns (host_result, packed) once a change is detected or cancel fires.
// Caller passes a `cancelled` closure so handlers.rs stays decoupled from
// WorkerJob internals.
pub(super) fn poll_notify_dir_until_change(
    ctx: &HandlerCtx<'_>,
    args: [u64; 4],
    cancelled: impl Fn() -> bool,
) -> (u64, u64) {
    use std::thread;
    use std::time::Duration;
    loop {
        if cancelled() {
            return (hc::HC_CANCELED, 0);
        }
        let (host_result, packed) = execute_notify_dir(ctx, args);
        if host_result != hc::HC_OK {
            return (host_result, 0);
        }
        if packed != 0 {
            return (hc::HC_OK, packed);
        }
        thread::sleep(Duration::from_millis(10));
    }
}
pub(super) fn execute_win32k_call(ctx: &HandlerCtx<'_>, args: [u64; 4]) -> (u64, u64) {
    let packet_gpa = args[0];
    let packet_len = args[1] as usize;
    if packet_len < hc::WIN32K_CALL_PACKET_SIZE || packet_len > 1024 {
        return (hc::HC_INVALID, 0);
    }

    let bytes = {
        let mem = ctx.memory.read().unwrap();
        mem.read_bytes(Gpa(packet_gpa), packet_len).to_vec()
    };
    if bytes.len() < hc::WIN32K_CALL_PACKET_SIZE {
        return (hc::HC_INVALID, 0);
    }

    let version = match read_u32_le(&bytes, 0) {
        Some(v) => v,
        None => return (hc::HC_INVALID, 0),
    };
    let table = match read_u32_le(&bytes, 4) {
        Some(v) => v,
        None => return (hc::HC_INVALID, 0),
    };
    let syscall_nr = match read_u32_le(&bytes, 8) {
        Some(v) => v,
        None => return (hc::HC_INVALID, 0),
    };
    let arg_count = match read_u32_le(&bytes, 12) {
        Some(v) => v as usize,
        None => return (hc::HC_INVALID, 0),
    };
    let owner_pid = match read_u32_le(&bytes, 16) {
        Some(v) => v,
        None => return (hc::HC_INVALID, 0),
    };
    let owner_tid = match read_u32_le(&bytes, 20) {
        Some(v) => v,
        None => return (hc::HC_INVALID, 0),
    };

    if version != hc::WIN32K_CALL_PACKET_VERSION {
        return (hc::HC_INVALID, 0);
    }

    let mut call_args = [0u64; hc::WIN32K_CALL_MAX_ARGS];
    for i in 0..hc::WIN32K_CALL_MAX_ARGS {
        let off = 32 + i * 8;
        match read_u64_le(&bytes, off) {
            Some(v) => call_args[i] = v,
            None => return (hc::HC_INVALID, 0),
        }
    }
    let _effective_arg_count = core::cmp::min(arg_count, hc::WIN32K_CALL_MAX_ARGS);

    use winemu_shared::win32k_sysno as w;
    const NT_USER_CALL_ONE_PARAM_GET_SYS_COLOR: u64 = 9;
    const NT_USER_CALL_ONE_PARAM_GET_SYS_COLOR_BRUSH: u64 = 10;
    const NT_USER_CALL_ONE_PARAM_GET_SYS_COLOR_PEN: u64 = 11;
    const NT_USER_CALL_ONE_PARAM_GET_SYSTEM_METRICS: u64 = 12;
    const NT_USER_CALL_ONE_PARAM_REALIZE_PALETTE: u64 = 14;
    const NT_USER_CALL_ONE_PARAM_SET_THREAD_DPI_AWARENESS_CONTEXT: u64 = 19;
    const NT_USER_CALL_HWND_GET_WINDOW_DPI_AWARENESS_CONTEXT: u64 = 9;
    let call_name = win32k_call_name(table, syscall_nr as u16);
    let subcall_name = if table == 1 && syscall_nr as u16 == w::NT_USER_CALL_ONE_PARAM {
        Some(nt_user_call_one_param_name(call_args[1]))
    } else {
        None
    };
    let mut w32 = ctx.win32k.lock().unwrap();

    let result: u64 = match (table, syscall_nr as u16) {
        (1, w::NT_USER_INITIALIZE_CLIENT_PFN_ARRAYS) => status::SUCCESS as u64,
        (1, w::NT_USER_CREATE_WINDOW_EX) => w32.create_window_deferred(owner_tid),
        (1, w::NT_USER_REGISTER_CLASS_EX_WOW) => {
            handle_nt_user_register_class_ex_wow(ctx, &mut w32, owner_pid, call_args)
        }
        (1, w::NT_USER_GET_CLASS_INFO_EX) => {
            handle_nt_user_get_class_info_ex(ctx, &mut w32, owner_pid, call_args)
        }
        (1, w::NT_USER_PEEK_MESSAGE) => {
            let out_gpa = call_args[0];
            let mut msg = GuestMsg::default();
            let found = w32.peek_message(owner_tid, &mut msg);
            if found && out_gpa != 0 {
                let mut buf = [0u8; 40];
                buf[0..8].copy_from_slice(&msg.hwnd.to_le_bytes());
                buf[8..12].copy_from_slice(&msg.message.to_le_bytes());
                buf[12..16].copy_from_slice(&[0u8; 4]);
                buf[16..24].copy_from_slice(&msg.w_param.to_le_bytes());
                buf[24..32].copy_from_slice(&msg.l_param.to_le_bytes());
                buf[32..36].copy_from_slice(&msg.time.to_le_bytes());
                buf[36..40].copy_from_slice(&msg.pt_x.to_le_bytes());
                let mut mem = ctx.memory.write().unwrap();
                mem.write_bytes(Gpa(out_gpa), &buf);
                1u64
            } else {
                0u64
            }
        }
        (1, w::NT_USER_GET_MESSAGE) => {
            let out_gpa = call_args[0];
            let mut msg = GuestMsg::default();
            let found = w32.peek_message(owner_tid, &mut msg);
            if found && out_gpa != 0 {
                let mut buf = [0u8; 40];
                buf[0..8].copy_from_slice(&msg.hwnd.to_le_bytes());
                buf[8..12].copy_from_slice(&msg.message.to_le_bytes());
                buf[12..16].copy_from_slice(&[0u8; 4]);
                buf[16..24].copy_from_slice(&msg.w_param.to_le_bytes());
                buf[24..32].copy_from_slice(&msg.l_param.to_le_bytes());
                buf[32..36].copy_from_slice(&msg.time.to_le_bytes());
                buf[36..40].copy_from_slice(&msg.pt_x.to_le_bytes());
                let mut mem = ctx.memory.write().unwrap();
                mem.write_bytes(Gpa(out_gpa), &buf);
                1u64
            } else {
                0u64
            }
        }
        (1, w::NT_USER_MESSAGE_CALL) => handle_nt_user_message_call(ctx, &mut w32, call_args),
        (1, w::NT_USER_TRANSLATE_MESSAGE) => 1u64,
        (1, w::NT_USER_DISPATCH_MESSAGE) => 0u64,
        (1, w::NT_USER_POST_MESSAGE) => status::SUCCESS as u64,
        (1, w::NT_USER_POST_THREAD_MESSAGE) => w32.post_thread_message(
            call_args[0] as u32,
            call_args[1] as u32,
            call_args[2],
            call_args[3],
        ),
        (1, w::NT_USER_SHOW_WINDOW) | (1, w::NT_USER_SHOW_WINDOW_ASYNC) => {
            w32.show_window(call_args[0] as u32, call_args[1] as i32)
        }
        (1, w::NT_USER_DESTROY_WINDOW) => w32.destroy_window(call_args[0] as u32),
        (1, w::NT_USER_GET_DC) | (1, w::NT_USER_GET_DCEX) => w32.get_dc(call_args[0] as u32),
        (1, w::NT_USER_RELEASE_DC) => w32.release_dc(call_args[0] as u32, call_args[1] as u32),
        (1, w::NT_USER_BEGIN_PAINT) => w32.begin_paint(call_args[0] as u32),
        (1, w::NT_USER_END_PAINT) => w32.end_paint(call_args[0] as u32, call_args[1] as u32),
        (1, w::NT_USER_SET_WINDOW_POS) => w32.set_window_pos(
            call_args[0] as u32,
            call_args[2] as i32,
            call_args[3] as i32,
            call_args[4] as u32,
            call_args[5] as u32,
        ),
        (1, w::NT_USER_MOVE_WINDOW) => w32.move_window(
            call_args[0] as u32,
            call_args[1] as i32,
            call_args[2] as i32,
            call_args[3] as u32,
            call_args[4] as u32,
        ),
        (1, w::NT_USER_INVALIDATE_RECT) => w32.invalidate_rect(call_args[0] as u32),
        (1, w::NT_USER_VALIDATE_RECT) => w32.validate_rect(call_args[0] as u32),
        (1, w::NT_USER_ENUM_DISPLAY_MONITORS) => 1u64,
        (1, w::NT_USER_SYSTEM_PARAMETERS_INFO) => {
            let action = call_args[0] as u32;
            let ui_param = call_args[1] as u32;
            let out_gpa = call_args[2];
            let (result, payload) = w32.system_parameters_info_bytes(action, ui_param);
            if let Some(bytes) = payload.as_deref() {
                if out_gpa != 0 {
                    let mut mem = ctx.memory.write().unwrap();
                    mem.write_bytes(Gpa(out_gpa), bytes);
                }
            }
            result
        }
        (1, w::NT_USER_FIND_WINDOW_EX) => 0u64,
        (1, w::NT_USER_GET_FOREGROUND_WINDOW) => w32.foreground_hwnd() as u64,
        (1, w::NT_USER_GET_GUITHREAD_INFO) => {
            let out_gpa = call_args[1];
            let target_tid = if call_args[0] == 0 || call_args[0] > u64::from(u32::MAX) {
                owner_tid
            } else {
                call_args[0] as u32
            };
            if out_gpa == 0 {
                0
            } else {
                let info = w32.get_gui_thread_info_bytes(target_tid);
                let bytes = &info[..GUEST_GUITHREADINFO_SIZE];
                if write_guest_bytes(ctx.memory, out_gpa, bytes) {
                    1
                } else {
                    0
                }
            }
        }
        (1, w::NT_USER_GET_PROCESS_DPI_AWARENESS_CONTEXT) => {
            w32.get_process_dpi_awareness_context(owner_pid)
        }
        (1, w::NT_USER_GET_SYSTEM_DPI_FOR_PROCESS) => w32.get_system_dpi_for_process(owner_pid),
        (1, w::NT_USER_SET_TIMER) => w32.set_timer(
            call_args[0] as u32,
            owner_tid,
            call_args[1],
            call_args[2] as u32,
        ),
        (1, w::NT_USER_SET_PROCESS_DPI_AWARENESS_CONTEXT) => {
            w32.set_process_dpi_awareness_context(owner_pid, call_args[0] as u32)
        }
        (1, w::NT_USER_SET_WINDOWS_HOOK_EX) => u64::from(call_args[4] != 0),
        (1, w::NT_USER_KILL_TIMER) => w32.kill_timer(call_args[0] as u32, call_args[1]),
        (1, w::NT_USER_SET_CURSOR) => w32.set_cursor(call_args[0] as u32),
        (1, w::NT_USER_POST_QUIT_MESSAGE) => {
            w32.post_quit(owner_tid, call_args[0] as i32);
            status::SUCCESS as u64
        }
        (1, w::NT_USER_UNHOOK_WINDOWS_HOOK_EX) => u64::from(call_args[0] != 0),
        (1, w::NT_USER_CALL_ONE_PARAM) if call_args[1] == NT_USER_CALL_ONE_PARAM_GET_SYS_COLOR => {
            w32.get_sys_color(call_args[0] as u32)
        }
        (1, w::NT_USER_CALL_ONE_PARAM)
            if call_args[1] == NT_USER_CALL_ONE_PARAM_GET_SYS_COLOR_BRUSH =>
        {
            w32.get_sys_color_brush(call_args[0] as u32)
        }
        (1, w::NT_USER_CALL_ONE_PARAM)
            if call_args[1] == NT_USER_CALL_ONE_PARAM_GET_SYS_COLOR_PEN =>
        {
            w32.get_sys_color_pen(call_args[0] as u32)
        }
        (1, w::NT_USER_CALL_ONE_PARAM)
            if call_args[1] == NT_USER_CALL_ONE_PARAM_GET_SYSTEM_METRICS =>
        {
            w32.get_system_metrics(call_args[0] as u32)
        }
        (1, w::NT_USER_CALL_ONE_PARAM)
            if call_args[1] == NT_USER_CALL_ONE_PARAM_REALIZE_PALETTE =>
        {
            w32.realize_palette(call_args[0] as u32)
        }
        (1, w::NT_USER_CALL_ONE_PARAM)
            if call_args[1] == NT_USER_CALL_ONE_PARAM_SET_THREAD_DPI_AWARENESS_CONTEXT =>
        {
            w32.set_thread_dpi_awareness_context(owner_pid, owner_tid, call_args[0] as u32)
        }
        (1, w::NT_USER_CALL_TWO_PARAM)
            if call_args[2] == NT_USER_CALL_TWO_PARAM_GET_DIALOG_PROC =>
        {
            call_args[0]
        }
        (1, w::NT_USER_CALL_TWO_PARAM) if call_args[2] == NT_USER_CALL_TWO_PARAM_ALLOC_WIN_PROC => {
            call_args[0]
        }
        (1, w::NT_USER_CALL_HWND)
            if call_args[1] == NT_USER_CALL_HWND_GET_WINDOW_DPI_AWARENESS_CONTEXT =>
        {
            w32.get_window_dpi_awareness_context(call_args[0] as u32)
        }
        (1, w::NT_USER_CALL_NO_PARAM)
        | (1, w::NT_USER_CALL_ONE_PARAM)
        | (1, w::NT_USER_CALL_TWO_PARAM)
        | (1, w::NT_USER_CALL_HWND)
        | (1, w::NT_USER_CALL_HWND_PARAM) => 0u64,
        (1, w::NT_GDI_DELETE_OBJECT_APP) => w32.delete_object(call_args[0] as u32),
        (1, w::NT_GDI_BIT_BLT) => w32.bit_blt(call_args[0] as u32),
        (1, w::NT_GDI_STRETCH_BLT) => w32.stretch_blt(call_args[0] as u32),
        (1, w::NT_GDI_CREATE_BITMAP) => w32.create_bitmap(
            call_args[0] as u32,
            call_args[1] as u32,
            call_args[2] as u32,
            call_args[3] as u32,
        ),
        (1, w::NT_GDI_CREATE_COMPATIBLE_DC) => w32.create_compatible_dc(call_args[0] as u32),
        (1, w::NT_GDI_CREATE_COMPATIBLE_BITMAP) => w32.create_compatible_bitmap(
            call_args[0] as u32,
            call_args[1] as u32,
            call_args[2] as u32,
        ),
        (1, w::NT_GDI_CREATE_DIBITMAP_INTERNAL) => w32.create_dibitmap_internal(),
        (1, w::NT_GDI_CREATE_RECT_RGN) => w32.alloc_gdi_handle(),
        (1, w::NT_GDI_ENUM_FONTS) => 0,
        (1, w::NT_GDI_SELECT_BITMAP) => w32.select_bitmap(call_args[0] as u32, call_args[1] as u32),
        (1, w::NT_GDI_SELECT_BRUSH) => w32.select_brush(call_args[0] as u32, call_args[1] as u32),
        (1, w::NT_GDI_SELECT_PEN) => w32.select_pen(call_args[0] as u32, call_args[1] as u32),
        (1, w::NT_GDI_SELECT_FONT) => w32.select_font(call_args[0] as u32, call_args[1] as u32),
        (1, w::NT_GDI_RECTANGLE) => w32.gdi_rectangle(
            call_args[0] as u32,
            call_args[1] as i32,
            call_args[2] as i32,
            call_args[3] as i32,
            call_args[4] as i32,
        ),
        (1, w::NT_GDI_MOVE_TO) => w32.move_to(
            call_args[0] as u32,
            call_args[1] as i32,
            call_args[2] as i32,
        ),
        (1, w::NT_GDI_LINE_TO) => w32.line_to(
            call_args[0] as u32,
            call_args[1] as i32,
            call_args[2] as i32,
        ),
        (1, w::NT_GDI_GET_AND_SET_DCDWORD) => {
            // iType: 3=BkColor, 4=TextColor (Windows internal)
            let itype = call_args[1] as u32;
            let value = call_args[2] as u32;
            let hdc = call_args[0] as u32;
            match itype {
                3 => w32.set_bk_color(hdc, value),
                4 => w32.set_text_color(hdc, value),
                _ => 0,
            }
        }
        (1, w::NT_GDI_SET_PIXEL) => {
            // SetPixel(hdc, x, y, color) — draw single pixel
            let hdc = call_args[0] as u32;
            let x = call_args[1] as i32;
            let y = call_args[2] as i32;
            let color = call_args[3] as u32;
            w32.gdi_rectangle(hdc, x, y, x + 1, y + 1);
            let _ = (x, y, color);
            color as u64
        }
        // ── NtUserQueryWindow ────────────────────────────────────────────────
        (1, w::NT_USER_QUERY_WINDOW) => w32.query_window(call_args[0] as u32, call_args[1] as u32),

        // ── NtUserGetUpdateRect ──────────────────────────────────────────────
        (1, w::NT_USER_GET_UPDATE_RECT) => {
            let hwnd = call_args[0] as u32;
            let out_gpa = call_args[1];
            let (has_update, x0, y0, x1, y1) = w32.get_update_rect(hwnd);
            if out_gpa != 0 {
                let mut buf = [0u8; 16];
                buf[0..4].copy_from_slice(&x0.to_le_bytes());
                buf[4..8].copy_from_slice(&y0.to_le_bytes());
                buf[8..12].copy_from_slice(&x1.to_le_bytes());
                buf[12..16].copy_from_slice(&y1.to_le_bytes());
                let mut mem = ctx.memory.write().unwrap();
                mem.write_bytes(Gpa(out_gpa), &buf);
            }
            if has_update {
                1
            } else {
                0
            }
        }

        // ── NtUserGetWindowPlacement ─────────────────────────────────────────
        (1, w::NT_USER_GET_WINDOW_PLACEMENT) => {
            let hwnd = call_args[0] as u32;
            let out_gpa = call_args[1];
            let (x, y, w, h) = w32.get_window_placement(hwnd);
            if out_gpa != 0 {
                // WINDOWPLACEMENT: length(4), flags(4), showCmd(4), ptMin(8),
                //                  ptMax(8), rcNormal(16) = 44 bytes total
                let mut buf = [0u8; 44];
                buf[0..4].copy_from_slice(&44u32.to_le_bytes());
                buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // SW_SHOWNORMAL
                buf[28..32].copy_from_slice(&x.to_le_bytes());
                buf[32..36].copy_from_slice(&y.to_le_bytes());
                buf[36..40].copy_from_slice(&(x + w as i32).to_le_bytes());
                buf[40..44].copy_from_slice(&(y + h as i32).to_le_bytes());
                let mut mem = ctx.memory.write().unwrap();
                mem.write_bytes(Gpa(out_gpa), &buf);
            }
            1u64
        }

        // ── NtUserGetKeyState / NtUserGetAsyncKeyState ───────────────────────
        (1, w::NT_USER_GET_KEY_STATE) => w32.get_key_state(call_args[0] as u32),
        (1, w::NT_USER_GET_ASYNC_KEY_STATE) => w32.get_async_key_state(call_args[0] as u32),

        // ── NtUserGetKeyboardState ───────────────────────────────────────────
        (1, w::NT_USER_GET_KEYBOARD_STATE) => {
            // Write 256 zero bytes to pvParam — all keys up
            let out_gpa = call_args[0];
            if out_gpa != 0 {
                let buf = [0u8; 256];
                let mut mem = ctx.memory.write().unwrap();
                mem.write_bytes(Gpa(out_gpa), &buf);
            }
            1u64
        }

        // ── NtUserGetQueueStatus ─────────────────────────────────────────────
        (1, w::NT_USER_GET_QUEUE_STATUS) => w32.get_queue_status(owner_tid),

        // ── NtUserGetDoubleClickTime ─────────────────────────────────────────
        (1, w::NT_USER_GET_DOUBLE_CLICK_TIME) => w32.get_double_click_time(),

        // ── NtUserGetCaretBlinkTime ──────────────────────────────────────────
        (1, w::NT_USER_GET_CARET_BLINK_TIME) => w32.get_caret_blink_time(),

        // ── NtUserWindowFromPoint ────────────────────────────────────────────
        (1, w::NT_USER_WINDOW_FROM_POINT) => w32.foreground_hwnd() as u64,

        // ── NtUserGetWindowDC ────────────────────────────────────────────────
        (1, w::NT_USER_GET_WINDOW_DC) => w32.get_dc(call_args[0] as u32),

        // ── NtUserGetThreadState ─────────────────────────────────────────────
        (1, w::NT_USER_GET_THREAD_STATE) => 0u64,

        // ── NtGdiFlush ───────────────────────────────────────────────────────
        (1, w::NT_GDI_FLUSH) => 1u64,

        // ── NtGdiCreateSolidBrush ────────────────────────────────────────────
        (1, w::NT_GDI_CREATE_SOLID_BRUSH) => w32.create_solid_brush(call_args[0] as u32),

        // ── NtGdiCreatePatternBrushInternal ─────────────────────────────────
        (1, w::NT_GDI_CREATE_PATTERN_BRUSH_INTERNAL) => w32.create_pattern_brush_internal(),

        // ── NtGdiCreatePen ───────────────────────────────────────────────────
        (1, w::NT_GDI_CREATE_PEN) => w32.create_pen(
            call_args[0] as u32,
            call_args[1] as u32,
            call_args[2] as u32,
        ),
        (1, w::NT_GDI_HFONT_CREATE) => {
            let logfont_gpa = call_args[0];
            let requested_size = call_args[1] as usize;
            let read_len = requested_size.min(92);
            if logfont_gpa == 0 || read_len < 92 {
                0
            } else {
                let logfont = {
                    let mem = ctx.memory.read().unwrap();
                    mem.read_bytes(Gpa(logfont_gpa), read_len).to_vec()
                };
                w32.create_font(&logfont)
            }
        }
        (1, w::NT_GDI_OPEN_DCW) => w32.open_dc_w(),
        (1, w::NT_GDI_GET_TEXT_CHARSET_INFO) => {
            let hdc = call_args[0] as u32;
            let out_gpa = call_args[1];
            match w32.get_text_charset_info(hdc) {
                Some((charset, sig)) => {
                    if out_gpa != 0 {
                        let mut mem = ctx.memory.write().unwrap();
                        mem.write_bytes(Gpa(out_gpa), &sig);
                    }
                    charset as u64
                }
                None => 0,
            }
        }
        (1, w::NT_GDI_GET_TEXT_METRICS_W) => {
            let hdc = call_args[0] as u32;
            let out_gpa = call_args[1];
            match w32.get_text_metrics(hdc) {
                Some(metrics) => {
                    if out_gpa != 0 {
                        let mut mem = ctx.memory.write().unwrap();
                        mem.write_bytes(Gpa(out_gpa), &metrics);
                    }
                    1
                }
                None => 0,
            }
        }
        (1, w::NT_GDI_GET_DEVICE_CAPS) => {
            w32.get_device_caps(call_args[0] as u32, call_args[1] as u32)
        }

        // ── NtGdiExtGetObjectW ───────────────────────────────────────────────
        (1, w::NT_GDI_EXT_GET_OBJECT_W) => {
            let handle = call_args[0] as u32;
            let count = call_args[1] as usize;
            let out_gpa = call_args[2];
            match w32.ext_get_object(handle, count) {
                Some(bytes) => {
                    if out_gpa != 0 {
                        let mut mem = ctx.memory.write().unwrap();
                        mem.write_bytes(Gpa(out_gpa), &bytes);
                    }
                    bytes.len() as u64
                }
                None => 0,
            }
        }

        // ── NtGdiEllipse ─────────────────────────────────────────────────────
        (1, w::NT_GDI_ELLIPSE) => w32.gdi_ellipse(
            call_args[0] as u32,
            call_args[1] as i32,
            call_args[2] as i32,
            call_args[3] as i32,
            call_args[4] as i32,
        ),

        // ── NtGdiPolyPolyDraw ────────────────────────────────────────────────
        (1, w::NT_GDI_POLY_POLY_DRAW) => w32.poly_poly_draw(call_args[0] as u32),

        // ── NtGdiFillRgn ─────────────────────────────────────────────────────
        (1, w::NT_GDI_FILL_RGN) => w32.fill_rgn(
            call_args[0] as u32,
            call_args[1] as u32,
            call_args[2] as u32,
        ),

        _ => {
            log::trace!("win32k unhandled table={} nr={:#x}", table, syscall_nr);
            status::NOT_IMPLEMENTED as u64
        }
    };

    let trace_call = call_name == "unknown"
        || matches!(subcall_name, Some("unknown"))
        || result == status::NOT_IMPLEMENTED as u64;

    if trace_call {
        match subcall_name {
            Some(subcall) => log::debug!(
                "win32k: table={} syscall_nr={:#x}({}) subcall={} owner_tid={} arg0={:#x} arg1={:#x} -> {:#x}",
                table,
                syscall_nr,
                call_name,
                subcall,
                owner_tid,
                call_args[0],
                call_args[1],
                result
            ),
            None => log::debug!(
                "win32k: table={} syscall_nr={:#x}({}) owner_tid={} arg0={:#x} arg1={:#x} -> {:#x}",
                table,
                syscall_nr,
                call_name,
                owner_tid,
                call_args[0],
                call_args[1],
                result
            ),
        }
    }

    (hc::HC_OK, result)
}
