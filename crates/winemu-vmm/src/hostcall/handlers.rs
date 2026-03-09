// handlers.rs — Concrete hostcall implementations
//
// All execute_* functions live here. broker.rs keeps only the scheduling
// framework (queues, workers, stats, routing).

use std::sync::{Arc, Mutex, RwLock};
use winemu_core::addr::Gpa;
use winemu_shared::hostcall as hc;
use winemu_shared::status;

use crate::host_file::HostFileTable;
use crate::memory::GuestMemory;
use crate::vaspace::VaSpace;
use crate::hostcall::modules::win32k::Win32kState;
use crate::hostcall::modules::win32k::state::GuestMsg;

pub(super) const MAX_HOST_PATH: usize = 1024;
pub(super) const MAX_IO_SIZE: usize = 64 * 1024 * 1024;
pub(super) const MAX_DIR_BUF: usize = 4096;
pub(super) const NOTIFY_OPT_WATCH_TREE: u64 = 1u64 << 63;
pub(super) const NOTIFY_OPT_FILTER_MASK: u64 = 0xFFFF_FFFF;

// ── Shared context passed to every handler ────────────────────────────────────
pub(super) struct HandlerCtx<'a> {
    pub memory:     &'a Arc<RwLock<GuestMemory>>,
    pub host_files: &'a Arc<HostFileTable>,
    pub vaspace:    &'a Arc<Mutex<VaSpace>>,
    pub win32k:     &'a Mutex<Win32kState>,
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

// ── Packet helpers ────────────────────────────────────────────────────────────
pub(super) fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let src = bytes.get(off..end)?;
    Some(u32::from_le_bytes([src[0], src[1], src[2], src[3]]))
}

pub(super) fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let src = bytes.get(off..end)?;
    Some(u64::from_le_bytes([
        src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
    ]))
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
    let ret = ctx.host_files.notify_dir_change(fd, &mut buf, watch_tree, completion_filter);
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
                fd, offset, size, gpa
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
    if ok { (hc::HC_OK, 0) } else { (hc::HC_IO_ERROR, 0) }
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

    let version    = match read_u32_le(&bytes, 0)  { Some(v) => v, None => return (hc::HC_INVALID, 0) };
    let table      = match read_u32_le(&bytes, 4)  { Some(v) => v, None => return (hc::HC_INVALID, 0) };
    let syscall_nr = match read_u32_le(&bytes, 8)  { Some(v) => v, None => return (hc::HC_INVALID, 0) };
    let arg_count  = match read_u32_le(&bytes, 12) { Some(v) => v as usize, None => return (hc::HC_INVALID, 0) };
    let _owner_pid = match read_u32_le(&bytes, 16) { Some(v) => v, None => return (hc::HC_INVALID, 0) };
    let owner_tid  = match read_u32_le(&bytes, 20) { Some(v) => v, None => return (hc::HC_INVALID, 0) };

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
    let mut w32 = ctx.win32k.lock().unwrap();

    let result: u64 = match (table, syscall_nr as u16) {
        (1, w::NT_USER_INITIALIZE_CLIENT_PFN_ARRAYS) => status::SUCCESS as u64,
        (1, w::NT_USER_CREATE_WINDOW_EX) => w32.create_window_deferred(owner_tid),
        (1, w::NT_USER_REGISTER_CLASS_EX_WOW) => 0xC001u64,
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
        (1, w::NT_USER_TRANSLATE_MESSAGE) => 1u64,
        (1, w::NT_USER_DISPATCH_MESSAGE) => 0u64,
        (1, w::NT_USER_POST_MESSAGE) => status::SUCCESS as u64,
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
        (1, w::NT_USER_FIND_WINDOW_EX) => 0u64,
        (1, w::NT_USER_GET_FOREGROUND_WINDOW) => w32.foreground_hwnd() as u64,
        (1, w::NT_USER_SET_TIMER) => w32.set_timer(
            call_args[0] as u32,
            owner_tid,
            call_args[1],
            call_args[2] as u32,
        ),
        (1, w::NT_USER_KILL_TIMER) => w32.kill_timer(call_args[0] as u32, call_args[1]),
        (1, w::NT_USER_SET_CURSOR) => w32.set_cursor(call_args[0] as u32),
        (1, w::NT_USER_POST_QUIT_MESSAGE) => {
            w32.post_quit(owner_tid, call_args[0] as i32);
            status::SUCCESS as u64
        }
        (1, w::NT_USER_CALL_NO_PARAM)
        | (1, w::NT_USER_CALL_ONE_PARAM)
        | (1, w::NT_USER_CALL_TWO_PARAM)
        | (1, w::NT_USER_CALL_HWND)
        | (1, w::NT_USER_CALL_HWND_PARAM) => 0u64,
        (0, w::NT_GDI_DELETE_OBJECT_APP) => w32.delete_object(call_args[0] as u32),
        (0, w::NT_GDI_BIT_BLT) => w32.bit_blt(call_args[0] as u32),
        (0, w::NT_GDI_STRETCH_BLT) => w32.stretch_blt(call_args[0] as u32),
        (0, w::NT_GDI_CREATE_COMPATIBLE_DC) => w32.create_compatible_dc(call_args[0] as u32),
        (0, w::NT_GDI_CREATE_COMPATIBLE_BITMAP) => {
            w32.create_compatible_bitmap(call_args[0] as u32, call_args[1] as u32, call_args[2] as u32)
        }
        (0, w::NT_GDI_CREATE_RECT_RGN) => w32.alloc_gdi_handle(),
        (0, w::NT_GDI_SELECT_BITMAP) => w32.select_object(call_args[0] as u32, call_args[1] as u32),
        (0, w::NT_GDI_SELECT_BRUSH) => w32.select_object(call_args[0] as u32, call_args[1] as u32),
        (0, w::NT_GDI_SELECT_PEN) => w32.select_object(call_args[0] as u32, call_args[1] as u32),
        (0, w::NT_GDI_SELECT_FONT) => w32.select_object(call_args[0] as u32, call_args[1] as u32),
        (0, w::NT_GDI_RECTANGLE) => w32.gdi_rectangle(
            call_args[0] as u32,
            call_args[1] as i32,
            call_args[2] as i32,
            call_args[3] as i32,
            call_args[4] as i32,
        ),
        (0, w::NT_GDI_MOVE_TO) => w32.move_to(call_args[0] as u32, call_args[1] as i32, call_args[2] as i32),
        (0, w::NT_GDI_LINE_TO) => w32.line_to(call_args[0] as u32, call_args[1] as i32, call_args[2] as i32),
        (0, w::NT_GDI_GET_AND_SET_DCDWORD) => {
            // iType: 3=BkColor, 4=TextColor (Windows internal)
            let itype = call_args[1] as u32;
            let value = call_args[2] as u32;
            let hdc   = call_args[0] as u32;
            match itype {
                3 => w32.set_bk_color(hdc, value),
                4 => w32.set_text_color(hdc, value),
                _ => 0,
            }
        }
        (0, w::NT_GDI_SET_PIXEL) => {
            // SetPixel(hdc, x, y, color) — draw single pixel
            let hdc   = call_args[0] as u32;
            let x     = call_args[1] as i32;
            let y     = call_args[2] as i32;
            let color = call_args[3] as u32;
            w32.gdi_rectangle(hdc, x, y, x + 1, y + 1);
            let _ = (x, y, color);
            color as u64
        }
        // ── NtUserQueryWindow ────────────────────────────────────────────────
        (1, w::NT_USER_QUERY_WINDOW) => w32.query_window(call_args[0] as u32, call_args[1] as u32),

        // ── NtUserGetUpdateRect ──────────────────────────────────────────────
        (1, w::NT_USER_GET_UPDATE_RECT) => {
            let hwnd    = call_args[0] as u32;
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
            if has_update { 1 } else { 0 }
        }

        // ── NtUserGetWindowPlacement ─────────────────────────────────────────
        (1, w::NT_USER_GET_WINDOW_PLACEMENT) => {
            let hwnd    = call_args[0] as u32;
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
        (1, w::NT_USER_GET_KEY_STATE)       => w32.get_key_state(call_args[0] as u32),
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
        (0, w::NT_GDI_FLUSH) => 1u64,

        // ── NtGdiCreateSolidBrush ────────────────────────────────────────────
        (0, w::NT_GDI_CREATE_SOLID_BRUSH) => w32.create_solid_brush(call_args[0] as u32),

        // ── NtGdiCreatePen ───────────────────────────────────────────────────
        (0, w::NT_GDI_CREATE_PEN) => w32.create_pen(
            call_args[0] as u32,
            call_args[1] as u32,
            call_args[2] as u32,
        ),

        // ── NtGdiExtGetObjectW ───────────────────────────────────────────────
        (0, w::NT_GDI_EXT_GET_OBJECT_W) => w32.ext_get_object(call_args[0] as u32),

        // ── NtGdiEllipse ─────────────────────────────────────────────────────
        (0, w::NT_GDI_ELLIPSE) => w32.gdi_ellipse(
            call_args[0] as u32,
            call_args[1] as i32,
            call_args[2] as i32,
            call_args[3] as i32,
            call_args[4] as i32,
        ),

        // ── NtGdiPolyPolyDraw ────────────────────────────────────────────────
        (0, w::NT_GDI_POLY_POLY_DRAW) => w32.poly_poly_draw(call_args[0] as u32),

        // ── NtGdiFillRgn ─────────────────────────────────────────────────────
        (0, w::NT_GDI_FILL_RGN) => w32.fill_rgn(
            call_args[0] as u32,
            call_args[1] as u32,
            call_args[2] as u32,
        ),

        _ => {
            log::trace!("win32k unhandled table={} nr={:#x}", table, syscall_nr);
            status::NOT_IMPLEMENTED as u64
        }
    };

    (hc::HC_OK, result)
}
