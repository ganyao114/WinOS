// win32k/state.rs — Host-side win32k runtime (winit + softbuffer)
//
// Win32kState is held in BrokerInner behind a Mutex.
// Window creation requires &ActiveEventLoop and is deferred to the main thread
// via on_event_loop_tick() called from the winit AboutToWait handler.

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroU32;
use std::sync::Arc;

use softbuffer::Surface;
use winit::dpi::PhysicalSize;
use winit::event::WindowEvent;
use winit::event_loop::ActiveEventLoop;
use winit::window::{Window, WindowId};

// ── WM_ constants ─────────────────────────────────────────────────────────────
pub const WM_PAINT:         u32 = 0x000F;
pub const WM_TIMER:         u32 = 0x0113;
pub const WM_QUIT:          u32 = 0x0012;
pub const WM_SIZE:          u32 = 0x0005;
pub const WM_CLOSE:         u32 = 0x0010;
pub const WM_MOUSEMOVE:     u32 = 0x0200;
pub const WM_LBUTTONDOWN:   u32 = 0x0201;
pub const WM_LBUTTONUP:     u32 = 0x0202;
pub const WM_RBUTTONDOWN:   u32 = 0x0204;
pub const WM_RBUTTONUP:     u32 = 0x0205;
pub const WM_KEYDOWN:       u32 = 0x0100;
pub const WM_KEYUP:         u32 = 0x0101;
pub const WM_CHAR:          u32 = 0x0102;
pub const WM_DESTROY:       u32 = 0x0002;
pub const WM_ERASEBKGND:    u32 = 0x0014;

// ── Guest MSG layout (matches Windows MSG struct) ────────────────────────────
#[derive(Clone, Copy, Default)]
pub struct GuestMsg {
    pub hwnd:    u64,
    pub message: u32,
    pub w_param: u64,
    pub l_param: u64,
    pub time:    u32,
    pub pt_x:    i32,
    pub pt_y:    i32,
}

// ── GDI object kinds ──────────────────────────────────────────────────────────
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GdiKind {
    Bitmap,
    Brush,
    Pen,
    Font,
    Region,
    Other,
}

struct GdiObject {
    kind: GdiKind,
}

// ── DC state ──────────────────────────────────────────────────────────────────
struct DcState {
    hwnd:          u32,
    sel_bitmap:    u32,
    sel_brush:     u32,
    sel_pen:       u32,
    sel_font:      u32,
    bk_color:      u32,
    text_color:    u32,
    cur_x:         i32,
    cur_y:         i32,
}

impl DcState {
    fn new(hwnd: u32) -> Self {
        Self {
            hwnd,
            sel_bitmap:  0,
            sel_brush:   0,
            sel_pen:     0,
            sel_font:    0,
            bk_color:    0x00FF_FFFF,
            text_color:  0x0000_0000,
            cur_x:       0,
            cur_y:       0,
        }
    }
}

// ── Timer ─────────────────────────────────────────────────────────────────────
struct Timer {
    hwnd:     u32,
    tid:      u32,
    timer_id: u64,
    interval: u32, // ms
    elapsed:  u32,
}

// ── Window state ─────────────────────────────────────────────────────────────
struct WinState {
    window:    Arc<Window>,
    surface:   Surface<Arc<Window>, Arc<Window>>,
    width:     u32,
    height:    u32,
    visible:   bool,
    owner_tid: u32,
    // Framebuffer: XRGB8888, row-major
    framebuf:  Vec<u32>,
}

impl WinState {
    fn fb_size(&self) -> usize {
        (self.width as usize) * (self.height as usize)
    }

    fn ensure_fb(&mut self) {
        let needed = self.fb_size();
        if self.framebuf.len() != needed {
            self.framebuf.resize(needed, 0xFF20_2020);
        }
    }

    fn present(&mut self) {
        let w = self.width.max(1);
        let h = self.height.max(1);
        if ws_resize_surface(&mut self.surface, w, h).is_err() { return; }
        if let Ok(mut buf) = self.surface.buffer_mut() {
            let src = &self.framebuf;
            let len = (w as usize * h as usize).min(buf.len()).min(src.len());
            buf[..len].copy_from_slice(&src[..len]);
            let _ = buf.present();
        }
    }
}

fn ws_resize_surface(
    surface: &mut Surface<Arc<Window>, Arc<Window>>,
    w: u32, h: u32,
) -> Result<(), ()> {
    surface.resize(
        NonZeroU32::new(w).ok_or(())?,
        NonZeroU32::new(h).ok_or(())?,
    ).map_err(|_| ())
}

// ── Win32kState ───────────────────────────────────────────────────────────────
pub struct Win32kState {
    windows:        HashMap<u32, WinState>,
    dcs:            HashMap<u32, DcState>,
    gdi_objects:    HashMap<u32, GdiObject>,
    msg_queues:     HashMap<u32, VecDeque<GuestMsg>>,
    timers:         Vec<Timer>,
    next_hwnd:      u32,
    next_hdc:       u32,
    next_gdi:       u32,
    foreground:     u32,
    pending_create: VecDeque<(u32, u32)>, // (hwnd, owner_tid)
    tick_ms:        u32,
    brush_colors:   HashMap<u32, u32>,
    pen_colors:     HashMap<u32, u32>,
}

impl Win32kState {
    pub fn new() -> Self {
        Self {
            windows:        HashMap::new(),
            dcs:            HashMap::new(),
            gdi_objects:    HashMap::new(),
            msg_queues:     HashMap::new(),
            timers:         Vec::new(),
            next_hwnd:      0x1000,
            next_hdc:       0x2000,
            next_gdi:       0x3000,
            foreground:     0,
            pending_create: VecDeque::new(),
            tick_ms:        0,
            brush_colors:   HashMap::new(),
            pen_colors:     HashMap::new(),
        }
    }

    fn alloc_hwnd(&mut self) -> u32 {
        let h = self.next_hwnd;
        self.next_hwnd += 4;
        h
    }

    fn alloc_gdi_typed(&mut self, kind: GdiKind) -> u32 {
        let h = self.next_gdi;
        self.next_gdi += 4;
        self.gdi_objects.insert(h, GdiObject { kind });
        h
    }

    fn alloc_hdc(&mut self) -> u32 {
        let h = self.next_hdc;
        self.next_hdc += 4;
        h
    }

    // ── NtUserCreateWindowEx ─────────────────────────────────────────────────
    pub fn create_window_deferred(&mut self, owner_tid: u32) -> u64 {
        let hwnd = self.alloc_hwnd();
        self.pending_create.push_back((hwnd, owner_tid));
        if self.foreground == 0 {
            self.foreground = hwnd;
        }
        hwnd as u64
    }

    // Called from the winit event loop (main thread) to flush pending creates.
    pub fn on_event_loop_tick(&mut self, el: &ActiveEventLoop, elapsed_ms: u32) {
        // Flush pending window creates
        while let Some((hwnd, owner_tid)) = self.pending_create.pop_front() {
            let attrs = winit::window::Window::default_attributes()
                .with_title("WinEmu")
                .with_inner_size(PhysicalSize::new(800u32, 600u32));
            let Ok(win) = el.create_window(attrs) else { continue };
            let win = Arc::new(win);
            let Ok(ctx) = softbuffer::Context::new(win.clone()) else { continue };
            let Ok(surface) = softbuffer::Surface::new(&ctx, win.clone()) else { continue };
            let mut ws = WinState {
                window: win,
                surface,
                width: 800,
                height: 600,
                visible: false,
                owner_tid,
                framebuf: Vec::new(),
            };
            ws.ensure_fb();
            self.windows.insert(hwnd, ws);
        }

        // Advance timers — collect fired events first to avoid borrow conflict
        let delta = elapsed_ms.saturating_sub(self.tick_ms);
        self.tick_ms = elapsed_ms;
        if delta > 0 {
            let mut fired: Vec<(u32, u32, u64)> = Vec::new(); // (hwnd, tid, timer_id)
            for t in &mut self.timers {
                t.elapsed = t.elapsed.saturating_add(delta);
                if t.elapsed >= t.interval {
                    t.elapsed = 0;
                    fired.push((t.hwnd, t.tid, t.timer_id));
                }
            }
            for (hwnd, tid, timer_id) in fired {
                let q = self.msg_queues.entry(tid).or_default();
                q.push_back(GuestMsg {
                    hwnd:    hwnd as u64,
                    message: WM_TIMER,
                    w_param: timer_id,
                    ..Default::default()
                });
            }
        }
    }

    // ── NtUserShowWindow ─────────────────────────────────────────────────────
    pub fn show_window(&mut self, hwnd: u32, cmd: i32) -> u64 {
        if let Some(ws) = self.windows.get_mut(&hwnd) {
            match cmd {
                0 => { ws.visible = false; ws.window.set_visible(false); }
                _ => { ws.visible = true;  ws.window.set_visible(true);  }
            }
        }
        1u64
    }

    // ── NtUserDestroyWindow ──────────────────────────────────────────────────
    pub fn destroy_window(&mut self, hwnd: u32) -> u64 {
        if let Some(ws) = self.windows.remove(&hwnd) {
            let tid = ws.owner_tid;
            let q = self.msg_queues.entry(tid).or_default();
            q.push_back(GuestMsg { hwnd: hwnd as u64, message: WM_DESTROY, ..Default::default() });
        }
        if self.foreground == hwnd { self.foreground = 0; }
        1u64
    }

    // ── NtUserGetDC / NtUserGetDCEx ──────────────────────────────────────────
    pub fn get_dc(&mut self, hwnd: u32) -> u64 {
        let hdc = self.alloc_hdc();
        self.dcs.insert(hdc, DcState::new(hwnd));
        hdc as u64
    }

    // ── NtUserReleaseDC ──────────────────────────────────────────────────────
    pub fn release_dc(&mut self, _hwnd: u32, hdc: u32) -> u64 {
        self.dcs.remove(&hdc);
        1u64
    }

    // ── NtUserBeginPaint ─────────────────────────────────────────────────────
    pub fn begin_paint(&mut self, hwnd: u32) -> u64 {
        self.get_dc(hwnd)
    }

    // ── NtUserEndPaint ───────────────────────────────────────────────────────
    pub fn end_paint(&mut self, hwnd: u32, hdc: u32) -> u64 {
        if let Some(ws) = self.windows.get_mut(&hwnd) {
            ws.present();
        }
        self.dcs.remove(&hdc);
        1u64
    }

    // ── NtUserSetWindowPos ───────────────────────────────────────────────────
    pub fn set_window_pos(&mut self, hwnd: u32, x: i32, y: i32, w: u32, h: u32) -> u64 {
        if let Some(ws) = self.windows.get_mut(&hwnd) {
            if w > 0 && h > 0 {
                let _ = ws.window.request_inner_size(PhysicalSize::new(w, h));
                ws.width  = w;
                ws.height = h;
                ws.ensure_fb();
            }
            ws.window.set_outer_position(winit::dpi::PhysicalPosition::new(x, y));
        }
        0u64
    }

    // ── NtUserMoveWindow ─────────────────────────────────────────────────────
    pub fn move_window(&mut self, hwnd: u32, x: i32, y: i32, w: u32, h: u32) -> u64 {
        self.set_window_pos(hwnd, x, y, w, h)
    }

    // ── NtUserInvalidateRect ─────────────────────────────────────────────────
    pub fn invalidate_rect(&mut self, hwnd: u32) -> u64 {
        if let Some(ws) = self.windows.get(&hwnd) {
            ws.window.request_redraw();
        }
        1u64
    }

    // ── NtUserValidateRect ───────────────────────────────────────────────────
    pub fn validate_rect(&mut self, _hwnd: u32) -> u64 { 1u64 }

    // ── NtUserPostQuitMessage ────────────────────────────────────────────────
    pub fn post_quit(&mut self, tid: u32, exit_code: i32) {
        let q = self.msg_queues.entry(tid).or_default();
        q.push_back(GuestMsg {
            message: WM_QUIT,
            w_param: exit_code as u64,
            ..Default::default()
        });
    }

    // ── NtUserSetTimer ───────────────────────────────────────────────────────
    pub fn set_timer(&mut self, hwnd: u32, tid: u32, timer_id: u64, interval_ms: u32) -> u64 {
        self.timers.retain(|t| !(t.hwnd == hwnd && t.timer_id == timer_id));
        self.timers.push(Timer { hwnd, tid, timer_id, interval: interval_ms.max(1), elapsed: 0 });
        timer_id
    }

    // ── NtUserKillTimer ──────────────────────────────────────────────────────
    pub fn kill_timer(&mut self, hwnd: u32, timer_id: u64) -> u64 {
        let before = self.timers.len();
        self.timers.retain(|t| !(t.hwnd == hwnd && t.timer_id == timer_id));
        if self.timers.len() < before { 1 } else { 0 }
    }

    // ── NtUserSetCursor ──────────────────────────────────────────────────────
    pub fn set_cursor(&mut self, _hcursor: u32) -> u64 { 0 }

    // ── NtUserGetForegroundWindow ─────────────────────────────────────────────
    pub fn foreground_hwnd(&self) -> u32 { self.foreground }

    // ── NtGdiDeleteObjectApp ─────────────────────────────────────────────────
    pub fn delete_object(&mut self, h: u32) -> u64 {
        self.gdi_objects.remove(&h);
        self.dcs.remove(&h);
        1u64
    }

    // ── NtGdiSelectBitmap/Brush/Pen/Font ─────────────────────────────────────
    pub fn select_object(&mut self, hdc: u32, hobj: u32) -> u64 {
        let kind = self.gdi_objects.get(&hobj).map(|o| o.kind).unwrap_or(GdiKind::Other);
        if let Some(dc) = self.dcs.get_mut(&hdc) {
            let prev = match kind {
                GdiKind::Bitmap => { let p = dc.sel_bitmap; dc.sel_bitmap = hobj; p }
                GdiKind::Brush  => { let p = dc.sel_brush;  dc.sel_brush  = hobj; p }
                GdiKind::Pen    => { let p = dc.sel_pen;    dc.sel_pen    = hobj; p }
                GdiKind::Font   => { let p = dc.sel_font;   dc.sel_font   = hobj; p }
                _               => 0,
            };
            return prev as u64;
        }
        0u64
    }

    // ── NtGdiGetStockObject ──────────────────────────────────────────────────
    pub fn get_stock_object(&mut self, idx: u32) -> u64 {
        0x8000_0000u64 | idx as u64
    }

    // ── NtGdiCreateCompatibleDC ──────────────────────────────────────────────
    pub fn create_compatible_dc(&mut self, hdc: u32) -> u64 {
        let hwnd = self.dcs.get(&hdc).map(|d| d.hwnd).unwrap_or(0);
        self.get_dc(hwnd)
    }

    // ── NtGdiCreateCompatibleBitmap ──────────────────────────────────────────
    pub fn create_compatible_bitmap(&mut self, _hdc: u32, _w: u32, _h: u32) -> u64 {
        self.alloc_gdi_typed(GdiKind::Bitmap) as u64
    }

    // ── NtGdiBitBlt ──────────────────────────────────────────────────────────
    pub fn bit_blt(&mut self, hdc: u32) -> u64 {
        let hwnd = match self.dcs.get(&hdc) {
            Some(dc) => dc.hwnd,
            None => return 0,
        };
        if let Some(ws) = self.windows.get_mut(&hwnd) {
            ws.ensure_fb();
            ws.framebuf.fill(0x00_20_20_20);
            ws.present();
        }
        1u64
    }

    // ── NtGdiStretchBlt ──────────────────────────────────────────────────────
    pub fn stretch_blt(&mut self, hdc: u32) -> u64 { self.bit_blt(hdc) }

    // ── NtGdiRectangle ───────────────────────────────────────────────────────
    pub fn gdi_rectangle(&mut self, hdc: u32, x0: i32, y0: i32, x1: i32, y1: i32) -> u64 {
        let (hwnd, color) = match self.dcs.get(&hdc) {
            Some(dc) => (dc.hwnd, dc.bk_color),
            None => return 0,
        };
        if let Some(ws) = self.windows.get_mut(&hwnd) {
            ws.ensure_fb();
            let w = ws.width as i32;
            let h = ws.height as i32;
            let lx = x0.max(0) as u32;
            let ly = y0.max(0) as u32;
            let rx = x1.min(w) as u32;
            let ry = y1.min(h) as u32;
            for row in ly..ry {
                let base = row as usize * ws.width as usize;
                for col in lx..rx {
                    if let Some(px) = ws.framebuf.get_mut(base + col as usize) {
                        *px = color;
                    }
                }
            }
        }
        1u64
    }

    // ── NtGdiSetBkColor / NtGdiSetTextColor ──────────────────────────────────
    pub fn set_bk_color(&mut self, hdc: u32, color: u32) -> u64 {
        if let Some(dc) = self.dcs.get_mut(&hdc) {
            let prev = dc.bk_color; dc.bk_color = color; return prev as u64;
        }
        0u64
    }

    pub fn set_text_color(&mut self, hdc: u32, color: u32) -> u64 {
        if let Some(dc) = self.dcs.get_mut(&hdc) {
            let prev = dc.text_color; dc.text_color = color; return prev as u64;
        }
        0u64
    }

    // ── NtGdiMoveTo / NtGdiLineTo ─────────────────────────────────────────────
    pub fn move_to(&mut self, hdc: u32, x: i32, y: i32) -> u64 {
        if let Some(dc) = self.dcs.get_mut(&hdc) { dc.cur_x = x; dc.cur_y = y; }
        1u64
    }

    pub fn line_to(&mut self, hdc: u32, x1: i32, y1: i32) -> u64 {
        let (hwnd, x0, y0, color) = match self.dcs.get_mut(&hdc) {
            Some(dc) => { let r = (dc.hwnd, dc.cur_x, dc.cur_y, dc.text_color); dc.cur_x = x1; dc.cur_y = y1; r }
            None => return 0,
        };
        if let Some(ws) = self.windows.get_mut(&hwnd) {
            ws.ensure_fb();
            draw_line(&mut ws.framebuf, ws.width, ws.height, x0, y0, x1, y1, color);
        }
        1u64
    }

    // ── NtUserQueryWindow ────────────────────────────────────────────────────
    // cmd: 0=HWND_DESKTOP, 1=HWND_OWNER, 2=HWND_PARENT, 3=HWND_NEXT,
    //      4=HWND_PREV, 5=HWND_CHILD, 6=HWND_ISICONIC, 7=HWND_ISVISIBLE,
    //      8=HWND_LASTACTIVE, 9=HWND_HINSTANCE, 10=HWND_WNDPROC,
    //      11=HWND_STYLE, 12=HWND_EXSTYLE, 13=HWND_ID, 14=HWND_ISARRANGED
    pub fn query_window(&self, hwnd: u32, cmd: u32) -> u64 {
        match cmd {
            6  => if self.windows.contains_key(&hwnd) { 0 } else { 0 }, // IsIconic
            7  => if self.windows.get(&hwnd).map(|w| w.visible).unwrap_or(false) { 1 } else { 0 },
            11 => 0x14CF_0000u64, // WS_OVERLAPPEDWINDOW | WS_VISIBLE
            12 => 0x0000_0100u64, // WS_EX_WINDOWEDGE
            _  => 0,
        }
    }

    // ── NtUserGetUpdateRect ──────────────────────────────────────────────────
    // Returns 1 if update region non-empty; writes RECT to out_gpa (caller handles)
    pub fn get_update_rect(&self, hwnd: u32) -> (bool, i32, i32, i32, i32) {
        if let Some(ws) = self.windows.get(&hwnd) {
            (true, 0, 0, ws.width as i32, ws.height as i32)
        } else {
            (false, 0, 0, 0, 0)
        }
    }

    // ── NtUserGetWindowPlacement ─────────────────────────────────────────────
    pub fn get_window_placement(&self, hwnd: u32) -> (i32, i32, u32, u32) {
        if let Some(ws) = self.windows.get(&hwnd) {
            (0, 0, ws.width, ws.height)
        } else {
            (0, 0, 800, 600)
        }
    }

    // ── NtUserGetKeyState ────────────────────────────────────────────────────
    pub fn get_key_state(&self, _vk: u32) -> u64 { 0 }
    pub fn get_async_key_state(&self, _vk: u32) -> u64 { 0 }
    pub fn get_keyboard_state(&self, _buf_gpa: u64) -> u64 { 1 }

    // ── NtUserGetQueueStatus ─────────────────────────────────────────────────
    pub fn get_queue_status(&self, tid: u32) -> u64 {
        let has_msg = self.msg_queues.get(&tid).map(|q| !q.is_empty()).unwrap_or(false);
        if has_msg { 0x0004_0004 } else { 0 } // QS_POSTMESSAGE
    }

    // ── NtUserGetDoubleClickTime ─────────────────────────────────────────────
    pub fn get_double_click_time(&self) -> u64 { 500 }

    // ── NtUserGetCaretBlinkTime ──────────────────────────────────────────────
    pub fn get_caret_blink_time(&self) -> u64 { 530 }

    // ── NtUserSystemParametersInfo ───────────────────────────────────────────
    // uiAction values we care about:
    //   SPI_GETWORKAREA        = 0x0030 → write RECT(0,0,w,h) to pvParam
    //   SPI_GETNONCLIENTMETRICS= 0x0029 → stub
    //   SPI_GETFONTSMOOTHING   = 0x004A → return 1
    //   SPI_GETICONTITLELOGFONT= 0x001F → stub
    //   SPI_GETANIMATION       = 0x0048 → stub
    pub fn system_parameters_info(&self, action: u32) -> (u64, Option<[i32; 4]>) {
        match action {
            0x0030 => (1, Some([0, 0, 1920, 1080])), // SPI_GETWORKAREA
            0x004A => (1, None),                      // SPI_GETFONTSMOOTHING → true
            _      => (1, None),
        }
    }

    // ── NtGdiCreateSolidBrush ────────────────────────────────────────────────
    pub fn create_solid_brush(&mut self, color: u32) -> u64 {
        let h = self.alloc_gdi_typed(GdiKind::Brush);
        // Store color in a side table keyed by handle
        self.brush_colors.insert(h, color);
        h as u64
    }

    // ── NtGdiCreatePen ───────────────────────────────────────────────────────
    pub fn create_pen(&mut self, _style: u32, _width: u32, color: u32) -> u64 {
        let h = self.alloc_gdi_typed(GdiKind::Pen);
        self.pen_colors.insert(h, color);
        h as u64
    }

    // ── NtGdiExtGetObjectW ───────────────────────────────────────────────────
    // Returns object size; stub returns 0 (caller checks)
    pub fn ext_get_object(&self, _h: u32) -> u64 { 0 }

    // ── NtGdiEllipse ─────────────────────────────────────────────────────────
    pub fn gdi_ellipse(&mut self, hdc: u32, x0: i32, y0: i32, x1: i32, y1: i32) -> u64 {
        // Approximate with filled rectangle for now
        self.gdi_rectangle(hdc, x0, y0, x1, y1)
    }

    // ── NtGdiPolyPolyDraw ────────────────────────────────────────────────────
    pub fn poly_poly_draw(&mut self, _hdc: u32) -> u64 { 1 }

    // ── NtGdiFillRgn ─────────────────────────────────────────────────────────
    pub fn fill_rgn(&mut self, hdc: u32, _hrgn: u32, hbrush: u32) -> u64 {
        let (hwnd, color) = {
            let dc = match self.dcs.get(&hdc) { Some(d) => d, None => return 0 };
            let c = self.brush_colors.get(&hbrush).copied().unwrap_or(dc.bk_color);
            (dc.hwnd, c)
        };
        if let Some(ws) = self.windows.get_mut(&hwnd) {
            ws.ensure_fb();
            ws.framebuf.fill(color);
        }
        1u64
    }

    // ── alloc_gdi_handle (public, used by handlers) ───────────────────────────
    pub fn alloc_gdi_handle(&mut self) -> u64 {
        self.alloc_gdi_typed(GdiKind::Other) as u64
    }

    // ── peek_message ─────────────────────────────────────────────────────────
    pub fn peek_message(&mut self, tid: u32, out: &mut GuestMsg) -> bool {
        if let Some(q) = self.msg_queues.get_mut(&tid) {
            if let Some(msg) = q.pop_front() { *out = msg; return true; }
        }
        false
    }

    // ── on_window_event ──────────────────────────────────────────────────────
    pub fn on_window_event(&mut self, win_id: WindowId, event: &WindowEvent) {
        let hwnd = match self.windows.iter().find(|(_, ws)| ws.window.id() == win_id) {
            Some((&h, _)) => h,
            None => return,
        };
        let tid = self.windows[&hwnd].owner_tid;
        let q = self.msg_queues.entry(tid).or_default();
        match event {
            WindowEvent::CloseRequested => {
                q.push_back(GuestMsg { hwnd: hwnd as u64, message: WM_CLOSE, ..Default::default() });
            }
            WindowEvent::RedrawRequested => {
                if let Some(ws) = self.windows.get_mut(&hwnd) { ws.present(); }
                q.push_back(GuestMsg { hwnd: hwnd as u64, message: WM_PAINT, ..Default::default() });
            }
            WindowEvent::Resized(sz) => {
                if let Some(ws) = self.windows.get_mut(&hwnd) {
                    ws.width  = sz.width.max(1);
                    ws.height = sz.height.max(1);
                    ws.ensure_fb();
                }
                let packed = ((sz.height as u64) << 16) | (sz.width as u64 & 0xFFFF);
                q.push_back(GuestMsg { hwnd: hwnd as u64, message: WM_SIZE, l_param: packed, ..Default::default() });
            }
            WindowEvent::KeyboardInput { event: ke, .. } => {
                let msg = if ke.state == winit::event::ElementState::Pressed { WM_KEYDOWN } else { WM_KEYUP };
                let vk = winit_key_to_vk(&ke.logical_key);
                q.push_back(GuestMsg { hwnd: hwnd as u64, message: msg, w_param: vk, ..Default::default() });
            }
            WindowEvent::CursorMoved { position, .. } => {
                let packed = ((position.y as i32 as u64) << 32) | (position.x as i32 as u64 & 0xFFFF_FFFF);
                q.push_back(GuestMsg { hwnd: hwnd as u64, message: WM_MOUSEMOVE, l_param: packed, ..Default::default() });
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let msg = match (button, state) {
                    (winit::event::MouseButton::Left,  winit::event::ElementState::Pressed)  => WM_LBUTTONDOWN,
                    (winit::event::MouseButton::Left,  winit::event::ElementState::Released) => WM_LBUTTONUP,
                    (winit::event::MouseButton::Right, winit::event::ElementState::Pressed)  => WM_RBUTTONDOWN,
                    (winit::event::MouseButton::Right, winit::event::ElementState::Released) => WM_RBUTTONUP,
                    _ => return,
                };
                q.push_back(GuestMsg { hwnd: hwnd as u64, message: msg, ..Default::default() });
            }
            _ => {}
        }
    }
}

// ── Bresenham line ────────────────────────────────────────────────────────────
fn draw_line(fb: &mut Vec<u32>, w: u32, h: u32, x0: i32, y0: i32, x1: i32, y1: i32, color: u32) {
    let (mut x, mut y) = (x0, y0);
    let dx = (x1 - x0).abs();
    let dy = (y1 - y0).abs();
    let sx = if x0 < x1 { 1i32 } else { -1 };
    let sy = if y0 < y1 { 1i32 } else { -1 };
    let mut err = dx - dy;
    loop {
        if x >= 0 && y >= 0 && (x as u32) < w && (y as u32) < h {
            fb[y as usize * w as usize + x as usize] = color;
        }
        if x == x1 && y == y1 { break; }
        let e2 = 2 * err;
        if e2 > -dy { err -= dy; x += sx; }
        if e2 <  dx { err += dx; y += sy; }
    }
}

// ── winit key → Windows VK ────────────────────────────────────────────────────
fn winit_key_to_vk(key: &winit::keyboard::Key) -> u64 {
    use winit::keyboard::{Key, NamedKey};
    match key {
        Key::Named(NamedKey::Enter)      => 0x0D,
        Key::Named(NamedKey::Escape)     => 0x1B,
        Key::Named(NamedKey::Space)      => 0x20,
        Key::Named(NamedKey::Backspace)  => 0x08,
        Key::Named(NamedKey::Tab)        => 0x09,
        Key::Named(NamedKey::ArrowLeft)  => 0x25,
        Key::Named(NamedKey::ArrowUp)    => 0x26,
        Key::Named(NamedKey::ArrowRight) => 0x27,
        Key::Named(NamedKey::ArrowDown)  => 0x28,
        Key::Named(NamedKey::Delete)     => 0x2E,
        Key::Named(NamedKey::Home)       => 0x24,
        Key::Named(NamedKey::End)        => 0x23,
        Key::Named(NamedKey::PageUp)     => 0x21,
        Key::Named(NamedKey::PageDown)   => 0x22,
        Key::Named(NamedKey::F1)         => 0x70,
        Key::Named(NamedKey::F2)         => 0x71,
        Key::Named(NamedKey::F3)         => 0x72,
        Key::Named(NamedKey::F4)         => 0x73,
        Key::Named(NamedKey::F5)         => 0x74,
        Key::Named(NamedKey::F6)         => 0x75,
        Key::Named(NamedKey::F7)         => 0x76,
        Key::Named(NamedKey::F8)         => 0x77,
        Key::Named(NamedKey::F9)         => 0x78,
        Key::Named(NamedKey::F10)        => 0x79,
        Key::Named(NamedKey::F11)        => 0x7A,
        Key::Named(NamedKey::F12)        => 0x7B,
        Key::Character(s) => s.chars().next().unwrap_or('\0').to_ascii_uppercase() as u64,
        _ => 0,
    }
}
