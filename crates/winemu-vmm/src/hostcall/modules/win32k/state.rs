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
use winit::error::OsError;
use winit::event::WindowEvent;
use winit::event_loop::ActiveEventLoop;
use winit::window::{Window, WindowId};

const USER_DEFAULT_SCREEN_DPI: u32 = 96;
const NTUSER_DPI_UNAWARE: u32 = 0x6010;
const NTUSER_DPI_CONTEXT_FLAG_PROCESS: u32 = 0x8000_0000;
const DEFAULT_SCREEN_WIDTH: u32 = 800;
const DEFAULT_SCREEN_HEIGHT: u32 = 600;
const FIRST_GDI_HANDLE: u32 = 32;
const STOCK_WHITE_BRUSH: u32 = FIRST_GDI_HANDLE;
const STOCK_BLACK_BRUSH: u32 = FIRST_GDI_HANDLE + 4;
const STOCK_BLACK_PEN: u32 = FIRST_GDI_HANDLE + 7;
const STOCK_SYSTEM_FONT: u32 = FIRST_GDI_HANDLE + 13;
const STOCK_DEFAULT_GUI_FONT: u32 = FIRST_GDI_HANDLE + 17;
const STOCK_DC_BRUSH: u32 = FIRST_GDI_HANDLE + 18;
const STOCK_DC_PEN: u32 = FIRST_GDI_HANDLE + 19;
const STOCK_DEFAULT_BITMAP: u32 = FIRST_GDI_HANDLE + 20;
const HDC_RANGE_START: u32 = 0x2000;
const HDC_RANGE_END: u32 = 0x3000;
const BITMAP_RANGE_START: u32 = 0x3000;
const BITMAP_RANGE_END: u32 = 0x3800;
const BRUSH_RANGE_START: u32 = 0x3800;
const BRUSH_RANGE_END: u32 = 0x4000;
const PEN_RANGE_START: u32 = 0x4000;
const PEN_RANGE_END: u32 = 0x4800;
const FONT_RANGE_START: u32 = 0x4800;
const FONT_RANGE_END: u32 = 0x5800;
const OTHER_RANGE_START: u32 = 0x5800;
const OTHER_RANGE_END: u32 = 0x6000;
const FIRST_CLASS_ATOM: u16 = 0xC000;
const POPUPMENU_CLASS_ATOM: u16 = 32768;
const DESKTOP_CLASS_ATOM: u16 = 32769;
const DIALOG_CLASS_ATOM: u16 = 32770;
const ICONTITLE_CLASS_ATOM: u16 = 32772;
const CS_VREDRAW: u32 = 0x0000_0001;
const CS_HREDRAW: u32 = 0x0000_0002;
const CS_DBLCLKS: u32 = 0x0000_0008;
const CS_PARENTDC: u32 = 0x0000_0080;
const CS_SAVEBITS: u32 = 0x0000_0800;
const CS_DROPSHADOW: u32 = 0x0002_0000;
const COLOR_BACKGROUND: u64 = 1;
const COLOR_MENU: u64 = 4;
const COLOR_APPWORKSPACE: u64 = 12;
const DLGWINDOWEXTRA: i32 = 30;
const SCROLL_BAR_WIN_DATA_SIZE: i32 = 28;
const BUILTIN_WINPROC_HANDLE: u64 = 0xffff_0000;
const NTUSER_WNDPROC_SCROLLBAR: u64 = 0;
const NTUSER_WNDPROC_MESSAGE: u64 = 1;
const NTUSER_WNDPROC_MENU: u64 = 2;
const NTUSER_WNDPROC_DESKTOP: u64 = 3;
const NTUSER_WNDPROC_ICONTITLE: u64 = 5;
const NTUSER_WNDPROC_BUTTON: u64 = 7;
const NTUSER_WNDPROC_COMBO: u64 = 8;
const NTUSER_WNDPROC_COMBOLBOX: u64 = 9;
const NTUSER_WNDPROC_DIALOG: u64 = 10;
const NTUSER_WNDPROC_EDIT: u64 = 11;
const NTUSER_WNDPROC_LISTBOX: u64 = 12;
const NTUSER_WNDPROC_MDICLIENT: u64 = 13;
const NTUSER_WNDPROC_STATIC: u64 = 14;
const NTUSER_WNDPROC_IME: u64 = 15;
// ── WM_ constants ─────────────────────────────────────────────────────────────
pub const WM_PAINT: u32 = 0x000F;
pub const WM_TIMER: u32 = 0x0113;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_RBUTTONUP: u32 = 0x0205;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
#[allow(dead_code)]
pub const WM_CHAR: u32 = 0x0102;
pub const WM_DESTROY: u32 = 0x0002;
#[allow(dead_code)]
pub const WM_ERASEBKGND: u32 = 0x0014;

// ── Guest MSG layout (matches Windows MSG struct) ────────────────────────────
#[derive(Clone, Copy, Default)]
pub struct GuestMsg {
    pub hwnd: u64,
    pub message: u32,
    pub w_param: u64,
    pub l_param: u64,
    pub time: u32,
    pub pt_x: i32,
    #[allow(dead_code)]
    pub pt_y: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ClassLookupKey {
    Atom(u16),
    Name(String),
}

impl ClassLookupKey {
    pub fn from_name(name: &str) -> Self {
        Self::Name(name.to_lowercase())
    }
}

const fn builtin_wndproc(index: u64) -> u64 {
    BUILTIN_WINPROC_HANDLE | index
}

const fn system_color_brush(index: u64) -> u64 {
    index + 1
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GuestClientMenuName {
    pub name_a: u64,
    pub name_w: u64,
    pub name_us: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GuestWndClassEx {
    pub style: u32,
    pub lpfn_wnd_proc: u64,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub h_instance: u64,
    pub h_icon: u64,
    pub h_cursor: u64,
    pub hbr_background: u64,
    pub lpsz_menu_name: u64,
    pub lpsz_class_name: u64,
    pub h_icon_sm: u64,
}

#[derive(Clone, Debug)]
struct RegisteredClass {
    owner_pid: u32,
    atom: u16,
    key: ClassLookupKey,
    instance: u64,
    info: GuestWndClassEx,
    menu_name: GuestClientMenuName,
}

// ── GDI object kinds ──────────────────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GdiKind {
    Bitmap,
    Brush,
    Pen,
    #[allow(dead_code)]
    Font,
    #[allow(dead_code)]
    Region,
    Other,
}

struct GdiObject {
    kind: GdiKind,
}

#[derive(Clone, Copy, Default)]
struct StockObjects {
    default_bitmap: u32,
    white_brush: u32,
    dc_brush: u32,
    black_pen: u32,
    dc_pen: u32,
    system_font: u32,
    default_gui_font: u32,
}

impl StockObjects {
    fn is_stock(self, handle: u32) -> bool {
        (FIRST_GDI_HANDLE..=STOCK_DEFAULT_BITMAP).contains(&Win32kState::raw_gdi_handle(handle))
    }
}

#[derive(Clone, Copy)]
struct FontInfo {
    height: i32,
    width: i32,
    weight: i32,
    italic: u8,
    underline: u8,
    strike_out: u8,
    charset: u8,
    pitch_and_family: u8,
    logfont: [u8; 92],
}

impl FontInfo {
    const LOGFONTW_SIZE: usize = 92;
    const TEXTMETRICW_SIZE: usize = 60;
    const VARIABLE_SWISS: u8 = 0x22;

    fn build_logfont(
        height: i32,
        width: i32,
        weight: i32,
        italic: u8,
        underline: u8,
        strike_out: u8,
        charset: u8,
        pitch_and_family: u8,
        face_name: &str,
    ) -> [u8; Self::LOGFONTW_SIZE] {
        let mut logfont = [0u8; Self::LOGFONTW_SIZE];
        logfont[0..4].copy_from_slice(&height.to_le_bytes());
        logfont[4..8].copy_from_slice(&width.to_le_bytes());
        logfont[16..20].copy_from_slice(&weight.to_le_bytes());
        logfont[20] = italic;
        logfont[21] = underline;
        logfont[22] = strike_out;
        logfont[23] = charset;
        logfont[27] = pitch_and_family;
        for (idx, ch) in face_name.encode_utf16().take(32).enumerate() {
            let off = 28 + idx * 2;
            logfont[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        logfont
    }

    fn stock_font(
        height: i32,
        width: i32,
        weight: i32,
        charset: u8,
        pitch_and_family: u8,
        face_name: &str,
    ) -> Self {
        Self {
            height,
            width,
            weight,
            italic: 0,
            underline: 0,
            strike_out: 0,
            charset,
            pitch_and_family,
            logfont: Self::build_logfont(
                height,
                width,
                weight,
                0,
                0,
                0,
                charset,
                pitch_and_family,
                face_name,
            ),
        }
    }

    fn stock_system() -> Self {
        Self::stock_font(16, 7, 700, 0, Self::VARIABLE_SWISS, "System")
    }

    fn stock_default_gui() -> Self {
        Self::stock_font(-11, 0, 400, 0, Self::VARIABLE_SWISS, "MS Shell Dlg")
    }

    fn system_default() -> Self {
        Self::stock_default_gui()
    }

    fn from_logfont_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::LOGFONTW_SIZE {
            return None;
        }
        let mut logfont = [0u8; Self::LOGFONTW_SIZE];
        logfont.copy_from_slice(&bytes[..Self::LOGFONTW_SIZE]);
        let read_i32 = |off| -> Option<i32> {
            Some(i32::from_le_bytes(
                bytes.get(off..off + 4)?.try_into().ok()?,
            ))
        };
        Some(Self {
            height: read_i32(0)?,
            width: read_i32(4)?,
            weight: read_i32(16)?,
            italic: *bytes.get(20)?,
            underline: *bytes.get(21)?,
            strike_out: *bytes.get(22)?,
            charset: *bytes.get(23)?,
            pitch_and_family: *bytes.get(27)?,
            logfont,
        })
    }

    fn logfont_bytes(self) -> [u8; Self::LOGFONTW_SIZE] {
        self.logfont
    }

    fn text_metric_bytes(self) -> [u8; Self::TEXTMETRICW_SIZE] {
        let height = self.height.unsigned_abs().max(16) as i32;
        let internal_leading = (height / 8).max(1);
        let ascent = (height - internal_leading).max(1);
        let descent = (height - ascent).max(1);
        let ave_char_width = if self.width != 0 {
            self.width.unsigned_abs().max(1) as i32
        } else {
            (height / 2).max(7)
        };
        let max_char_width = ave_char_width.max(height * 2 / 3);

        let mut buf = [0u8; Self::TEXTMETRICW_SIZE];
        fn write_i32(buf: &mut [u8], off: &mut usize, value: i32) {
            buf[*off..*off + 4].copy_from_slice(&value.to_le_bytes());
            *off += 4;
        }
        fn write_u16(buf: &mut [u8], off: &mut usize, value: u16) {
            buf[*off..*off + 2].copy_from_slice(&value.to_le_bytes());
            *off += 2;
        }
        fn write_u8(buf: &mut [u8], off: &mut usize, value: u8) {
            buf[*off] = value;
            *off += 1;
        }

        let mut off = 0usize;
        write_i32(&mut buf, &mut off, height);
        write_i32(&mut buf, &mut off, ascent);
        write_i32(&mut buf, &mut off, descent);
        write_i32(&mut buf, &mut off, internal_leading);
        write_i32(&mut buf, &mut off, 0);
        write_i32(&mut buf, &mut off, ave_char_width);
        write_i32(&mut buf, &mut off, max_char_width);
        write_i32(&mut buf, &mut off, self.weight.max(0));
        write_i32(&mut buf, &mut off, 0);
        write_i32(&mut buf, &mut off, USER_DEFAULT_SCREEN_DPI as i32);
        write_i32(&mut buf, &mut off, USER_DEFAULT_SCREEN_DPI as i32);
        write_u16(&mut buf, &mut off, 0x0020);
        write_u16(&mut buf, &mut off, 0x007e);
        write_u16(&mut buf, &mut off, 0x003f);
        write_u16(&mut buf, &mut off, 0x0020);
        write_u8(&mut buf, &mut off, self.italic);
        write_u8(&mut buf, &mut off, self.underline);
        write_u8(&mut buf, &mut off, self.strike_out);
        write_u8(&mut buf, &mut off, self.pitch_and_family);
        write_u8(&mut buf, &mut off, self.charset);
        buf
    }
}

// ── DC state ──────────────────────────────────────────────────────────────────
struct DcState {
    hwnd: u32,
    sel_bitmap: u32,
    sel_brush: u32,
    sel_pen: u32,
    sel_font: u32,
    bk_color: u32,
    text_color: u32,
    cur_x: i32,
    cur_y: i32,
}

impl DcState {
    fn new(hwnd: u32, stock: StockObjects) -> Self {
        Self {
            hwnd,
            sel_bitmap: stock.default_bitmap,
            sel_brush: stock.white_brush,
            sel_pen: stock.black_pen,
            sel_font: stock.system_font,
            bk_color: 0x00FF_FFFF,
            text_color: 0x0000_0000,
            cur_x: 0,
            cur_y: 0,
        }
    }
}

// ── Timer ─────────────────────────────────────────────────────────────────────
struct Timer {
    hwnd: u32,
    tid: u32,
    timer_id: u64,
    interval: u32, // ms
    elapsed: u32,
}

// ── Window state ─────────────────────────────────────────────────────────────
struct WinState {
    window: Arc<Window>,
    surface: Surface<Arc<Window>, Arc<Window>>,
    width: u32,
    height: u32,
    visible: bool,
    owner_tid: u32,
    // Framebuffer: XRGB8888, row-major
    framebuf: Vec<u32>,
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
        if ws_resize_surface(&mut self.surface, w, h).is_err() {
            return;
        }
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
    w: u32,
    h: u32,
) -> Result<(), ()> {
    surface
        .resize(NonZeroU32::new(w).ok_or(())?, NonZeroU32::new(h).ok_or(())?)
        .map_err(|_| ())
}

fn system_color_rgb(index: u32) -> u32 {
    match index {
        0 => 0x00c8_c8c8,  // COLOR_SCROLLBAR
        1 => 0x0000_0000,  // COLOR_BACKGROUND
        2 => 0x0099_b4d1,  // COLOR_ACTIVECAPTION
        3 => 0x00bf_cddb,  // COLOR_INACTIVECAPTION
        4 => 0x00f0_f0f0,  // COLOR_MENU
        5 => 0x00ff_ffff,  // COLOR_WINDOW
        6 => 0x0064_6464,  // COLOR_WINDOWFRAME
        7 => 0x0000_0000,  // COLOR_MENUTEXT
        8 => 0x0000_0000,  // COLOR_WINDOWTEXT
        9 => 0x0000_0000,  // COLOR_CAPTIONTEXT
        10 => 0x00b4_b4b4, // COLOR_ACTIVEBORDER
        11 => 0x00bf_cdcd, // COLOR_INACTIVEBORDER
        12 => 0x00ab_abab, // COLOR_APPWORKSPACE
        13 => 0x0033_99ff, // COLOR_HIGHLIGHT
        14 => 0x00ff_ffff, // COLOR_HIGHLIGHTTEXT
        15 => 0x00f0_f0f0, // COLOR_BTNFACE
        16 => 0x00a0_a0a0, // COLOR_BTNSHADOW
        17 => 0x006d_6d6d, // COLOR_GRAYTEXT
        18 => 0x0000_0000, // COLOR_BTNTEXT
        19 => 0x0043_4343, // COLOR_INACTIVECAPTIONTEXT
        20 => 0x00ff_ffff, // COLOR_BTNHIGHLIGHT
        21 => 0x0069_6969, // COLOR_3DDKSHADOW
        22 => 0x00e3_e3e3, // COLOR_3DLIGHT
        23 => 0x0000_0000, // COLOR_INFOTEXT
        24 => 0x00ff_ffff, // COLOR_INFOBK
        26 => 0x00cc_6600, // COLOR_HOTLIGHT
        27 => 0x00b9_d1ea, // COLOR_GRADIENTACTIVECAPTION
        28 => 0x00d7_e4f2, // COLOR_GRADIENTINACTIVECAPTION
        29 => 0x0033_99ff, // COLOR_MENUHILIGHT
        30 => 0x00f0_f0f0, // COLOR_MENUBAR
        _ => 0x00f0_f0f0,
    }
}

// ── Win32kState ───────────────────────────────────────────────────────────────
pub struct Win32kState {
    windows: HashMap<u32, WinState>,
    dcs: HashMap<u32, DcState>,
    gdi_objects: HashMap<u32, GdiObject>,
    classes: Vec<RegisteredClass>,
    msg_queues: HashMap<u32, VecDeque<GuestMsg>>,
    process_dpi_contexts: HashMap<u32, u32>,
    thread_dpi_contexts: HashMap<u32, u32>,
    timers: Vec<Timer>,
    next_hwnd: u32,
    next_hdc: u32,
    next_bitmap: u32,
    next_brush: u32,
    next_pen: u32,
    next_font: u32,
    next_other: u32,
    next_class_atom: u16,
    foreground: u32,
    pending_create: VecDeque<(u32, u32)>, // (hwnd, owner_tid)
    pending_visibility: HashMap<u32, bool>,
    tick_ms: u32,
    stock: StockObjects,
    brush_colors: HashMap<u32, u32>,
    pen_colors: HashMap<u32, u32>,
    font_infos: HashMap<u32, FontInfo>,
}

impl Win32kState {
    fn raw_gdi_handle(handle: u32) -> u32 {
        handle & 0xffff
    }

    pub fn new() -> Self {
        let mut state = Self {
            windows: HashMap::new(),
            dcs: HashMap::new(),
            gdi_objects: HashMap::new(),
            classes: Vec::new(),
            msg_queues: HashMap::new(),
            process_dpi_contexts: HashMap::new(),
            thread_dpi_contexts: HashMap::new(),
            timers: Vec::new(),
            next_hwnd: 0x1000,
            next_hdc: HDC_RANGE_START,
            next_bitmap: BITMAP_RANGE_START,
            next_brush: BRUSH_RANGE_START,
            next_pen: PEN_RANGE_START,
            next_font: FONT_RANGE_START,
            next_other: OTHER_RANGE_START,
            next_class_atom: FIRST_CLASS_ATOM,
            foreground: 0,
            pending_create: VecDeque::new(),
            pending_visibility: HashMap::new(),
            tick_ms: 0,
            stock: StockObjects::default(),
            brush_colors: HashMap::new(),
            pen_colors: HashMap::new(),
            font_infos: HashMap::new(),
        };
        state.init_stock_objects();
        state.init_builtin_classes();
        state
    }

    fn register_builtin_name(&mut self, name: &str, info: GuestWndClassEx) {
        let atom = self.alloc_class_atom();
        self.classes.push(RegisteredClass {
            owner_pid: 0,
            atom,
            key: ClassLookupKey::from_name(name),
            instance: 0,
            info,
            menu_name: GuestClientMenuName::default(),
        });
    }

    fn register_builtin_atom(&mut self, atom: u16, info: GuestWndClassEx) {
        self.classes.push(RegisteredClass {
            owner_pid: 0,
            atom,
            key: ClassLookupKey::Atom(atom),
            instance: 0,
            info,
            menu_name: GuestClientMenuName::default(),
        });
    }

    fn init_builtin_classes(&mut self) {
        let ptr_size = core::mem::size_of::<u64>() as i32;
        let handle_size = ptr_size;

        self.register_builtin_atom(
            DESKTOP_CLASS_ATOM,
            GuestWndClassEx {
                style: CS_DBLCLKS,
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_DESKTOP),
                hbr_background: system_color_brush(COLOR_BACKGROUND),
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_name(
            "Message",
            GuestWndClassEx {
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_MESSAGE),
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_name(
            "Button",
            GuestWndClassEx {
                style: CS_DBLCLKS | CS_VREDRAW | CS_HREDRAW | CS_PARENTDC,
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_BUTTON),
                cb_wnd_extra: core::mem::size_of::<u32>() as i32 + 2 * handle_size,
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_name(
            "ComboBox",
            GuestWndClassEx {
                style: CS_PARENTDC | CS_DBLCLKS | CS_HREDRAW | CS_VREDRAW,
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_COMBO),
                cb_wnd_extra: ptr_size,
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_name(
            "ComboLBox",
            GuestWndClassEx {
                style: CS_DBLCLKS | CS_SAVEBITS,
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_COMBOLBOX),
                cb_wnd_extra: ptr_size,
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_atom(
            DIALOG_CLASS_ATOM,
            GuestWndClassEx {
                style: CS_SAVEBITS | CS_DBLCLKS,
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_DIALOG),
                cb_wnd_extra: DLGWINDOWEXTRA,
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_atom(
            ICONTITLE_CLASS_ATOM,
            GuestWndClassEx {
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_ICONTITLE),
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_name(
            "IME",
            GuestWndClassEx {
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_IME),
                cb_wnd_extra: 2 * ptr_size,
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_name(
            "ListBox",
            GuestWndClassEx {
                style: CS_DBLCLKS,
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_LISTBOX),
                cb_wnd_extra: ptr_size,
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_name(
            "SysListView32",
            GuestWndClassEx {
                style: CS_DBLCLKS | CS_VREDRAW | CS_HREDRAW | CS_PARENTDC,
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_LISTBOX),
                cb_wnd_extra: ptr_size,
                hbr_background: system_color_brush(COLOR_BACKGROUND),
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_name(
            "SysTreeView32",
            GuestWndClassEx {
                style: CS_DBLCLKS | CS_VREDRAW | CS_HREDRAW | CS_PARENTDC,
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_LISTBOX),
                cb_wnd_extra: ptr_size,
                hbr_background: system_color_brush(COLOR_BACKGROUND),
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_atom(
            POPUPMENU_CLASS_ATOM,
            GuestWndClassEx {
                style: CS_DROPSHADOW | CS_SAVEBITS | CS_DBLCLKS,
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_MENU),
                cb_wnd_extra: handle_size,
                hbr_background: system_color_brush(COLOR_MENU),
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_name(
            "MDIClient",
            GuestWndClassEx {
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_MDICLIENT),
                cb_wnd_extra: 2 * ptr_size,
                hbr_background: system_color_brush(COLOR_APPWORKSPACE),
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_name(
            "ScrollBar",
            GuestWndClassEx {
                style: CS_DBLCLKS | CS_VREDRAW | CS_HREDRAW | CS_PARENTDC,
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_SCROLLBAR),
                cb_wnd_extra: SCROLL_BAR_WIN_DATA_SIZE,
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_name(
            "Static",
            GuestWndClassEx {
                style: CS_DBLCLKS | CS_PARENTDC,
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_STATIC),
                cb_wnd_extra: 2 * handle_size,
                ..GuestWndClassEx::default()
            },
        );
        self.register_builtin_name(
            "Edit",
            GuestWndClassEx {
                style: CS_DBLCLKS | CS_PARENTDC,
                lpfn_wnd_proc: builtin_wndproc(NTUSER_WNDPROC_EDIT),
                cb_wnd_extra: core::mem::size_of::<u64>() as i32,
                ..GuestWndClassEx::default()
            },
        );
    }

    fn alloc_hwnd(&mut self) -> u32 {
        let h = self.next_hwnd;
        self.next_hwnd += 4;
        h
    }

    fn alloc_gdi_typed(&mut self, kind: GdiKind) -> u32 {
        let (next, limit) = match kind {
            GdiKind::Bitmap => (&mut self.next_bitmap, BITMAP_RANGE_END),
            GdiKind::Brush => (&mut self.next_brush, BRUSH_RANGE_END),
            GdiKind::Pen => (&mut self.next_pen, PEN_RANGE_END),
            GdiKind::Font => (&mut self.next_font, FONT_RANGE_END),
            GdiKind::Region | GdiKind::Other => (&mut self.next_other, OTHER_RANGE_END),
        };
        if *next >= limit {
            log::error!("win32k: exhausted {:?} handle range", kind);
            return 0;
        }
        let h = *next;
        *next += 4;
        self.gdi_objects.insert(h, GdiObject { kind });
        h
    }

    fn alloc_hdc(&mut self) -> u32 {
        if self.next_hdc >= HDC_RANGE_END {
            log::error!("win32k: exhausted DC handle range");
            return 0;
        }
        let h = self.next_hdc;
        self.next_hdc += 4;
        h
    }

    fn install_gdi_handle(&mut self, handle: u32, kind: GdiKind) {
        self.gdi_objects.insert(handle, GdiObject { kind });
    }

    fn init_stock_objects(&mut self) {
        let default_bitmap = STOCK_DEFAULT_BITMAP;
        self.install_gdi_handle(default_bitmap, GdiKind::Bitmap);

        let white_brush = STOCK_WHITE_BRUSH;
        self.install_gdi_handle(white_brush, GdiKind::Brush);
        self.brush_colors.insert(white_brush, 0x00ff_ffff);

        self.install_gdi_handle(STOCK_BLACK_BRUSH, GdiKind::Brush);
        self.brush_colors.insert(STOCK_BLACK_BRUSH, 0x0000_0000);

        let dc_brush = STOCK_DC_BRUSH;
        self.install_gdi_handle(dc_brush, GdiKind::Brush);
        self.brush_colors.insert(dc_brush, 0x00ff_ffff);

        let black_pen = STOCK_BLACK_PEN;
        self.install_gdi_handle(black_pen, GdiKind::Pen);
        self.pen_colors.insert(black_pen, 0x0000_0000);

        let dc_pen = STOCK_DC_PEN;
        self.install_gdi_handle(dc_pen, GdiKind::Pen);
        self.pen_colors.insert(dc_pen, 0x0000_0000);

        let system_font = STOCK_SYSTEM_FONT;
        self.install_gdi_handle(system_font, GdiKind::Font);
        self.font_infos
            .insert(system_font, FontInfo::stock_system());

        let default_gui_font = STOCK_DEFAULT_GUI_FONT;
        self.install_gdi_handle(default_gui_font, GdiKind::Font);
        self.font_infos
            .insert(default_gui_font, FontInfo::stock_default_gui());

        self.stock = StockObjects {
            default_bitmap,
            white_brush,
            dc_brush,
            black_pen,
            dc_pen,
            system_font,
            default_gui_font,
        };
    }

    fn select_object_slot(&mut self, hdc: u32, slot_kind: GdiKind, hobj: u32) -> u64 {
        let hdc = Self::raw_gdi_handle(hdc);
        let hobj = Self::raw_gdi_handle(hobj);
        if hobj == 0 {
            return 0;
        }
        if let Some(obj) = self.gdi_objects.get(&hobj) {
            if obj.kind != slot_kind {
                log::debug!(
                    "win32k: rejecting select_object hdc={:#x} hobj={:#x} slot={:?} obj={:?}",
                    hdc,
                    hobj,
                    slot_kind,
                    obj.kind
                );
                return 0;
            }
        }
        let dc = match self.dcs.get_mut(&hdc) {
            Some(dc) => dc,
            None => return 0,
        };
        let slot = match slot_kind {
            GdiKind::Bitmap => &mut dc.sel_bitmap,
            GdiKind::Brush => &mut dc.sel_brush,
            GdiKind::Pen => &mut dc.sel_pen,
            GdiKind::Font => &mut dc.sel_font,
            GdiKind::Region | GdiKind::Other => return 0,
        };
        let prev = *slot;
        *slot = hobj;
        prev as u64
    }

    fn primary_screen_size(&self) -> (u32, u32) {
        self.windows
            .values()
            .next()
            .map(|ws| (ws.width.max(1), ws.height.max(1)))
            .unwrap_or((DEFAULT_SCREEN_WIDTH, DEFAULT_SCREEN_HEIGHT))
    }

    fn mm_from_pixels(px: u32, dpi: u32) -> u64 {
        let dpi = dpi.max(1);
        ((u64::from(px) * 254) / (u64::from(dpi) * 10)).max(1)
    }

    fn primary_thread_hwnd(&self, tid: u32) -> u32 {
        if self.foreground != 0
            && self
                .windows
                .get(&self.foreground)
                .map(|ws| ws.owner_tid == tid)
                .unwrap_or(false)
        {
            return self.foreground;
        }

        self.windows
            .iter()
            .filter(|(_, ws)| ws.owner_tid == tid)
            .map(|(&hwnd, ws)| (!ws.visible, hwnd))
            .min()
            .map(|(_, hwnd)| hwnd)
            .unwrap_or(0)
    }

    fn class_instance_matches(registered: u64, query: u64) -> bool {
        if query == 0 || registered == 0 || registered == query {
            return true;
        }
        registered > 0xffff && query > 0xffff && (registered & !0xffff) == (query & !0xffff)
    }

    fn alloc_class_atom(&mut self) -> u16 {
        let atom = self.next_class_atom;
        self.next_class_atom = self.next_class_atom.saturating_add(1);
        atom
    }

    pub fn register_class(
        &mut self,
        owner_pid: u32,
        key: ClassLookupKey,
        info: GuestWndClassEx,
        menu_name: Option<GuestClientMenuName>,
        is_ansi: bool,
    ) -> u16 {
        if let Some(existing) = self.classes.iter().find(|class| {
            class.owner_pid == owner_pid
                && class.key == key
                && Self::class_instance_matches(class.instance, info.h_instance)
        }) {
            return existing.atom;
        }
        if let Some(existing) = self
            .classes
            .iter()
            .find(|class| class.owner_pid == 0 && class.key == key)
        {
            return existing.atom;
        }

        let mut menu_name = menu_name.unwrap_or_default();
        if menu_name.name_a == 0 && menu_name.name_w == 0 && menu_name.name_us == 0 {
            if is_ansi {
                menu_name.name_a = info.lpsz_menu_name;
            } else {
                menu_name.name_w = info.lpsz_menu_name;
            }
        }

        let atom = self.alloc_class_atom();
        self.classes.push(RegisteredClass {
            owner_pid,
            atom,
            key,
            instance: info.h_instance,
            info,
            menu_name,
        });
        atom
    }

    pub fn get_class_info(
        &self,
        owner_pid: u32,
        instance: u64,
        key: &ClassLookupKey,
    ) -> Option<(u16, GuestWndClassEx, GuestClientMenuName)> {
        self.classes
            .iter()
            .rev()
            .find(|class| {
                class.owner_pid == owner_pid
                    && &class.key == key
                    && Self::class_instance_matches(class.instance, instance)
            })
            .or_else(|| {
                self.classes
                    .iter()
                    .find(|class| class.owner_pid == 0 && &class.key == key)
            })
            .map(|class| (class.atom, class.info, class.menu_name))
    }

    // ── NtUserCreateWindowEx ─────────────────────────────────────────────────
    pub fn create_window_deferred(&mut self, owner_tid: u32) -> u64 {
        let hwnd = self.alloc_hwnd();
        self.pending_create.push_back((hwnd, owner_tid));
        self.pending_visibility.insert(hwnd, false);
        if self.foreground == 0 {
            self.foreground = hwnd;
        }
        hwnd as u64
    }

    fn flush_pending_creates(
        &mut self,
        mut create_window: impl FnMut(winit::window::WindowAttributes) -> Result<Window, OsError>,
    ) {
        while let Some((hwnd, owner_tid)) = self.pending_create.pop_front() {
            let title = format!("WinEmu hwnd={:#x}", hwnd);
            let attrs = winit::window::Window::default_attributes()
                .with_title(title)
                .with_inner_size(PhysicalSize::new(800u32, 600u32));
            let win = match create_window(attrs) {
                Ok(win) => win,
                Err(e) => {
                    log::error!("win32k: create_window failed hwnd={:#x}: {}", hwnd, e);
                    continue;
                }
            };
            let win = Arc::new(win);
            let ctx = match softbuffer::Context::new(win.clone()) {
                Ok(ctx) => ctx,
                Err(e) => {
                    log::error!("win32k: softbuffer context failed hwnd={:#x}: {}", hwnd, e);
                    continue;
                }
            };
            let surface = match softbuffer::Surface::new(&ctx, win.clone()) {
                Ok(surface) => surface,
                Err(e) => {
                    log::error!("win32k: softbuffer surface failed hwnd={:#x}: {}", hwnd, e);
                    continue;
                }
            };
            let mut ws = WinState {
                window: win,
                surface,
                width: 800,
                height: 600,
                visible: self.pending_visibility.remove(&hwnd).unwrap_or(false),
                owner_tid,
                framebuf: Vec::new(),
            };
            ws.window.set_visible(ws.visible);
            ws.window.request_redraw();
            ws.ensure_fb();
            self.windows.insert(hwnd, ws);
        }
    }

    fn advance_timers(&mut self, elapsed_ms: u32) {
        // Collect fired events first to avoid borrow conflict.
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
                    hwnd: hwnd as u64,
                    message: WM_TIMER,
                    w_param: timer_id,
                    ..Default::default()
                });
            }
        }
    }

    // Called from the winit event loop (main thread) to flush pending creates.
    pub fn on_event_loop_tick(&mut self, el: &ActiveEventLoop, elapsed_ms: u32) {
        self.flush_pending_creates(|attrs| el.create_window(attrs));
        self.advance_timers(elapsed_ms);
    }

    // ── NtUserShowWindow ─────────────────────────────────────────────────────
    pub fn show_window(&mut self, hwnd: u32, cmd: i32) -> u64 {
        let visible = cmd != 0;
        if let Some(ws) = self.windows.get_mut(&hwnd) {
            ws.visible = visible;
            ws.window.set_visible(visible);
            if visible {
                self.foreground = hwnd;
                ws.window.request_redraw();
            }
        } else if self.pending_visibility.contains_key(&hwnd) {
            self.pending_visibility.insert(hwnd, visible);
        }
        1u64
    }

    // ── NtUserDestroyWindow ──────────────────────────────────────────────────
    pub fn destroy_window(&mut self, hwnd: u32) -> u64 {
        self.pending_visibility.remove(&hwnd);
        if let Some(ws) = self.windows.remove(&hwnd) {
            let tid = ws.owner_tid;
            let q = self.msg_queues.entry(tid).or_default();
            q.push_back(GuestMsg {
                hwnd: hwnd as u64,
                message: WM_DESTROY,
                ..Default::default()
            });
        }
        if self.foreground == hwnd {
            self.foreground = 0;
        }
        1u64
    }

    // ── NtUserGetDC / NtUserGetDCEx ──────────────────────────────────────────
    pub fn get_dc(&mut self, hwnd: u32) -> u64 {
        let hdc = self.alloc_hdc();
        if hdc == 0 {
            return 0;
        }
        self.dcs.insert(hdc, DcState::new(hwnd, self.stock));
        hdc as u64
    }

    // ── NtUserReleaseDC ──────────────────────────────────────────────────────
    pub fn release_dc(&mut self, _hwnd: u32, hdc: u32) -> u64 {
        self.dcs.remove(&Self::raw_gdi_handle(hdc));
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
        self.dcs.remove(&Self::raw_gdi_handle(hdc));
        1u64
    }

    // ── NtUserSetWindowPos ───────────────────────────────────────────────────
    pub fn set_window_pos(&mut self, hwnd: u32, x: i32, y: i32, w: u32, h: u32) -> u64 {
        if let Some(ws) = self.windows.get_mut(&hwnd) {
            if w > 0 && h > 0 {
                let _ = ws.window.request_inner_size(PhysicalSize::new(w, h));
                ws.width = w;
                ws.height = h;
                ws.ensure_fb();
            }
            ws.window
                .set_outer_position(winit::dpi::PhysicalPosition::new(x, y));
            return 1u64;
        }
        if self.pending_visibility.contains_key(&hwnd) {
            return 1u64;
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
    pub fn validate_rect(&mut self, _hwnd: u32) -> u64 {
        1u64
    }

    // ── NtUserPostQuitMessage ────────────────────────────────────────────────
    pub fn post_quit(&mut self, tid: u32, exit_code: i32) {
        let q = self.msg_queues.entry(tid).or_default();
        q.push_back(GuestMsg {
            message: WM_QUIT,
            w_param: exit_code as u64,
            ..Default::default()
        });
    }

    pub fn post_thread_message(
        &mut self,
        tid: u32,
        message: u32,
        w_param: u64,
        l_param: u64,
    ) -> u64 {
        let q = self.msg_queues.entry(tid).or_default();
        q.push_back(GuestMsg {
            hwnd: 0,
            message,
            w_param,
            l_param,
            ..Default::default()
        });
        1
    }

    // ── NtUserSetTimer ───────────────────────────────────────────────────────
    pub fn set_timer(&mut self, hwnd: u32, tid: u32, timer_id: u64, interval_ms: u32) -> u64 {
        self.timers
            .retain(|t| !(t.hwnd == hwnd && t.timer_id == timer_id));
        self.timers.push(Timer {
            hwnd,
            tid,
            timer_id,
            interval: interval_ms.max(1),
            elapsed: 0,
        });
        timer_id
    }

    // ── NtUserKillTimer ──────────────────────────────────────────────────────
    pub fn kill_timer(&mut self, hwnd: u32, timer_id: u64) -> u64 {
        let before = self.timers.len();
        self.timers
            .retain(|t| !(t.hwnd == hwnd && t.timer_id == timer_id));
        if self.timers.len() < before {
            1
        } else {
            0
        }
    }

    // ── NtUserSetCursor ──────────────────────────────────────────────────────
    pub fn set_cursor(&mut self, _hcursor: u32) -> u64 {
        0
    }

    // ── NtUserGetForegroundWindow ─────────────────────────────────────────────
    pub fn foreground_hwnd(&self) -> u32 {
        self.foreground
    }

    pub fn set_process_dpi_awareness_context(&mut self, pid: u32, context: u32) -> u64 {
        if pid == 0 {
            return 0;
        }
        self.process_dpi_contexts.insert(pid, context);
        1
    }

    pub fn get_process_dpi_awareness_context(&self, pid: u32) -> u64 {
        self.process_dpi_contexts
            .get(&pid)
            .copied()
            .unwrap_or(NTUSER_DPI_UNAWARE) as u64
    }

    pub fn get_system_dpi_for_process(&self, _pid: u32) -> u64 {
        USER_DEFAULT_SCREEN_DPI as u64
    }

    pub fn set_thread_dpi_awareness_context(&mut self, pid: u32, tid: u32, context: u32) -> u64 {
        let prev = self
            .thread_dpi_contexts
            .get(&tid)
            .copied()
            .unwrap_or_else(|| {
                self.process_dpi_contexts
                    .get(&pid)
                    .copied()
                    .unwrap_or(NTUSER_DPI_UNAWARE)
                    | NTUSER_DPI_CONTEXT_FLAG_PROCESS
            });
        if (context & NTUSER_DPI_CONTEXT_FLAG_PROCESS) != 0 {
            self.thread_dpi_contexts.remove(&tid);
        } else {
            self.thread_dpi_contexts.insert(tid, context);
        }
        prev as u64
    }

    pub fn get_window_dpi_awareness_context(&self, hwnd: u32) -> u64 {
        self.windows
            .get(&hwnd)
            .and_then(|ws| self.thread_dpi_contexts.get(&ws.owner_tid).copied())
            .unwrap_or(NTUSER_DPI_UNAWARE) as u64
    }

    pub fn get_gui_thread_info_bytes(&self, tid: u32) -> [u8; 72] {
        let hwnd = self.primary_thread_hwnd(tid);
        let mut buf = [0u8; 72];

        buf[0..4].copy_from_slice(&(72u32).to_le_bytes());
        buf[4..8].copy_from_slice(&0u32.to_le_bytes());
        buf[8..16].copy_from_slice(&u64::from(hwnd).to_le_bytes());
        buf[16..24].copy_from_slice(&u64::from(hwnd).to_le_bytes());
        buf[24..32].copy_from_slice(&0u64.to_le_bytes());
        buf[32..40].copy_from_slice(&0u64.to_le_bytes());
        buf[40..48].copy_from_slice(&0u64.to_le_bytes());
        buf[48..56].copy_from_slice(&0u64.to_le_bytes());
        buf
    }

    // ── NtGdiDeleteObjectApp ─────────────────────────────────────────────────
    pub fn delete_object(&mut self, h: u32) -> u64 {
        let h = Self::raw_gdi_handle(h);
        if self.stock.is_stock(h) {
            return 0;
        }
        self.gdi_objects.remove(&h);
        self.dcs.remove(&h);
        self.brush_colors.remove(&h);
        self.pen_colors.remove(&h);
        self.font_infos.remove(&h);
        1u64
    }

    // ── NtGdiSelectBitmap/Brush/Pen/Font ─────────────────────────────────────
    pub fn select_bitmap(&mut self, hdc: u32, hobj: u32) -> u64 {
        self.select_object_slot(hdc, GdiKind::Bitmap, hobj)
    }

    pub fn select_brush(&mut self, hdc: u32, hobj: u32) -> u64 {
        self.select_object_slot(hdc, GdiKind::Brush, hobj)
    }

    pub fn select_pen(&mut self, hdc: u32, hobj: u32) -> u64 {
        self.select_object_slot(hdc, GdiKind::Pen, hobj)
    }

    pub fn select_font(&mut self, hdc: u32, hobj: u32) -> u64 {
        self.select_object_slot(hdc, GdiKind::Font, hobj)
    }

    // ── NtGdiGetStockObject ──────────────────────────────────────────────────
    #[allow(dead_code)]
    pub fn get_stock_object(&mut self, idx: u32) -> u64 {
        match idx {
            0 => STOCK_WHITE_BRUSH as u64,
            4 => STOCK_BLACK_BRUSH as u64,
            7 => STOCK_BLACK_PEN as u64,
            13 => STOCK_SYSTEM_FONT as u64,
            17 => STOCK_DEFAULT_GUI_FONT as u64,
            18 => self.stock.dc_brush as u64,
            19 => self.stock.dc_pen as u64,
            20 => STOCK_DEFAULT_BITMAP as u64,
            _ => 0,
        }
    }

    // ── NtGdiCreateCompatibleDC ──────────────────────────────────────────────
    pub fn create_compatible_dc(&mut self, hdc: u32) -> u64 {
        let hdc = Self::raw_gdi_handle(hdc);
        let hwnd = self.dcs.get(&hdc).map(|d| d.hwnd).unwrap_or(0);
        self.get_dc(hwnd)
    }

    // ── NtGdiCreateCompatibleBitmap ──────────────────────────────────────────
    pub fn create_compatible_bitmap(&mut self, _hdc: u32, _w: u32, _h: u32) -> u64 {
        self.alloc_gdi_typed(GdiKind::Bitmap) as u64
    }

    pub fn create_bitmap(&mut self, _w: u32, _h: u32, _planes: u32, _bpp: u32) -> u64 {
        self.alloc_gdi_typed(GdiKind::Bitmap) as u64
    }

    pub fn create_dibitmap_internal(&mut self) -> u64 {
        self.alloc_gdi_typed(GdiKind::Bitmap) as u64
    }

    pub fn open_dc_w(&mut self) -> u64 {
        self.get_dc(0)
    }

    // ── NtGdiBitBlt ──────────────────────────────────────────────────────────
    pub fn bit_blt(&mut self, hdc: u32) -> u64 {
        let hdc = Self::raw_gdi_handle(hdc);
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
    pub fn stretch_blt(&mut self, hdc: u32) -> u64 {
        self.bit_blt(hdc)
    }

    // ── NtGdiRectangle ───────────────────────────────────────────────────────
    pub fn gdi_rectangle(&mut self, hdc: u32, x0: i32, y0: i32, x1: i32, y1: i32) -> u64 {
        let hdc = Self::raw_gdi_handle(hdc);
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
        let hdc = Self::raw_gdi_handle(hdc);
        if let Some(dc) = self.dcs.get_mut(&hdc) {
            let prev = dc.bk_color;
            dc.bk_color = color;
            return prev as u64;
        }
        0u64
    }

    pub fn set_text_color(&mut self, hdc: u32, color: u32) -> u64 {
        let hdc = Self::raw_gdi_handle(hdc);
        if let Some(dc) = self.dcs.get_mut(&hdc) {
            let prev = dc.text_color;
            dc.text_color = color;
            return prev as u64;
        }
        0u64
    }

    // ── NtGdiMoveTo / NtGdiLineTo ─────────────────────────────────────────────
    pub fn move_to(&mut self, hdc: u32, x: i32, y: i32) -> u64 {
        if let Some(dc) = self.dcs.get_mut(&hdc) {
            dc.cur_x = x;
            dc.cur_y = y;
        }
        1u64
    }

    pub fn line_to(&mut self, hdc: u32, x1: i32, y1: i32) -> u64 {
        let (hwnd, x0, y0, color) = match self.dcs.get_mut(&hdc) {
            Some(dc) => {
                let r = (dc.hwnd, dc.cur_x, dc.cur_y, dc.text_color);
                dc.cur_x = x1;
                dc.cur_y = y1;
                r
            }
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
            6 => {
                if self.windows.contains_key(&hwnd) {
                    0
                } else {
                    0
                }
            } // IsIconic
            // Only report visible once a real host window exists.
            7 => {
                if self.windows.get(&hwnd).map(|w| w.visible).unwrap_or(false) {
                    1
                } else {
                    0
                }
            }
            11 => 0x14CF_0000u64, // WS_OVERLAPPEDWINDOW | WS_VISIBLE
            12 => 0x0000_0100u64, // WS_EX_WINDOWEDGE
            _ => 0,
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
    pub fn get_key_state(&self, _vk: u32) -> u64 {
        0
    }
    pub fn get_async_key_state(&self, _vk: u32) -> u64 {
        0
    }
    #[allow(dead_code)]
    pub fn get_keyboard_state(&self, _buf_gpa: u64) -> u64 {
        1
    }

    // ── NtUserGetQueueStatus ─────────────────────────────────────────────────
    pub fn get_queue_status(&self, tid: u32) -> u64 {
        let has_msg = self
            .msg_queues
            .get(&tid)
            .map(|q| !q.is_empty())
            .unwrap_or(false);
        if has_msg {
            0x0004_0004
        } else {
            0
        } // QS_POSTMESSAGE
    }

    // ── NtUserGetDoubleClickTime ─────────────────────────────────────────────
    pub fn get_double_click_time(&self) -> u64 {
        500
    }

    // ── NtUserGetCaretBlinkTime ──────────────────────────────────────────────
    pub fn get_caret_blink_time(&self) -> u64 {
        530
    }

    pub fn get_sys_color(&self, index: u32) -> u64 {
        system_color_rgb(index) as u64
    }

    pub fn get_sys_color_brush(&mut self, index: u32) -> u64 {
        self.create_solid_brush(system_color_rgb(index))
    }

    pub fn get_sys_color_pen(&mut self, index: u32) -> u64 {
        self.create_pen(0, 1, system_color_rgb(index))
    }

    pub fn get_system_metrics(&self, index: u32) -> u64 {
        let (screen_w, screen_h) = self.primary_screen_size();
        let frame_x = 8u64;
        let frame_y = 8u64;
        let caption = 23u64;
        match index {
            0 => screen_w as u64,                                          // SM_CXSCREEN
            1 => screen_h as u64,                                          // SM_CYSCREEN
            4 => caption,                                                  // SM_CYCAPTION
            5 | 6 => 1,    // SM_CXBORDER / SM_CYBORDER
            7 | 8 => 3,    // SM_CXDLGFRAME / SM_CYDLGFRAME
            9 | 10 => 16,  // thumb sizes
            11 | 12 => 32, // icon sizes
            13 | 14 => 32, // cursor sizes
            15 => 19,      // SM_CYMENU
            16 => (screen_w as u64).saturating_sub(frame_x * 2), // SM_CXFULLSCREEN
            17 => (screen_h as u64).saturating_sub(frame_y * 2 + caption), // SM_CYFULLSCREEN
            18 => 0,       // SM_CYKANJIWINDOW
            19 => 1,       // SM_MOUSEPRESENT
            20 | 21 => 16, // scrollbars
            22 | 23 => 0,  // debug / swap buttons
            28 => 112,     // SM_CXMIN
            29 => 27,      // SM_CYMIN
            30 | 31 => 30, // SM_CXSIZE / SM_CYSIZE
            32 | 33 => frame_x.max(frame_y), // SM_CXFRAME / SM_CYFRAME
            34 => 112,     // SM_CXMINTRACK
            35 => 27,      // SM_CYMINTRACK
            36 | 37 => 4,  // double click box
            38 => 75,      // SM_CXICONSPACING
            39 => 75,      // SM_CYICONSPACING
            40 | 41 | 42 => 0, // menu/drop/pen/dbcs
            43 => 3,       // SM_CMOUSEBUTTONS
            44 => 0,       // SM_SECURE
            45 | 46 => 2,  // SM_CXEDGE / SM_CYEDGE
            47 | 48 => 2,  // min spacing
            49 | 50 => 16, // small icons
            51 => 16,      // small caption height
            52 | 53 => 16, // small caption buttons
            54 | 55 => 18, // menu size
            56 => 0,       // arrange
            57 => 160,     // minimized width
            58 => 24,      // minimized height
            59 | 61 | 78 => screen_w as u64, // maxtrack/maximized/virtual width
            60 | 62 | 79 => screen_h as u64, // maxtrack/maximized/virtual height
            63 | 67 | 70 | 73 | 74 | 86 | 87 | 88 | 89 => 0, // misc feature flags
            68 | 69 => 4,  // drag box
            71 | 72 => 13, // menu check size
            75 | 81 | 82 | 91 => 1, // wheel/display/ime
            76 | 77 => 0,  // virtual origin
            80 => 1,       // SM_CMONITORS
            83 | 84 => 1,  // focus border
            90 => 90,      // SM_CMETRICS
            92 => 0,       // padded border
            0x1000 => 0,   // SM_REMOTESESSION
            0x2000 | 0x2001 => 0, // shutting down / remote control
            0x2002 => 1,   // caret blinking enabled
            _ => 0,
        }
    }

    pub fn get_device_caps(&self, hdc: u32, cap: u32) -> u64 {
        const DRIVERVERSION: u32 = 0;
        const TECHNOLOGY: u32 = 2;
        const HORZSIZE: u32 = 4;
        const VERTSIZE: u32 = 6;
        const HORZRES: u32 = 8;
        const VERTRES: u32 = 10;
        const BITSPIXEL: u32 = 12;
        const PLANES: u32 = 14;
        const NUMBRUSHES: u32 = 16;
        const NUMPENS: u32 = 18;
        const NUMMARKERS: u32 = 20;
        const NUMFONTS: u32 = 22;
        const NUMCOLORS: u32 = 24;
        const PDEVICESIZE: u32 = 26;
        const CURVECAPS: u32 = 28;
        const LINECAPS: u32 = 30;
        const POLYGONALCAPS: u32 = 32;
        const TEXTCAPS: u32 = 34;
        const CLIPCAPS: u32 = 36;
        const RASTERCAPS: u32 = 38;
        const ASPECTX: u32 = 40;
        const ASPECTY: u32 = 42;
        const ASPECTXY: u32 = 44;
        const LOGPIXELSX: u32 = 88;
        const LOGPIXELSY: u32 = 90;
        const CAPS1: u32 = 94;
        const SIZEPALETTE: u32 = 104;
        const NUMRESERVED: u32 = 106;
        const COLORRES: u32 = 108;
        const PHYSICALWIDTH: u32 = 110;
        const PHYSICALHEIGHT: u32 = 111;
        const PHYSICALOFFSETX: u32 = 112;
        const PHYSICALOFFSETY: u32 = 113;
        const SCALINGFACTORX: u32 = 114;
        const SCALINGFACTORY: u32 = 115;
        const VREFRESH: u32 = 116;
        const DESKTOPVERTRES: u32 = 117;
        const DESKTOPHORZRES: u32 = 118;
        const BLTALIGNMENT: u32 = 119;
        const SHADEBLENDCAPS: u32 = 120;
        const COLORMGMTCAPS: u32 = 121;

        const DT_RASDISPLAY: u64 = 1;
        const CC_ALL: u64 = 0x01ff;
        const LC_ALL: u64 = 0x00fe;
        const PC_ALL: u64 = 0x017f;
        const TEXT_CAPS: u64 = 0x0000_78f7;
        const CLIP_CAPS: u64 = 0x0000_0001;
        const RASTER_CAPS: u64 = 0x0000_be99;

        let hdc = Self::raw_gdi_handle(hdc);
        if hdc != 0 && !self.dcs.contains_key(&hdc) {
            return 0;
        }

        let (screen_w, screen_h) = self.primary_screen_size();
        let dpi = USER_DEFAULT_SCREEN_DPI;

        match cap {
            DRIVERVERSION => 0x4000,
            TECHNOLOGY => DT_RASDISPLAY,
            HORZSIZE => Self::mm_from_pixels(screen_w, dpi),
            VERTSIZE => Self::mm_from_pixels(screen_h, dpi),
            HORZRES => u64::from(screen_w),
            VERTRES => u64::from(screen_h),
            BITSPIXEL => 32,
            PLANES => 1,
            NUMBRUSHES | NUMPENS => u32::MAX as u64,
            NUMMARKERS | NUMFONTS | PDEVICESIZE | SIZEPALETTE | CAPS1 => 0,
            CURVECAPS => CC_ALL,
            LINECAPS => LC_ALL,
            POLYGONALCAPS => PC_ALL,
            TEXTCAPS => TEXT_CAPS,
            CLIPCAPS => CLIP_CAPS,
            RASTERCAPS => RASTER_CAPS,
            ASPECTX | ASPECTY => 36,
            ASPECTXY => 51,
            LOGPIXELSX | LOGPIXELSY => u64::from(dpi),
            NUMRESERVED => 20,
            NUMCOLORS => u32::MAX as u64,
            COLORRES => 24,
            PHYSICALWIDTH | DESKTOPHORZRES => u64::from(screen_w),
            PHYSICALHEIGHT | DESKTOPVERTRES => u64::from(screen_h),
            PHYSICALOFFSETX | PHYSICALOFFSETY => 0,
            SCALINGFACTORX | SCALINGFACTORY => 0,
            VREFRESH => 60,
            BLTALIGNMENT | SHADEBLENDCAPS | COLORMGMTCAPS => 0,
            _ => 0,
        }
    }

    pub fn realize_palette(&self, hdc: u32) -> u64 {
        u64::from(self.dcs.contains_key(&hdc))
    }

    // ── NtUserSystemParametersInfo ───────────────────────────────────────────
    // uiAction values we care about:
    //   SPI_GETWORKAREA        = 0x0030 → write RECT(0,0,w,h) to pvParam
    //   SPI_GETNONCLIENTMETRICS= 0x0029 → stub
    //   SPI_GETFONTSMOOTHING   = 0x004A → return 1
    //   SPI_GETICONTITLELOGFONT= 0x001F → stub
    //   SPI_GETANIMATION       = 0x0048 → stub
    #[allow(dead_code)]
    pub fn system_parameters_info(&self, action: u32) -> (u64, Option<[i32; 4]>) {
        match action {
            0x0030 => (1, Some([0, 0, 1920, 1080])), // SPI_GETWORKAREA
            0x004A => (1, None),                     // SPI_GETFONTSMOOTHING → true
            _ => (1, None),
        }
    }

    pub fn system_parameters_info_bytes(
        &self,
        action: u32,
        ui_param: u32,
    ) -> (u64, Option<Vec<u8>>) {
        const SPI_GET_NONCLIENT_METRICS: u32 = 0x0029;
        const SPI_GET_WORK_AREA: u32 = 0x0030;
        const SPI_GET_FONT_SMOOTHING: u32 = 0x004A;

        match action {
            SPI_GET_WORK_AREA => {
                let mut buf = vec![0u8; 16];
                buf[8..12].copy_from_slice(&(1920i32).to_le_bytes());
                buf[12..16].copy_from_slice(&(1080i32).to_le_bytes());
                (1, Some(buf))
            }
            SPI_GET_FONT_SMOOTHING => (1, None),
            SPI_GET_NONCLIENT_METRICS => {
                let size = ui_param as usize;
                if size != 500 && size != 504 {
                    return (0, None);
                }
                let mut buf = vec![0u8; size];
                let write_i32 = |buf: &mut [u8], off: usize, value: i32| {
                    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
                };
                let font = self
                    .font_infos
                    .get(&self.stock.default_gui_font)
                    .copied()
                    .or_else(|| self.font_infos.get(&self.stock.system_font).copied())
                    .unwrap_or_else(FontInfo::system_default)
                    .logfont_bytes();

                write_i32(&mut buf, 0, size as i32);
                write_i32(&mut buf, 4, 1);
                write_i32(&mut buf, 8, 17);
                write_i32(&mut buf, 12, 17);
                write_i32(&mut buf, 16, 18);
                write_i32(&mut buf, 20, 18);
                buf[24..24 + FontInfo::LOGFONTW_SIZE].copy_from_slice(&font);
                write_i32(&mut buf, 116, 16);
                write_i32(&mut buf, 120, 16);
                buf[124..124 + FontInfo::LOGFONTW_SIZE].copy_from_slice(&font);
                write_i32(&mut buf, 216, 18);
                write_i32(&mut buf, 220, 18);
                buf[224..224 + FontInfo::LOGFONTW_SIZE].copy_from_slice(&font);
                buf[316..316 + FontInfo::LOGFONTW_SIZE].copy_from_slice(&font);
                buf[408..408 + FontInfo::LOGFONTW_SIZE].copy_from_slice(&font);
                if size >= 504 {
                    write_i32(&mut buf, 500, 0);
                }
                (1, Some(buf))
            }
            _ => (1, None),
        }
    }

    // ── NtGdiCreateSolidBrush ────────────────────────────────────────────────
    pub fn create_solid_brush(&mut self, color: u32) -> u64 {
        let h = self.alloc_gdi_typed(GdiKind::Brush);
        if h == 0 {
            return 0;
        }
        // Store color in a side table keyed by handle
        self.brush_colors.insert(h, color);
        h as u64
    }

    // ── NtGdiCreatePen ───────────────────────────────────────────────────────
    pub fn create_pen(&mut self, _style: u32, _width: u32, color: u32) -> u64 {
        let h = self.alloc_gdi_typed(GdiKind::Pen);
        if h == 0 {
            return 0;
        }
        self.pen_colors.insert(h, color);
        h as u64
    }

    pub fn create_font(&mut self, logfont: &[u8]) -> u64 {
        let Some(info) = FontInfo::from_logfont_bytes(logfont) else {
            return 0;
        };
        let h = self.alloc_gdi_typed(GdiKind::Font);
        if h == 0 {
            return 0;
        }
        self.font_infos.insert(h, info);
        h as u64
    }

    pub fn get_text_metrics(&self, hdc: u32) -> Option<[u8; FontInfo::TEXTMETRICW_SIZE]> {
        let hdc = Self::raw_gdi_handle(hdc);
        let dc = self.dcs.get(&hdc)?;
        let info = self
            .font_infos
            .get(&Self::raw_gdi_handle(dc.sel_font))
            .copied()
            .or_else(|| self.font_infos.get(&self.stock.default_gui_font).copied())
            .or_else(|| self.font_infos.get(&self.stock.system_font).copied())
            .unwrap_or_else(FontInfo::system_default);
        Some(info.text_metric_bytes())
    }

    pub fn get_text_charset_info(&self, hdc: u32) -> Option<(u32, [u8; 24])> {
        let hdc = Self::raw_gdi_handle(hdc);
        let dc = self.dcs.get(&hdc)?;
        let info = self
            .font_infos
            .get(&Self::raw_gdi_handle(dc.sel_font))
            .copied()
            .or_else(|| self.font_infos.get(&self.stock.default_gui_font).copied())
            .or_else(|| self.font_infos.get(&self.stock.system_font).copied())
            .unwrap_or_else(FontInfo::system_default);

        let mut sig = [0u8; 24];
        sig[0..4].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        sig[16..20].copy_from_slice(&1u32.to_le_bytes());
        let charset = if info.charset == 0 {
            1
        } else {
            info.charset as u32
        };
        Some((charset, sig))
    }

    pub fn create_pattern_brush_internal(&mut self) -> u64 {
        let h = self.alloc_gdi_typed(GdiKind::Brush);
        if h == 0 {
            return 0;
        }
        h as u64
    }

    // ── NtGdiExtGetObjectW ───────────────────────────────────────────────────
    pub fn ext_get_object(&self, h: u32, count: usize) -> Option<Vec<u8>> {
        let h = Self::raw_gdi_handle(h);
        if count == 0 {
            return None;
        }
        let font = self
            .font_infos
            .get(&h)
            .copied()
            .or_else(|| self.font_infos.get(&self.stock.default_gui_font).copied())
            .or_else(|| self.font_infos.get(&self.stock.system_font).copied())
            .unwrap_or_else(FontInfo::system_default)
            .logfont_bytes();
        let write_len = count.min(FontInfo::LOGFONTW_SIZE);
        Some(font[..write_len].to_vec())
    }

    // ── NtGdiEllipse ─────────────────────────────────────────────────────────
    pub fn gdi_ellipse(&mut self, hdc: u32, x0: i32, y0: i32, x1: i32, y1: i32) -> u64 {
        // Approximate with filled rectangle for now
        self.gdi_rectangle(hdc, x0, y0, x1, y1)
    }

    // ── NtGdiPolyPolyDraw ────────────────────────────────────────────────────
    pub fn poly_poly_draw(&mut self, _hdc: u32) -> u64 {
        1
    }

    // ── NtGdiFillRgn ─────────────────────────────────────────────────────────
    pub fn fill_rgn(&mut self, hdc: u32, _hrgn: u32, hbrush: u32) -> u64 {
        let hdc = Self::raw_gdi_handle(hdc);
        let hbrush = Self::raw_gdi_handle(hbrush);
        let (hwnd, color) = {
            let dc = match self.dcs.get(&hdc) {
                Some(d) => d,
                None => return 0,
            };
            let c = self
                .brush_colors
                .get(&hbrush)
                .copied()
                .unwrap_or(dc.bk_color);
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
            if let Some(msg) = q.pop_front() {
                *out = msg;
                return true;
            }
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
                if let Some(ws) = self.windows.get_mut(&hwnd) {
                    ws.visible = false;
                    ws.window.set_visible(false);
                }
                q.push_back(GuestMsg {
                    hwnd: hwnd as u64,
                    message: WM_CLOSE,
                    ..Default::default()
                });
            }
            WindowEvent::RedrawRequested => {
                q.push_back(GuestMsg {
                    hwnd: hwnd as u64,
                    message: WM_PAINT,
                    ..Default::default()
                });
            }
            WindowEvent::Resized(sz) => {
                if let Some(ws) = self.windows.get_mut(&hwnd) {
                    ws.width = sz.width.max(1);
                    ws.height = sz.height.max(1);
                    ws.ensure_fb();
                }
                let packed = ((sz.height as u64) << 16) | (sz.width as u64 & 0xFFFF);
                q.push_back(GuestMsg {
                    hwnd: hwnd as u64,
                    message: WM_SIZE,
                    l_param: packed,
                    ..Default::default()
                });
            }
            WindowEvent::KeyboardInput { event: ke, .. } => {
                let msg = if ke.state == winit::event::ElementState::Pressed {
                    WM_KEYDOWN
                } else {
                    WM_KEYUP
                };
                let vk = winit_key_to_vk(&ke.logical_key);
                q.push_back(GuestMsg {
                    hwnd: hwnd as u64,
                    message: msg,
                    w_param: vk,
                    ..Default::default()
                });
            }
            WindowEvent::CursorMoved { position, .. } => {
                let packed =
                    ((position.y as i32 as u64) << 32) | (position.x as i32 as u64 & 0xFFFF_FFFF);
                q.push_back(GuestMsg {
                    hwnd: hwnd as u64,
                    message: WM_MOUSEMOVE,
                    l_param: packed,
                    ..Default::default()
                });
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let msg = match (button, state) {
                    (winit::event::MouseButton::Left, winit::event::ElementState::Pressed) => {
                        WM_LBUTTONDOWN
                    }
                    (winit::event::MouseButton::Left, winit::event::ElementState::Released) => {
                        WM_LBUTTONUP
                    }
                    (winit::event::MouseButton::Right, winit::event::ElementState::Pressed) => {
                        WM_RBUTTONDOWN
                    }
                    (winit::event::MouseButton::Right, winit::event::ElementState::Released) => {
                        WM_RBUTTONUP
                    }
                    _ => return,
                };
                q.push_back(GuestMsg {
                    hwnd: hwnd as u64,
                    message: msg,
                    ..Default::default()
                });
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
        if x == x1 && y == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 > -dy {
            err -= dy;
            x += sx;
        }
        if e2 < dx {
            err += dx;
            y += sy;
        }
    }
}

// ── winit key → Windows VK ────────────────────────────────────────────────────
fn winit_key_to_vk(key: &winit::keyboard::Key) -> u64 {
    use winit::keyboard::{Key, NamedKey};
    match key {
        Key::Named(NamedKey::Enter) => 0x0D,
        Key::Named(NamedKey::Escape) => 0x1B,
        Key::Named(NamedKey::Space) => 0x20,
        Key::Named(NamedKey::Backspace) => 0x08,
        Key::Named(NamedKey::Tab) => 0x09,
        Key::Named(NamedKey::ArrowLeft) => 0x25,
        Key::Named(NamedKey::ArrowUp) => 0x26,
        Key::Named(NamedKey::ArrowRight) => 0x27,
        Key::Named(NamedKey::ArrowDown) => 0x28,
        Key::Named(NamedKey::Delete) => 0x2E,
        Key::Named(NamedKey::Home) => 0x24,
        Key::Named(NamedKey::End) => 0x23,
        Key::Named(NamedKey::PageUp) => 0x21,
        Key::Named(NamedKey::PageDown) => 0x22,
        Key::Named(NamedKey::F1) => 0x70,
        Key::Named(NamedKey::F2) => 0x71,
        Key::Named(NamedKey::F3) => 0x72,
        Key::Named(NamedKey::F4) => 0x73,
        Key::Named(NamedKey::F5) => 0x74,
        Key::Named(NamedKey::F6) => 0x75,
        Key::Named(NamedKey::F7) => 0x76,
        Key::Named(NamedKey::F8) => 0x77,
        Key::Named(NamedKey::F9) => 0x78,
        Key::Named(NamedKey::F10) => 0x79,
        Key::Named(NamedKey::F11) => 0x7A,
        Key::Named(NamedKey::F12) => 0x7B,
        Key::Character(s) => s.chars().next().unwrap_or('\0').to_ascii_uppercase() as u64,
        _ => 0,
    }
}
