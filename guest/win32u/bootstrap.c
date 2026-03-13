#include <stdarg.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winnls.h"
#include "winternl.h"
#include "ntgdi.h"
#include "ntuser.h"
#include "wine/unixlib.h"

#define FIRST_GDI_HANDLE 32
#define DEFAULT_BITMAP (STOCK_LAST + 1)
#define SCALED_OEM_FIXED_FONT 9
#define SCALED_SYSTEM_FONT (STOCK_LAST + 2)
#define SCALED_SYSTEM_FIXED_FONT (STOCK_LAST + 3)
#define SCALED_DEFAULT_GUI_FONT (STOCK_LAST + 4)
#define HDC_RANGE_START 0x2000
#define HDC_RANGE_END   0x3000
#define BITMAP_RANGE_START 0x3000
#define BITMAP_RANGE_END   0x3800
#define BRUSH_RANGE_START 0x3800
#define BRUSH_RANGE_END    0x4000
#define PEN_RANGE_START    0x4000
#define PEN_RANGE_END      0x4800
#define FONT_RANGE_START   0x4800
#define FONT_RANGE_END     0x5800
#define OTHER_RANGE_START  0x5800
#define OTHER_RANGE_END    0x6000

/* Minimal local dispatcher for generated win32u syscall thunks.
 * The thunk sets x8=syscall number and x9=original LR before branching here. */
__attribute__((naked))
static NTSTATUS __winemu_syscall_dispatcher_impl(void)
{
    __asm__ __volatile__(
        "svc #0\n"
        "mov x30, x9\n"
        "ret\n");
}

static NTSTATUS WINAPI __winemu_unix_call_dispatcher_impl(
    unixlib_handle_t handle,
    unsigned int ordinal,
    void *args
)
{
    (void)handle;
    (void)ordinal;
    (void)args;
    return STATUS_NOT_IMPLEMENTED;
}

void *__wine_syscall_dispatcher = (void *)__winemu_syscall_dispatcher_impl;
NTSTATUS (WINAPI *__wine_unix_call_dispatcher)(unixlib_handle_t, unsigned int, void *) =
    __winemu_unix_call_dispatcher_impl;
unixlib_handle_t __wine_unixlib_handle;
static GDI_SHARED_MEMORY *g_winemu_gdi_shared;

extern ULONG_PTR win32u_syscall_0175(ULONG_PTR hdc);
extern ULONG_PTR win32u_syscall_0808(ULONG_PTR hwnd, ULONG_PTR ps);
extern ULONG_PTR win32u_syscall_1004(ULONG_PTR hwnd);
extern ULONG_PTR win32u_syscall_1005(ULONG_PTR hwnd, ULONG_PTR clip_rgn, ULONG_PTR flags);
extern ULONG_PTR win32u_syscall_1119(ULONG_PTR hwnd);

static void winemu_set_gdi_entry(unsigned int idx, unsigned int type, BOOL stock)
{
    GDI_HANDLE_ENTRY *entry = &g_winemu_gdi_shared->Handles[idx];
    entry->ExtType = type >> NTGDI_HANDLE_TYPE_SHIFT;
    entry->Type = entry->ExtType & 0x1f;
    entry->StockFlag = stock ? 1 : 0;
    entry->Generation = 0;
}

static void winemu_mark_gdi_range(unsigned int start, unsigned int end, unsigned int type)
{
    for (unsigned int idx = start; idx < end; idx += 4) winemu_set_gdi_entry(idx, type, FALSE);
}

static void winemu_init_gdi_stock_handles(void)
{
    static const struct
    {
        unsigned int slot;
        unsigned int type;
    } stocks[] =
    {
        {WHITE_BRUSH, NTGDI_OBJ_BRUSH},
        {LTGRAY_BRUSH, NTGDI_OBJ_BRUSH},
        {GRAY_BRUSH, NTGDI_OBJ_BRUSH},
        {DKGRAY_BRUSH, NTGDI_OBJ_BRUSH},
        {BLACK_BRUSH, NTGDI_OBJ_BRUSH},
        {NULL_BRUSH, NTGDI_OBJ_BRUSH},
        {WHITE_PEN, NTGDI_OBJ_PEN},
        {BLACK_PEN, NTGDI_OBJ_PEN},
        {NULL_PEN, NTGDI_OBJ_PEN},
        {SCALED_OEM_FIXED_FONT, NTGDI_OBJ_FONT},
        {OEM_FIXED_FONT, NTGDI_OBJ_FONT},
        {ANSI_FIXED_FONT, NTGDI_OBJ_FONT},
        {ANSI_VAR_FONT, NTGDI_OBJ_FONT},
        {SYSTEM_FONT, NTGDI_OBJ_FONT},
        {DEVICE_DEFAULT_FONT, NTGDI_OBJ_FONT},
        {DEFAULT_PALETTE, NTGDI_OBJ_PAL},
        {SYSTEM_FIXED_FONT, NTGDI_OBJ_FONT},
        {DEFAULT_GUI_FONT, NTGDI_OBJ_FONT},
        {DC_BRUSH, NTGDI_OBJ_BRUSH},
        {DC_PEN, NTGDI_OBJ_PEN},
        {DEFAULT_BITMAP, NTGDI_OBJ_BITMAP},
        {SCALED_SYSTEM_FONT, NTGDI_OBJ_FONT},
        {SCALED_SYSTEM_FIXED_FONT, NTGDI_OBJ_FONT},
        {SCALED_DEFAULT_GUI_FONT, NTGDI_OBJ_FONT},
    };

    for (unsigned int i = 0; i < ARRAY_SIZE(stocks); ++i)
        winemu_set_gdi_entry(FIRST_GDI_HANDLE + stocks[i].slot, stocks[i].type, TRUE);
}

static GDI_HANDLE_ENTRY *winemu_handle_entry(HANDLE handle)
{
    unsigned int idx = LOWORD(handle);

    if (!g_winemu_gdi_shared) return NULL;
    if (idx < GDI_MAX_HANDLE_COUNT && g_winemu_gdi_shared->Handles[idx].Type)
    {
        if (!HIWORD(handle) || HIWORD(handle) == g_winemu_gdi_shared->Handles[idx].Unique)
            return &g_winemu_gdi_shared->Handles[idx];
    }
    return NULL;
}

static HANDLE winemu_full_gdi_handle(HANDLE handle)
{
    GDI_HANDLE_ENTRY *entry = winemu_handle_entry(handle);
    UINT_PTR idx = LOWORD(handle);

    if (!entry) return handle;
    return (HANDLE)(idx | ((UINT_PTR)entry->Unique << NTGDI_HANDLE_TYPE_SHIFT));
}

static DC_ATTR *winemu_alloc_dc_attr(void)
{
    SIZE_T size = sizeof(DC_ATTR);
    void *base = NULL;

    if (NtAllocateVirtualMemory(
            NtCurrentProcess(),
            &base,
            0,
            &size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE))
        return NULL;
    return base;
}

static void winemu_init_dc_attr(DC_ATTR *attr, HDC hdc)
{
    memset(attr, 0, sizeof(*attr));
    attr->hdc = HandleToULong(hdc);
    attr->wnd_ext.cx = 1;
    attr->wnd_ext.cy = 1;
    attr->vport_ext.cx = 1;
    attr->vport_ext.cy = 1;
    attr->miter_limit = 10.0f;
    attr->rop_mode = R2_COPYPEN;
    attr->font_code_page = CP_ACP;
    attr->poly_fill_mode = ALTERNATE;
    attr->stretch_blt_mode = BLACKONWHITE;
    attr->rel_abs_mode = ABSOLUTE;
    attr->background_mode = OPAQUE;
    attr->background_color = RGB(255, 255, 255);
    attr->brush_color = RGB(255, 255, 255);
    attr->pen_color = RGB(0, 0, 0);
    attr->text_color = RGB(0, 0, 0);
    attr->map_mode = MM_TEXT;
    attr->graphics_mode = GM_COMPATIBLE;
}

static HDC winemu_attach_dc_attr(HDC hdc)
{
    GDI_HANDLE_ENTRY *entry;
    DC_ATTR *attr;

    if (!hdc) return hdc;
    entry = winemu_handle_entry(hdc);
    if (!entry) return hdc;
    if (entry->UserPointer) return hdc;

    attr = winemu_alloc_dc_attr();
    if (!attr) return hdc;

    winemu_init_dc_attr(attr, hdc);
    entry->UserPointer = (UINT_PTR)attr;
    return (HDC)winemu_full_gdi_handle(hdc);
}

static void winemu_init_gdi_shared_handle_table(void)
{
    SIZE_T size;
    void *base;

    if (g_winemu_gdi_shared) return;

    size = sizeof(*g_winemu_gdi_shared);
    base = NULL;
    if (NtAllocateVirtualMemory(
            NtCurrentProcess(),
            &base,
            0,
            &size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE))
        return;

    g_winemu_gdi_shared = base;
    winemu_init_gdi_stock_handles();
    winemu_mark_gdi_range(HDC_RANGE_START, HDC_RANGE_END, NTGDI_OBJ_DC);
    winemu_mark_gdi_range(BITMAP_RANGE_START, BITMAP_RANGE_END, NTGDI_OBJ_BITMAP);
    winemu_mark_gdi_range(BRUSH_RANGE_START, BRUSH_RANGE_END, NTGDI_OBJ_BRUSH);
    winemu_mark_gdi_range(PEN_RANGE_START, PEN_RANGE_END, NTGDI_OBJ_PEN);
    winemu_mark_gdi_range(FONT_RANGE_START, FONT_RANGE_END, NTGDI_OBJ_FONT);
    winemu_mark_gdi_range(OTHER_RANGE_START, OTHER_RANGE_END, NTGDI_OBJ_REGION);

    NtCurrentTeb()->Peb->GdiSharedHandleTable = g_winemu_gdi_shared;
}

HDC WINAPI NtGdiCreateCompatibleDC(HDC hdc)
{
    return winemu_attach_dc_attr((HDC)(UINT_PTR)win32u_syscall_0175((ULONG_PTR)hdc));
}

HDC WINAPI NtUserBeginPaint(HWND hwnd, PAINTSTRUCT *ps)
{
    return winemu_attach_dc_attr((HDC)(UINT_PTR)win32u_syscall_0808((ULONG_PTR)hwnd, (ULONG_PTR)ps));
}

HDC WINAPI NtUserGetDC(HWND hwnd)
{
    return winemu_attach_dc_attr((HDC)(UINT_PTR)win32u_syscall_1004((ULONG_PTR)hwnd));
}

HDC WINAPI NtUserGetDCEx(HWND hwnd, HRGN clip_rgn, DWORD flags)
{
    return winemu_attach_dc_attr(
        (HDC)(UINT_PTR)win32u_syscall_1005((ULONG_PTR)hwnd, (ULONG_PTR)clip_rgn, flags));
}

HDC WINAPI NtUserGetWindowDC(HWND hwnd)
{
    return winemu_attach_dc_attr((HDC)(UINT_PTR)win32u_syscall_1119((ULONG_PTR)hwnd));
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, void *reserved)
{
    (void)inst;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) winemu_init_gdi_shared_handle_table();
    return TRUE;
}
