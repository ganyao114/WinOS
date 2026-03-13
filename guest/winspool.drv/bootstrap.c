/*
 * Minimal WinEmu guest winspool.drv bootstrap.
 *
 * Keep the module in our source/build chain and preserve Wine-compatible
 * unixlib exports, without pulling the full print provider stack in yet.
 */

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#define WINE_UNIX_LIB
#include "wine/unixlib.h"

static NTSTATUS WINAPI winemu_winspool_unix_noop(void *args)
{
    (void)args;
    return STATUS_SUCCESS;
}

DECLSPEC_EXPORT const unixlib_entry_t __wine_unix_call_funcs[] = {
    winemu_winspool_unix_noop,
};

DECLSPEC_EXPORT const unixlib_entry_t __wine_unix_call_wow64_funcs[] = {
    winemu_winspool_unix_noop,
};

BOOL WINAPI ClosePrinter(HANDLE printer)
{
    (void)printer;
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
