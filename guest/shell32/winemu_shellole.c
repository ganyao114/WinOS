/*
 * Minimal shell32 allocator exports for WinEmu.
 *
 * Implementations copied from Wine dlls/shell32/shellole.c and kept in a
 * separate translation unit until the full shell32 Wine header model is wired
 * into the guest build.
 */

#include <objbase.h>

/*************************************************************************
 * SHGetMalloc [SHELL32.@]
 */
HRESULT WINAPI SHGetMalloc(LPMALLOC *lpmal)
{
    return CoGetMalloc(MEMCTX_TASK, lpmal);
}

/*************************************************************************
 * SHAlloc [SHELL32.196]
 */
LPVOID WINAPI SHAlloc(DWORD len)
{
    return CoTaskMemAlloc(len);
}

/*************************************************************************
 * SHFree [SHELL32.195]
 */
void WINAPI SHFree(LPVOID pv)
{
    CoTaskMemFree(pv);
}
