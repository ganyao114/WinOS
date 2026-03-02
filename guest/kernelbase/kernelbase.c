/*
 * Minimal kernelbase.dll scaffold for WinEmu guest runtime.
 *
 * This module is introduced to host kernelbase-owned compatibility exports
 * incrementally instead of crowding ntdll.c.
 */
#include <stdint.h>

typedef void* HANDLE;
typedef uint32_t ULONG;

#ifdef _MSC_VER
#  define EXPORT __declspec(dllexport)
#else
#  define EXPORT __attribute__((visibility("default")))
#endif

EXPORT int DllMain(HANDLE inst, ULONG reason, void* reserved) {
    (void)inst;
    (void)reason;
    (void)reserved;
    return 1;
}

int DllMainCRTStartup(HANDLE inst, ULONG reason, void* reserved) {
    return DllMain(inst, reason, reserved);
}
