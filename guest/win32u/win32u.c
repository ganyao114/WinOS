#include <stdint.h>

typedef void* HANDLE;
typedef uint32_t ULONG;

#ifdef _MSC_VER
#  define EXPORT __declspec(dllexport)
#else
#  define EXPORT __attribute__((visibility("default")))
#endif

/* win32k/syscall table = 1 */
#define WIN32K_NT_GDI_CREATE_COMPATIBLE_DC          0x1012
#define WIN32K_NT_GDI_BITBLT                        0x1001
#define WIN32K_NT_USER_CREATE_WINDOW_EX             0x1056
#define WIN32K_NT_USER_SHOW_WINDOW                  0x10C3
#define WIN32K_NT_USER_MESSAGE_CALL                 0x1069
#define WIN32K_NT_USER_DESTROY_WINDOW               0x1025
#define WIN32K_NT_USER_INIT_CLIENT_PFN_ARRAYS       0x1127

#define WINEMU_STR2(x) #x
#define WINEMU_STR(x) WINEMU_STR2(x)

/*
 * Keep wrappers as naked trampolines so x0-x7 pass through unchanged.
 * Kernel decodes table/number from x8 and dispatches win32k syscall path.
 */
__attribute__((naked)) EXPORT void NtGdiCreateCompatibleDC(void) {
    asm volatile(
        "movz x8, #" WINEMU_STR(WIN32K_NT_GDI_CREATE_COMPATIBLE_DC) "\n"
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) EXPORT void NtGdiBitBlt(void) {
    asm volatile(
        "movz x8, #" WINEMU_STR(WIN32K_NT_GDI_BITBLT) "\n"
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) EXPORT void NtUserCreateWindowEx(void) {
    asm volatile(
        "movz x8, #" WINEMU_STR(WIN32K_NT_USER_CREATE_WINDOW_EX) "\n"
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) EXPORT void NtUserShowWindow(void) {
    asm volatile(
        "movz x8, #" WINEMU_STR(WIN32K_NT_USER_SHOW_WINDOW) "\n"
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) EXPORT void NtUserMessageCall(void) {
    asm volatile(
        "movz x8, #" WINEMU_STR(WIN32K_NT_USER_MESSAGE_CALL) "\n"
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) EXPORT void NtUserDestroyWindow(void) {
    asm volatile(
        "movz x8, #" WINEMU_STR(WIN32K_NT_USER_DESTROY_WINDOW) "\n"
        "svc #0\n"
        "ret\n");
}

__attribute__((naked)) EXPORT void NtUserInitializeClientPfnArrays(void) {
    asm volatile(
        "movz x8, #" WINEMU_STR(WIN32K_NT_USER_INIT_CLIENT_PFN_ARRAYS) "\n"
        "svc #0\n"
        "ret\n");
}

EXPORT int DllMain(HANDLE inst, ULONG reason, void* reserved) {
    (void)inst;
    (void)reason;
    (void)reserved;
    return 1;
}

int DllMainCRTStartup(HANDLE inst, ULONG reason, void* reserved) {
    return DllMain(inst, reason, reserved);
}
