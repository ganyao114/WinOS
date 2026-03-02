/* ── DLL entry point ─────────────────────────────────────────── */

EXPORT int DllMain(HANDLE inst, ULONG reason, void* reserved) {
    (void)inst; (void)reason; (void)reserved;
    return 1;
}

/* Required by linker when using -nostdlib */
int DllMainCRTStartup(HANDLE inst, ULONG reason, void* reserved) {
    return DllMain(inst, reason, reserved);
}
