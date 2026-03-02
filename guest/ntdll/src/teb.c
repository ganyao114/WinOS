/* ── TEB ─────────────────────────────────────────────────────── */

EXPORT void* NtCurrentTeb(void) {
    void* teb;
    asm("mov %0, x18" : "=r"(teb));
    return teb;
}

