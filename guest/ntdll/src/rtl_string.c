/* ── String helpers ──────────────────────────────────────────── */

typedef struct { uint16_t Length, MaximumLength; uint32_t _pad; WCHAR* Buffer; } UNICODE_STRING;
typedef struct { uint16_t Length, MaximumLength; uint32_t _pad; UCHAR* Buffer; } ANSI_STRING;

EXPORT void RtlInitUnicodeString(UNICODE_STRING* dest, const WCHAR* src) {
    if (!src) { dest->Length = dest->MaximumLength = 0; dest->Buffer = NULL; return; }
    size_t len = 0;
    while (src[len]) len++;
    dest->Length        = (uint16_t)(len * 2);
    dest->MaximumLength = (uint16_t)(len * 2 + 2);
    dest->Buffer        = (WCHAR*)src;
}

EXPORT void RtlInitAnsiString(ANSI_STRING* dest, const UCHAR* src) {
    if (!src) { dest->Length = dest->MaximumLength = 0; dest->Buffer = NULL; return; }
    size_t len = 0;
    while (src[len]) len++;
    dest->Length        = (uint16_t)len;
    dest->MaximumLength = (uint16_t)(len + 1);
    dest->Buffer        = (UCHAR*)src;
}

