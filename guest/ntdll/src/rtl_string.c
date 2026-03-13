/* ── String helpers ──────────────────────────────────────────── */

typedef struct { uint16_t Length, MaximumLength; uint32_t _pad; WCHAR* Buffer; } UNICODE_STRING;
typedef struct { uint16_t Length, MaximumLength; uint32_t _pad; UCHAR* Buffer; } ANSI_STRING;
typedef UCHAR BOOLEAN;
typedef struct {
    union {
        struct {
            UCHAR s_b1;
            UCHAR s_b2;
            UCHAR s_b3;
            UCHAR s_b4;
        } S_un_b;
        uint32_t S_addr;
    } S_un;
} IN_ADDR;
typedef struct {
    UCHAR Byte[16];
} IN6_ADDR;

#define STATUS_BUFFER_TOO_SMALL 0xC0000023U

static int winemu_ascii_is_digit(char ch) {
    return ch >= '0' && ch <= '9';
}

static WORD winemu_bswap16(WORD value) {
    return (WORD)((value >> 8) | (value << 8));
}

static char* winemu_append_u32_ascii(char* dst, unsigned value) {
    char tmp[10];
    unsigned len = 0;
    do {
        tmp[len++] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value);
    while (len) *dst++ = tmp[--len];
    return dst;
}

static WCHAR* winemu_append_u32_wide(WCHAR* dst, unsigned value) {
    char tmp[10];
    unsigned len = 0;
    do {
        tmp[len++] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value);
    while (len) *dst++ = (WCHAR)tmp[--len];
    return dst;
}

static ULONG winemu_copy_ascii_nt(char* dst, const char* src) {
    ULONG i = 0;
    while (src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return i + 1;
}

static ULONG winemu_copy_wide_nt(WCHAR* dst, const WCHAR* src) {
    ULONG i = 0;
    while (src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
    return i + 1;
}

static int winemu_parse_ipv4_octet_a(const char** cur, unsigned* value) {
    unsigned acc = 0;
    int digits = 0;

    if (!cur || !*cur || !value || !winemu_ascii_is_digit(**cur)) return 0;
    while (winemu_ascii_is_digit(**cur)) {
        acc = acc * 10u + (unsigned)(**cur - '0');
        if (acc > 255u) return 0;
        (*cur)++;
        digits++;
    }
    if (!digits) return 0;
    *value = acc;
    return 1;
}

static NTSTATUS winemu_ipv4_string_to_address_a(
    const char* str,
    BOOLEAN strict,
    const char** terminator,
    IN_ADDR* address,
    WORD* port)
{
    const char* cur = str;
    unsigned octets[4];
    unsigned port_value = 0;

    (void)strict;

    if (!str || !address) return STATUS_INVALID_PARAMETER;

    for (int i = 0; i < 4; i++) {
        if (!winemu_parse_ipv4_octet_a(&cur, &octets[i])) {
            if (terminator) *terminator = cur;
            return STATUS_INVALID_PARAMETER;
        }
        if (i != 3) {
            if (*cur != '.') {
                if (terminator) *terminator = cur;
                return STATUS_INVALID_PARAMETER;
            }
            cur++;
        }
    }

    address->S_un.S_un_b.s_b1 = (UCHAR)octets[0];
    address->S_un.S_un_b.s_b2 = (UCHAR)octets[1];
    address->S_un.S_un_b.s_b3 = (UCHAR)octets[2];
    address->S_un.S_un_b.s_b4 = (UCHAR)octets[3];

    if (port) {
        if (*cur == ':') {
            cur++;
            if (!winemu_ascii_is_digit(*cur)) {
                if (terminator) *terminator = cur;
                return STATUS_INVALID_PARAMETER;
            }
            while (winemu_ascii_is_digit(*cur)) {
                port_value = port_value * 10u + (unsigned)(*cur - '0');
                if (port_value > 65535u) {
                    if (terminator) *terminator = cur;
                    return STATUS_INVALID_PARAMETER;
                }
                cur++;
            }
        }
        *port = (WORD)((port_value << 8) | (port_value >> 8));
    }

    if (terminator) *terminator = cur;
    if (!terminator && *cur) return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

static size_t winemu_wide_to_ascii_copy(const WCHAR* src, char* dst, size_t cap) {
    size_t i = 0;
    if (!src || !dst || cap == 0) return 0;
    while (src[i] && i + 1 < cap) {
        if (src[i] > 0x7f) return 0;
        dst[i] = (char)src[i];
        i++;
    }
    if (src[i] && i + 1 >= cap) return 0;
    dst[i] = '\0';
    return i;
}

static void winemu_zero_bytes(void* dst, size_t len) {
    UCHAR* p = (UCHAR*)dst;
    for (size_t i = 0; i < len; i++) p[i] = 0;
}

EXPORT void RtlInitUnicodeString(UNICODE_STRING* dest, const WCHAR* src) {
    if (!src) { dest->Length = dest->MaximumLength = 0; dest->Buffer = NULL; return; }
    size_t len = 0;
    while (src[len]) len++;
    dest->Length        = (uint16_t)(len * 2);
    dest->MaximumLength = (uint16_t)(len * 2 + 2);
    dest->Buffer        = (WCHAR*)src;
}

EXPORT void RtlFreeUnicodeString(UNICODE_STRING* str) {
    if (!str) return;
    if (str->Buffer) {
        RtlFreeHeap(NULL, 0, str->Buffer);
    }
    str->Length = 0;
    str->MaximumLength = 0;
    str->Buffer = NULL;
}

EXPORT void RtlInitAnsiString(ANSI_STRING* dest, const UCHAR* src) {
    if (!src) { dest->Length = dest->MaximumLength = 0; dest->Buffer = NULL; return; }
    size_t len = 0;
    while (src[len]) len++;
    dest->Length        = (uint16_t)len;
    dest->MaximumLength = (uint16_t)(len + 1);
    dest->Buffer        = (UCHAR*)src;
}

EXPORT NTSTATUS RtlIpv4StringToAddressA(
    const char* str,
    BOOLEAN strict,
    const char** terminator,
    IN_ADDR* address)
{
    return winemu_ipv4_string_to_address_a(str, strict, terminator, address, NULL);
}

EXPORT NTSTATUS RtlIpv4StringToAddressExA(
    const char* str,
    BOOLEAN strict,
    IN_ADDR* address,
    WORD* port)
{
    return winemu_ipv4_string_to_address_a(str, strict, NULL, address, port);
}

EXPORT NTSTATUS RtlIpv4StringToAddressW(
    const WCHAR* str,
    BOOLEAN strict,
    const WCHAR** terminator,
    IN_ADDR* address)
{
    char ascii[64];
    const char* ascii_term = NULL;
    NTSTATUS status;

    if (!str || !address) return STATUS_INVALID_PARAMETER;
    if (!winemu_wide_to_ascii_copy(str, ascii, sizeof(ascii))) return STATUS_INVALID_PARAMETER;

    status = winemu_ipv4_string_to_address_a(ascii, strict, &ascii_term, address, NULL);
    if (terminator) *terminator = str + (ascii_term ? (ascii_term - ascii) : 0);
    return status;
}

EXPORT NTSTATUS RtlIpv4StringToAddressExW(
    const WCHAR* str,
    BOOLEAN strict,
    IN_ADDR* address,
    WORD* port)
{
    char ascii[64];

    if (!str || !address || !port) return STATUS_INVALID_PARAMETER;
    if (!winemu_wide_to_ascii_copy(str, ascii, sizeof(ascii))) return STATUS_INVALID_PARAMETER;
    return winemu_ipv4_string_to_address_a(ascii, strict, NULL, address, port);
}

EXPORT NTSTATUS RtlIpv6StringToAddressA(
    const char* str,
    const char** terminator,
    IN6_ADDR* address)
{
    if (terminator) *terminator = str;
    if (!str || !address) return STATUS_INVALID_PARAMETER;
    winemu_zero_bytes(address, sizeof(*address));
    return STATUS_INVALID_PARAMETER;
}

EXPORT NTSTATUS RtlIpv6StringToAddressW(
    const WCHAR* str,
    const WCHAR** terminator,
    IN6_ADDR* address)
{
    if (terminator) *terminator = str;
    if (!str || !address) return STATUS_INVALID_PARAMETER;
    winemu_zero_bytes(address, sizeof(*address));
    return STATUS_INVALID_PARAMETER;
}

EXPORT NTSTATUS RtlIpv6StringToAddressExA(
    const char* str,
    IN6_ADDR* address,
    ULONG* scope,
    WORD* port)
{
    if (!str || !address || !scope || !port) return STATUS_INVALID_PARAMETER;
    winemu_zero_bytes(address, sizeof(*address));
    *scope = 0;
    *port = 0;
    return STATUS_INVALID_PARAMETER;
}

EXPORT NTSTATUS RtlIpv6StringToAddressExW(
    const WCHAR* str,
    IN6_ADDR* address,
    ULONG* scope,
    WORD* port)
{
    if (!str || !address || !scope || !port) return STATUS_INVALID_PARAMETER;
    winemu_zero_bytes(address, sizeof(*address));
    *scope = 0;
    *port = 0;
    return STATUS_INVALID_PARAMETER;
}

EXPORT NTSTATUS RtlIpv4AddressToStringExA(
    const IN_ADDR* address,
    WORD port,
    char* str,
    ULONG* size)
{
    char tmp[32];
    char* cur = tmp;
    ULONG needed;

    if (!address || !size) return STATUS_INVALID_PARAMETER;

    cur = winemu_append_u32_ascii(cur, address->S_un.S_un_b.s_b1);
    *cur++ = '.';
    cur = winemu_append_u32_ascii(cur, address->S_un.S_un_b.s_b2);
    *cur++ = '.';
    cur = winemu_append_u32_ascii(cur, address->S_un.S_un_b.s_b3);
    *cur++ = '.';
    cur = winemu_append_u32_ascii(cur, address->S_un.S_un_b.s_b4);
    if (port) {
        *cur++ = ':';
        cur = winemu_append_u32_ascii(cur, winemu_bswap16(port));
    }
    *cur++ = '\0';
    needed = (ULONG)(cur - tmp);

    if (!str || *size < needed) {
        *size = needed;
        return STATUS_BUFFER_TOO_SMALL;
    }

    for (ULONG i = 0; i < needed; i++) str[i] = tmp[i];
    *size = needed;
    return STATUS_SUCCESS;
}

EXPORT NTSTATUS RtlIpv4AddressToStringExW(
    const IN_ADDR* address,
    WORD port,
    WCHAR* str,
    ULONG* size)
{
    WCHAR tmp[32];
    WCHAR* cur = tmp;
    ULONG needed;

    if (!address || !size) return STATUS_INVALID_PARAMETER;

    cur = winemu_append_u32_wide(cur, address->S_un.S_un_b.s_b1);
    *cur++ = '.';
    cur = winemu_append_u32_wide(cur, address->S_un.S_un_b.s_b2);
    *cur++ = '.';
    cur = winemu_append_u32_wide(cur, address->S_un.S_un_b.s_b3);
    *cur++ = '.';
    cur = winemu_append_u32_wide(cur, address->S_un.S_un_b.s_b4);
    if (port) {
        *cur++ = ':';
        cur = winemu_append_u32_wide(cur, winemu_bswap16(port));
    }
    *cur++ = 0;
    needed = (ULONG)(cur - tmp);

    if (!str || *size < needed) {
        *size = needed;
        return STATUS_BUFFER_TOO_SMALL;
    }

    for (ULONG i = 0; i < needed; i++) str[i] = tmp[i];
    *size = needed;
    return STATUS_SUCCESS;
}

EXPORT char* RtlIpv4AddressToStringA(const IN_ADDR* address, char* str) {
    ULONG size = 16;
    if (RtlIpv4AddressToStringExA(address, 0, str, &size) != STATUS_SUCCESS && str) str[0] = '\0';
    return str;
}

EXPORT WCHAR* RtlIpv4AddressToStringW(const IN_ADDR* address, WCHAR* str) {
    ULONG size = 16;
    if (RtlIpv4AddressToStringExW(address, 0, str, &size) != STATUS_SUCCESS && str) str[0] = 0;
    return str;
}

EXPORT NTSTATUS RtlIpv6AddressToStringExA(
    const IN6_ADDR* address,
    LONG scope,
    WORD port,
    char* str,
    ULONG* size)
{
    char tmp[32];
    char* cur = tmp;
    ULONG needed;

    if (!address || !size) return STATUS_INVALID_PARAMETER;

    if (scope || port) {
        *cur++ = '[';
        *cur++ = ':';
        *cur++ = ':';
        *cur++ = ']';
        if (port) {
            *cur++ = ':';
            cur = winemu_append_u32_ascii(cur, winemu_bswap16(port));
        }
    } else {
        *cur++ = ':';
        *cur++ = ':';
    }
    *cur++ = '\0';
    needed = (ULONG)(cur - tmp);

    if (!str || *size < needed) {
        *size = needed;
        return STATUS_BUFFER_TOO_SMALL;
    }

    for (ULONG i = 0; i < needed; i++) str[i] = tmp[i];
    *size = needed;
    return STATUS_SUCCESS;
}

EXPORT NTSTATUS RtlIpv6AddressToStringExW(
    const IN6_ADDR* address,
    LONG scope,
    WORD port,
    WCHAR* str,
    ULONG* size)
{
    static const WCHAR zero_addr[] = { ':', ':', 0 };
    WCHAR tmp[32];
    WCHAR* cur = tmp;
    ULONG needed;

    if (!address || !size) return STATUS_INVALID_PARAMETER;

    if (scope || port) {
        *cur++ = '[';
        *cur++ = ':';
        *cur++ = ':';
        *cur++ = ']';
        if (port) {
            *cur++ = ':';
            cur = winemu_append_u32_wide(cur, winemu_bswap16(port));
        }
        *cur++ = 0;
        needed = (ULONG)(cur - tmp);
        if (!str || *size < needed) {
            *size = needed;
            return STATUS_BUFFER_TOO_SMALL;
        }
        for (ULONG i = 0; i < needed; i++) str[i] = tmp[i];
        *size = needed;
        return STATUS_SUCCESS;
    }

    needed = (ULONG)(sizeof(zero_addr) / sizeof(zero_addr[0]));
    if (!str || *size < needed) {
        *size = needed;
        return STATUS_BUFFER_TOO_SMALL;
    }
    *size = winemu_copy_wide_nt(str, zero_addr);
    return STATUS_SUCCESS;
}

EXPORT char* RtlIpv6AddressToStringA(const IN6_ADDR* address, char* str) {
    ULONG size = 32;
    if (RtlIpv6AddressToStringExA(address, 0, 0, str, &size) != STATUS_SUCCESS && str) str[0] = '\0';
    return str;
}

EXPORT WCHAR* RtlIpv6AddressToStringW(const IN6_ADDR* address, WCHAR* str) {
    ULONG size = 32;
    if (RtlIpv6AddressToStringExW(address, 0, 0, str, &size) != STATUS_SUCCESS && str) str[0] = 0;
    return str;
}
