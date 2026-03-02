/* ── Basic CRT exports required by kernelbase/kernel32 ─────── */

__attribute__((naked))
EXPORT ULONG_PTR __chkstk(void) {
    asm volatile(
        // Windows arm64 ABI: allocation size is passed in x15 in 16-byte units.
        // Probe one page at a time from current SP downward so guard growth and
        // stack overflow behavior are fault-driven and deterministic.
        "mov x9, sp\n\t"
        "lsl x10, x15, #4\n\t"
        "cbz x10, 2f\n\t"
        "1:\n\t"
        "cmp x10, #0x1000\n\t"
        "b.lo 3f\n\t"
        "sub x9, x9, #0x1000\n\t"
        "ldr x11, [x9]\n\t"
        "sub x10, x10, #0x1000\n\t"
        "cbnz x10, 1b\n\t"
        "b 2f\n\t"
        "3:\n\t"
        "sub x9, x9, x10\n\t"
        "ldr x11, [x9]\n\t"
        "2:\n\t"
        "mov x0, x15\n\t"
        "ret\n\t");
}

EXPORT void* memset(void* dst, int c, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    for (size_t i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}

EXPORT void* memcpy(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

EXPORT void* memmove(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    if (d == s || n == 0) return dst;
    if (d < s) {
        for (size_t i = 0; i < n; i++) d[i] = s[i];
    } else {
        size_t i = n;
        while (i != 0) {
            i--;
            d[i] = s[i];
        }
    }
    return dst;
}

EXPORT int memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    for (size_t i = 0; i < n; i++) {
        if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    }
    return 0;
}

static int ascii_tolower(int ch) {
    if (ch >= 'A' && ch <= 'Z') return ch + 32;
    return ch;
}

static int wide_tolower(int ch) {
    if (ch >= L'A' && ch <= L'Z') return ch + 32;
    return ch;
}

EXPORT int tolower(int ch) {
    return ascii_tolower(ch);
}

EXPORT int towupper(int ch) {
    if (ch >= L'a' && ch <= L'z') return ch - 32;
    return ch;
}

EXPORT int isalpha(int ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
}

EXPORT int isalnum(int ch) {
    return isalpha(ch) || (ch >= '0' && ch <= '9');
}

EXPORT int isxdigit(int ch) {
    return (ch >= '0' && ch <= '9')
        || (ch >= 'a' && ch <= 'f')
        || (ch >= 'A' && ch <= 'F');
}

EXPORT size_t strlen(const char* s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

EXPORT int strcmp(const char* a, const char* b) {
    size_t i = 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) return (unsigned char)a[i] - (unsigned char)b[i];
        i++;
    }
    return (unsigned char)a[i] - (unsigned char)b[i];
}

EXPORT int strncmp(const char* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char ac = (unsigned char)a[i];
        unsigned char bc = (unsigned char)b[i];
        if (ac != bc) return ac - bc;
        if (ac == 0) return 0;
    }
    return 0;
}

EXPORT char* strcpy(char* dst, const char* src) {
    size_t i = 0;
    do {
        dst[i] = src[i];
    } while (src[i++] != 0);
    return dst;
}

EXPORT char* strcat(char* dst, const char* src) {
    size_t d = strlen(dst);
    size_t i = 0;
    do {
        dst[d + i] = src[i];
    } while (src[i++] != 0);
    return dst;
}

EXPORT char* strchr(const char* s, int ch) {
    unsigned char c = (unsigned char)ch;
    while (*s) {
        if ((unsigned char)*s == c) return (char*)s;
        s++;
    }
    if (c == 0) return (char*)s;
    return NULL;
}

EXPORT char* strrchr(const char* s, int ch) {
    char* last = NULL;
    unsigned char c = (unsigned char)ch;
    while (*s) {
        if ((unsigned char)*s == c) last = (char*)s;
        s++;
    }
    if (c == 0) return (char*)s;
    return last;
}

EXPORT int _strnicmp(const char* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int ac = ascii_tolower((unsigned char)a[i]);
        int bc = ascii_tolower((unsigned char)b[i]);
        if (ac != bc) return ac - bc;
        if (ac == 0) return 0;
    }
    return 0;
}

EXPORT long strtol(const char* nptr, char** endptr, int base) {
    const char* p = nptr;
    int neg = 0;
    unsigned long v = 0;
    if (!p) {
        if (endptr) *endptr = (char*)nptr;
        return 0;
    }
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '+' || *p == '-') {
        neg = (*p == '-');
        p++;
    }
    if (base == 0) {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
            base = 16;
            p += 2;
        } else if (p[0] == '0') {
            base = 8;
            p++;
        } else {
            base = 10;
        }
    }
    while (*p) {
        int d;
        if (*p >= '0' && *p <= '9') d = *p - '0';
        else if (*p >= 'a' && *p <= 'z') d = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'Z') d = *p - 'A' + 10;
        else break;
        if (d >= base) break;
        v = v * (unsigned)base + (unsigned)d;
        p++;
    }
    if (endptr) *endptr = (char*)p;
    return neg ? -(long)v : (long)v;
}

EXPORT size_t wcslen(const WCHAR* s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

EXPORT size_t wcsnlen(const WCHAR* s, size_t n) {
    size_t i = 0;
    if (!s) return 0;
    while (i < n && s[i]) i++;
    return i;
}

EXPORT int wcscmp(const WCHAR* a, const WCHAR* b) {
    size_t i = 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) return (int)a[i] - (int)b[i];
        i++;
    }
    return (int)a[i] - (int)b[i];
}

EXPORT int wcsncmp(const WCHAR* a, const WCHAR* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)a[i] - (int)b[i];
        if (a[i] == 0) return 0;
    }
    return 0;
}

EXPORT WCHAR* wcscpy(WCHAR* dst, const WCHAR* src) {
    size_t i = 0;
    do {
        dst[i] = src[i];
    } while (src[i++] != 0);
    return dst;
}

EXPORT WCHAR* wcscat(WCHAR* dst, const WCHAR* src) {
    size_t d = wcslen(dst);
    size_t i = 0;
    do {
        dst[d + i] = src[i];
    } while (src[i++] != 0);
    return dst;
}

EXPORT WCHAR* wcschr(const WCHAR* s, WCHAR ch) {
    while (*s) {
        if (*s == ch) return (WCHAR*)s;
        s++;
    }
    if (ch == 0) return (WCHAR*)s;
    return NULL;
}

EXPORT WCHAR* wcsrchr(const WCHAR* s, WCHAR ch) {
    WCHAR* last = NULL;
    while (*s) {
        if (*s == ch) last = (WCHAR*)s;
        s++;
    }
    if (ch == 0) return (WCHAR*)s;
    return last;
}

EXPORT WCHAR* wcspbrk(const WCHAR* s, const WCHAR* accept) {
    for (; *s; s++) {
        for (const WCHAR* a = accept; *a; a++) {
            if (*s == *a) return (WCHAR*)s;
        }
    }
    return NULL;
}

EXPORT size_t wcscspn(const WCHAR* s, const WCHAR* reject) {
    size_t n = 0;
    while (s[n]) {
        for (const WCHAR* r = reject; *r; r++) {
            if (s[n] == *r) return n;
        }
        n++;
    }
    return n;
}

EXPORT size_t wcsspn(const WCHAR* s, const WCHAR* accept) {
    size_t n = 0;
    while (s[n]) {
        int ok = 0;
        for (const WCHAR* a = accept; *a; a++) {
            if (s[n] == *a) {
                ok = 1;
                break;
            }
        }
        if (!ok) break;
        n++;
    }
    return n;
}

EXPORT WCHAR* wcsstr(const WCHAR* haystack, const WCHAR* needle) {
    if (!needle || !needle[0]) return (WCHAR*)haystack;
    for (size_t i = 0; haystack[i]; i++) {
        size_t j = 0;
        while (needle[j] && haystack[i + j] == needle[j]) j++;
        if (!needle[j]) return (WCHAR*)(haystack + i);
    }
    return NULL;
}

EXPORT int _wcsicmp(const WCHAR* a, const WCHAR* b) {
    size_t i = 0;
    while (a[i] && b[i]) {
        int ac = wide_tolower(a[i]);
        int bc = wide_tolower(b[i]);
        if (ac != bc) return ac - bc;
        i++;
    }
    return wide_tolower(a[i]) - wide_tolower(b[i]);
}

EXPORT int _wcsnicmp(const WCHAR* a, const WCHAR* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int ac = wide_tolower(a[i]);
        int bc = wide_tolower(b[i]);
        if (ac != bc) return ac - bc;
        if (ac == 0) return 0;
    }
    return 0;
}

EXPORT long wcstol(const WCHAR* nptr, WCHAR** endptr, int base) {
    const WCHAR* p = nptr;
    int neg = 0;
    unsigned long v = 0;
    if (!p) {
        if (endptr) *endptr = (WCHAR*)nptr;
        return 0;
    }
    while (*p == L' ' || *p == L'\t' || *p == L'\n' || *p == L'\r') p++;
    if (*p == L'+' || *p == L'-') {
        neg = (*p == L'-');
        p++;
    }
    if (base == 0) {
        if (p[0] == L'0' && (p[1] == L'x' || p[1] == L'X')) {
            base = 16;
            p += 2;
        } else if (p[0] == L'0') {
            base = 8;
            p++;
        } else {
            base = 10;
        }
    }
    while (*p) {
        int d;
        if (*p >= L'0' && *p <= L'9') d = *p - L'0';
        else if (*p >= L'a' && *p <= L'z') d = *p - L'a' + 10;
        else if (*p >= L'A' && *p <= L'Z') d = *p - L'A' + 10;
        else break;
        if (d >= base) break;
        v = v * (unsigned)base + (unsigned)d;
        p++;
    }
    if (endptr) *endptr = (WCHAR*)p;
    return neg ? -(long)v : (long)v;
}

EXPORT unsigned long wcstoul(const WCHAR* nptr, WCHAR** endptr, int base) {
    long v = wcstol(nptr, endptr, base);
    return (unsigned long)v;
}

