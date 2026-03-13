/* ── Minimal NLS / locale bootstrap ─────────────────────────── */

typedef uint16_t USHORT;
typedef uint32_t UINT;
typedef int INT;
typedef int BOOL;
typedef ULONG LCID;
typedef USHORT LANGID;

typedef struct {
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG Attributes;
    void* SecurityDescriptor;
    void* SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct {
    uint64_t status;
    uint64_t info;
} IO_STATUS_BLOCK;

typedef struct {
    USHORT CodePage;
    USHORT MaximumCharacterSize;
    USHORT DefaultChar;
    USHORT UniDefaultChar;
    USHORT TransDefaultChar;
    USHORT TransUniDefaultChar;
    USHORT DBCSCodePage;
    UCHAR LeadByte[12];
    USHORT* MultiByteTable;
    void* WideCharTable;
    USHORT* DBCSRanges;
    USHORT* DBCSOffsets;
} CPTABLEINFO;

typedef struct {
    CPTABLEINFO OemTableInfo;
    CPTABLEINFO AnsiTableInfo;
    USHORT* UpperCaseTable;
    USHORT* LowerCaseTable;
} NLSTABLEINFO;

#define GENERIC_READ 0x80000000U
#define FILE_SHARE_READ 0x00000001U
#define FILE_OPEN 1U
#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010U
#define SECTION_MAP_READ 0x0004U
#define PAGE_READONLY 0x00000002U
#define SEC_COMMIT 0x08000000U
#define VIEW_SHARE 1U
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034U
#define STATUS_INVALID_PARAMETER_1 0xC00000EFU
#define STATUS_UNSUCCESSFUL 0xC0000001U
#define CP_UTF8 65001U
#define CP_ACP 0U
#define CP_OEMCP 1U
#define CP_THREAD_ACP 3U
#define LOCALE_EN_US 0x0409U
#define LANG_EN_US 0x0409U
#define MB_PRECOMPOSED 0x00000001U
#define MB_COMPOSITE 0x00000002U
#define MB_USEGLYPHCHARS 0x00000004U
#define MB_ERR_INVALID_CHARS 0x00000008U
#define WC_COMPOSITECHECK 0x00000200U
#define WC_DISCARDNS 0x00000010U
#define WC_SEPCHARS 0x00000020U
#define WC_DEFAULTCHAR 0x00000040U
#define WC_ERR_INVALID_CHARS 0x00000080U
#define WC_NO_BEST_FIT_CHARS 0x00000400U
#define ERROR_INVALID_FLAGS 1004U
#define ERROR_INVALID_PARAMETER 87U
#define ERROR_INSUFFICIENT_BUFFER 122U
#define ERROR_NO_UNICODE_TRANSLATION 1113U
#define TRUE 1
#define FALSE 0

typedef struct {
    UINT MaxCharSize;
    char DefaultChar[2];
    char LeadByte[12];
} CPINFO;

enum winemu_nls_section_type {
    WINEMU_NLS_SECTION_SORTKEYS = 9,
    WINEMU_NLS_SECTION_CASEMAP = 10,
    WINEMU_NLS_SECTION_CODEPAGE = 11,
    WINEMU_NLS_SECTION_NORMALIZE = 12,
};

enum winemu_norm_form {
    WINEMU_NORMALIZATION_C = 0x1,
    WINEMU_NORMALIZATION_D = 0x2,
    WINEMU_NORMALIZATION_KC = 0x5,
    WINEMU_NORMALIZATION_KD = 0x6,
    WINEMU_NORMALIZATION_IDNA = 13,
};

typedef struct {
    ULONG type;
    ULONG id;
    void* ptr;
    size_t size;
} WinEmuNlsCacheEntry;

static void* g_locale_nls_ptr;
static size_t g_locale_nls_size;
static WinEmuNlsCacheEntry g_nls_cache[16];

static void winemu_init_object_attributes(
    OBJECT_ATTRIBUTES* attr,
    UNICODE_STRING* name,
    ULONG attributes,
    HANDLE root_directory)
{
    attr->Length = sizeof(*attr);
    attr->RootDirectory = root_directory;
    attr->ObjectName = name;
    attr->Attributes = attributes;
    attr->SecurityDescriptor = NULL;
    attr->SecurityQualityOfService = NULL;
}

static void winemu_ascii_to_unicode(WCHAR* dst, const char* src) {
    size_t i = 0;
    while (src[i]) {
        dst[i] = (WCHAR)(unsigned char)src[i];
        i++;
    }
    dst[i] = 0;
}

static char* winemu_ascii_copy(char* dst, const char* src) {
    size_t i = 0;
    do {
        dst[i] = src[i];
    } while (src[i++] != 0);
    return dst;
}

static char* winemu_append_u32(char* dst, ULONG value, unsigned min_digits) {
    char tmp[16];
    unsigned digits = 0;
    do {
        tmp[digits++] = (char)('0' + (value % 10));
        value /= 10;
    } while (value != 0 && digits < sizeof(tmp));
    while (digits < min_digits && digits < sizeof(tmp)) {
        tmp[digits++] = '0';
    }
    while (digits != 0) {
        digits--;
        *dst++ = tmp[digits];
    }
    *dst = 0;
    return dst;
}

static NTSTATUS winemu_open_ascii_file_readonly(const char* path, HANDLE* file) {
    WCHAR wide_path[128];
    UNICODE_STRING path_us;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    if (!path || !file) return STATUS_INVALID_PARAMETER;
    winemu_ascii_to_unicode(wide_path, path);
    RtlInitUnicodeString(&path_us, wide_path);
    winemu_init_object_attributes(&attr, &path_us, 0, 0);
    iosb.status = 0;
    iosb.info = 0;
    return NtOpenFile(
        file,
        GENERIC_READ,
        &attr,
        &iosb,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_ALERT);
}

static NTSTATUS winemu_map_ascii_file_readonly(
    const char* path,
    void** mapped_ptr,
    size_t* mapped_size)
{
    HANDLE file = 0;
    HANDLE section = 0;
    size_t view_size = 0;
    void* base = NULL;
    NTSTATUS status;

    if (!mapped_ptr) return STATUS_INVALID_PARAMETER;
    status = winemu_open_ascii_file_readonly(path, &file);
    if (status != STATUS_SUCCESS) return status;

    status = NtCreateSection(&section, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_COMMIT, file);
    NtClose(file);
    if (status != STATUS_SUCCESS) return status;

    status = NtMapViewOfSection(
        section,
        (HANDLE)(intptr_t)-1,
        &base,
        0,
        0,
        NULL,
        &view_size,
        VIEW_SHARE,
        0,
        PAGE_READONLY);
    NtClose(section);
    if (status != STATUS_SUCCESS) return status;

    *mapped_ptr = base;
    if (mapped_size) *mapped_size = view_size;
    return STATUS_SUCCESS;
}

static NTSTATUS winemu_try_map_nls_file(
    const char* filename,
    void** mapped_ptr,
    size_t* mapped_size)
{
    char path[96];
    NTSTATUS status;

    winemu_ascii_copy(path, "guest/sysroot/nls/");
    winemu_ascii_copy(path + strlen(path), filename);
    status = winemu_map_ascii_file_readonly(path, mapped_ptr, mapped_size);
    if (status == STATUS_SUCCESS) return status;

    winemu_ascii_copy(path, "guest/nls/");
    winemu_ascii_copy(path + strlen(path), filename);
    return winemu_map_ascii_file_readonly(path, mapped_ptr, mapped_size);
}

static const char* winemu_nls_filename(ULONG type, ULONG id, char* buffer) {
    if (!buffer) return NULL;
    switch (type) {
    case WINEMU_NLS_SECTION_SORTKEYS:
        if (id != 0) return NULL;
        return "sortdefault.nls";
    case WINEMU_NLS_SECTION_CASEMAP:
        if (id != 0) return NULL;
        return "l_intl.nls";
    case WINEMU_NLS_SECTION_CODEPAGE:
        winemu_ascii_copy(buffer, "c_");
        winemu_append_u32(buffer + 2, id, 3);
        winemu_ascii_copy(buffer + strlen(buffer), ".nls");
        return buffer;
    case WINEMU_NLS_SECTION_NORMALIZE:
        switch (id) {
        case WINEMU_NORMALIZATION_C:
            return "normnfc.nls";
        case WINEMU_NORMALIZATION_D:
            return "normnfd.nls";
        case WINEMU_NORMALIZATION_KC:
            return "normnfkc.nls";
        case WINEMU_NORMALIZATION_KD:
            return "normnfkd.nls";
        case WINEMU_NORMALIZATION_IDNA:
            return "normidna.nls";
        default:
            return NULL;
        }
    default:
        return NULL;
    }
}

static WinEmuNlsCacheEntry* winemu_find_nls_cache(ULONG type, ULONG id) {
    for (size_t i = 0; i < sizeof(g_nls_cache) / sizeof(g_nls_cache[0]); i++) {
        if (!g_nls_cache[i].ptr) continue;
        if (g_nls_cache[i].type == type && g_nls_cache[i].id == id) {
            return &g_nls_cache[i];
        }
    }
    return NULL;
}

static void winemu_store_nls_cache(ULONG type, ULONG id, void* ptr, size_t size) {
    for (size_t i = 0; i < sizeof(g_nls_cache) / sizeof(g_nls_cache[0]); i++) {
        if (g_nls_cache[i].ptr) continue;
        g_nls_cache[i].type = type;
        g_nls_cache[i].id = id;
        g_nls_cache[i].ptr = ptr;
        g_nls_cache[i].size = size;
        return;
    }
}

static void winemu_init_codepage_table(USHORT* ptr, CPTABLEINFO* info) {
    USHORT hdr_size = ptr[0];

    info->CodePage = ptr[1];
    info->MaximumCharacterSize = ptr[2];
    info->DefaultChar = ptr[3];
    info->UniDefaultChar = ptr[4];
    info->TransDefaultChar = ptr[5];
    info->TransUniDefaultChar = ptr[6];
    memcpy(info->LeadByte, ptr + 7, sizeof(info->LeadByte));
    ptr += hdr_size;

    info->WideCharTable = ptr + ptr[0] + 1;
    info->MultiByteTable = ++ptr;
    ptr += 256;
    if (*ptr++) ptr += 256;
    info->DBCSRanges = ptr;
    if (*ptr) {
        info->DBCSCodePage = 1;
        info->DBCSOffsets = ptr + 1;
    } else {
        info->DBCSCodePage = 0;
        info->DBCSOffsets = NULL;
    }
}

EXPORT NTSTATUS NtInitializeNlsFiles(void** ptr, LCID* lcid, int64_t* size) {
    if (!ptr || !lcid) return STATUS_INVALID_PARAMETER;

    if (!g_locale_nls_ptr) {
        NTSTATUS status = winemu_try_map_nls_file("locale.nls", &g_locale_nls_ptr, &g_locale_nls_size);
        if (status != STATUS_SUCCESS) return status;
    }

    *ptr = g_locale_nls_ptr;
    *lcid = LOCALE_EN_US;
    if (size) *size = (int64_t)g_locale_nls_size;
    return STATUS_SUCCESS;
}

EXPORT NTSTATUS NtGetNlsSectionPtr(
    ULONG type,
    ULONG id,
    void* unknown,
    void** ptr,
    size_t* size)
{
    char name_buf[24];
    const char* filename;
    void* mapped_ptr = NULL;
    size_t mapped_size = 0;
    WinEmuNlsCacheEntry* cached;
    NTSTATUS status;

    (void)unknown;
    if (!ptr) return STATUS_INVALID_PARAMETER;

    cached = winemu_find_nls_cache(type, id);
    if (cached) {
        *ptr = cached->ptr;
        if (size) *size = cached->size;
        return STATUS_SUCCESS;
    }

    filename = winemu_nls_filename(type, id, name_buf);
    if (!filename) {
        return (type == WINEMU_NLS_SECTION_SORTKEYS ||
                type == WINEMU_NLS_SECTION_CASEMAP ||
                type == WINEMU_NLS_SECTION_CODEPAGE ||
                type == WINEMU_NLS_SECTION_NORMALIZE)
            ? STATUS_OBJECT_NAME_NOT_FOUND
            : STATUS_INVALID_PARAMETER_1;
    }

    status = winemu_try_map_nls_file(filename, &mapped_ptr, &mapped_size);
    if (status != STATUS_SUCCESS) return status;

    winemu_store_nls_cache(type, id, mapped_ptr, mapped_size);
    *ptr = mapped_ptr;
    if (size) *size = mapped_size;
    return STATUS_SUCCESS;
}

EXPORT NTSTATUS NtQueryDefaultLocale(UCHAR user, LCID* lcid) {
    (void)user;
    if (!lcid) return STATUS_INVALID_PARAMETER;
    *lcid = LOCALE_EN_US;
    return STATUS_SUCCESS;
}

EXPORT NTSTATUS NtQueryDefaultUILanguage(LANGID* language) {
    if (!language) return STATUS_INVALID_PARAMETER;
    *language = LANG_EN_US;
    return STATUS_SUCCESS;
}

EXPORT NTSTATUS NtQueryInstallUILanguage(LANGID* language) {
    if (!language) return STATUS_INVALID_PARAMETER;
    *language = LANG_EN_US;
    return STATUS_SUCCESS;
}

EXPORT NTSTATUS RtlGetLocaleFileMappingAddress(void** ptr, LCID* lcid, int64_t* size) {
    return NtInitializeNlsFiles(ptr, lcid, size);
}

EXPORT void RtlInitCodePageTable(USHORT* ptr, CPTABLEINFO* info) {
    static const CPTABLEINFO utf8_cpinfo = { CP_UTF8, 4, '?', 0xfffd, '?', '?' };

    if (!ptr || !info) return;
    if (ptr[1] == CP_UTF8) {
        *info = utf8_cpinfo;
        return;
    }
    winemu_init_codepage_table(ptr, info);
}

EXPORT void RtlInitNlsTables(USHORT* ansi, USHORT* oem, USHORT* casetable, NLSTABLEINFO* info) {
    if (!ansi || !oem || !casetable || !info) return;
    RtlInitCodePageTable(ansi, &info->AnsiTableInfo);
    RtlInitCodePageTable(oem, &info->OemTableInfo);
    info->UpperCaseTable = casetable + 2;
    info->LowerCaseTable = casetable + casetable[1] + 2;
}

static UINT winemu_effective_codepage(UINT codepage) {
    switch (codepage) {
    case CP_ACP:
    case CP_OEMCP:
    case CP_THREAD_ACP:
        return CP_UTF8;
    default:
        return codepage;
    }
}

static void winemu_set_last_error(ULONG code) {
    RtlSetLastWin32Error(code);
}

static int winemu_utf8_decode_char(
    const unsigned char* src,
    int srclen,
    uint32_t* codepoint,
    int* consumed,
    int strict)
{
    uint32_t cp;
    int need;

    if (!src || srclen <= 0 || !codepoint || !consumed) return 0;
    if (src[0] < 0x80) {
        *codepoint = src[0];
        *consumed = 1;
        return 1;
    }
    if ((src[0] & 0xE0) == 0xC0) {
        cp = src[0] & 0x1F;
        need = 2;
        if (cp < 0x02 && strict) return 0;
    } else if ((src[0] & 0xF0) == 0xE0) {
        cp = src[0] & 0x0F;
        need = 3;
    } else if ((src[0] & 0xF8) == 0xF0) {
        cp = src[0] & 0x07;
        need = 4;
        if (cp > 0x04 && strict) return 0;
    } else {
        return 0;
    }
    if (srclen < need) return 0;
    for (int i = 1; i < need; ++i) {
        if ((src[i] & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (src[i] & 0x3F);
    }
    if (strict) {
        if ((need == 2 && cp < 0x80) ||
            (need == 3 && cp < 0x800) ||
            (need == 4 && cp < 0x10000) ||
            cp > 0x10FFFF ||
            (cp >= 0xD800 && cp <= 0xDFFF)) {
            return 0;
        }
    }
    *codepoint = cp;
    *consumed = need;
    return 1;
}

static int winemu_utf8_encode_char(uint32_t cp, char* dst, int dstlen) {
    if (cp <= 0x7F) {
        if (dstlen < 1) return 0;
        dst[0] = (char)cp;
        return 1;
    }
    if (cp <= 0x7FF) {
        if (dstlen < 2) return 0;
        dst[0] = (char)(0xC0 | (cp >> 6));
        dst[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp <= 0xFFFF) {
        if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
        if (dstlen < 3) return 0;
        dst[0] = (char)(0xE0 | (cp >> 12));
        dst[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        dst[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    if (cp <= 0x10FFFF) {
        if (dstlen < 4) return 0;
        dst[0] = (char)(0xF0 | (cp >> 18));
        dst[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        dst[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        dst[3] = (char)(0x80 | (cp & 0x3F));
        return 4;
    }
    return 0;
}

EXPORT INT MultiByteToWideChar(
    UINT codepage,
    DWORD flags,
    const char* src,
    INT srclen,
    WCHAR* dst,
    INT dstlen)
{
    UINT cp = winemu_effective_codepage(codepage);
    int required = 0;
    int produced = 0;
    int strict = (flags & MB_ERR_INVALID_CHARS) != 0;

    if (!src || !srclen || (!dst && dstlen) || dstlen < 0) {
        winemu_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (flags & ~(MB_PRECOMPOSED | MB_COMPOSITE | MB_USEGLYPHCHARS | MB_ERR_INVALID_CHARS)) {
        winemu_set_last_error(ERROR_INVALID_FLAGS);
        return 0;
    }
    if (srclen < 0) srclen = (INT)strlen(src) + 1;

    if (cp == CP_UTF8) {
        int i = 0;
        while (i < srclen) {
            uint32_t ch;
            int consumed;
            if (!winemu_utf8_decode_char((const unsigned char*)src + i, srclen - i, &ch, &consumed, strict)) {
                if (strict) {
                    winemu_set_last_error(ERROR_NO_UNICODE_TRANSLATION);
                    return 0;
                }
                ch = '?';
                consumed = 1;
            }
            required += (ch > 0xFFFF) ? 2 : 1;
            if (dst) {
                if (produced + ((ch > 0xFFFF) ? 2 : 1) > dstlen) {
                    winemu_set_last_error(ERROR_INSUFFICIENT_BUFFER);
                    return 0;
                }
                if (ch > 0xFFFF) {
                    ch -= 0x10000;
                    dst[produced++] = (WCHAR)(0xD800 + (ch >> 10));
                    dst[produced++] = (WCHAR)(0xDC00 + (ch & 0x3FF));
                } else {
                    dst[produced++] = (WCHAR)ch;
                }
            }
            i += consumed;
        }
    } else {
        required = srclen;
        if (dst) {
            if (required > dstlen) {
                winemu_set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            for (produced = 0; produced < srclen; ++produced) {
                dst[produced] = (unsigned char)src[produced];
            }
        }
    }
    return dst ? produced : required;
}

EXPORT INT WideCharToMultiByte(
    UINT codepage,
    DWORD flags,
    const WCHAR* src,
    INT srclen,
    char* dst,
    INT dstlen,
    const char* default_char,
    BOOL* used_default)
{
    UINT cp = winemu_effective_codepage(codepage);
    int required = 0;
    int produced = 0;
    (void)default_char;

    if (used_default) *used_default = FALSE;
    if (!src || !srclen || (!dst && dstlen) || dstlen < 0) {
        winemu_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (flags & ~(WC_COMPOSITECHECK | WC_DISCARDNS | WC_SEPCHARS | WC_DEFAULTCHAR |
                  WC_ERR_INVALID_CHARS | WC_NO_BEST_FIT_CHARS)) {
        winemu_set_last_error(ERROR_INVALID_FLAGS);
        return 0;
    }
    if (srclen < 0) {
        srclen = 0;
        while (src[srclen]) srclen++;
        srclen++;
    }

    if (cp == CP_UTF8) {
        for (int i = 0; i < srclen; ++i) {
            uint32_t ch = src[i];
            char encoded[4];
            int enc_len;

            if (ch >= 0xD800 && ch <= 0xDBFF) {
                if (i + 1 >= srclen || src[i + 1] < 0xDC00 || src[i + 1] > 0xDFFF) {
                    if (flags & WC_ERR_INVALID_CHARS) {
                        winemu_set_last_error(ERROR_NO_UNICODE_TRANSLATION);
                        return 0;
                    }
                    ch = '?';
                    if (used_default) *used_default = TRUE;
                } else {
                    ch = 0x10000 + (((ch - 0xD800) << 10) | (src[++i] - 0xDC00));
                }
            } else if (ch >= 0xDC00 && ch <= 0xDFFF) {
                if (flags & WC_ERR_INVALID_CHARS) {
                    winemu_set_last_error(ERROR_NO_UNICODE_TRANSLATION);
                    return 0;
                }
                ch = '?';
                if (used_default) *used_default = TRUE;
            }

            enc_len = winemu_utf8_encode_char(ch, encoded, sizeof(encoded));
            if (!enc_len) {
                if (flags & WC_ERR_INVALID_CHARS) {
                    winemu_set_last_error(ERROR_NO_UNICODE_TRANSLATION);
                    return 0;
                }
                encoded[0] = '?';
                enc_len = 1;
                if (used_default) *used_default = TRUE;
            }
            required += enc_len;
            if (dst) {
                if (produced + enc_len > dstlen) {
                    winemu_set_last_error(ERROR_INSUFFICIENT_BUFFER);
                    return 0;
                }
                for (int j = 0; j < enc_len; ++j) dst[produced++] = encoded[j];
            }
        }
    } else {
        required = srclen;
        if (dst) {
            if (required > dstlen) {
                winemu_set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            for (int i = 0; i < srclen; ++i) {
                if (src[i] > 0x00FF && used_default) *used_default = TRUE;
                dst[i] = (src[i] <= 0x00FF) ? (char)src[i] : '?';
            }
            produced = srclen;
        }
    }
    return dst ? produced : required;
}
