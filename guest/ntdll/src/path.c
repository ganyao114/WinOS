/* ── Path helpers ───────────────────────────────────────────── */

typedef enum {
    INVALID_PATH = 0,
    UNC_PATH,
    ABSOLUTE_DRIVE_PATH,
    RELATIVE_DRIVE_PATH,
    ABSOLUTE_PATH,
    RELATIVE_PATH,
    DEVICE_PATH,
    UNC_DOT_PATH
} DOS_PATHNAME_TYPE;

typedef struct {
    UNICODE_STRING DosPath;
    void* Handle;
} CURDIR;

typedef struct {
    UNICODE_STRING RelativeName;
    HANDLE ContainerDirectory;
    void* CurDirRef;
} RTL_RELATIVE_NAME;

#define STATUS_OBJECT_NAME_INVALID 0xC0000033U
#define STATUS_OBJECT_PATH_NOT_FOUND 0xC000003AU
#define WINEMU_PEB_PROCESS_PARAMETERS_OFF 0x20
#define WINEMU_UPP_CURRENT_DIR_OFF 0x38
#define WINEMU_DEFAULT_DIR_MAX 260

static const WCHAR winemu_default_current_dir[] = {
    'C', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 0
};

static WCHAR* g_current_dir = NULL;
static uint16_t g_current_dir_len = 0;
static uint16_t g_current_dir_max = 0;

EXPORT DOS_PATHNAME_TYPE RtlDetermineDosPathNameType_U(const WCHAR* path);
EXPORT ULONG RtlGetFullPathName_U(
    const WCHAR* name,
    ULONG size,
    WCHAR* buffer,
    WCHAR** file_part);

static int winemu_is_sep(WCHAR ch) {
    return ch == '\\' || ch == '/';
}

static WCHAR winemu_ascii_tolower_w(WCHAR ch) {
    if (ch >= 'A' && ch <= 'Z') return (WCHAR)(ch + ('a' - 'A'));
    return ch;
}

static int winemu_drive_eq_ci(WCHAR lhs, WCHAR rhs) {
    return winemu_ascii_tolower_w(lhs) == winemu_ascii_tolower_w(rhs);
}

static size_t winemu_unicode_string_chars(const UNICODE_STRING* us) {
    if (!us) return 0;
    return (size_t)(us->Length / sizeof(WCHAR));
}

static UNICODE_STRING* winemu_process_current_dir_us(void) {
    uint8_t* peb = (uint8_t*)RtlGetCurrentPeb();
    uint8_t* params;
    if (!peb) return NULL;
    params = *(uint8_t**)(peb + WINEMU_PEB_PROCESS_PARAMETERS_OFF);
    if (!params) return NULL;
    return (UNICODE_STRING*)(params + WINEMU_UPP_CURRENT_DIR_OFF);
}

static void winemu_sync_current_dir_to_process_params(void) {
    UNICODE_STRING* us;
    if (!g_current_dir || !g_current_dir_max) return;
    us = winemu_process_current_dir_us();
    if (!us) return;

    if (!us->Buffer || us->MaximumLength < g_current_dir_max) {
        WCHAR* new_buf = (WCHAR*)RtlAllocateHeap(NULL, 0, g_current_dir_max);
        if (!new_buf) return;
        if (us->Buffer) RtlFreeHeap(NULL, 0, us->Buffer);
        us->Buffer = new_buf;
        us->MaximumLength = g_current_dir_max;
    }

    memcpy(us->Buffer, g_current_dir, g_current_dir_max);
    us->Length = g_current_dir_len;
}

static int winemu_store_current_dir(const WCHAR* path, size_t chars) {
    uint16_t bytes;
    uint16_t max_bytes;

    if (!path) return 0;
    if (chars == 0 || path[chars - 1] != '\\') {
        return 0;
    }
    if (chars > 0x7ffeu) return 0;

    bytes = (uint16_t)(chars * sizeof(WCHAR));
    max_bytes = (uint16_t)(bytes + sizeof(WCHAR));

    if (!g_current_dir || g_current_dir_max < max_bytes) {
        WCHAR* new_buf = (WCHAR*)RtlAllocateHeap(NULL, 0, max_bytes);
        if (!new_buf) return 0;
        if (g_current_dir) RtlFreeHeap(NULL, 0, g_current_dir);
        g_current_dir = new_buf;
        g_current_dir_max = max_bytes;
    }

    memcpy(g_current_dir, path, bytes);
    g_current_dir[chars] = 0;
    g_current_dir_len = bytes;
    winemu_sync_current_dir_to_process_params();
    return 1;
}

static void winemu_init_current_dir(void) {
    UNICODE_STRING* us;
    size_t chars;

    if (g_current_dir) return;

    us = winemu_process_current_dir_us();
    chars = winemu_unicode_string_chars(us);
    if (us && us->Buffer && chars >= 3 && chars < 0x7ffeu) {
        WCHAR tmp[WINEMU_DEFAULT_DIR_MAX];
        size_t copy_chars = chars;
        if (copy_chars + 1 >= WINEMU_DEFAULT_DIR_MAX) copy_chars = WINEMU_DEFAULT_DIR_MAX - 2;
        memcpy(tmp, us->Buffer, copy_chars * sizeof(WCHAR));
        if (copy_chars == 0 || tmp[copy_chars - 1] != '\\') {
            tmp[copy_chars++] = '\\';
        }
        tmp[copy_chars] = 0;
        if (winemu_store_current_dir(tmp, copy_chars)) return;
    }

    (void)winemu_store_current_dir(
        winemu_default_current_dir, wcslen(winemu_default_current_dir));
}

static const WCHAR* winemu_current_dir_ptr(void) {
    winemu_init_current_dir();
    return g_current_dir ? g_current_dir : winemu_default_current_dir;
}

static size_t winemu_current_dir_chars(void) {
    winemu_init_current_dir();
    if (g_current_dir) return (size_t)(g_current_dir_len / sizeof(WCHAR));
    return wcslen(winemu_default_current_dir);
}

static const WCHAR* winemu_skip_unc_prefix(const WCHAR* ptr) {
    ptr += 2;
    while (*ptr && !winemu_is_sep(*ptr)) ptr++;
    while (winemu_is_sep(*ptr)) ptr++;
    while (*ptr && !winemu_is_sep(*ptr)) ptr++;
    while (winemu_is_sep(*ptr)) ptr++;
    return ptr;
}

static void winemu_collapse_path(WCHAR* path, unsigned mark) {
    WCHAR* p;
    WCHAR* next;

    for (p = path; *p; p++) {
        if (*p == '/') *p = '\\';
    }

    next = path + (mark > 1 ? mark : 1);
    for (p = next; *p; p++) {
        if (*p != '\\' || next[-1] != '\\') *next++ = *p;
    }
    *next = 0;

    p = path + mark;
    while (*p) {
        if (*p == '.') {
            if (p[1] == '\\') {
                next = p + 2;
                memmove(p, next, (wcslen(next) + 1) * sizeof(WCHAR));
                continue;
            }
            if (!p[1]) {
                if (p > path + mark) p--;
                *p = 0;
                continue;
            }
            if (p[1] == '.') {
                if (p[2] == '\\') {
                    next = p + 3;
                    if (p > path + mark) {
                        p--;
                        while (p > path + mark && p[-1] != '\\') p--;
                    }
                    memmove(p, next, (wcslen(next) + 1) * sizeof(WCHAR));
                    continue;
                }
                if (!p[2]) {
                    if (p > path + mark) {
                        p--;
                        while (p > path + mark && p[-1] != '\\') p--;
                        if (p > path + mark) p--;
                    }
                    *p = 0;
                    continue;
                }
            }
        }

        while (*p && *p != '\\') p++;
        if (*p == '\\') {
            if (p > path + mark && p[-1] == '.') {
                memmove(p - 1, p, (wcslen(p) + 1) * sizeof(WCHAR));
            } else {
                p++;
            }
        }
    }

    while (p > path + mark && (p[-1] == ' ' || p[-1] == '.')) p--;
    *p = 0;
}

static int winemu_path_is_all_spaces(const WCHAR* name) {
    const WCHAR* ptr = name;
    if (!ptr) return 1;
    while (*ptr) {
        if (*ptr != ' ') return 0;
        ptr++;
    }
    return 1;
}

static size_t winemu_build_full_dos_path(
    const WCHAR* name,
    WCHAR* buffer,
    size_t cap_chars,
    size_t* file_part_index)
{
    DOS_PATHNAME_TYPE type;
    const WCHAR* current_dir;
    size_t current_len;
    size_t src_len;
    size_t out = 0;
    unsigned mark = 0;
    const WCHAR* unc_ptr;

    if (file_part_index) *file_part_index = (size_t)-1;
    if (!name || !*name || !buffer || cap_chars == 0) return 0;
    if (winemu_path_is_all_spaces(name)) return 0;

    type = RtlDetermineDosPathNameType_U(name);
    current_dir = winemu_current_dir_ptr();
    current_len = winemu_current_dir_chars();
    src_len = wcslen(name);

    switch (type) {
    case ABSOLUTE_DRIVE_PATH:
        if (src_len + 1 > cap_chars) return 0;
        memcpy(buffer, name, (src_len + 1) * sizeof(WCHAR));
        mark = 3;
        break;
    case RELATIVE_DRIVE_PATH:
        if (current_len >= 2 && winemu_drive_eq_ci(current_dir[0], name[0])) {
            if (current_len + src_len - 1 >= cap_chars) return 0;
            memcpy(buffer, current_dir, current_len * sizeof(WCHAR));
            out = current_len;
        } else {
            if (src_len + 3 >= cap_chars) return 0;
            buffer[out++] = name[0];
            buffer[out++] = ':';
            buffer[out++] = '\\';
        }
        memcpy(buffer + out, name + 2, (src_len - 1) * sizeof(WCHAR));
        mark = 3;
        break;
    case ABSOLUTE_PATH:
        if (current_len < 2 || current_dir[1] != ':') return 0;
        if (src_len + 3 > cap_chars) return 0;
        buffer[out++] = current_dir[0];
        buffer[out++] = ':';
        memcpy(buffer + out, name, (src_len + 1) * sizeof(WCHAR));
        mark = 3;
        break;
    case RELATIVE_PATH:
        if (current_len + src_len + 1 > cap_chars) return 0;
        memcpy(buffer, current_dir, current_len * sizeof(WCHAR));
        out = current_len;
        if (out && buffer[out - 1] != '\\') buffer[out++] = '\\';
        memcpy(buffer + out, name, (src_len + 1) * sizeof(WCHAR));
        mark = 3;
        break;
    case UNC_PATH:
        if (src_len + 1 > cap_chars) return 0;
        memcpy(buffer, name, (src_len + 1) * sizeof(WCHAR));
        unc_ptr = winemu_skip_unc_prefix(buffer);
        mark = (unsigned)(unc_ptr - buffer);
        break;
    case DEVICE_PATH:
        if (src_len + 1 > cap_chars) return 0;
        memcpy(buffer, name, (src_len + 1) * sizeof(WCHAR));
        mark = 4;
        break;
    case UNC_DOT_PATH:
        if (src_len + 2 > cap_chars) return 0;
        memcpy(buffer, name, (src_len + 1) * sizeof(WCHAR));
        if (buffer[src_len - 1] != '\\') {
            buffer[src_len] = '\\';
            buffer[src_len + 1] = 0;
        }
        mark = 4;
        break;
    case INVALID_PATH:
    default:
        return 0;
    }

    winemu_collapse_path(buffer, mark);

    if (file_part_index) {
        WCHAR* last = wcsrchr(buffer, '\\');
        if (last && last[1]) {
            *file_part_index = (size_t)(last + 1 - buffer);
        }
    }
    return wcslen(buffer);
}

static int winemu_path_has_nt_prefix(const WCHAR* dos_path) {
    if (!dos_path) return 0;
    if (dos_path[0] == '\\' && dos_path[1] == '?' && dos_path[2] == '?' && dos_path[3] == '\\') {
        return 1;
    }
    if (dos_path[0] == '\\' && dos_path[1] == '\\' &&
        (dos_path[2] == '?' || dos_path[2] == '.') && dos_path[3] == '\\') {
        return 1;
    }
    return 0;
}

EXPORT DOS_PATHNAME_TYPE RtlDetermineDosPathNameType_U(const WCHAR* path) {
    if (!path || !*path) return INVALID_PATH;
    if (winemu_is_sep(path[0])) {
        if (!winemu_is_sep(path[1])) return ABSOLUTE_PATH;
        if (path[2] != '.' && path[2] != '?') return UNC_PATH;
        if (winemu_is_sep(path[3])) return DEVICE_PATH;
        if (path[3]) return UNC_PATH;
        return UNC_DOT_PATH;
    }
    if (!path[0] || path[1] != ':') return RELATIVE_PATH;
    if (winemu_is_sep(path[2])) return ABSOLUTE_DRIVE_PATH;
    return RELATIVE_DRIVE_PATH;
}

EXPORT ULONG RtlGetCurrentDirectory_U(ULONG buflen, WCHAR* buf) {
    const WCHAR* current_dir = winemu_current_dir_ptr();
    size_t len = winemu_current_dir_chars();

    if (len > 0 && current_dir[len - 1] == '\\' && !(len == 3 && current_dir[1] == ':')) {
        len--;
    }

    if (buf && buflen / sizeof(WCHAR) > len) {
        memcpy(buf, current_dir, len * sizeof(WCHAR));
        buf[len] = 0;
    } else {
        len++;
    }

    return (ULONG)(len * sizeof(WCHAR));
}

EXPORT ULONG RtlGetFullPathName_U(
    const WCHAR* name,
    ULONG size,
    WCHAR* buffer,
    WCHAR** file_part)
{
    WCHAR local[1024];
    WCHAR* scratch = local;
    size_t needed_chars;
    size_t current_len;
    size_t file_index = (size_t)-1;

    if (file_part) *file_part = NULL;
    if (!name || !*name) return 0;

    current_len = winemu_current_dir_chars();
    needed_chars = current_len + wcslen(name) + 8;
    if (needed_chars > (sizeof(local) / sizeof(local[0]))) {
        scratch = (WCHAR*)RtlAllocateHeap(NULL, 0, needed_chars * sizeof(WCHAR));
        if (!scratch) return 0;
    }

    needed_chars = winemu_build_full_dos_path(name, scratch, needed_chars, &file_index);
    if (!needed_chars) {
        if (scratch != local) RtlFreeHeap(NULL, 0, scratch);
        return 0;
    }

    if (!buffer || size < (needed_chars + 1) * sizeof(WCHAR)) {
        if (scratch != local) RtlFreeHeap(NULL, 0, scratch);
        return (ULONG)((needed_chars + 1) * sizeof(WCHAR));
    }

    memcpy(buffer, scratch, (needed_chars + 1) * sizeof(WCHAR));
    if (file_part && file_index != (size_t)-1) {
        *file_part = buffer + file_index;
    }
    if (scratch != local) RtlFreeHeap(NULL, 0, scratch);
    return (ULONG)(needed_chars * sizeof(WCHAR));
}

EXPORT NTSTATUS RtlDosPathNameToNtPathName_U_WithStatus(
    const WCHAR* dos_path,
    UNICODE_STRING* ntpath,
    WCHAR** file_part,
    CURDIR* cd)
{
    static const WCHAR prefix[] = {'\\', '?', '?', '\\', 0};
    static const WCHAR unc_prefix[] = {'\\', '?', '?', '\\', 'U', 'N', 'C', '\\', 0};
    WCHAR local[1024];
    WCHAR* scratch = local;
    WCHAR* out;
    size_t full_chars;
    size_t out_chars;
    size_t current_len;
    size_t file_index = (size_t)-1;
    DOS_PATHNAME_TYPE type;

    if (file_part) *file_part = NULL;
    if (cd) memset(cd, 0, sizeof(*cd));
    if (!ntpath) return STATUS_INVALID_PARAMETER;
    ntpath->Length = 0;
    ntpath->MaximumLength = 0;
    ntpath->Buffer = NULL;

    if (!dos_path || !*dos_path) return STATUS_OBJECT_NAME_INVALID;

    if (winemu_path_has_nt_prefix(dos_path)) {
        out_chars = wcslen(dos_path);
        out = (WCHAR*)RtlAllocateHeap(NULL, 0, (out_chars + 1) * sizeof(WCHAR));
        if (!out) return STATUS_NO_MEMORY;
        memcpy(out, dos_path, (out_chars + 1) * sizeof(WCHAR));
        if (out[0] == '\\' && out[1] == '\\' &&
            (out[2] == '?' || out[2] == '.') && out[3] == '\\') {
            out[1] = '?';
            out[2] = '?';
        }
        ntpath->Buffer = out;
        ntpath->Length = (uint16_t)(out_chars * sizeof(WCHAR));
        ntpath->MaximumLength = (uint16_t)((out_chars + 1) * sizeof(WCHAR));
        if (file_part) {
            WCHAR* last = wcsrchr(out, '\\');
            if (last && last[1]) *file_part = last + 1;
        }
        return STATUS_SUCCESS;
    }

    current_len = winemu_current_dir_chars();
    out_chars = current_len + wcslen(dos_path) + 8;
    if (out_chars > (sizeof(local) / sizeof(local[0]))) {
        scratch = (WCHAR*)RtlAllocateHeap(NULL, 0, out_chars * sizeof(WCHAR));
        if (!scratch) return STATUS_NO_MEMORY;
    }

    full_chars = winemu_build_full_dos_path(dos_path, scratch, out_chars, &file_index);
    if (!full_chars) {
        if (scratch != local) RtlFreeHeap(NULL, 0, scratch);
        return STATUS_OBJECT_NAME_INVALID;
    }

    type = RtlDetermineDosPathNameType_U(scratch);
    if (type == UNC_PATH) {
        out_chars = 8 + (full_chars >= 2 ? full_chars - 2 : 0);
        out = (WCHAR*)RtlAllocateHeap(NULL, 0, (out_chars + 1) * sizeof(WCHAR));
        if (!out) {
            if (scratch != local) RtlFreeHeap(NULL, 0, scratch);
            return STATUS_NO_MEMORY;
        }
        wcscpy(out, unc_prefix);
        wcscat(out, scratch + 2);
    } else {
        out_chars = 4 + full_chars;
        out = (WCHAR*)RtlAllocateHeap(NULL, 0, (out_chars + 1) * sizeof(WCHAR));
        if (!out) {
            if (scratch != local) RtlFreeHeap(NULL, 0, scratch);
            return STATUS_NO_MEMORY;
        }
        wcscpy(out, prefix);
        wcscat(out, scratch);
    }

    ntpath->Buffer = out;
    ntpath->Length = (uint16_t)(wcslen(out) * sizeof(WCHAR));
    ntpath->MaximumLength = (uint16_t)((wcslen(out) + 1) * sizeof(WCHAR));
    if (file_part && file_index != (size_t)-1) {
        if (type == UNC_PATH) *file_part = out + 8 + file_index - 2;
        else *file_part = out + 4 + file_index;
    }

    if (scratch != local) RtlFreeHeap(NULL, 0, scratch);
    return STATUS_SUCCESS;
}

EXPORT BOOLEAN RtlDosPathNameToNtPathName_U(
    const WCHAR* dos_path,
    UNICODE_STRING* ntpath,
    WCHAR** file_part,
    CURDIR* cd)
{
    return RtlDosPathNameToNtPathName_U_WithStatus(dos_path, ntpath, file_part, cd)
        == STATUS_SUCCESS;
}

EXPORT NTSTATUS RtlDosPathNameToRelativeNtPathName_U_WithStatus(
    const WCHAR* dos_path,
    UNICODE_STRING* ntpath,
    WCHAR** file_part,
    RTL_RELATIVE_NAME* relative)
{
    if (relative) memset(relative, 0, sizeof(*relative));
    return RtlDosPathNameToNtPathName_U_WithStatus(dos_path, ntpath, file_part, NULL);
}

EXPORT BOOLEAN RtlDosPathNameToRelativeNtPathName_U(
    const WCHAR* dos_path,
    UNICODE_STRING* ntpath,
    WCHAR** file_part,
    RTL_RELATIVE_NAME* relative)
{
    return RtlDosPathNameToRelativeNtPathName_U_WithStatus(
        dos_path, ntpath, file_part, relative) == STATUS_SUCCESS;
}

EXPORT void RtlReleaseRelativeName(RTL_RELATIVE_NAME* relative) {
    if (!relative) return;
    memset(relative, 0, sizeof(*relative));
}

EXPORT NTSTATUS RtlSetCurrentDirectory_U(const UNICODE_STRING* dir) {
    WCHAR local[1024];
    WCHAR* scratch = local;
    size_t needed_chars;
    size_t file_index = (size_t)-1;
    size_t path_chars;

    if (!dir || !dir->Buffer || dir->Length == 0) return STATUS_INVALID_PARAMETER;

    needed_chars = winemu_current_dir_chars() + winemu_unicode_string_chars(dir) + 8;
    if (needed_chars > (sizeof(local) / sizeof(local[0]))) {
        scratch = (WCHAR*)RtlAllocateHeap(NULL, 0, needed_chars * sizeof(WCHAR));
        if (!scratch) return STATUS_NO_MEMORY;
    }

    path_chars = winemu_build_full_dos_path(dir->Buffer, scratch, needed_chars, &file_index);
    if (!path_chars) {
        if (scratch != local) RtlFreeHeap(NULL, 0, scratch);
        return STATUS_OBJECT_NAME_INVALID;
    }

    if (path_chars == 0 || scratch[path_chars - 1] != '\\') {
        if (path_chars + 1 >= needed_chars) {
            WCHAR* grown;
            size_t new_chars = needed_chars + 2;
            if (scratch == local) {
                grown = (WCHAR*)RtlAllocateHeap(NULL, 0, new_chars * sizeof(WCHAR));
                if (!grown) return STATUS_NO_MEMORY;
                memcpy(grown, scratch, (path_chars + 1) * sizeof(WCHAR));
                scratch = grown;
            } else {
                grown = (WCHAR*)RtlReAllocateHeap(NULL, 0, scratch, new_chars * sizeof(WCHAR));
                if (!grown) {
                    RtlFreeHeap(NULL, 0, scratch);
                    return STATUS_NO_MEMORY;
                }
                scratch = grown;
            }
            needed_chars = new_chars;
        }
        scratch[path_chars++] = '\\';
        scratch[path_chars] = 0;
    }

    if (!winemu_store_current_dir(scratch, path_chars)) {
        if (scratch != local) RtlFreeHeap(NULL, 0, scratch);
        return STATUS_NO_MEMORY;
    }

    if (scratch != local) RtlFreeHeap(NULL, 0, scratch);
    return STATUS_SUCCESS;
}
