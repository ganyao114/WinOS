/* ── Loader / export lookup ─────────────────────────────────── */

#define STATUS_DLL_NOT_FOUND        0xC0000135U
#define STATUS_PROCEDURE_NOT_FOUND  0xC000007AU
#define STATUS_BUFFER_TOO_SMALL     0xC0000023U
#define STATUS_INVALID_IMAGE_FORMAT 0xC000007BU
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4DU
#endif
#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE  0x00004550U
#endif
#define REG_DWORD 4U

#define PEB_IMAGE_BASE_ADDRESS_OFF          0x10
#define PEB_LDR_OFF                       0x18
#define LDR_IN_LOAD_ORDER_LIST_OFF        0x10
#define LDR_IN_MEMORY_ORDER_LIST_OFF      0x20
#define LDR_IN_INIT_ORDER_LIST_OFF        0x30
#define LDR_ENTRY_IN_LOAD_ORDER_LINK_OFF  0x00
#define LDR_ENTRY_IN_MEMORY_ORDER_LINK_OFF 0x10
#define LDR_ENTRY_IN_INIT_ORDER_LINK_OFF  0x20
#define LDR_ENTRY_DLL_BASE_OFF            0x30
#define LDR_ENTRY_ENTRY_POINT_OFF         0x38
#define LDR_ENTRY_SIZE_OF_IMAGE_OFF       0x40
#define LDR_ENTRY_FULL_DLL_NAME_OFF       0x48
#define LDR_ENTRY_BASE_DLL_NAME_OFF       0x58
#define LDR_ENTRY_FLAGS_OFF               0x68
#define LDR_ENTRY_LOAD_COUNT_OFF          0x6c

#define WINEMU_LDR_ENTRY_SIZE 0x120
#define WINEMU_LDR_FLAG_PROCESS_ATTACH_PENDING 0x80000000U
#define WINEMU_MAX_RECURSIVE_DLLS 128
#define DLL_PROCESS_ATTACH 1
#define PDH_CSTATUS_VALID_DATA 0x00000000U
#define PDH_MORE_DATA 0x800007D2U
#define PDH_INVALID_ARGUMENT 0xC0000BBDU

typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

typedef struct {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

typedef int (*DLL_ENTRY_FN)(HANDLE, ULONG, void*);

static int winemu_loader_ascii_tolower(int ch) {
    if (ch >= 'A' && ch <= 'Z') return ch + ('a' - 'A');
    return ch;
}

static int winemu_ascii_strcmp(const char* lhs, const char* rhs) {
    size_t i = 0;
    while (lhs[i] && rhs[i]) {
        if ((unsigned char)lhs[i] != (unsigned char)rhs[i]) {
            return (int)(unsigned char)lhs[i] - (int)(unsigned char)rhs[i];
        }
        i++;
    }
    return (int)(unsigned char)lhs[i] - (int)(unsigned char)rhs[i];
}

static int winemu_unicode_eq_unicode_ci(const UNICODE_STRING* lhs, const UNICODE_STRING* rhs) {
    if (!lhs || !rhs) return 0;
    if (lhs->Length != rhs->Length) return 0;
    if (lhs->Length == 0) return 1;
    if (!lhs->Buffer || !rhs->Buffer) return 0;

    size_t chars = (size_t)(lhs->Length / 2);
    for (size_t i = 0; i < chars; i++) {
        uint16_t a = lhs->Buffer[i];
        uint16_t b = rhs->Buffer[i];
        int al = winemu_loader_ascii_tolower((int)(a & 0xff));
        int bl = winemu_loader_ascii_tolower((int)(b & 0xff));
        if ((a >> 8) != 0 || (b >> 8) != 0 || al != bl) {
            return 0;
        }
    }
    return 1;
}

static int winemu_unicode_eq_ascii_ci(const UNICODE_STRING* lhs, const char* rhs) {
    size_t i = 0;
    size_t chars;

    if (!lhs || !rhs || !lhs->Buffer) return 0;
    chars = (size_t)(lhs->Length / 2);
    while (rhs[i]) {
        if (i >= chars) return 0;
        if ((lhs->Buffer[i] >> 8) != 0) return 0;
        if (winemu_loader_ascii_tolower((int)(lhs->Buffer[i] & 0xff))
            != winemu_loader_ascii_tolower((unsigned char)rhs[i])) {
            return 0;
        }
        i++;
    }
    return i == chars;
}

static void winemu_unicode_basename(const UNICODE_STRING* src, UNICODE_STRING* out) {
    size_t chars;
    size_t start = 0;

    out->Length = 0;
    out->MaximumLength = 0;
    out->Buffer = NULL;
    if (!src || !src->Buffer || !src->Length) return;

    chars = (size_t)(src->Length / 2);
    for (size_t i = 0; i < chars; i++) {
        uint16_t ch = src->Buffer[i];
        if ((ch >> 8) == 0 && ((ch & 0xff) == '\\' || (ch & 0xff) == '/' || (ch & 0xff) == ':')) {
            start = i + 1;
        }
    }

    out->Buffer = src->Buffer + start;
    out->Length = (uint16_t)((chars - start) * 2);
    out->MaximumLength = out->Length;
}

static size_t winemu_ascii_len(const char* s) {
    size_t len = 0;
    if (!s) return 0;
    while (s[len]) len++;
    return len;
}

static const char* winemu_ascii_basename(const char* name) {
    const char* base = name;
    if (!name) return NULL;
    for (const char* p = name; *p; p++) {
        if (*p == '\\' || *p == '/' || *p == ':') base = p + 1;
    }
    return base;
}

static size_t winemu_unicode_to_ascii(const UNICODE_STRING* src, char* dst, size_t cap) {
    size_t chars;

    if (!src || !src->Buffer || !dst || cap == 0) return 0;
    chars = (size_t)(src->Length / 2);
    if (chars + 1 > cap) return 0;
    for (size_t i = 0; i < chars; i++) {
        uint16_t ch = src->Buffer[i];
        if ((ch >> 8) != 0) return 0;
        dst[i] = (char)(ch & 0xff);
    }
    dst[chars] = '\0';
    return chars;
}

static void winemu_loader_ascii_to_unicode(const char* src, WCHAR* dst) {
    size_t i = 0;
    while (src && src[i]) {
        dst[i] = (WCHAR)(unsigned char)src[i];
        i++;
    }
    dst[i] = 0;
}

static void* winemu_find_loaded_module(const UNICODE_STRING* module_name) {
    UNICODE_STRING base_name_view;
    if (!module_name) return NULL;
    winemu_unicode_basename(module_name, &base_name_view);
    if (!base_name_view.Buffer || !base_name_view.Length) return NULL;

    uint8_t* peb = (uint8_t*)RtlGetCurrentPeb();
    if (!peb) return NULL;

    uint64_t ldr = *(uint64_t*)(uintptr_t)(peb + PEB_LDR_OFF);
    if (!ldr) return NULL;

    uint64_t head = ldr + LDR_IN_LOAD_ORDER_LIST_OFF;
    uint64_t link = *(uint64_t*)(uintptr_t)head;
    for (unsigned i = 0; i < 4096 && link && link != head; i++) {
        if (link < LDR_ENTRY_IN_LOAD_ORDER_LINK_OFF) break;
        uint64_t entry = link - LDR_ENTRY_IN_LOAD_ORDER_LINK_OFF;
        UNICODE_STRING* base_name =
            (UNICODE_STRING*)(uintptr_t)(entry + LDR_ENTRY_BASE_DLL_NAME_OFF);
        if (winemu_unicode_eq_unicode_ci(base_name, &base_name_view)) {
            uint64_t dll_base = *(uint64_t*)(uintptr_t)(entry + LDR_ENTRY_DLL_BASE_OFF);
            if (dll_base) return (void*)(uintptr_t)dll_base;
            return NULL;
        }
        link = *(uint64_t*)(uintptr_t)link;
    }
    return NULL;
}

static uint64_t winemu_current_image_base(void) {
    uint8_t* peb = (uint8_t*)RtlGetCurrentPeb();
    if (!peb) return 0;
    return *(uint64_t*)(uintptr_t)(peb + PEB_IMAGE_BASE_ADDRESS_OFF);
}

static uint64_t winemu_find_loaded_module_entry(void* module) {
    if (!module) return 0;

    uint8_t* peb = (uint8_t*)RtlGetCurrentPeb();
    if (!peb) return 0;

    uint64_t ldr = *(uint64_t*)(uintptr_t)(peb + PEB_LDR_OFF);
    if (!ldr) return 0;

    uint64_t head = ldr + LDR_IN_LOAD_ORDER_LIST_OFF;
    uint64_t link = *(uint64_t*)(uintptr_t)head;
    for (unsigned i = 0; i < 4096 && link && link != head; i++) {
        if (link < LDR_ENTRY_IN_LOAD_ORDER_LINK_OFF) break;
        uint64_t entry = link - LDR_ENTRY_IN_LOAD_ORDER_LINK_OFF;
        uint64_t dll_base = *(uint64_t*)(uintptr_t)(entry + LDR_ENTRY_DLL_BASE_OFF);
        if (dll_base == (uint64_t)(uintptr_t)module) {
            return entry;
        }
        link = *(uint64_t*)(uintptr_t)link;
    }
    return 0;
}

static int winemu_loaded_module_matches_ascii(void* module, const char* base_name) {
    uint64_t entry = winemu_find_loaded_module_entry(module);
    if (!entry) return 0;
    return winemu_unicode_eq_ascii_ci(
        (const UNICODE_STRING*)(uintptr_t)(entry + LDR_ENTRY_BASE_DLL_NAME_OFF),
        base_name
    );
}

static uint32_t winemu_pdh_connect_machine_a(const char* machine_name) {
    (void)machine_name;
    return 0;
}

static uint32_t winemu_pdh_connect_machine_w(const WCHAR* machine_name) {
    (void)machine_name;
    return 0;
}

static uint32_t winemu_pdh_enum_objects_a(
    const char* data_source,
    const char* machine_name,
    char* object_list,
    uint32_t* buffer_length,
    uint32_t detail_level,
    int refresh)
{
    static const char objects[] =
        "Processor\0"
        "Processor Information\0"
        "System\0"
        "Memory\0"
        "Process\0"
        "\0";
    uint32_t required = (uint32_t)sizeof(objects);

    (void)data_source;
    (void)machine_name;
    (void)detail_level;
    (void)refresh;
    if (!buffer_length) return PDH_INVALID_ARGUMENT;
    if (!object_list || *buffer_length < required) {
        *buffer_length = required;
        return PDH_MORE_DATA;
    }
    memcpy(object_list, objects, required);
    *buffer_length = required;
    return PDH_CSTATUS_VALID_DATA;
}

static uint32_t winemu_pdh_enum_objects_w(
    const WCHAR* data_source,
    const WCHAR* machine_name,
    WCHAR* object_list,
    uint32_t* buffer_length,
    uint32_t detail_level,
    int refresh)
{
    static const WCHAR objects[] = {
        'P','r','o','c','e','s','s','o','r',0,
        'P','r','o','c','e','s','s','o','r',' ','I','n','f','o','r','m','a','t','i','o','n',0,
        'S','y','s','t','e','m',0,
        'M','e','m','o','r','y',0,
        'P','r','o','c','e','s','s',0,
        0
    };
    uint32_t required = (uint32_t)(sizeof(objects) / sizeof(objects[0]));

    (void)data_source;
    (void)machine_name;
    (void)detail_level;
    (void)refresh;
    if (!buffer_length) return PDH_INVALID_ARGUMENT;
    if (!object_list || *buffer_length < required) {
        *buffer_length = required;
        return PDH_MORE_DATA;
    }
    memcpy(object_list, objects, sizeof(objects));
    *buffer_length = required;
    return PDH_CSTATUS_VALID_DATA;
}

static uint32_t winemu_pdh_enum_machines_a(
    const char* data_source,
    char* machine_list,
    uint32_t* buffer_length,
    int refresh)
{
    static const char machines[] = "WinEmu\0\0";
    uint32_t required = (uint32_t)sizeof(machines);

    (void)data_source;
    (void)refresh;
    if (!buffer_length) return PDH_INVALID_ARGUMENT;
    if (!machine_list || *buffer_length < required) {
        *buffer_length = required;
        return PDH_MORE_DATA;
    }
    memcpy(machine_list, machines, required);
    *buffer_length = required;
    return PDH_CSTATUS_VALID_DATA;
}

static uint32_t winemu_pdh_enum_machines_w(
    const WCHAR* data_source,
    WCHAR* machine_list,
    uint32_t* buffer_length,
    int refresh)
{
    static const WCHAR machines[] = { 'W','i','n','E','m','u',0,0 };
    uint32_t required = (uint32_t)(sizeof(machines) / sizeof(machines[0]));

    (void)data_source;
    (void)refresh;
    if (!buffer_length) return PDH_INVALID_ARGUMENT;
    if (!machine_list || *buffer_length < required) {
        *buffer_length = required;
        return PDH_MORE_DATA;
    }
    memcpy(machine_list, machines, sizeof(machines));
    *buffer_length = required;
    return PDH_CSTATUS_VALID_DATA;
}

static void* winemu_builtin_override_export(void* image_base, const char* routine_name) {
    if (!image_base || !routine_name) return NULL;
    if (!winemu_loaded_module_matches_ascii(image_base, "pdh.dll")) return NULL;
    if (winemu_ascii_strcmp(routine_name, "PdhConnectMachineW") == 0) {
        return (void*)(uintptr_t)winemu_pdh_connect_machine_w;
    }
    if (winemu_ascii_strcmp(routine_name, "PdhConnectMachineA") == 0) {
        return (void*)(uintptr_t)winemu_pdh_connect_machine_a;
    }
    if (winemu_ascii_strcmp(routine_name, "PdhEnumObjectsW") == 0) {
        return (void*)(uintptr_t)winemu_pdh_enum_objects_w;
    }
    if (winemu_ascii_strcmp(routine_name, "PdhEnumObjectsA") == 0) {
        return (void*)(uintptr_t)winemu_pdh_enum_objects_a;
    }
    if (winemu_ascii_strcmp(routine_name, "PdhEnumMachinesW") == 0) {
        return (void*)(uintptr_t)winemu_pdh_enum_machines_w;
    }
    if (winemu_ascii_strcmp(routine_name, "PdhEnumMachinesA") == 0) {
        return (void*)(uintptr_t)winemu_pdh_enum_machines_a;
    }
    return NULL;
}

static NTSTATUS winemu_copy_unicode_string(
    UNICODE_STRING* dst,
    const UNICODE_STRING* src)
{
    ULONG src_len;
    ULONG copy_len;
    NTSTATUS status;

    if (!dst) return STATUS_INVALID_PARAMETER;

    src_len = (src && src->Buffer) ? src->Length : 0;
    copy_len = src_len;
    if (copy_len > dst->MaximumLength) copy_len = dst->MaximumLength;

    if (dst->Buffer && copy_len) memcpy(dst->Buffer, src->Buffer, copy_len);
    dst->Length = (uint16_t)copy_len;

    if (dst->Buffer && copy_len + sizeof(WCHAR) <= dst->MaximumLength) {
        ((unsigned char*)dst->Buffer)[copy_len] = 0;
        ((unsigned char*)dst->Buffer)[copy_len + 1] = 0;
    }

    status = (dst->MaximumLength < src_len + sizeof(WCHAR))
        ? STATUS_BUFFER_TOO_SMALL
        : STATUS_SUCCESS;
    return status;
}

static WCHAR* winemu_alloc_wide_ascii(const char* src) {
    size_t len = winemu_ascii_len(src);
    size_t bytes = (len + 1) * sizeof(WCHAR);
    WCHAR* dst = (WCHAR*)RtlAllocateHeap(NULL, 0, bytes);
    if (!dst) return NULL;
    winemu_loader_ascii_to_unicode(src, dst);
    return dst;
}

static NTSTATUS winemu_sys_load_dll_ascii(const char* name, size_t len, HANDLE* module_handle) {
    if (!name || !len || !module_handle) return STATUS_INVALID_PARAMETER;
    return syscall4(
        NR_WINEMU_LOAD_DLL,
        (uint64_t)(uintptr_t)name,
        (uint64_t)len,
        (uint64_t)(uintptr_t)module_handle,
        0
    );
}

static int winemu_query_module_pe_info(
    void* module,
    uint32_t* size_of_image,
    uint64_t* entry_point,
    uint32_t* import_rva,
    uint32_t* import_size)
{
    uint8_t* image = (uint8_t*)module;
    uint32_t lfanew;
    uint8_t* nt;
    uint8_t* opt;
    uint32_t entry_rva;

    if (!image) return 0;
    if (*(uint16_t*)(uintptr_t)image != IMAGE_DOS_SIGNATURE) return 0;

    lfanew = *(uint32_t*)(uintptr_t)(image + 0x3c);
    nt = image + lfanew;
    if (*(uint32_t*)(uintptr_t)nt != IMAGE_NT_SIGNATURE) return 0;

    opt = nt + 24;
    if (*(uint16_t*)(uintptr_t)opt != 0x20b) return 0;

    entry_rva = *(uint32_t*)(uintptr_t)(opt + 0x10);
    if (size_of_image) *size_of_image = *(uint32_t*)(uintptr_t)(opt + 0x38);
    if (entry_point) {
        *entry_point = entry_rva ? (uint64_t)(uintptr_t)(image + entry_rva) : 0;
    }
    if (import_rva) *import_rva = *(uint32_t*)(uintptr_t)(opt + 0x70 + IMAGE_DIRECTORY_ENTRY_IMPORT * 8);
    if (import_size) *import_size = *(uint32_t*)(uintptr_t)(opt + 0x74 + IMAGE_DIRECTORY_ENTRY_IMPORT * 8);
    return 1;
}

static void winemu_list_insert_tail(uint64_t head_ptr, uint64_t entry_ptr) {
    uint64_t blink = *(uint64_t*)(uintptr_t)(head_ptr + 8);
    *(uint64_t*)(uintptr_t)(entry_ptr + 0) = head_ptr;
    *(uint64_t*)(uintptr_t)(entry_ptr + 8) = blink;
    *(uint64_t*)(uintptr_t)(blink + 0) = entry_ptr;
    *(uint64_t*)(uintptr_t)(head_ptr + 8) = entry_ptr;
}

static NTSTATUS winemu_insert_loaded_module_entry(
    void* module,
    const char* full_name,
    const char* base_name,
    uint64_t* entry_out)
{
    uint8_t* peb;
    uint64_t ldr;
    uint32_t size_of_image = 0;
    uint64_t entry_point = 0;
    size_t full_len;
    size_t base_len;
    size_t full_bytes;
    size_t base_bytes;
    size_t total;
    uint8_t* entry_mem;
    WCHAR* full_buf;
    WCHAR* base_buf;
    uint64_t entry_va;

    if (!module || !full_name || !base_name) return STATUS_INVALID_PARAMETER;
    if (!winemu_query_module_pe_info(module, &size_of_image, &entry_point, NULL, NULL)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    peb = (uint8_t*)RtlGetCurrentPeb();
    if (!peb) return STATUS_INVALID_PARAMETER;
    ldr = *(uint64_t*)(uintptr_t)(peb + PEB_LDR_OFF);
    if (!ldr) return STATUS_INVALID_PARAMETER;

    full_len = winemu_ascii_len(full_name);
    base_len = winemu_ascii_len(base_name);
    full_bytes = (full_len + 1) * sizeof(WCHAR);
    base_bytes = (base_len + 1) * sizeof(WCHAR);
    total = WINEMU_LDR_ENTRY_SIZE + full_bytes + base_bytes;

    entry_mem = RtlAllocateHeap(NULL, 0, total);
    if (!entry_mem) return STATUS_NO_MEMORY;
    memset(entry_mem, 0, total);

    entry_va = (uint64_t)(uintptr_t)entry_mem;
    full_buf = (WCHAR*)(void*)(entry_mem + WINEMU_LDR_ENTRY_SIZE);
    base_buf = (WCHAR*)(void*)((uint8_t*)full_buf + full_bytes);
    winemu_loader_ascii_to_unicode(full_name, full_buf);
    winemu_loader_ascii_to_unicode(base_name, base_buf);

    *(uint64_t*)(uintptr_t)(entry_va + LDR_ENTRY_DLL_BASE_OFF) = (uint64_t)(uintptr_t)module;
    *(uint64_t*)(uintptr_t)(entry_va + LDR_ENTRY_ENTRY_POINT_OFF) = entry_point;
    *(uint32_t*)(uintptr_t)(entry_va + LDR_ENTRY_SIZE_OF_IMAGE_OFF) = size_of_image;
    *(uint32_t*)(uintptr_t)(entry_va + LDR_ENTRY_FLAGS_OFF) =
        0x0004U | WINEMU_LDR_FLAG_PROCESS_ATTACH_PENDING;
    *(uint16_t*)(uintptr_t)(entry_va + LDR_ENTRY_LOAD_COUNT_OFF) = 0xffffU;

    {
        UNICODE_STRING* full_us = (UNICODE_STRING*)(uintptr_t)(entry_va + LDR_ENTRY_FULL_DLL_NAME_OFF);
        full_us->Length = (uint16_t)(full_len * sizeof(WCHAR));
        full_us->MaximumLength = (uint16_t)full_bytes;
        full_us->Buffer = full_buf;
    }
    {
        UNICODE_STRING* base_us = (UNICODE_STRING*)(uintptr_t)(entry_va + LDR_ENTRY_BASE_DLL_NAME_OFF);
        base_us->Length = (uint16_t)(base_len * sizeof(WCHAR));
        base_us->MaximumLength = (uint16_t)base_bytes;
        base_us->Buffer = base_buf;
    }

    winemu_list_insert_tail(ldr + LDR_IN_LOAD_ORDER_LIST_OFF, entry_va + LDR_ENTRY_IN_LOAD_ORDER_LINK_OFF);
    winemu_list_insert_tail(ldr + LDR_IN_MEMORY_ORDER_LIST_OFF, entry_va + LDR_ENTRY_IN_MEMORY_ORDER_LINK_OFF);
    winemu_list_insert_tail(ldr + LDR_IN_INIT_ORDER_LIST_OFF, entry_va + LDR_ENTRY_IN_INIT_ORDER_LINK_OFF);

    if (entry_out) *entry_out = entry_va;
    return STATUS_SUCCESS;
}

static void winemu_process_attach_module_entry(uint64_t entry_va) {
    uint32_t* flags;
    uint64_t dll_base;
    uint64_t entry_point;

    if (!entry_va) return;
    flags = (uint32_t*)(uintptr_t)(entry_va + LDR_ENTRY_FLAGS_OFF);
    if (!(*flags & WINEMU_LDR_FLAG_PROCESS_ATTACH_PENDING)) return;

    *flags &= ~WINEMU_LDR_FLAG_PROCESS_ATTACH_PENDING;
    dll_base = *(uint64_t*)(uintptr_t)(entry_va + LDR_ENTRY_DLL_BASE_OFF);
    entry_point = *(uint64_t*)(uintptr_t)(entry_va + LDR_ENTRY_ENTRY_POINT_OFF);
    if (!dll_base || !entry_point) return;
    if (dll_base == winemu_current_image_base()) return;

    (void)((DLL_ENTRY_FN)(uintptr_t)entry_point)((HANDLE)(uintptr_t)dll_base, DLL_PROCESS_ATTACH, NULL);
}

static int winemu_pending_contains(void* const* pending, unsigned pending_count, void* module) {
    for (unsigned i = 0; i < pending_count; i++) {
        if (pending[i] == module) return 1;
    }
    return 0;
}

static NTSTATUS winemu_publish_module_recursive(
    void* module,
    const char* full_name,
    const char* base_name,
    void** pending,
    unsigned* pending_count)
{
    uint64_t existing_entry;
    uint32_t import_rva = 0;
    uint32_t import_size = 0;
    IMAGE_IMPORT_DESCRIPTOR* imports;
    uint32_t import_count;
    NTSTATUS status = STATUS_SUCCESS;

    if (!module || !full_name || !base_name || !pending_count) return STATUS_INVALID_PARAMETER;

    existing_entry = winemu_find_loaded_module_entry(module);
    if (existing_entry) {
        winemu_process_attach_module_entry(existing_entry);
        return STATUS_SUCCESS;
    }
    if (winemu_pending_contains(pending, *pending_count, module)) return STATUS_SUCCESS;
    if (*pending_count >= WINEMU_MAX_RECURSIVE_DLLS) return STATUS_NO_MEMORY;

    pending[(*pending_count)++] = module;

    if (!winemu_query_module_pe_info(module, NULL, NULL, &import_rva, &import_size)) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto done;
    }

    if (import_rva && import_size >= sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        imports = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)module + import_rva);
        import_count = import_size / (uint32_t)sizeof(IMAGE_IMPORT_DESCRIPTOR);
        for (uint32_t i = 0; i < import_count; i++) {
            HANDLE dep_module = NULL;
            const char* dep_name;
            size_t dep_len;

            if (!imports[i].OriginalFirstThunk && !imports[i].TimeDateStamp &&
                !imports[i].ForwarderChain && !imports[i].Name && !imports[i].FirstThunk) {
                break;
            }
            if (!imports[i].Name) continue;

            dep_name = (const char*)((uint8_t*)module + imports[i].Name);
            dep_len = winemu_ascii_len(dep_name);
            if (!dep_len) continue;

            status = winemu_sys_load_dll_ascii(dep_name, dep_len, &dep_module);
            if (status != STATUS_SUCCESS) goto done;

            status = winemu_publish_module_recursive(
                dep_module,
                dep_name,
                winemu_ascii_basename(dep_name),
                pending,
                pending_count
            );
            if (status != STATUS_SUCCESS) goto done;
        }
    }

    existing_entry = winemu_find_loaded_module_entry(module);
    if (!existing_entry) {
        status = winemu_insert_loaded_module_entry(module, full_name, base_name, &existing_entry);
        if (status != STATUS_SUCCESS) goto done;
    }
    winemu_process_attach_module_entry(existing_entry);

done:
    if (*pending_count) (*pending_count)--;
    return status;
}

static void* winemu_export_by_ordinal(void* image_base, uint32_t ordinal) {
    ULONG dir_size = 0;
    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)RtlImageDirectoryEntryToData(
            image_base, 1, IMAGE_DIRECTORY_ENTRY_EXPORT, &dir_size);
    if (!exp || dir_size < sizeof(*exp)) return NULL;
    if (!exp->AddressOfFunctions || exp->NumberOfFunctions == 0) return NULL;
    if (ordinal < exp->Base) return NULL;

    uint32_t index = ordinal - exp->Base;
    if (index >= exp->NumberOfFunctions) return NULL;

    uint32_t* funcs = (uint32_t*)((uint8_t*)image_base + exp->AddressOfFunctions);
    uint32_t rva = funcs[index];
    if (!rva) return NULL;
    return (uint8_t*)image_base + rva;
}

static void* winemu_export_by_name(void* image_base, const char* routine_name) {
    if (!image_base || !routine_name || !routine_name[0]) return NULL;
    {
        void* override = winemu_builtin_override_export(image_base, routine_name);
        if (override) return override;
    }

    ULONG dir_size = 0;
    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)RtlImageDirectoryEntryToData(
            image_base, 1, IMAGE_DIRECTORY_ENTRY_EXPORT, &dir_size);
    if (!exp || dir_size < sizeof(*exp)) return NULL;
    if (!exp->AddressOfNames || !exp->AddressOfNameOrdinals || !exp->AddressOfFunctions) {
        return NULL;
    }

    uint32_t* names = (uint32_t*)((uint8_t*)image_base + exp->AddressOfNames);
    uint16_t* ordinals = (uint16_t*)((uint8_t*)image_base + exp->AddressOfNameOrdinals);
    uint32_t* funcs = (uint32_t*)((uint8_t*)image_base + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)image_base + names[i];
        if (!name) continue;
        if (winemu_ascii_strcmp(name, routine_name) != 0) continue;

        uint32_t ord = ordinals[i];
        if (ord >= exp->NumberOfFunctions) return NULL;
        uint32_t rva = funcs[ord];
        if (!rva) return NULL;
        return (uint8_t*)image_base + rva;
    }

    return NULL;
}

EXPORT void* RtlFindExportedRoutineByName(void* image_base, const char* routine_name) {
    return winemu_export_by_name(image_base, routine_name);
}

EXPORT NTSTATUS LdrGetDllHandle(
    const WCHAR* path_to_file,
    ULONG* flags,
    const UNICODE_STRING* module_file_name,
    HANDLE* module_handle)
{
    (void)path_to_file;
    (void)flags;
    if (!module_handle || !module_file_name) return STATUS_INVALID_PARAMETER;

    void* base = winemu_find_loaded_module(module_file_name);
    if (!base) {
        *module_handle = NULL;
        return STATUS_DLL_NOT_FOUND;
    }

    *module_handle = (HANDLE)base;
    return STATUS_SUCCESS;
}

EXPORT NTSTATUS LdrGetDllHandleEx(
    ULONG flags,
    const WCHAR* path_to_file,
    ULONG_PTR reserved,
    const UNICODE_STRING* module_file_name,
    HANDLE* module_handle)
{
    (void)reserved;
    return LdrGetDllHandle(path_to_file, &flags, module_file_name, module_handle);
}

EXPORT NTSTATUS LdrGetDllFullName(HANDLE module, UNICODE_STRING* name) {
    uint64_t entry;
    UNICODE_STRING* full_name;

    if (!name) return STATUS_INVALID_PARAMETER;
    if (!module) module = (HANDLE)(uintptr_t)winemu_current_image_base();
    if (!module) return STATUS_DLL_NOT_FOUND;

    entry = winemu_find_loaded_module_entry(module);
    if (!entry) return STATUS_DLL_NOT_FOUND;

    full_name = (UNICODE_STRING*)(uintptr_t)(entry + LDR_ENTRY_FULL_DLL_NAME_OFF);
    return winemu_copy_unicode_string(name, full_name);
}

EXPORT NTSTATUS LdrGetProcedureAddress(
    HANDLE module_handle,
    const ANSI_STRING* procedure_name,
    ULONG procedure_number,
    void** procedure_address)
{
    if (!procedure_address || !module_handle) return STATUS_INVALID_PARAMETER;
    *procedure_address = NULL;

    if (procedure_name && procedure_name->Buffer && procedure_name->Length) {
        char name_buf[256];
        size_t len = (size_t)procedure_name->Length;
        if (len >= sizeof(name_buf)) return STATUS_INVALID_PARAMETER;
        for (size_t i = 0; i < len; i++) {
            name_buf[i] = (char)procedure_name->Buffer[i];
        }
        name_buf[len] = '\0';
        *procedure_address = winemu_export_by_name(module_handle, name_buf);
    } else if (procedure_number) {
        *procedure_address = winemu_export_by_ordinal(module_handle, procedure_number);
    } else {
        return STATUS_INVALID_PARAMETER;
    }

    if (!*procedure_address) return STATUS_PROCEDURE_NOT_FOUND;
    return STATUS_SUCCESS;
}

EXPORT NTSTATUS LdrGetDllPath(
    const WCHAR* module,
    ULONG flags,
    WCHAR** path,
    WCHAR** unknown)
{
    static const char system_path_ascii[] =
        "C:\\windows\\system32;C:\\windows\\system;C:\\windows";

    (void)module;
    (void)flags;

    if (!path || !unknown) return STATUS_INVALID_PARAMETER;

    *path = winemu_alloc_wide_ascii(system_path_ascii);
    if (!*path) {
        *unknown = NULL;
        return STATUS_NO_MEMORY;
    }

    *unknown = NULL;
    return STATUS_SUCCESS;
}

EXPORT NTSTATUS LdrLoadDll(
    const WCHAR* path_to_file,
    DWORD flags,
    const UNICODE_STRING* module_file_name,
    HANDLE* module_handle)
{
    char name_buf[512];
    size_t name_len;
    void* pending[WINEMU_MAX_RECURSIVE_DLLS];
    unsigned pending_count = 0;
    NTSTATUS status;

    (void)path_to_file;
    (void)flags;

    if (!module_handle || !module_file_name || !module_file_name->Buffer || !module_file_name->Length) {
        return STATUS_INVALID_PARAMETER;
    }

    status = LdrGetDllHandle(path_to_file, NULL, module_file_name, module_handle);
    if (status == STATUS_SUCCESS && *module_handle) return STATUS_SUCCESS;

    name_len = winemu_unicode_to_ascii(module_file_name, name_buf, sizeof(name_buf));
    if (!name_len) return STATUS_INVALID_PARAMETER;

    *module_handle = NULL;
    status = winemu_sys_load_dll_ascii(name_buf, name_len, module_handle);
    if (status != STATUS_SUCCESS) return status;

    return winemu_publish_module_recursive(
        *module_handle,
        name_buf,
        winemu_ascii_basename(name_buf),
        pending,
        &pending_count
    );
}

/* Minimal IFEO query used by user32/win32u startup.
 * For now we report "option absent" as DWORD 0 to keep startup path moving. */
EXPORT NTSTATUS LdrQueryImageFileExecutionOptions(
    const UNICODE_STRING* sub_key,
    const WCHAR* value_name,
    ULONG type,
    void* buffer,
    ULONG buffer_size,
    ULONG* result_size)
{
    (void)sub_key;
    (void)value_name;

    if (result_size) *result_size = 0;
    if (!buffer || buffer_size == 0) return STATUS_INVALID_PARAMETER;

    if (type == REG_DWORD) {
        if (buffer_size < sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
        *(ULONG*)buffer = 0;
        if (result_size) *result_size = sizeof(ULONG);
        return STATUS_SUCCESS;
    }

    {
        uint8_t* p = (uint8_t*)buffer;
        for (ULONG i = 0; i < buffer_size; i++) p[i] = 0;
    }
    if (result_size) *result_size = buffer_size;
    return STATUS_SUCCESS;
}

/* Wine ARM64X helper: when module == -1 this is used as an initialization
 * shim to resolve dispatcher symbols and publish them into slot_out. */
EXPORT ULONG_PTR LdrDisableThreadCalloutsForDll(
    HANDLE module,
    const char* routine_name,
    ULONG min_version,
    void** slot_out,
    ULONG slot_size,
    void* reserved)
{
    (void)min_version;
    (void)slot_size;
    (void)reserved;

    if ((uintptr_t)module == (uintptr_t)-1) {
        if (!routine_name || !slot_out) return 0;
        if (*slot_out) return 1;

        static const WCHAR k_ntdll_name[] = {
            'n','t','d','l','l','.','d','l','l',0
        };
        UNICODE_STRING ntdll_us;
        HANDLE ntdll = NULL;
        RtlInitUnicodeString(&ntdll_us, k_ntdll_name);
        if (LdrGetDllHandle(NULL, NULL, &ntdll_us, &ntdll) != STATUS_SUCCESS || !ntdll) {
            return 0;
        }

        void* resolved = RtlFindExportedRoutineByName(ntdll, routine_name);
        if (!resolved) {
            return 0;
        }
        *slot_out = *(void**)resolved;
        return 1;
    }

    return STATUS_SUCCESS;
}

EXPORT void RtlReleasePath(WCHAR* path) {
    if (!path) return;
    (void)RtlFreeHeap(NULL, 0, path);
}

/* WinEmu syscall trampoline used by win32u stubs:
 * - x8 = syscall number, x0-x7 = args
 * - x9 carries the original caller LR from the thunk
 * Restore x30 from x9 before returning so thunk `ret` goes back to caller. */
__attribute__((naked))
static NTSTATUS __winemu_syscall_dispatcher_impl(void) {
    asm volatile(
        "svc #0\n"
        "mov x30, x9\n"
        "ret\n");
}

static NTSTATUS __wine_unix_call_dispatcher_impl(void* handle, ULONG ordinal, void* args) {
    (void)handle;
    (void)ordinal;
    (void)args;
    return STATUS_NOT_IMPLEMENTED;
}

/* Exported data symbol consumed by guest win32u bootstrap patching. */
EXPORT ULONG_PTR __winemu_syscall_dispatcher =
    (ULONG_PTR)(uintptr_t)__winemu_syscall_dispatcher_impl;

/* Keep Wine-compatible export name as alias for compatibility. */
EXPORT ULONG_PTR __wine_syscall_dispatcher =
    (ULONG_PTR)(uintptr_t)__winemu_syscall_dispatcher_impl;
EXPORT ULONG_PTR __wine_unix_call_dispatcher =
    (ULONG_PTR)(uintptr_t)__wine_unix_call_dispatcher_impl;
