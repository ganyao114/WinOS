/* ── Loader / export lookup ─────────────────────────────────── */

#define STATUS_DLL_NOT_FOUND        0xC0000135U
#define STATUS_PROCEDURE_NOT_FOUND  0xC000007AU
#define STATUS_BUFFER_TOO_SMALL     0xC0000023U
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define REG_DWORD 4U

#define PEB_LDR_OFF                       0x18
#define LDR_IN_LOAD_ORDER_LIST_OFF        0x10
#define LDR_ENTRY_IN_LOAD_ORDER_LINK_OFF  0x00
#define LDR_ENTRY_DLL_BASE_OFF            0x30
#define LDR_ENTRY_BASE_DLL_NAME_OFF       0x58

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

static void* winemu_find_loaded_module(const UNICODE_STRING* module_name) {
    if (!module_name) return NULL;

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
        if (winemu_unicode_eq_unicode_ci(base_name, module_name)) {
            uint64_t dll_base = *(uint64_t*)(uintptr_t)(entry + LDR_ENTRY_DLL_BASE_OFF);
            if (dll_base) return (void*)(uintptr_t)dll_base;
            return NULL;
        }
        link = *(uint64_t*)(uintptr_t)link;
    }
    return NULL;
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
