/* ── User thread bootstrap ───────────────────────────────────── */

#define PEB_IMAGE_BASE_OFF               0x10
#define PEB_LDR_OFF                      0x18
#define LDR_IN_INIT_ORDER_LIST_OFF       0x30
#define LDR_ENTRY_IN_INIT_ORDER_LINK_OFF 0x20
#define LDR_ENTRY_DLL_BASE_OFF           0x30
#define LDR_ENTRY_ENTRY_POINT_OFF        0x38
#define LDR_ENTRY_BASE_DLL_NAME_OFF      0x58
#define DLL_PROCESS_ATTACH               1
#define DLL_THREAD_ATTACH                2
#define KB_LOCALE_FALLBACK_PTR_OFF       0x13f938

typedef int (*DLL_ENTRY_FN)(HANDLE, ULONG, void*);
typedef void (*EXE_ENTRY_FN)(void);
typedef ULONG (*THREAD_ENTRY_FN)(void*);
typedef void (*BASE_THREAD_INIT_THUNK_FN)(ULONG, THREAD_ENTRY_FN, void*);

EXPORT NTSTATUS LdrGetDllHandle(
    const WCHAR* path_to_file,
    ULONG* flags,
    const UNICODE_STRING* module_file_name,
    HANDLE* module_handle);
EXPORT NTSTATUS LdrGetProcedureAddress(
    HANDLE module_handle,
    const ANSI_STRING* procedure_name,
    ULONG procedure_number,
    void** procedure_address);
EXPORT void RtlInitUnicodeString(UNICODE_STRING* dest, const WCHAR* src);
EXPORT void RtlInitAnsiString(ANSI_STRING* dest, const UCHAR* src);

static uint16_t g_kernelbase_locale_fallback[16];
static int g_kernelbase_locale_fallback_ready = 0;
static BASE_THREAD_INIT_THUNK_FN g_base_thread_init_thunk = NULL;
static int g_base_thread_init_thunk_ready = 0;

static void winemu_init_kernelbase_locale_fallback(void) {
    if (g_kernelbase_locale_fallback_ready) return;
    for (size_t i = 0; i < (sizeof(g_kernelbase_locale_fallback) / sizeof(g_kernelbase_locale_fallback[0])); i++) {
        g_kernelbase_locale_fallback[i] = 0;
    }
    /* init_locale reads *(u16*)(ptr + 8). */
    g_kernelbase_locale_fallback[4] = 0x0c00;
    g_kernelbase_locale_fallback_ready = 1;
}

static int winemu_ascii_tolower(int ch) {
    if (ch >= 'A' && ch <= 'Z') return ch + ('a' - 'A');
    return ch;
}

static int winemu_us_name_equals_ascii_ci(uint64_t us_ptr, const char* ascii) {
    if (!us_ptr || !ascii) return 0;
    uint16_t name_len = *(uint16_t*)(uintptr_t)us_ptr;
    uint64_t buf = *(uint64_t*)(uintptr_t)(us_ptr + 8);
    if (!buf) return 0;

    size_t ascii_len = 0;
    while (ascii[ascii_len]) ascii_len++;
    if (name_len != (uint16_t)(ascii_len * 2)) return 0;

    for (size_t i = 0; i < ascii_len; i++) {
        uint16_t wc = *(uint16_t*)(uintptr_t)(buf + i * 2);
        int a = winemu_ascii_tolower((int)ascii[i]);
        int b = winemu_ascii_tolower((int)(wc & 0xff));
        if (a != b || (wc >> 8) != 0) {
            return 0;
        }
    }
    return 1;
}

static void winemu_patch_kernelbase_locale_fallback(uint64_t dll_base, uint64_t entry_ptr) {
    if (!winemu_us_name_equals_ascii_ci(entry_ptr + LDR_ENTRY_BASE_DLL_NAME_OFF, "kernelbase.dll")) {
        return;
    }
    winemu_init_kernelbase_locale_fallback();
    uint64_t* fallback_slot = (uint64_t*)(uintptr_t)(dll_base + KB_LOCALE_FALLBACK_PTR_OFF);
    if (*fallback_slot == 0) {
        *fallback_slot = (uint64_t)(uintptr_t)g_kernelbase_locale_fallback;
    }
}

static void winemu_call_dll_reason(uint8_t* peb, ULONG reason) {
    if (!peb) return;

    uint64_t image_base = *(uint64_t*)(peb + PEB_IMAGE_BASE_OFF);
    uint64_t ldr = *(uint64_t*)(peb + PEB_LDR_OFF);
    if (!ldr) return;

    uint64_t head = ldr + LDR_IN_INIT_ORDER_LIST_OFF;
    uint64_t link = *(uint64_t*)(uintptr_t)head;
    for (unsigned i = 0; i < 2048 && link && link != head; i++) {
        uint64_t next = *(uint64_t*)(uintptr_t)link;
        if (link < LDR_ENTRY_IN_INIT_ORDER_LINK_OFF) {
            break;
        }
        uint64_t entry = link - LDR_ENTRY_IN_INIT_ORDER_LINK_OFF;
        uint64_t dll_base = *(uint64_t*)(uintptr_t)(entry + LDR_ENTRY_DLL_BASE_OFF);
        uint64_t ep = *(uint64_t*)(uintptr_t)(entry + LDR_ENTRY_ENTRY_POINT_OFF);
        if (dll_base) {
            winemu_patch_kernelbase_locale_fallback(dll_base, entry);
        }
        if (ep && dll_base && dll_base != image_base) {
            DLL_ENTRY_FN dll_main = (DLL_ENTRY_FN)(uintptr_t)ep;
            (void)dll_main((HANDLE)(uintptr_t)dll_base, reason, NULL);
        }
        link = next;
    }
}

static void winemu_call_process_attach(uint8_t* peb) {
    winemu_call_dll_reason(peb, DLL_PROCESS_ATTACH);
}

static void winemu_call_thread_attach(uint8_t* peb) {
    winemu_call_dll_reason(peb, DLL_THREAD_ATTACH);
}

static uint64_t winemu_query_main_entry(uint8_t* peb) {
    if (!peb) return 0;
    uint8_t* image = *(uint8_t**)(peb + PEB_IMAGE_BASE_OFF);
    IMAGE_NT_HEADERS64* nt = image_nt_headers(image);
    if (!nt) return 0;
    uint32_t entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    if (!entry_rva) return 0;
    return (uint64_t)(uintptr_t)(image + entry_rva);
}

static BASE_THREAD_INIT_THUNK_FN winemu_resolve_base_thread_init_thunk(void) {
    static const WCHAR kernel32_name[] = {
        'k','e','r','n','e','l','3','2','.','d','l','l',0
    };
    static const UCHAR thunk_name[] = "BaseThreadInitThunk";
    HANDLE module = NULL;
    void* proc = NULL;
    UNICODE_STRING module_us;
    ANSI_STRING proc_as;

    if (g_base_thread_init_thunk_ready) return g_base_thread_init_thunk;
    g_base_thread_init_thunk_ready = 1;

    RtlInitUnicodeString(&module_us, kernel32_name);
    if (LdrGetDllHandle(NULL, NULL, &module_us, &module) != STATUS_SUCCESS || !module) {
        return NULL;
    }
    RtlInitAnsiString(&proc_as, thunk_name);
    if (LdrGetProcedureAddress(module, &proc_as, 0, &proc) != STATUS_SUCCESS || !proc) {
        return NULL;
    }
    g_base_thread_init_thunk = (BASE_THREAD_INIT_THUNK_FN)(uintptr_t)proc;
    return g_base_thread_init_thunk;
}

EXPORT __attribute__((noreturn))
void WinEmuProcessStart(void* start, void* peb_arg) {
    uint8_t* peb = (uint8_t*)peb_arg;
    if (!peb) {
        peb = (uint8_t*)RtlGetCurrentPeb();
    }

    winemu_call_process_attach(peb);

    uint64_t entry = (uint64_t)(uintptr_t)start;
    if (!entry) {
        entry = winemu_query_main_entry(peb);
    }

    if (entry) {
        EXE_ENTRY_FN exe_entry = (EXE_ENTRY_FN)(uintptr_t)entry;
        exe_entry();
    }

    RtlExitUserProcess(0);
}

EXPORT __attribute__((noreturn))
void RtlUserThreadStart(void* start, void* arg) {
    uint8_t* peb = (uint8_t*)RtlGetCurrentPeb();
    THREAD_ENTRY_FN entry = (THREAD_ENTRY_FN)(uintptr_t)start;
    BASE_THREAD_INIT_THUNK_FN thunk = winemu_resolve_base_thread_init_thunk();
    ULONG exit_code = 0;

    winemu_call_thread_attach(peb);

    if (thunk && entry) {
        thunk(0, entry, arg);
        RtlExitUserThread(0);
    }

    if (entry) {
        exit_code = entry(arg);
    }
    RtlExitUserThread((NTSTATUS)exit_code);
}

/* Kernelbase locale/bootstrap expects this entry to return an opaque
 * connection blob with a few offset tables already wired. */
static uint8_t g_emu_work_conn[0x2000];
static int g_emu_work_conn_ready = 0;

static void wu32_raw(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void winemu_init_emu_work_conn(void) {
    if (g_emu_work_conn_ready) return;

    for (size_t i = 0; i < sizeof(g_emu_work_conn); i++) {
        g_emu_work_conn[i] = 0;
    }

    /* Top-level offsets used by kernelbase!init_locale */
    wu32_raw(&g_emu_work_conn[0x10], 0x0100);
    wu32_raw(&g_emu_work_conn[0x14], 0x0400);
    wu32_raw(&g_emu_work_conn[0x18], 0x0800);

    /* Secondary tables read by init_locale */
    wu32_raw(&g_emu_work_conn[0x0100 + 0x2c], 0x0000);
    wu32_raw(&g_emu_work_conn[0x0100 + 0x30], 0x0000);
    wu32_raw(&g_emu_work_conn[0x0100 + 0x40], 0x0000);

    wu32_raw(&g_emu_work_conn[0x0800 + 0x0c], 0x0000);
    wu32_raw(&g_emu_work_conn[0x0800 + 0x10], 0x0000);
    wu32_raw(&g_emu_work_conn[0x0800 + 0x14], 0x0000);
    wu32_raw(&g_emu_work_conn[0x0800 + 0x18], 0x0000);

    /* Root offsets reused later in the same routine. */
    wu32_raw(&g_emu_work_conn[0x00], 0x0c00);
    wu32_raw(&g_emu_work_conn[0x04], 0x0c20);
    wu32_raw(&g_emu_work_conn[0x08], 0x0c40);
    wu32_raw(&g_emu_work_conn[0x0c], 0x0c60);

    g_emu_work_conn_ready = 1;
}

EXPORT NTSTATUS RtlOpenCrossProcessEmulatorWorkConnection(
    void** out_connection,
    void* locale_name,
    void* scratch
) {
    (void)locale_name;
    (void)scratch;
    if (!out_connection) {
        return STATUS_INVALID_PARAMETER;
    }
    winemu_init_emu_work_conn();
    *out_connection = (void*)g_emu_work_conn;
    return STATUS_SUCCESS;
}
