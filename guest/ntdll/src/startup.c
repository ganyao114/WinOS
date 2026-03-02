/* ── User thread bootstrap ───────────────────────────────────── */

#define PEB_IMAGE_BASE_OFF               0x10
#define PEB_LDR_OFF                      0x18
#define LDR_IN_INIT_ORDER_LIST_OFF       0x30
#define LDR_ENTRY_IN_INIT_ORDER_LINK_OFF 0x20
#define LDR_ENTRY_DLL_BASE_OFF           0x30
#define LDR_ENTRY_ENTRY_POINT_OFF        0x38
#define DLL_PROCESS_ATTACH               1

typedef int (*DLL_ENTRY_FN)(HANDLE, ULONG, void*);
typedef void (*EXE_ENTRY_FN)(void);

static void winemu_call_process_attach(uint8_t* peb) {
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
        if (ep && dll_base && dll_base != image_base) {
            DLL_ENTRY_FN dll_main = (DLL_ENTRY_FN)(uintptr_t)ep;
            (void)dll_main((HANDLE)(uintptr_t)dll_base, DLL_PROCESS_ATTACH, NULL);
        }
        link = next;
    }
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

EXPORT __attribute__((noreturn))
void RtlUserThreadStart(void* start, void* peb_arg) {
    (void)start;
    uint8_t* peb = (uint8_t*)peb_arg;
    if (!peb) {
        peb = (uint8_t*)RtlGetCurrentPeb();
    }

    winemu_call_process_attach(peb);

    uint64_t main_entry = winemu_query_main_entry(peb);
    if (main_entry) {
        EXE_ENTRY_FN exe_entry = (EXE_ENTRY_FN)(uintptr_t)main_entry;
        exe_entry();
    }

    RtlExitUserProcess(0);
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

