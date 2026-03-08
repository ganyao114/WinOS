#include <stdint.h>
#include <stddef.h>

typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef uint16_t USHORT;
typedef uint16_t WCHAR;
typedef void* HANDLE;

typedef struct {
    uint64_t Status;
    uint64_t Information;
} IO_STATUS_BLOCK;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    uint32_t _pad;
    WCHAR* Buffer;
} UNICODE_STRING;

typedef struct {
    uint32_t Length;
    uint32_t _pad0;
    HANDLE RootDirectory;
    UNICODE_STRING* ObjectName;
    uint32_t Attributes;
    uint32_t _pad1;
    void* SecurityDescriptor;
    void* SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct {
    uint32_t EventType;
    uint32_t EventState;
} EVENT_BASIC_INFORMATION;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_ACCESS_DENIED 0xC0000022U
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034U
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035U
#define STATUS_OBJECT_NAME_EXISTS 0x40000000U
#define STATUS_BUFFER_TOO_SMALL 0xC0000023U

#define OBJ_CASE_INSENSITIVE 0x40U
#define OBJ_OPENIF 0x80U

#define NR_CLEAR_EVENT 0x003EU
#define NR_OPEN_EVENT 0x0200U
#define NR_OPEN_MUTANT 0x0020U
#define NR_OPEN_SEMAPHORE 0x0035U
#define NR_QUERY_EVENT 0x0056U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) NTSTATUS NtCreateEvent(
    HANDLE* event_handle, ULONG desired_access, void* object_attributes, ULONG event_type, uint8_t initial_state);
__declspec(dllimport) NTSTATUS NtSetEvent(HANDLE event_handle, ULONG* previous_state);
__declspec(dllimport) NTSTATUS NtCreateMutant(
    HANDLE* mutant_handle, ULONG desired_access, void* object_attributes, uint8_t initial_owner);
__declspec(dllimport) NTSTATUS NtCreateSemaphore(
    HANDLE* semaphore_handle, ULONG desired_access, void* object_attributes, int32_t initial_count, int32_t maximum_count);
__declspec(dllimport) NTSTATUS NtClose(HANDLE handle);
__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);

static uint32_t g_pass = 0;
static uint32_t g_fail = 0;

static void write_str(const char* s) {
    IO_STATUS_BLOCK iosb = {0};
    ULONG len = 0;
    while (s[len]) {
        len++;
    }
    (void)NtWriteFile(STDOUT_HANDLE, 0, 0, 0, &iosb, s, len, 0, 0);
}

static void check(const char* name, int ok) {
    if (ok) {
        g_pass++;
        write_str("[PASS] ");
    } else {
        g_fail++;
        write_str("[FAIL] ");
    }
    write_str(name);
    write_str("\r\n");
}

static __attribute__((noreturn)) void terminate_current_process(uint32_t code) {
    NtTerminateProcess(NT_CURRENT_PROCESS, code);
    for (;;) {
        __asm__ volatile("wfi" ::: "memory");
    }
}

static NTSTATUS raw_nt_clear_event(HANDLE event_handle) {
    register uint64_t x0 __asm__("x0") = (uint64_t)(uintptr_t)event_handle;
    register uint64_t x8 __asm__("x8") = NR_CLEAR_EVENT;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x8)
        : "x1", "x2", "x3", "x4", "x5", "x6", "x7", "memory"
    );
    return (NTSTATUS)x0;
}

static NTSTATUS raw_nt_query_event(
    HANDLE event_handle,
    ULONG event_info_class,
    void* event_info,
    ULONG event_info_len,
    ULONG* ret_len
) {
    register uint64_t x0 __asm__("x0") = (uint64_t)(uintptr_t)event_handle;
    register uint64_t x1 __asm__("x1") = (uint64_t)event_info_class;
    register uint64_t x2 __asm__("x2") = (uint64_t)(uintptr_t)event_info;
    register uint64_t x3 __asm__("x3") = (uint64_t)event_info_len;
    register uint64_t x4 __asm__("x4") = (uint64_t)(uintptr_t)ret_len;
    register uint64_t x8 __asm__("x8") = NR_QUERY_EVENT;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "x5", "x6", "x7", "memory"
    );
    return (NTSTATUS)x0;
}

static NTSTATUS raw_nt_open_event(
    HANDLE* event_handle,
    ULONG desired_access,
    OBJECT_ATTRIBUTES* object_attributes
) {
    register uint64_t x0 __asm__("x0") = (uint64_t)(uintptr_t)event_handle;
    register uint64_t x1 __asm__("x1") = (uint64_t)desired_access;
    register uint64_t x2 __asm__("x2") = (uint64_t)(uintptr_t)object_attributes;
    register uint64_t x8 __asm__("x8") = NR_OPEN_EVENT;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "x3", "x4", "x5", "x6", "x7", "memory"
    );
    return (NTSTATUS)x0;
}

static NTSTATUS raw_nt_open_mutant(
    HANDLE* mutant_handle,
    ULONG desired_access,
    OBJECT_ATTRIBUTES* object_attributes
) {
    register uint64_t x0 __asm__("x0") = (uint64_t)(uintptr_t)mutant_handle;
    register uint64_t x1 __asm__("x1") = (uint64_t)desired_access;
    register uint64_t x2 __asm__("x2") = (uint64_t)(uintptr_t)object_attributes;
    register uint64_t x8 __asm__("x8") = NR_OPEN_MUTANT;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "x3", "x4", "x5", "x6", "x7", "memory"
    );
    return (NTSTATUS)x0;
}

static NTSTATUS raw_nt_open_semaphore(
    HANDLE* semaphore_handle,
    ULONG desired_access,
    OBJECT_ATTRIBUTES* object_attributes
) {
    register uint64_t x0 __asm__("x0") = (uint64_t)(uintptr_t)semaphore_handle;
    register uint64_t x1 __asm__("x1") = (uint64_t)desired_access;
    register uint64_t x2 __asm__("x2") = (uint64_t)(uintptr_t)object_attributes;
    register uint64_t x8 __asm__("x8") = NR_OPEN_SEMAPHORE;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "x3", "x4", "x5", "x6", "x7", "memory"
    );
    return (NTSTATUS)x0;
}

static void init_unicode(UNICODE_STRING* us, WCHAR* storage, const char* ascii) {
    uint32_t n = 0;
    while (ascii[n]) {
        storage[n] = (WCHAR)ascii[n];
        n++;
    }
    storage[n] = 0;
    us->Length = (USHORT)(n * 2);
    us->MaximumLength = (USHORT)((n + 1) * 2);
    us->Buffer = storage;
}

static void init_oa(OBJECT_ATTRIBUTES* oa, UNICODE_STRING* name, uint32_t attrs) {
    oa->Length = (uint32_t)sizeof(OBJECT_ATTRIBUTES);
    oa->_pad0 = 0;
    oa->RootDirectory = 0;
    oa->ObjectName = name;
    oa->Attributes = attrs;
    oa->_pad1 = 0;
    oa->SecurityDescriptor = 0;
    oa->SecurityQualityOfService = 0;
}

void mainCRTStartup(void) {
    NTSTATUS st;
    HANDLE h = 0;
    HANDLE h2 = 0;
    ULONG ret_len = 0;
    EVENT_BASIC_INFORMATION ebi = {0};
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    WCHAR name_buf[96];
    WCHAR missing_buf[96];

    write_str("== syscall_sync_test ==\r\n");

    h = 0;
    st = NtCreateEvent(&h, 0, 0, 1, 0);
    check("NtCreateEvent(valid access) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateEvent(valid access) returns handle", h != 0);
    if (h != 0) {
        check("NtClose(event) returns STATUS_SUCCESS", NtClose(h) == STATUS_SUCCESS);
    }

    h = 0;
    st = NtCreateEvent(&h, 0x80000000U, 0, 1, 0);
    check("NtCreateEvent(invalid access) returns STATUS_ACCESS_DENIED", st == STATUS_ACCESS_DENIED);
    check("NtCreateEvent(invalid access) does not return handle", h == 0);

    h = 0;
    st = NtCreateMutant(&h, 0, 0, 0);
    check("NtCreateMutant(valid access) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateMutant(valid access) returns handle", h != 0);
    if (h != 0) {
        check("NtClose(mutant) returns STATUS_SUCCESS", NtClose(h) == STATUS_SUCCESS);
    }

    h = 0;
    st = NtCreateMutant(&h, 0x80000000U, 0, 0);
    check("NtCreateMutant(invalid access) returns STATUS_ACCESS_DENIED", st == STATUS_ACCESS_DENIED);
    check("NtCreateMutant(invalid access) does not return handle", h == 0);

    h = 0;
    st = NtCreateSemaphore(&h, 0, 0, 1, 2);
    check("NtCreateSemaphore(valid access) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateSemaphore(valid access) returns handle", h != 0);
    if (h != 0) {
        check("NtClose(semaphore) returns STATUS_SUCCESS", NtClose(h) == STATUS_SUCCESS);
    }

    h = 0;
    st = NtCreateSemaphore(&h, 0x80000000U, 0, 1, 2);
    check("NtCreateSemaphore(invalid access) returns STATUS_ACCESS_DENIED", st == STATUS_ACCESS_DENIED);
    check("NtCreateSemaphore(invalid access) does not return handle", h == 0);

    init_unicode(&us, name_buf, "\\BaseNamedObjects\\WinEmuSyncNamedEvent");
    init_oa(&oa, &us, OBJ_CASE_INSENSITIVE);
    h = 0;
    st = NtCreateEvent(&h, 0, &oa, 1, 0);
    check("NtCreateEvent(named) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateEvent(named) returns handle", h != 0);

    h2 = 0;
    st = NtCreateEvent(&h2, 0, &oa, 1, 0);
    check("NtCreateEvent(named duplicate) returns STATUS_OBJECT_NAME_COLLISION", st == STATUS_OBJECT_NAME_COLLISION);
    check("NtCreateEvent(named duplicate) returns handle", h2 != 0);

    init_oa(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_OPENIF);
    HANDLE h_openif = 0;
    st = NtCreateEvent(&h_openif, 0, &oa, 1, 0);
    check("NtCreateEvent(named with OBJ_OPENIF) returns STATUS_OBJECT_NAME_EXISTS", st == STATUS_OBJECT_NAME_EXISTS);
    check("NtCreateEvent(named with OBJ_OPENIF) returns handle", h_openif != 0);

    init_oa(&oa, &us, OBJ_CASE_INSENSITIVE);
    HANDLE h_open = 0;
    st = raw_nt_open_event(&h_open, 0, &oa);
    check("NtOpenEvent(existing named) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtOpenEvent(existing named) returns handle", h_open != 0);

    ret_len = 0;
    ebi.EventState = 0xFFFFFFFFU;
    st = raw_nt_query_event(h_open, 0, &ebi, (ULONG)sizeof(ebi), &ret_len);
    check("NtQueryEvent(EventBasicInformation) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQueryEvent(EventBasicInformation) reports 8 bytes", ret_len == 8);
    check("NtQueryEvent(EventBasicInformation) initial state is non-signaled", ebi.EventState == 0);

    st = NtSetEvent(h_open, 0);
    check("NtSetEvent(named) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    ebi.EventState = 0;
    ret_len = 0;
    st = raw_nt_query_event(h_open, 0, &ebi, (ULONG)sizeof(ebi), &ret_len);
    check("NtQueryEvent after NtSetEvent returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQueryEvent after NtSetEvent state is signaled", ebi.EventState == 1);

    st = raw_nt_clear_event(h_open);
    check("NtClearEvent(named) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    ebi.EventState = 0xFFFFFFFFU;
    ret_len = 0;
    st = raw_nt_query_event(h_open, 0, &ebi, (ULONG)sizeof(ebi), &ret_len);
    check("NtQueryEvent after NtClearEvent returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQueryEvent after NtClearEvent state is non-signaled", ebi.EventState == 0);

    ret_len = 0;
    st = raw_nt_query_event(h_open, 0, &ebi, 4, &ret_len);
    check("NtQueryEvent(short buffer) returns STATUS_BUFFER_TOO_SMALL", st == STATUS_BUFFER_TOO_SMALL);
    check("NtQueryEvent(short buffer) reports 8 bytes", ret_len == 8);

    init_unicode(&us, missing_buf, "\\BaseNamedObjects\\WinEmuSyncMissingEvent");
    init_oa(&oa, &us, OBJ_CASE_INSENSITIVE);
    HANDLE h_missing = 0;
    st = raw_nt_open_event(&h_missing, 0, &oa);
    check("NtOpenEvent(missing named) returns STATUS_OBJECT_NAME_NOT_FOUND", st == STATUS_OBJECT_NAME_NOT_FOUND);

    init_unicode(&us, name_buf, "\\BaseNamedObjects\\WinEmuSyncNamedMutant");
    init_oa(&oa, &us, OBJ_CASE_INSENSITIVE);
    HANDLE hm = 0;
    HANDLE hm_open = 0;
    st = NtCreateMutant(&hm, 0, &oa, 0);
    check("NtCreateMutant(named) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    st = raw_nt_open_mutant(&hm_open, 0, &oa);
    check("NtOpenMutant(existing named) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtOpenMutant(existing named) returns handle", hm_open != 0);
    init_unicode(&us, missing_buf, "\\BaseNamedObjects\\WinEmuSyncMissingMutant");
    init_oa(&oa, &us, OBJ_CASE_INSENSITIVE);
    st = raw_nt_open_mutant(&h_missing, 0, &oa);
    check("NtOpenMutant(missing named) returns STATUS_OBJECT_NAME_NOT_FOUND", st == STATUS_OBJECT_NAME_NOT_FOUND);

    init_unicode(&us, name_buf, "\\BaseNamedObjects\\WinEmuSyncNamedSemaphore");
    init_oa(&oa, &us, OBJ_CASE_INSENSITIVE);
    HANDLE hs = 0;
    HANDLE hs_open = 0;
    st = NtCreateSemaphore(&hs, 0, &oa, 1, 2);
    check("NtCreateSemaphore(named) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    st = raw_nt_open_semaphore(&hs_open, 0, &oa);
    check("NtOpenSemaphore(existing named) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtOpenSemaphore(existing named) returns handle", hs_open != 0);
    init_unicode(&us, missing_buf, "\\BaseNamedObjects\\WinEmuSyncMissingSemaphore");
    init_oa(&oa, &us, OBJ_CASE_INSENSITIVE);
    st = raw_nt_open_semaphore(&h_missing, 0, &oa);
    check("NtOpenSemaphore(missing named) returns STATUS_OBJECT_NAME_NOT_FOUND", st == STATUS_OBJECT_NAME_NOT_FOUND);

    if (h_open) (void)NtClose(h_open);
    if (h_openif) (void)NtClose(h_openif);
    if (h2) (void)NtClose(h2);
    if (h) (void)NtClose(h);
    if (hm_open) (void)NtClose(hm_open);
    if (hm) (void)NtClose(hm);
    if (hs_open) (void)NtClose(hs_open);
    if (hs) (void)NtClose(hs);

    write_str("syscall_sync_test summary complete\r\n");
    terminate_current_process(g_fail == 0 ? 0 : 1);
}
