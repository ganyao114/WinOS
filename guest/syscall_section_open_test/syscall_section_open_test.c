#include <stdint.h>
#include <stddef.h>

typedef uint16_t USHORT;
typedef uint16_t WCHAR;
typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
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

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_INVALID_PARAMETER 0xC000000DU
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035U
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034U

#define PAGE_READWRITE 0x04U
#define SEC_COMMIT 0x08000000U
#define OBJ_CASE_INSENSITIVE 0x40U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);
__declspec(dllimport) NTSTATUS NtCreateSection(
    HANDLE* section_handle, ULONG desired_access, OBJECT_ATTRIBUTES* object_attributes,
    uint64_t* max_size, ULONG page_prot, ULONG alloc_attrs, HANDLE file_handle);
__declspec(dllimport) NTSTATUS NtOpenSection(
    HANDLE* section_handle, ULONG desired_access, OBJECT_ATTRIBUTES* object_attributes);
__declspec(dllimport) NTSTATUS NtClose(HANDLE handle);

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

static void write_u64_hex(uint64_t value) {
    char buf[19];
    const char* hex = "0123456789abcdef";
    int i;
    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 16; i++) {
        buf[2 + i] = hex[(value >> ((15 - i) * 4)) & 0xF];
    }
    buf[18] = '\0';
    write_str(buf);
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

static void init_oa(OBJECT_ATTRIBUTES* oa, UNICODE_STRING* name, HANDLE root) {
    oa->Length = (ULONG)sizeof(OBJECT_ATTRIBUTES);
    oa->_pad0 = 0;
    oa->RootDirectory = root;
    oa->ObjectName = name;
    oa->Attributes = OBJ_CASE_INSENSITIVE;
    oa->_pad1 = 0;
    oa->SecurityDescriptor = 0;
    oa->SecurityQualityOfService = 0;
}

void mainCRTStartup(void) {
    NTSTATUS st;
    HANDLE section_a = 0;
    HANDLE section_b = 0;
    HANDLE section_c = 0;
    uint64_t section_size = 0x2000;
    WCHAR named_buf[96];
    WCHAR missing_buf[96];
    UNICODE_STRING named_name;
    UNICODE_STRING missing_name;
    OBJECT_ATTRIBUTES named_oa;
    OBJECT_ATTRIBUTES missing_oa;

    write_str("== syscall_section_open_test ==\r\n");

    init_unicode(&named_name, named_buf, "\\BaseNamedObjects\\WinEmuOpenSectionTest");
    init_oa(&named_oa, &named_name, 0);

    st = NtCreateSection(&section_a, 0, &named_oa, &section_size, PAGE_READWRITE, SEC_COMMIT, 0);
    check("NtCreateSection(named) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateSection(named) returns non-zero handle", section_a != 0);

    st = NtOpenSection(&section_b, 0, &named_oa);
    check("NtOpenSection(existing name) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtOpenSection(existing name) returns non-zero handle", section_b != 0);

    section_c = 0;
    st = NtCreateSection(&section_c, 0, &named_oa, &section_size, PAGE_READWRITE, SEC_COMMIT, 0);
    check("NtCreateSection(duplicate name) returns STATUS_OBJECT_NAME_COLLISION", st == STATUS_OBJECT_NAME_COLLISION);

    init_unicode(&missing_name, missing_buf, "\\BaseNamedObjects\\WinEmuOpenSectionMissing");
    init_oa(&missing_oa, &missing_name, 0);
    section_c = 0;
    st = NtOpenSection(&section_c, 0, &missing_oa);
    check("NtOpenSection(missing name) returns STATUS_OBJECT_NAME_NOT_FOUND", st == STATUS_OBJECT_NAME_NOT_FOUND);

    section_c = 0;
    st = NtOpenSection(&section_c, 0, 0);
    check("NtOpenSection(NULL oa) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    st = NtClose(section_b);
    check("NtClose(opened section) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    st = NtClose(section_a);
    check("NtClose(created section) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    write_str("syscall_section_open_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    terminate_current_process(g_fail == 0 ? 0 : 1);
}
