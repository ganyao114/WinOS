#include <stdint.h>
#include <stddef.h>

typedef uint8_t UCHAR;
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

typedef struct {
    int64_t CreationTime;
    int64_t LastAccessTime;
    int64_t LastWriteTime;
    int64_t ChangeTime;
    uint32_t FileAttributes;
    uint32_t _pad;
} FILE_BASIC_INFORMATION;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_NOT_IMPLEMENTED 0xC0000002U
#define STATUS_INVALID_HANDLE 0xC0000008U
#define STATUS_INVALID_PARAMETER 0xC000000DU
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034U

#define OBJ_CASE_INSENSITIVE 0x40U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);
__declspec(dllimport) NTSTATUS NtQueryAttributesFile(
    OBJECT_ATTRIBUTES* object_attributes, FILE_BASIC_INFORMATION* file_information);
__declspec(dllimport) NTSTATUS NtDeviceIoControlFile(
    HANDLE file_handle, HANDLE event, void* apc_routine, void* apc_context,
    IO_STATUS_BLOCK* io_status_block, ULONG io_control_code, void* input_buffer, ULONG input_buffer_length,
    void* output_buffer, ULONG output_buffer_length);
__declspec(dllimport) NTSTATUS NtFsControlFile(
    HANDLE file_handle, HANDLE event, void* apc_routine, void* apc_context,
    IO_STATUS_BLOCK* io_status_block, ULONG fs_control_code, void* input_buffer, ULONG input_buffer_length,
    void* output_buffer, ULONG output_buffer_length);

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

static void init_oa(OBJECT_ATTRIBUTES* oa, UNICODE_STRING* name) {
    oa->Length = (ULONG)sizeof(OBJECT_ATTRIBUTES);
    oa->_pad0 = 0;
    oa->RootDirectory = 0;
    oa->ObjectName = name;
    oa->Attributes = OBJ_CASE_INSENSITIVE;
    oa->_pad1 = 0;
    oa->SecurityDescriptor = 0;
    oa->SecurityQualityOfService = 0;
}

void mainCRTStartup(void) {
    NTSTATUS st;
    IO_STATUS_BLOCK iosb;
    FILE_BASIC_INFORMATION fbi;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    WCHAR path_buf[128];

    write_str("== syscall_file_control_test ==\r\n");

    init_unicode(&us, path_buf, "guest/sysroot/hello_win.exe");
    init_oa(&oa, &us);
    fbi.CreationTime = 0;
    fbi.FileAttributes = 0;
    st = NtQueryAttributesFile(&oa, &fbi);
    check("NtQueryAttributesFile(existing) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQueryAttributesFile(existing) returns non-zero attributes", fbi.FileAttributes != 0);

    init_unicode(&us, path_buf, "guest/sysroot/definitely_missing_123.exe");
    init_oa(&oa, &us);
    st = NtQueryAttributesFile(&oa, &fbi);
    check("NtQueryAttributesFile(missing) returns STATUS_OBJECT_NAME_NOT_FOUND", st == STATUS_OBJECT_NAME_NOT_FOUND);

    st = NtQueryAttributesFile(&oa, (FILE_BASIC_INFORMATION*)0);
    check("NtQueryAttributesFile(NULL out) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtDeviceIoControlFile(
        STDOUT_HANDLE, 0, 0, 0, &iosb, 0x1234U, 0, 0, 0, 0
    );
    check("NtDeviceIoControlFile(stdout) returns STATUS_NOT_IMPLEMENTED", st == STATUS_NOT_IMPLEMENTED);
    check("NtDeviceIoControlFile(stdout) IOSB status is STATUS_NOT_IMPLEMENTED",
          (NTSTATUS)iosb.Status == STATUS_NOT_IMPLEMENTED);

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtDeviceIoControlFile(
        (HANDLE)(uint64_t)0x7fffffffULL, 0, 0, 0, &iosb, 0x1234U, 0, 0, 0, 0
    );
    check("NtDeviceIoControlFile(invalid) returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);
    check("NtDeviceIoControlFile(invalid) IOSB status is STATUS_INVALID_HANDLE",
          (NTSTATUS)iosb.Status == STATUS_INVALID_HANDLE);

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtFsControlFile(
        STDOUT_HANDLE, 0, 0, 0, &iosb, 0x2222U, 0, 0, 0, 0
    );
    check("NtFsControlFile(stdout) returns STATUS_NOT_IMPLEMENTED", st == STATUS_NOT_IMPLEMENTED);
    check("NtFsControlFile(stdout) IOSB status is STATUS_NOT_IMPLEMENTED",
          (NTSTATUS)iosb.Status == STATUS_NOT_IMPLEMENTED);

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtFsControlFile(
        (HANDLE)(uint64_t)0x7fffffffULL, 0, 0, 0, &iosb, 0x2222U, 0, 0, 0, 0
    );
    check("NtFsControlFile(invalid) returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);
    check("NtFsControlFile(invalid) IOSB status is STATUS_INVALID_HANDLE",
          (NTSTATUS)iosb.Status == STATUS_INVALID_HANDLE);

    write_str("syscall_file_control_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    terminate_current_process(g_fail == 0 ? 0 : 1);
}
