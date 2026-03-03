#include <stddef.h>
#include <stdint.h>

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

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_PENDING 0x00000103U

#define OBJ_CASE_INSENSITIVE 0x40U

#define FILE_SHARE_READ 0x00000001U
#define FILE_SHARE_WRITE 0x00000002U
#define FILE_SHARE_DELETE 0x00000004U
#define FILE_OVERWRITE_IF 0x00000005U
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020U
#define FILE_NON_DIRECTORY_FILE 0x00000040U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) NTSTATUS NtReadFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) NTSTATUS NtCreateFile(
    HANDLE* file_handle, ULONG desired_access, OBJECT_ATTRIBUTES* object_attributes,
    IO_STATUS_BLOCK* io_status_block, uint64_t* allocation_size, ULONG file_attributes,
    ULONG share_access, ULONG create_disposition, ULONG create_options, void* ea_buffer, ULONG ea_length);
__declspec(dllimport) NTSTATUS NtCreateEvent(
    HANDLE* event_handle, ULONG desired_access, OBJECT_ATTRIBUTES* object_attributes, ULONG event_type, UCHAR initial_state);
__declspec(dllimport) NTSTATUS NtWaitForSingleObject(HANDLE handle, UCHAR alertable, int64_t* timeout);
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
    static uint8_t write_buf[256 * 1024];
    static uint8_t read_buf[256 * 1024];
    HANDLE file_handle = 0;
    HANDLE io_event = 0;
    IO_STATUS_BLOCK iosb = {0};
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING path_us;
    WCHAR path_buf[128];
    uint64_t offset = 0;
    int64_t wait_timeout_100ns = -50 * 1000 * 1000; /* 5s */
    NTSTATUS st;
    uint32_t i;
    uint32_t len = (uint32_t)sizeof(write_buf);
    int mismatch = 0;

    write_str("== syscall_file_async_test ==\r\n");

    for (i = 0; i < len; i++) {
        write_buf[i] = (uint8_t)(i ^ 0x5A);
        read_buf[i] = 0;
    }

    init_unicode(&path_us, path_buf, "guest/sysroot/async_rw_test.bin");
    init_oa(&oa, &path_us);
    st = NtCreateFile(
        &file_handle,
        0x00000003U, /* FILE_READ_DATA | FILE_WRITE_DATA */
        &oa,
        &iosb,
        0,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        0,
        0);
    check("NtCreateFile(async file) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateFile(async file) returns valid handle", file_handle != 0);

    st = NtCreateEvent(&io_event, 0, 0, 1, 0);
    check("NtCreateEvent returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateEvent returns handle", io_event != 0);

    if (file_handle == 0 || io_event == 0) {
        terminate_current_process(1);
    }

    iosb.Status = 0;
    iosb.Information = 0;
    offset = 0;
    st = NtWriteFile(file_handle, io_event, 0, 0, &iosb, write_buf, len, &offset, 0);
    check("NtWriteFile(async) returns STATUS_PENDING", st == STATUS_PENDING);
    st = NtWaitForSingleObject(io_event, 0, &wait_timeout_100ns);
    check("NtWaitForSingleObject(write event) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtWriteFile completion iosb is STATUS_SUCCESS", (NTSTATUS)iosb.Status == STATUS_SUCCESS);
    check("NtWriteFile completion bytes == len", iosb.Information == len);

    iosb.Status = 0;
    iosb.Information = 0;
    offset = 0;
    st = NtReadFile(file_handle, io_event, 0, 0, &iosb, read_buf, len, &offset, 0);
    check("NtReadFile(async) returns STATUS_PENDING", st == STATUS_PENDING);
    st = NtWaitForSingleObject(io_event, 0, &wait_timeout_100ns);
    check("NtWaitForSingleObject(read event) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtReadFile completion iosb is STATUS_SUCCESS", (NTSTATUS)iosb.Status == STATUS_SUCCESS);
    check("NtReadFile completion bytes == len", iosb.Information == len);

    for (i = 0; i < len; i++) {
        if (read_buf[i] != write_buf[i]) {
            mismatch = 1;
            break;
        }
    }
    check("async read/write data roundtrip matches", mismatch == 0);

    st = NtClose(file_handle);
    check("NtClose(file) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    st = NtClose(io_event);
    check("NtClose(event) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    write_str("syscall_file_async_test summary: pass=");
    write_str(" fail=");
    write_str("\r\n");

    terminate_current_process(g_fail ? 1 : 0);
}
