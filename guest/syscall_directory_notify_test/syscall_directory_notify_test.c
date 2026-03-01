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

typedef struct {
    ULONG NextEntryOffset;
    ULONG Action;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NOTIFY_INFORMATION;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define OBJ_CASE_INSENSITIVE 0x40U

#define FILE_LIST_DIRECTORY 0x00000001U
#define FILE_SHARE_READ 0x00000001U
#define FILE_SHARE_WRITE 0x00000002U
#define FILE_SHARE_DELETE 0x00000004U
#define FILE_OPEN 0x00000001U
#define FILE_OVERWRITE_IF 0x00000005U
#define FILE_NON_DIRECTORY_FILE 0x00000040U
#define FILE_DIRECTORY_FILE 0x00000001U
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020U
#define FILE_NOTIFY_CHANGE_FILE_NAME 0x00000001U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);
__declspec(dllimport) NTSTATUS NtCreateFile(
    HANDLE* file_handle, ULONG desired_access, OBJECT_ATTRIBUTES* object_attributes,
    IO_STATUS_BLOCK* io_status_block, uint64_t* allocation_size, ULONG file_attributes,
    ULONG share_access, ULONG create_disposition, ULONG create_options, void* ea_buffer, ULONG ea_length);
__declspec(dllimport) NTSTATUS NtNotifyChangeDirectoryFile(
    HANDLE file_handle, HANDLE event, void* apc_routine, void* apc_context,
    void* io_status_block, void* buffer, ULONG length, ULONG completion_filter, UCHAR watch_tree);
__declspec(dllimport) NTSTATUS NtQuerySystemTime(int64_t* time);
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

static int lower_ascii(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

static int unicode_contains_ascii_ci(const WCHAR* name, uint32_t name_bytes, const char* needle) {
    uint32_t name_len = name_bytes / 2;
    uint32_t needle_len = 0;
    uint32_t i;
    uint32_t j;
    while (needle[needle_len]) {
        needle_len++;
    }
    if (needle_len == 0 || name_len < needle_len) {
        return 0;
    }
    for (i = 0; i + needle_len <= name_len; i++) {
        int ok = 1;
        for (j = 0; j < needle_len; j++) {
            int a = lower_ascii((int)name[i + j]);
            int b = lower_ascii((int)needle[j]);
            if (a != b) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            return 1;
        }
    }
    return 0;
}

static void build_temp_path(char* out, uint64_t nonce_low32) {
    const char* prefix = "guest/sysroot/notify_";
    const char* suffix = ".tmp";
    const char* hex = "0123456789abcdef";
    uint32_t i = 0;
    uint32_t p = 0;

    while (prefix[p]) {
        out[i++] = prefix[p++];
    }
    for (p = 0; p < 8; p++) {
        out[i++] = hex[(nonce_low32 >> ((7 - p) * 4)) & 0xF];
    }
    p = 0;
    while (suffix[p]) {
        out[i++] = suffix[p++];
    }
    out[i] = 0;
}

void mainCRTStartup(void) {
    NTSTATUS st;
    HANDLE dir_handle = 0;
    HANDLE file_handle = 0;
    IO_STATUS_BLOCK iosb = {0};
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING dir_us;
    UNICODE_STRING file_us;
    WCHAR dir_wbuf[128];
    WCHAR file_wbuf[256];
    char file_abuf[256];
    uint8_t notify_buf[1024];
    int64_t now = 0;

    write_str("== syscall_directory_notify_test ==\r\n");

    init_unicode(&dir_us, dir_wbuf, "guest/sysroot");
    init_oa(&oa, &dir_us);
    st = NtCreateFile(
        &dir_handle,
        FILE_LIST_DIRECTORY,
        &oa,
        &iosb,
        0,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        0,
        0
    );
    check("NtCreateFile(directory) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateFile(directory) returns valid handle", dir_handle != 0);
    if (st != STATUS_SUCCESS || dir_handle == 0) {
        terminate_current_process(1);
    }

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtNotifyChangeDirectoryFile(
        dir_handle,
        0,
        0,
        0,
        &iosb,
        notify_buf,
        (ULONG)sizeof(notify_buf),
        FILE_NOTIFY_CHANGE_FILE_NAME,
        0
    );
    check("NtNotifyChangeDirectoryFile(prime) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    (void)NtQuerySystemTime(&now);
    build_temp_path(file_abuf, (uint64_t)now & 0xFFFFffffULL);
    init_unicode(&file_us, file_wbuf, file_abuf);
    init_oa(&oa, &file_us);
    iosb.Status = 0;
    iosb.Information = 0;
    st = NtCreateFile(
        &file_handle,
        0x80000000U | 0x40000000U,
        &oa,
        &iosb,
        0,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        0,
        0
    );
    check("NtCreateFile(temp file) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    if (st == STATUS_SUCCESS && file_handle != 0) {
        (void)NtClose(file_handle);
    }

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtNotifyChangeDirectoryFile(
        dir_handle,
        0,
        0,
        0,
        &iosb,
        notify_buf,
        (ULONG)sizeof(notify_buf),
        FILE_NOTIFY_CHANGE_FILE_NAME,
        0
    );
    check("NtNotifyChangeDirectoryFile(after create) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtNotifyChangeDirectoryFile(after create) returns non-zero info", iosb.Information >= 12);
    if (st == STATUS_SUCCESS && iosb.Information >= 12) {
        FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)notify_buf;
        check("Notify action is non-zero", fni->Action != 0);
        check("Notify file name contains \"notify_\"",
              unicode_contains_ascii_ci(fni->FileName, fni->FileNameLength, "notify_"));
    }

    st = NtClose(dir_handle);
    check("NtClose(directory handle) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    write_str("syscall_directory_notify_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    terminate_current_process(g_fail == 0 ? 0 : 1);
}
