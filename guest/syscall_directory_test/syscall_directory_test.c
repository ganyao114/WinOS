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
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_INVALID_PARAMETER 0xC000000DU
#define STATUS_NO_MORE_FILES 0x80000006U

#define OBJ_CASE_INSENSITIVE 0x40U

#define FILE_LIST_DIRECTORY 0x00000001U
#define FILE_SHARE_READ 0x00000001U
#define FILE_SHARE_WRITE 0x00000002U
#define FILE_SHARE_DELETE 0x00000004U
#define FILE_OPEN 0x00000001U
#define FILE_DIRECTORY_FILE 0x00000001U
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020U

#define FILE_NAMES_INFORMATION_CLASS 12U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);
__declspec(dllimport) NTSTATUS NtCreateFile(
    HANDLE* file_handle, ULONG desired_access, OBJECT_ATTRIBUTES* object_attributes,
    IO_STATUS_BLOCK* io_status_block, uint64_t* allocation_size, ULONG file_attributes,
    ULONG share_access, ULONG create_disposition, ULONG create_options, void* ea_buffer, ULONG ea_length);
__declspec(dllimport) NTSTATUS NtQueryDirectoryFile(
    HANDLE file_handle, HANDLE event, void* apc_routine, void* apc_context,
    IO_STATUS_BLOCK* io_status_block, void* file_information, ULONG length, ULONG file_information_class,
    UCHAR return_single_entry, UNICODE_STRING* file_name, UCHAR restart_scan);
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

static int unicode_ends_with_ascii_ci(const WCHAR* name, uint32_t name_bytes, const char* suffix) {
    uint32_t name_len = name_bytes / 2;
    uint32_t suffix_len = 0;
    uint32_t i;
    while (suffix[suffix_len]) {
        suffix_len++;
    }
    if (name_len < suffix_len) {
        return 0;
    }
    for (i = 0; i < suffix_len; i++) {
        int a = lower_ascii((int)name[name_len - suffix_len + i]);
        int b = lower_ascii((int)suffix[i]);
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

void mainCRTStartup(void) {
    NTSTATUS st;
    HANDLE dir_handle = 0;
    IO_STATUS_BLOCK iosb = {0};
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING path_us;
    UNICODE_STRING filter_us;
    WCHAR path_buf[128];
    WCHAR filter_buf[32];
    uint8_t out_buf[1024];
    int total_entries = 0;
    int saw_exe = 0;
    int reached_end = 0;
    int i;

    write_str("== syscall_directory_test ==\r\n");

    init_unicode(&path_us, path_buf, "guest/sysroot");
    init_oa(&oa, &path_us);
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
    st = NtQueryDirectoryFile(
        dir_handle,
        0,
        0,
        0,
        &iosb,
        out_buf,
        (ULONG)sizeof(out_buf),
        FILE_NAMES_INFORMATION_CLASS,
        1,
        0,
        1
    );
    check("NtQueryDirectoryFile(first, restart=TRUE) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQueryDirectoryFile(first) returns non-zero bytes", iosb.Information != 0);

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtQueryDirectoryFile(
        dir_handle,
        0,
        0,
        0,
        &iosb,
        out_buf,
        (ULONG)sizeof(out_buf),
        0xFFFFU,
        1,
        0,
        1
    );
    check("NtQueryDirectoryFile(invalid class) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    for (i = 0; i < 256; i++) {
        FILE_NAMES_INFORMATION* fni;
        iosb.Status = 0;
        iosb.Information = 0;
        st = NtQueryDirectoryFile(
            dir_handle,
            0,
            0,
            0,
            &iosb,
            out_buf,
            (ULONG)sizeof(out_buf),
            FILE_NAMES_INFORMATION_CLASS,
            1,
            0,
            (i == 0) ? 1 : 0
        );
        if (st == STATUS_NO_MORE_FILES) {
            reached_end = 1;
            break;
        }
        if (st != STATUS_SUCCESS) {
            break;
        }
        fni = (FILE_NAMES_INFORMATION*)out_buf;
        total_entries++;
        if (unicode_ends_with_ascii_ci(fni->FileName, fni->FileNameLength, ".exe")) {
            saw_exe = 1;
        }
    }
    check("NtQueryDirectoryFile iteration returns at least one entry", total_entries > 0);
    check("NtQueryDirectoryFile iteration eventually reaches STATUS_NO_MORE_FILES", reached_end != 0);
    check("NtQueryDirectoryFile iteration sees an .exe entry", saw_exe != 0);

    init_unicode(&filter_us, filter_buf, "*.exe");
    iosb.Status = 0;
    iosb.Information = 0;
    st = NtQueryDirectoryFile(
        dir_handle,
        0,
        0,
        0,
        &iosb,
        out_buf,
        (ULONG)sizeof(out_buf),
        FILE_NAMES_INFORMATION_CLASS,
        1,
        &filter_us,
        1
    );
    check("NtQueryDirectoryFile(\"*.exe\") returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    if (st == STATUS_SUCCESS) {
        FILE_NAMES_INFORMATION* fni = (FILE_NAMES_INFORMATION*)out_buf;
        check("NtQueryDirectoryFile(\"*.exe\") returns .exe entry",
              unicode_ends_with_ascii_ci(fni->FileName, fni->FileNameLength, ".exe"));
    }

    st = NtClose(dir_handle);
    check("NtClose(directory handle) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    write_str("syscall_directory_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    terminate_current_process(g_fail == 0 ? 0 : 1);
}
