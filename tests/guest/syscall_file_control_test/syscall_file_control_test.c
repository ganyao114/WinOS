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

typedef struct {
    int64_t CreationTime;
    int64_t LastAccessTime;
    int64_t LastWriteTime;
    int64_t ChangeTime;
    int64_t AllocationSize;
    int64_t EndOfFile;
    uint32_t FileAttributes;
    uint32_t _pad;
} FILE_NETWORK_OPEN_INFORMATION;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_PENDING 0x00000103U
#define STATUS_NOT_IMPLEMENTED 0xC0000002U
#define STATUS_INVALID_HANDLE 0xC0000008U
#define STATUS_INVALID_PARAMETER 0xC000000DU
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034U

#define FILE_ATTRIBUTE_NORMAL 0x00000080U
#define OBJ_CASE_INSENSITIVE 0x40U
#define EVENT_ALL_ACCESS 0x001F0003U

#define FILE_SHARE_READ 0x00000001U
#define FILE_SHARE_WRITE 0x00000002U
#define FILE_SHARE_DELETE 0x00000004U
#define FILE_OPEN 0x00000001U

#define IOCTL_WINEMU_HOST_PING 0x0022A000U
#define IOCTL_WINEMU_HOSTCALL_SYNC 0x0022A004U
#define WINEMU_PING_MAGIC 0x57454D55U

#define NR_QUERY_FULL_ATTRIBUTES_FILE 0x0151U
#define NR_FLUSH_BUFFERS_FILE 0x0202U
#define NR_CANCEL_IO_FILE 0x005DU

#define HOSTCALL_FLAG_FORCE_ASYNC (1ull << 1)
#define HOSTCALL_HC_OK 0ull
#define HOSTCALL_HC_IO_ERROR 5ull
#define HOSTCALL_OP_OPEN 1ull
#define HOSTCALL_OP_CLOSE 4ull

typedef struct {
    uint32_t version;
    uint32_t _reserved;
    uint64_t opcode;
    uint64_t flags;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t user_tag;
} WINEMU_HOSTCALL_REQUEST;

typedef struct {
    uint64_t host_result;
    uint64_t aux;
    uint64_t request_id;
} WINEMU_HOSTCALL_RESPONSE;

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);
__declspec(dllimport) NTSTATUS NtCreateFile(
    HANDLE* file_handle, ULONG desired_access, OBJECT_ATTRIBUTES* object_attributes,
    IO_STATUS_BLOCK* io_status_block, uint64_t* allocation_size, ULONG file_attributes,
    ULONG share_access, ULONG create_disposition, ULONG create_options, void* ea_buffer, ULONG ea_length);
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
__declspec(dllimport) NTSTATUS NtCreateEvent(
    HANDLE* event_handle, ULONG desired_access, OBJECT_ATTRIBUTES* object_attributes, ULONG event_type, UCHAR initial_state);
__declspec(dllimport) NTSTATUS NtWaitForSingleObject(HANDLE handle, UCHAR alertable, int64_t* timeout);
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

static NTSTATUS raw_nt_query_full_attributes_file(
    OBJECT_ATTRIBUTES* object_attributes,
    FILE_NETWORK_OPEN_INFORMATION* file_information
) {
    register uint64_t x0 __asm__("x0") = (uint64_t)(uintptr_t)object_attributes;
    register uint64_t x1 __asm__("x1") = (uint64_t)(uintptr_t)file_information;
    register uint64_t x8 __asm__("x8") = NR_QUERY_FULL_ATTRIBUTES_FILE;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x8)
        : "x2", "x3", "x4", "x5", "x6", "x7", "memory"
    );
    return (NTSTATUS)x0;
}

static NTSTATUS raw_nt_flush_buffers_file(HANDLE file_handle, IO_STATUS_BLOCK* io_status_block) {
    register uint64_t x0 __asm__("x0") = (uint64_t)(uintptr_t)file_handle;
    register uint64_t x1 __asm__("x1") = (uint64_t)(uintptr_t)io_status_block;
    register uint64_t x8 __asm__("x8") = NR_FLUSH_BUFFERS_FILE;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x8)
        : "x2", "x3", "x4", "x5", "x6", "x7", "memory"
    );
    return (NTSTATUS)x0;
}

static NTSTATUS raw_nt_cancel_io_file(HANDLE file_handle, IO_STATUS_BLOCK* io_status_block) {
    register uint64_t x0 __asm__("x0") = (uint64_t)(uintptr_t)file_handle;
    register uint64_t x1 __asm__("x1") = (uint64_t)(uintptr_t)io_status_block;
    register uint64_t x8 __asm__("x8") = NR_CANCEL_IO_FILE;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x8)
        : "x2", "x3", "x4", "x5", "x6", "x7", "memory"
    );
    return (NTSTATUS)x0;
}

void mainCRTStartup(void) {
    NTSTATUS st;
    IO_STATUS_BLOCK iosb;
    FILE_BASIC_INFORMATION fbi;
    FILE_NETWORK_OPEN_INFORMATION fnoi;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    WCHAR path_buf[128];
    HANDLE dev = 0;
    HANDLE file_handle = 0;
    HANDLE io_event = 0;
    ULONG ping = 0;
    uint64_t host_fd = 0;
    char host_open_path[] = "guest/sysroot/hello_win.exe";
    ULONG host_open_path_len = 0;
    WINEMU_HOSTCALL_REQUEST hreq;
    WINEMU_HOSTCALL_RESPONSE hresp;

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

    init_unicode(&us, path_buf, "guest/sysroot/hello_win.exe");
    init_oa(&oa, &us);
    fnoi.CreationTime = 0;
    fnoi.FileAttributes = 0;
    st = raw_nt_query_full_attributes_file(&oa, &fnoi);
    check("NtQueryFullAttributesFile(existing) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQueryFullAttributesFile(existing) returns FILE_ATTRIBUTE_NORMAL", fnoi.FileAttributes == FILE_ATTRIBUTE_NORMAL);

    init_unicode(&us, path_buf, "guest/sysroot/definitely_missing_123.exe");
    init_oa(&oa, &us);
    st = raw_nt_query_full_attributes_file(&oa, &fnoi);
    check("NtQueryFullAttributesFile(missing) returns STATUS_OBJECT_NAME_NOT_FOUND", st == STATUS_OBJECT_NAME_NOT_FOUND);

    st = raw_nt_query_full_attributes_file(&oa, (FILE_NETWORK_OPEN_INFORMATION*)0);
    check("NtQueryFullAttributesFile(NULL out) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    init_unicode(&us, path_buf, "guest/sysroot/hello_win.exe");
    init_oa(&oa, &us);
    iosb.Status = 0;
    iosb.Information = 0;
    st = NtCreateFile(
        &file_handle,
        0x0001U,
        &oa,
        &iosb,
        0,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        0,
        0,
        0
    );
    check("NtCreateFile(hello_win for flush/cancel) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateFile(hello_win for flush/cancel) returns handle", file_handle != 0);
    if (file_handle) {
        iosb.Status = 0;
        iosb.Information = 0;
        st = raw_nt_flush_buffers_file(file_handle, &iosb);
        check("NtFlushBuffersFile(file) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
        check("NtFlushBuffersFile(file) IOSB status is STATUS_SUCCESS",
              (NTSTATUS)iosb.Status == STATUS_SUCCESS);

        iosb.Status = 0;
        iosb.Information = 0;
        st = raw_nt_cancel_io_file(file_handle, &iosb);
        check("NtCancelIoFile(file) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
        check("NtCancelIoFile(file) IOSB status is STATUS_SUCCESS",
              (NTSTATUS)iosb.Status == STATUS_SUCCESS);

        st = NtClose(file_handle);
        check("NtClose(file handle) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
        file_handle = 0;
    }

    iosb.Status = 0;
    iosb.Information = 0;
    st = raw_nt_flush_buffers_file(STDOUT_HANDLE, &iosb);
    check("NtFlushBuffersFile(stdout) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    iosb.Status = 0;
    iosb.Information = 0;
    st = raw_nt_flush_buffers_file((HANDLE)(uint64_t)0x7fffffffULL, &iosb);
    check("NtFlushBuffersFile(invalid) returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);
    check("NtFlushBuffersFile(invalid) IOSB status is STATUS_INVALID_HANDLE",
          (NTSTATUS)iosb.Status == STATUS_INVALID_HANDLE);

    iosb.Status = 0;
    iosb.Information = 0;
    st = raw_nt_cancel_io_file((HANDLE)(uint64_t)0x7fffffffULL, &iosb);
    check("NtCancelIoFile(invalid) returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);
    check("NtCancelIoFile(invalid) IOSB status is STATUS_INVALID_HANDLE",
          (NTSTATUS)iosb.Status == STATUS_INVALID_HANDLE);

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

    init_unicode(&us, path_buf, "\\Device\\WinEmuHost");
    init_oa(&oa, &us);
    iosb.Status = 0;
    iosb.Information = 0;
    st = NtCreateFile(
        &dev,
        0x0001U,
        &oa,
        &iosb,
        0,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        0,
        0,
        0
    );
    check("NtCreateFile(\\\\Device\\\\WinEmuHost) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateFile(\\\\Device\\\\WinEmuHost) returns valid handle", dev != 0);
    if (st == STATUS_SUCCESS && dev != 0) {
        while (host_open_path[host_open_path_len]) {
            host_open_path_len++;
        }

        iosb.Status = 0;
        iosb.Information = 0;
        ping = 0;
        st = NtDeviceIoControlFile(
            dev, 0, 0, 0, &iosb, IOCTL_WINEMU_HOST_PING, 0, 0, &ping, (ULONG)sizeof(ping)
        );
        check("NtDeviceIoControlFile(WinEmuHost ping) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
        check("NtDeviceIoControlFile(WinEmuHost ping) IOSB status is STATUS_SUCCESS",
              (NTSTATUS)iosb.Status == STATUS_SUCCESS);
        check("NtDeviceIoControlFile(WinEmuHost ping) output magic matches", ping == WINEMU_PING_MAGIC);
        check("NtDeviceIoControlFile(WinEmuHost ping) reports 4 bytes",
              (ULONG)iosb.Information == (ULONG)sizeof(ping));

        hreq.version = 1;
        hreq._reserved = 0;
        hreq.opcode = HOSTCALL_OP_OPEN;
        hreq.flags = 0;
        hreq.arg0 = (uint64_t)(uintptr_t)host_open_path;
        hreq.arg1 = (uint64_t)host_open_path_len;
        hreq.arg2 = 0;
        hreq.arg3 = 0;
        hreq.user_tag = 0;
        hresp.host_result = 0;
        hresp.aux = 0;
        hresp.request_id = 0;
        iosb.Status = 0;
        iosb.Information = 0;
        st = NtDeviceIoControlFile(
            dev, 0, 0, 0, &iosb,
            IOCTL_WINEMU_HOSTCALL_SYNC,
            &hreq, (ULONG)sizeof(hreq),
            &hresp, (ULONG)sizeof(hresp)
        );
        check("NtDeviceIoControlFile(hostcall sync open) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
        check("NtDeviceIoControlFile(hostcall sync open) IOSB status is STATUS_SUCCESS",
              (NTSTATUS)iosb.Status == STATUS_SUCCESS);
        check("NtDeviceIoControlFile(hostcall sync open) returns response size",
              (ULONG)iosb.Information == (ULONG)sizeof(hresp));
        check("NtDeviceIoControlFile(hostcall sync open) host_result is HC_OK or HC_IO_ERROR",
              hresp.host_result == HOSTCALL_HC_OK || hresp.host_result == HOSTCALL_HC_IO_ERROR);
        check("NtDeviceIoControlFile(hostcall sync open) returns host fd when HC_OK",
              hresp.host_result != HOSTCALL_HC_OK || hresp.aux != 0);
        host_fd = hresp.aux;

        if (host_fd != 0) {
            hreq.opcode = HOSTCALL_OP_CLOSE;
            hreq.flags = 0;
            hreq.arg0 = host_fd;
            hreq.arg1 = 0;
            hreq.arg2 = 0;
            hreq.arg3 = 0;
            hresp.host_result = 0;
            hresp.aux = 0;
            hresp.request_id = 0;
            iosb.Status = 0;
            iosb.Information = 0;
            st = NtDeviceIoControlFile(
                dev, 0, 0, 0, &iosb,
                IOCTL_WINEMU_HOSTCALL_SYNC,
                &hreq, (ULONG)sizeof(hreq),
                &hresp, (ULONG)sizeof(hresp)
            );
            check("NtDeviceIoControlFile(hostcall sync close) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
            check("NtDeviceIoControlFile(hostcall sync close) host_result is HC_OK",
                  hresp.host_result == HOSTCALL_HC_OK);
        }

        st = NtCreateEvent(&io_event, EVENT_ALL_ACCESS, 0, 1, 0);
        check("NtCreateEvent(async ioctl event) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
        if (st == STATUS_SUCCESS && io_event != 0) {
            hreq.version = 1;
            hreq._reserved = 0;
            hreq.opcode = HOSTCALL_OP_OPEN;
            hreq.flags = HOSTCALL_FLAG_FORCE_ASYNC;
            hreq.arg0 = (uint64_t)(uintptr_t)host_open_path;
            hreq.arg1 = (uint64_t)host_open_path_len;
            hreq.arg2 = 0;
            hreq.arg3 = 0;
            hreq.user_tag = 0x11223344u;
            hresp.host_result = 0;
            hresp.aux = 0;
            hresp.request_id = 0;
            iosb.Status = 0;
            iosb.Information = 0;
            st = NtDeviceIoControlFile(
                dev, io_event, 0, 0, &iosb,
                IOCTL_WINEMU_HOSTCALL_SYNC,
                &hreq, (ULONG)sizeof(hreq),
                &hresp, (ULONG)sizeof(hresp)
            );
            check("NtDeviceIoControlFile(hostcall async open) returns STATUS_PENDING", st == STATUS_PENDING);
            if (st == STATUS_PENDING) {
                st = NtWaitForSingleObject(io_event, 0, 0);
                check("NtWaitForSingleObject(async ioctl event) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
                check("NtDeviceIoControlFile(hostcall async open) IOSB status is completed",
                      (NTSTATUS)iosb.Status != STATUS_PENDING);
                check("NtDeviceIoControlFile(hostcall async open) returns response size when IOSB success",
                      (NTSTATUS)iosb.Status != STATUS_SUCCESS || (ULONG)iosb.Information == (ULONG)sizeof(hresp));
                check("NtDeviceIoControlFile(hostcall async open) completion request_id is non-zero",
                      hresp.request_id != 0);
                check("NtDeviceIoControlFile(hostcall async open) host_result is HC_OK or HC_IO_ERROR",
                      hresp.host_result == HOSTCALL_HC_OK || hresp.host_result == HOSTCALL_HC_IO_ERROR);
                check("NtDeviceIoControlFile(hostcall async open) returns host fd when HC_OK",
                      hresp.host_result != HOSTCALL_HC_OK || hresp.aux != 0);

                host_fd = hresp.aux;
                if (host_fd != 0) {
                    hreq.opcode = HOSTCALL_OP_CLOSE;
                    hreq.flags = 0;
                    hreq.arg0 = host_fd;
                    hreq.arg1 = 0;
                    hreq.arg2 = 0;
                    hreq.arg3 = 0;
                    hresp.host_result = 0;
                    hresp.aux = 0;
                    hresp.request_id = 0;
                    iosb.Status = 0;
                    iosb.Information = 0;
                    st = NtDeviceIoControlFile(
                        dev, 0, 0, 0, &iosb,
                        IOCTL_WINEMU_HOSTCALL_SYNC,
                        &hreq, (ULONG)sizeof(hreq),
                        &hresp, (ULONG)sizeof(hresp)
                    );
                    check("NtDeviceIoControlFile(hostcall async-close cleanup) returns STATUS_SUCCESS",
                          st == STATUS_SUCCESS);
                    check("NtDeviceIoControlFile(hostcall async-close cleanup) host_result is HC_OK",
                          hresp.host_result == HOSTCALL_HC_OK);
                }
            }

            st = NtClose(io_event);
            check("NtClose(async ioctl event) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
        }

        st = NtClose(dev);
        check("NtClose(WinEmuHost handle) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    }

    write_str("syscall_file_control_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    terminate_current_process(g_fail == 0 ? 0 : 1);
}
