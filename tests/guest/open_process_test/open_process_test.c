#include <stdint.h>
#include <stddef.h>

typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef uint64_t ULONG_PTR;
typedef int64_t LARGE_INTEGER;
typedef void* HANDLE;

typedef struct {
    uint64_t Status;
    uint64_t Information;
} IO_STATUS_BLOCK;

typedef struct {
    int32_t ExitStatus;
    uint32_t _pad0;
    void* PebBaseAddress;
    uint64_t AffinityMask;
    int32_t BasePriority;
    uint32_t _pad1;
    uint64_t UniqueProcessId;
    uint64_t InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_INVALID_PARAMETER 0xC000000DU
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004U
#define STATUS_INVALID_HANDLE 0xC0000008U
#define STATUS_ACCESS_DENIED 0xC0000022U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len,
    uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) NTSTATUS NtQueryInformationProcess(
    HANDLE process, ULONG info_class, void* buf, ULONG len, ULONG* ret_len);
__declspec(dllimport) NTSTATUS NtOpenProcess(
    HANDLE* process_handle, ULONG desired_access, void* object_attributes, CLIENT_ID* client_id);
__declspec(dllimport) NTSTATUS NtQueryObject(
    HANDLE handle, ULONG object_info_class, void* object_info, ULONG object_info_len, ULONG* ret_len);
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

void mainCRTStartup(void) {
    NTSTATUS st;
    PROCESS_BASIC_INFORMATION self = {0};
    PROCESS_BASIC_INFORMATION opened = {0};
    ULONG ret_len = 0;
    HANDLE opened_handle = 0;
    CLIENT_ID cid = {0};
    uint8_t object_basic[56] = {0};
    uint8_t short_object_basic[8] = {0};

    write_str("== open_process_test ==\r\n");

    st = NtQueryInformationProcess(NT_CURRENT_PROCESS, 0, &self, sizeof(self), &ret_len);
    check("NtQueryInformationProcess(current) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("Current PID is non-zero", self.UniqueProcessId != 0);

    cid.UniqueProcess = (HANDLE)(ULONG_PTR)self.UniqueProcessId;
    cid.UniqueThread = 0;
    st = NtOpenProcess(&opened_handle, 0x001FFFFF, 0, &cid);
    check("NtOpenProcess(valid pid) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("Opened process handle is non-zero", opened_handle != 0);

    st = NtQueryInformationProcess(opened_handle, 0, &opened, sizeof(opened), &ret_len);
    check("NtQueryInformationProcess(opened handle) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check(
        "Opened process PID matches current PID",
        opened.UniqueProcessId == self.UniqueProcessId
    );

    st = NtClose(opened_handle);
    check("NtClose(opened process handle) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    ret_len = 0;
    st = NtQueryObject(NT_CURRENT_PROCESS, 0, object_basic, sizeof(object_basic), &ret_len);
    check("NtQueryObject(process handle, basic) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQueryObject basic return length is 56", ret_len == sizeof(object_basic));

    ret_len = 0;
    st = NtQueryObject(NT_CURRENT_PROCESS, 0, short_object_basic, sizeof(short_object_basic), &ret_len);
    check("NtQueryObject short buffer returns STATUS_INFO_LENGTH_MISMATCH", st == STATUS_INFO_LENGTH_MISMATCH);
    check("NtQueryObject short buffer reports required size", ret_len == sizeof(object_basic));

    ret_len = 0;
    st = NtQueryObject((HANDLE)(ULONG_PTR)0x7fffffffULL, 0, object_basic, sizeof(object_basic), &ret_len);
    check("NtQueryObject(invalid handle) returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);

    cid.UniqueProcess = (HANDLE)(ULONG_PTR)0x7fffffffULL;
    cid.UniqueThread = 0;
    opened_handle = 0;
    st = NtOpenProcess(&opened_handle, 0x001FFFFF, 0, &cid);
    check("NtOpenProcess(nonexistent pid) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    st = NtOpenProcess(0, 0x001FFFFF, 0, &cid);
    check("NtOpenProcess(NULL out handle) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    cid.UniqueProcess = (HANDLE)(ULONG_PTR)self.UniqueProcessId;
    cid.UniqueThread = 0;
    opened_handle = 0;
    st = NtOpenProcess(&opened_handle, 0x80000000U, 0, &cid);
    check("NtOpenProcess(invalid desired access) returns STATUS_ACCESS_DENIED", st == STATUS_ACCESS_DENIED);
    check("NtOpenProcess(invalid desired access) does not return handle", opened_handle == 0);

    write_str("open_process_test summary complete\r\n");
    terminate_current_process(g_fail == 0 ? 0 : 1);
}
