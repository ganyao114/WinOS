#include <stdint.h>

typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef void* HANDLE;

typedef struct {
    uint64_t Status;
    uint64_t Information;
} IO_STATUS_BLOCK;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_ACCESS_DENIED 0xC0000022U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) NTSTATUS NtCreateEvent(
    HANDLE* event_handle, ULONG desired_access, void* object_attributes, ULONG event_type, uint8_t initial_state);
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

void mainCRTStartup(void) {
    NTSTATUS st;
    HANDLE h = 0;

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

    write_str("syscall_sync_test summary complete\r\n");
    terminate_current_process(g_fail == 0 ? 0 : 1);
}
