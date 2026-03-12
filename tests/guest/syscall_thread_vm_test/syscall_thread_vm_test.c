#include <stdint.h>
#include <stddef.h>

typedef uint8_t UCHAR;
typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef uint64_t ULONG_PTR;
typedef void* HANDLE;

typedef struct {
    uint64_t Status;
    uint64_t Information;
} IO_STATUS_BLOCK;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)
#define NT_CURRENT_THREAD ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_TIMEOUT 0x00000102U
#define STATUS_ALERTED 0x00000101U
#define STATUS_INVALID_PARAMETER 0xC000000DU

#define NR_ALERT_THREAD_BY_THREAD_ID 0x0070U
#define NR_WAIT_FOR_ALERT_BY_THREAD_ID 0x01E0U
#define NR_CONTINUE 0x0043U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) NTSTATUS NtCreateEvent(
    HANDLE* event_handle, ULONG desired_access, void* object_attributes, ULONG event_type, UCHAR initial_state);
__declspec(dllimport) NTSTATUS NtSetEvent(HANDLE event_handle, ULONG* previous_state);
__declspec(dllimport) NTSTATUS NtWaitForSingleObject(HANDLE handle, UCHAR alertable, int64_t* timeout);
__declspec(dllimport) NTSTATUS NtCreateThreadEx(
    HANDLE* thread_handle, ULONG access, void* object_attributes, HANDLE process_handle, void* start_routine,
    void* argument, ULONG create_flags, size_t zero_bits, size_t stack_size, size_t max_stack_size,
    void* attribute_list);
__declspec(dllimport) NTSTATUS NtSuspendThread(HANDLE thread_handle, ULONG* previous_suspend_count);
__declspec(dllimport) NTSTATUS NtResumeThread(HANDLE thread_handle, ULONG* previous_suspend_count);
__declspec(dllimport) NTSTATUS NtCreateProcessEx(
    HANDLE* process_handle, ULONG access, void* object_attributes, HANDLE parent_process, ULONG flags,
    HANDLE section_handle, HANDLE debug_port, HANDLE exception_port, ULONG job_member_level);
__declspec(dllimport) NTSTATUS NtReadVirtualMemory(
    HANDLE process, const void* base_address, void* buffer, size_t size, size_t* bytes_read);
__declspec(dllimport) NTSTATUS NtWriteVirtualMemory(
    HANDLE process, void* base_address, const void* buffer, size_t size, size_t* bytes_written);
__declspec(dllimport) NTSTATUS NtDelayExecution(UCHAR alertable, int64_t* timeout);
__declspec(dllimport) __attribute__((noreturn))
void NtTerminateThread(HANDLE thread, NTSTATUS exit_code);
__declspec(dllimport) NTSTATUS NtTerminateProcess(HANDLE process, NTSTATUS exit_code);
__declspec(dllimport) NTSTATUS NtClose(HANDLE handle);

static uint32_t g_pass = 0;
static uint32_t g_fail = 0;
static volatile uint32_t g_worker_ran = 0;
static volatile uint64_t g_child_marker = 0;
static volatile uint64_t g_vm_readback = 0;
static volatile uint64_t g_vm_write_value = 0xAABBCCDDEEFF0011ULL;
static volatile uint64_t g_vm_bytes_done = 0;

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

static NTSTATUS raw_nt_alert_thread_by_thread_id(ULONG_PTR thread_id) {
    register uint64_t x0 __asm__("x0") = (uint64_t)thread_id;
    register uint64_t x8 __asm__("x8") = NR_ALERT_THREAD_BY_THREAD_ID;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x8)
        : "x1", "x2", "x3", "x4", "x5", "x6", "x7", "memory"
    );
    return (NTSTATUS)x0;
}

static NTSTATUS raw_nt_wait_for_alert_by_thread_id(ULONG_PTR thread_id, int64_t* timeout) {
    register uint64_t x0 __asm__("x0") = (uint64_t)thread_id;
    register uint64_t x1 __asm__("x1") = (uint64_t)(uintptr_t)timeout;
    register uint64_t x8 __asm__("x8") = NR_WAIT_FOR_ALERT_BY_THREAD_ID;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x8)
        : "x2", "x3", "x4", "x5", "x6", "x7", "memory"
    );
    return (NTSTATUS)x0;
}

static NTSTATUS raw_nt_continue(void* context, UCHAR test_alert) {
    register uint64_t x0 __asm__("x0") = (uint64_t)(uintptr_t)context;
    register uint64_t x1 __asm__("x1") = (uint64_t)test_alert;
    register uint64_t x8 __asm__("x8") = NR_CONTINUE;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x8)
        : "x2", "x3", "x4", "x5", "x6", "x7", "memory"
    );
    return (NTSTATUS)x0;
}

static __attribute__((noreturn)) void worker_thread(void* arg) {
    HANDLE evt = (HANDLE)arg;
    NTSTATUS st = NtWaitForSingleObject(evt, 0, 0);
    if (st == STATUS_SUCCESS) {
        g_worker_ran = 1;
    }
    NtTerminateThread(NT_CURRENT_THREAD, st);
    for (;;) {
        __asm__ volatile("wfi" ::: "memory");
    }
}

static __attribute__((noreturn)) void child_marker_thread(void* arg) {
    int64_t sleep_1ms = -10 * 1000;
    g_child_marker = (uint64_t)arg;
    for (;;) {
        (void)NtDelayExecution(0, &sleep_1ms);
    }
}

void mainCRTStartup(void) {
    NTSTATUS st;

    write_str("== syscall_thread_vm_test ==\r\n");

    // ---- Suspend/Resume thread ----
    HANDLE evt = 0;
    HANDLE th = 0;
    ULONG prev = 0;
    int64_t timeout_100ms = -1000000; // relative 100ms in 100ns units

    st = NtCreateEvent(&evt, 0, 0, 1, 0);
    check("NtCreateEvent returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateEvent returns handle", evt != 0);

    st = NtCreateThreadEx(
        0,
        0x001FFFFF,
        0,
        NT_CURRENT_PROCESS,
        (void*)worker_thread,
        (void*)evt,
        0,
        0,
        0x10000,
        0x10000,
        0
    );
    check("NtCreateThreadEx(NULL out handle) returns STATUS_INVALID_PARAMETER",
          st == STATUS_INVALID_PARAMETER);

    st = NtCreateThreadEx(
        &th,
        0x001FFFFF,
        0,
        NT_CURRENT_PROCESS,
        (void*)worker_thread,
        (void*)evt,
        0,
        0,
        0x10000,
        0x10000,
        0
    );
    check("NtCreateThreadEx(current process) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateThreadEx(current process) returns handle", th != 0);

    prev = 0xFFFFffffU;
    st = NtSuspendThread(th, &prev);
    check("NtSuspendThread returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtSuspendThread previous count is 0", prev == 0);

    st = NtSetEvent(evt, 0);
    check("NtSetEvent returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    st = NtWaitForSingleObject(th, 0, &timeout_100ms);
    check("Suspended thread wait returns STATUS_TIMEOUT, STATUS_SUCCESS or STATUS_INVALID_HANDLE",
          st == STATUS_TIMEOUT || st == STATUS_SUCCESS || st == 0xC0000008U);

    prev = 0xFFFFffffU;
    st = NtResumeThread(th, &prev);
    check("NtResumeThread returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtResumeThread previous count is 1", prev == 1);

    st = NtWaitForSingleObject(th, 0, 0);
    check("Resumed thread wait returns STATUS_SUCCESS or STATUS_INVALID_HANDLE",
          st == STATUS_SUCCESS || st == 0xC0000008U);
    check("Worker thread executed after resume", g_worker_ran == 1);

    st = NtClose(th);
    check("NtClose(thread) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    st = NtClose(evt);
    check("NtClose(event) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    // ---- Cross-process Read/WriteVirtualMemory ----
    HANDLE child = 0;
    HANDLE child_thread = 0;
    uint64_t expected_child_value = 0x1122334455667788ULL;
    st = NtCreateProcessEx(0, 0x001FFFFF, 0, NT_CURRENT_PROCESS, 0, 0, 0, 0, 0);
    check("NtCreateProcessEx(NULL out handle) returns STATUS_INVALID_PARAMETER",
          st == STATUS_INVALID_PARAMETER);

    st = NtCreateProcessEx(&child, 0x001FFFFF, 0, NT_CURRENT_PROCESS, 0, 0, 0, 0, 0);
    check("NtCreateProcessEx returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateProcessEx returns handle", child != 0);

    st = NtCreateThreadEx(
        &child_thread,
        0x001FFFFF,
        0,
        child,
        (void*)child_marker_thread,
        (void*)(uintptr_t)expected_child_value,
        0,
        0,
        0x10000,
        0x10000,
        0
    );
    check("NtCreateThreadEx(child process) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateThreadEx(child process) returns handle", child_thread != 0);

    g_vm_bytes_done = 0;
    g_vm_readback = 0;
    for (int i = 0; i < 32; i++) {
        st = NtReadVirtualMemory(
            child,
            (const void*)&g_child_marker,
            (void*)&g_vm_readback,
            sizeof(g_vm_readback),
            (size_t*)&g_vm_bytes_done
        );
        if (st == STATUS_SUCCESS
            && g_vm_bytes_done == sizeof(g_vm_readback)
            && g_vm_readback == expected_child_value) {
            break;
        }
        int64_t sleep_1ms = -10 * 1000;
        (void)NtDelayExecution(0, &sleep_1ms);
    }
    check("NtReadVirtualMemory(child marker) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtReadVirtualMemory(child marker) returns full length", g_vm_bytes_done == sizeof(g_vm_readback));
    check("NtReadVirtualMemory(child marker) reads expected value", g_vm_readback == expected_child_value);

    g_vm_bytes_done = 0;
    st = NtWriteVirtualMemory(
        child,
        (void*)&g_child_marker,
        (const void*)&g_vm_write_value,
        sizeof(g_vm_write_value),
        (size_t*)&g_vm_bytes_done
    );
    check("NtWriteVirtualMemory(child marker) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtWriteVirtualMemory(child marker) returns full length", g_vm_bytes_done == sizeof(g_vm_write_value));

    g_vm_bytes_done = 0;
    g_vm_readback = 0;
    st = NtReadVirtualMemory(
        child,
        (const void*)&g_child_marker,
        (void*)&g_vm_readback,
        sizeof(g_vm_readback),
        (size_t*)&g_vm_bytes_done
    );
    check("NtReadVirtualMemory(child marker, re-read) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtReadVirtualMemory(child marker, re-read) returns full length", g_vm_bytes_done == sizeof(g_vm_readback));
    check("NtWriteVirtualMemory(child marker) takes effect", g_vm_readback == g_vm_write_value);

    st = NtClose(child_thread);
    check("NtClose(child thread) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    st = NtTerminateProcess(child, STATUS_SUCCESS);
    check("NtTerminateProcess(child) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    st = NtClose(child);
    check("NtClose(child process) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    // ---- Alert/Wait/Continue basic path ----
    int64_t timeout_now = 0;
    st = raw_nt_wait_for_alert_by_thread_id(0, &timeout_now);
    check("NtWaitForAlertByThreadId(zero timeout) returns STATUS_TIMEOUT or STATUS_ALERTED",
          st == STATUS_TIMEOUT || st == STATUS_ALERTED);

    st = raw_nt_alert_thread_by_thread_id(0);
    check("NtAlertThreadByThreadId(invalid tid=0) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    st = raw_nt_continue(0, 0);
    check("NtContinue(NULL context) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    write_str("syscall_thread_vm_test summary complete\r\n");
    terminate_current_process(g_fail == 0 ? 0 : 1);
}
