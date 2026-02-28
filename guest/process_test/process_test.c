#include <stdint.h>
#include <stddef.h>

typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef uint64_t ULONG_PTR;
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

#define STATUS_SUCCESS 0x00000000U
#define STATUS_TIMEOUT 0x00000102U
#define STATUS_INVALID_HANDLE 0xC0000008U

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)
#define NT_CURRENT_THREAD ((HANDLE)(uint64_t)-1)

#define NR_WAIT_SINGLE 0x0004
#define NR_WRITE_FILE 0x0008
#define NR_CLOSE 0x000F
#define NR_QUERY_INFORMATION_PROCESS 0x0019
#define NR_TERMINATE_PROCESS 0x002C
#define NR_DUPLICATE_OBJECT 0x003C
#define NR_YIELD_EXECUTION 0x0046
#define NR_CREATE_PROCESS_EX 0x004B
#define NR_TERMINATE_THREAD 0x0053
#define NR_CREATE_THREAD_EX 0x00C1

static inline uint64_t svc8(uint64_t nr,
    uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
    register uint64_t x8 asm("x8") = nr;
    register uint64_t x0 asm("x0") = a0;
    register uint64_t x1 asm("x1") = a1;
    register uint64_t x2 asm("x2") = a2;
    register uint64_t x3 asm("x3") = a3;
    register uint64_t x4 asm("x4") = a4;
    register uint64_t x5 asm("x5") = a5;
    register uint64_t x6 asm("x6") = a6;
    register uint64_t x7 asm("x7") = a7;
    asm volatile("svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x7)
        : "memory");
    return x0;
}

static inline uint64_t svc9(uint64_t nr,
    uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
    uint64_t s0)
{
    register uint64_t x8 asm("x8") = nr;
    register uint64_t x0 asm("x0") = a0;
    register uint64_t x1 asm("x1") = a1;
    register uint64_t x2 asm("x2") = a2;
    register uint64_t x3 asm("x3") = a3;
    register uint64_t x4 asm("x4") = a4;
    register uint64_t x5 asm("x5") = a5;
    register uint64_t x6 asm("x6") = a6;
    register uint64_t x7 asm("x7") = a7;
    asm volatile(
        "str %[stack0], [sp, #-16]!\n"
        "svc #0\n"
        "add sp, sp, #16\n"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x7),
          [stack0] "r"(s0)
        : "memory");
    return x0;
}

static inline uint64_t svc11(uint64_t nr,
    uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
    uint64_t s0, uint64_t s1, uint64_t s2)
{
    register uint64_t x8 asm("x8") = nr;
    register uint64_t x0 asm("x0") = a0;
    register uint64_t x1 asm("x1") = a1;
    register uint64_t x2 asm("x2") = a2;
    register uint64_t x3 asm("x3") = a3;
    register uint64_t x4 asm("x4") = a4;
    register uint64_t x5 asm("x5") = a5;
    register uint64_t x6 asm("x6") = a6;
    register uint64_t x7 asm("x7") = a7;
    asm volatile(
        "stp %[stack1], %[stack2], [sp, #-16]!\n"
        "str %[stack0], [sp, #-16]!\n"
        "svc #0\n"
        "add sp, sp, #32\n"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x7),
          [stack0] "r"(s0), [stack1] "r"(s1), [stack2] "r"(s2)
        : "memory");
    return x0;
}

static inline NTSTATUS nt_write_file(HANDLE file, IO_STATUS_BLOCK* iosb, const void* buf, ULONG len) {
    return (NTSTATUS)svc9(
        NR_WRITE_FILE,
        (uint64_t)file,
        0,
        0,
        0,
        (uint64_t)iosb,
        (uint64_t)buf,
        len,
        0,
        0
    );
}

static inline NTSTATUS nt_query_information_process(
    HANDLE process, ULONG info_class, void* buf, ULONG len, ULONG* ret_len)
{
    return (NTSTATUS)svc8(
        NR_QUERY_INFORMATION_PROCESS,
        (uint64_t)process,
        (uint64_t)info_class,
        (uint64_t)buf,
        (uint64_t)len,
        (uint64_t)ret_len,
        0,
        0,
        0
    );
}

static inline NTSTATUS nt_create_process_ex(
    HANDLE* process_handle,
    ULONG access,
    HANDLE parent_process,
    ULONG flags,
    HANDLE section_handle)
{
    return (NTSTATUS)svc9(
        NR_CREATE_PROCESS_EX,
        (uint64_t)process_handle,
        (uint64_t)access,
        0,
        (uint64_t)parent_process,
        (uint64_t)flags,
        (uint64_t)section_handle,
        0,
        0,
        0
    );
}

static inline NTSTATUS nt_duplicate_object(HANDLE source_process, HANDLE source_handle,
    HANDLE target_process, HANDLE* target_handle)
{
    return (NTSTATUS)svc8(
        NR_DUPLICATE_OBJECT,
        (uint64_t)source_process,
        (uint64_t)source_handle,
        (uint64_t)target_process,
        (uint64_t)target_handle,
        0,
        0,
        0,
        0
    );
}

static inline NTSTATUS nt_create_thread_ex(
    HANDLE* thread_handle,
    HANDLE process_handle,
    void* start_routine,
    void* argument)
{
    return (NTSTATUS)svc11(
        NR_CREATE_THREAD_EX,
        (uint64_t)thread_handle,
        0x001FFFFF,
        0,
        (uint64_t)process_handle,
        (uint64_t)start_routine,
        (uint64_t)argument,
        0,
        0,
        0x10000,
        0x10000,
        0
    );
}

static inline NTSTATUS nt_wait_single_ex(HANDLE handle, int64_t* timeout) {
    return (NTSTATUS)svc8(
        NR_WAIT_SINGLE,
        (uint64_t)handle,
        0,
        (uint64_t)timeout,
        0,
        0,
        0,
        0,
        0
    );
}

static inline NTSTATUS nt_wait_single(HANDLE handle) {
    return nt_wait_single_ex(handle, NULL);
}

static inline NTSTATUS nt_terminate_process(HANDLE process, NTSTATUS code) {
    return (NTSTATUS)svc8(NR_TERMINATE_PROCESS, (uint64_t)process, (uint64_t)code, 0, 0, 0, 0, 0, 0);
}

static inline NTSTATUS nt_terminate_thread(HANDLE thread, NTSTATUS code) {
    return (NTSTATUS)svc8(NR_TERMINATE_THREAD, (uint64_t)thread, (uint64_t)code, 0, 0, 0, 0, 0, 0);
}

static inline NTSTATUS nt_close(HANDLE handle) {
    return (NTSTATUS)svc8(NR_CLOSE, (uint64_t)handle, 0, 0, 0, 0, 0, 0, 0);
}

static inline void nt_yield(void) {
    (void)svc8(NR_YIELD_EXECUTION, 0, 0, 0, 0, 0, 0, 0, 0);
}

static volatile uint64_t g_child_thread_pid = 0;
static uint32_t g_pass = 0;
static uint32_t g_fail = 0;

static void write_str(const char* s) {
    ULONG len = 0;
    IO_STATUS_BLOCK iosb = {0};
    while (s[len]) {
        len++;
    }
    (void)nt_write_file(STDOUT_HANDLE, &iosb, s, len);
}

static void write_u64_hex(uint64_t v) {
    char buf[19];
    const char* hex = "0123456789abcdef";
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; i++) {
        buf[2 + i] = hex[(v >> ((15 - i) * 4)) & 0xF];
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

static __attribute__((noreturn)) void spin_forever(void) {
    for (;;) {
        asm volatile("wfi" ::: "memory");
    }
}

static __attribute__((noreturn)) void fail_fast(const char* name, NTSTATUS st) {
    write_str("[FAIL] ");
    write_str(name);
    write_str(" st=");
    write_u64_hex((uint64_t)st);
    write_str("\r\n");
    (void)nt_terminate_process(NT_CURRENT_PROCESS, 1);
    spin_forever();
}

static __attribute__((noreturn)) void child_thread_entry(void* arg) {
    (void)arg;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ret_len = 0;
    NTSTATUS st = nt_query_information_process(
        NT_CURRENT_PROCESS,
        0,
        &pbi,
        sizeof(pbi),
        &ret_len
    );
    if (st == STATUS_SUCCESS) {
        g_child_thread_pid = pbi.UniqueProcessId;
    }
    (void)nt_terminate_thread(NT_CURRENT_THREAD, st);
    spin_forever();
}

void mainCRTStartup(void) {
    write_str("== process_test ==\r\n");

    PROCESS_BASIC_INFORMATION self_pbi;
    ULONG self_ret_len = 0;
    NTSTATUS st = nt_query_information_process(
        NT_CURRENT_PROCESS,
        0,
        &self_pbi,
        sizeof(self_pbi),
        &self_ret_len
    );
    if (st != STATUS_SUCCESS) {
        fail_fast("NtQueryInformationProcess(self)", st);
    }
    check("Query self PBI success", st == STATUS_SUCCESS);
    check("Self PID non-zero", self_pbi.UniqueProcessId != 0);

    HANDLE child = NULL;
    st = nt_create_process_ex(
        &child,
        0x001FFFFF,
        NT_CURRENT_PROCESS,
        0,
        NULL
    );
    if (st != STATUS_SUCCESS || child == NULL) {
        fail_fast("NtCreateProcessEx", st);
    }
    check("NtCreateProcessEx success", st == STATUS_SUCCESS);
    check("Child handle valid", child != NULL);

    PROCESS_BASIC_INFORMATION child_pbi;
    ULONG child_ret_len = 0;
    st = nt_query_information_process(child, 0, &child_pbi, sizeof(child_pbi), &child_ret_len);
    if (st != STATUS_SUCCESS) {
        fail_fast("NtQueryInformationProcess(child)", st);
    }
    check("Query child PBI success", st == STATUS_SUCCESS);
    check("Child PID differs from self", child_pbi.UniqueProcessId != self_pbi.UniqueProcessId);
    check(
        "Child parent PID matches self",
        child_pbi.InheritedFromUniqueProcessId == self_pbi.UniqueProcessId
    );

    int64_t timeout_now = 0;
    st = nt_wait_single_ex(child, &timeout_now);
    check("Wait child process immediate timeout before terminate", st == STATUS_TIMEOUT);

    HANDLE dup_child = NULL;
    st = nt_duplicate_object(
        NT_CURRENT_PROCESS,
        child,
        NT_CURRENT_PROCESS,
        &dup_child
    );
    check("NtDuplicateObject(child) success", st == STATUS_SUCCESS);
    check("Duplicated child handle valid", dup_child != NULL);

    HANDLE dup_from_child = NULL;
    st = nt_duplicate_object(
        child,
        child,
        NT_CURRENT_PROCESS,
        &dup_from_child
    );
    check("DuplicateObject validates source-process handle table", st == STATUS_INVALID_HANDLE);

    HANDLE child_thread = NULL;
    st = nt_create_thread_ex(
        &child_thread,
        child,
        (void*)child_thread_entry,
        NULL
    );
    if (st != STATUS_SUCCESS || child_thread == NULL) {
        fail_fast("NtCreateThreadEx(child)", st);
    }
    check("NtCreateThreadEx(child) success", st == STATUS_SUCCESS);

    st = nt_wait_single(child_thread);
    check("Wait child thread success", st == STATUS_SUCCESS);
    (void)nt_close(child_thread);

    for (int i = 0; i < 256 && g_child_thread_pid == 0; i++) {
        nt_yield();
    }
    check(
        "Child thread observed child PID",
        g_child_thread_pid == child_pbi.UniqueProcessId
    );

    st = nt_terminate_process(child, 0x55667788U);
    check("NtTerminateProcess(child) success", st == STATUS_SUCCESS);
    st = nt_wait_single(child);
    check("Wait terminated child process success", st == STATUS_SUCCESS);

    PROCESS_BASIC_INFORMATION child_after;
    ULONG child_after_ret_len = 0;
    st = nt_query_information_process(child, 0, &child_after, sizeof(child_after), &child_after_ret_len);
    check("Query terminated child success", st == STATUS_SUCCESS);
    check("Child exit status recorded", (uint32_t)child_after.ExitStatus == 0x55667788U);

    (void)nt_close(child);
    if (dup_child) {
        (void)nt_close(dup_child);
    }

    HANDLE invalid_child = NULL;
    st = nt_create_process_ex(
        &invalid_child,
        0x001FFFFF,
        (HANDLE)(uint64_t)0x12345678ULL,
        0,
        NULL
    );
    check("Invalid parent returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);

    write_str("process_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    (void)nt_terminate_process(NT_CURRENT_PROCESS, g_fail == 0 ? 0 : 1);
    spin_forever();
}
