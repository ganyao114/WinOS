#include <stdint.h>
#include <stddef.h>

typedef uint8_t BOOLEAN;
typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef uint64_t ULONG_PTR;
typedef int64_t LARGE_INTEGER;
typedef void *HANDLE;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004U
#define STATUS_INVALID_PARAMETER 0xC000000DU

#define SYSTEM_BASIC_INFORMATION_CLASS 0U
#define SYSTEM_TIME_OF_DAY_INFORMATION_CLASS 3U

#define NR_WRITE_FILE 0x0008
#define NR_TERMINATE_PROCESS 0x002C
#define NR_QUERY_PERFORMANCE_COUNTER 0x0031
#define NR_QUERY_SYSTEM_INFORMATION 0x0036
#define NR_DELAY_EXECUTION 0x0034
#define NR_QUERY_SYSTEM_TIME 0x005A

typedef struct {
    uint64_t Status;
    uint64_t Information;
} IO_STATUS_BLOCK;

typedef struct {
    uint32_t Reserved;
    uint32_t TimerResolution100ns;
    uint32_t PageSize;
    uint32_t NumberOfPhysicalPages;
    uint32_t LowestPhysicalPageNumber;
    uint32_t HighestPhysicalPageNumber;
    uint32_t AllocationGranularity;
    uint64_t MinimumUserModeAddress;
    uint64_t MaximumUserModeAddress;
    uint64_t ActiveProcessorsAffinityMask;
    uint8_t NumberOfProcessors;
    uint8_t Pad[3];
} SYSTEM_BASIC_INFORMATION;

typedef struct {
    int64_t BootTime;
    int64_t CurrentTime;
    int64_t TimeZoneBias;
    uint32_t TimeZoneId;
    uint32_t Reserved;
    uint64_t BootTimeBias;
    uint64_t SleepTimeBias;
} SYSTEM_TIME_OF_DAY_INFORMATION;

static inline uint64_t svc8(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                            uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) {
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

static inline uint64_t svc10(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                             uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                             uint64_t s0, uint64_t s1) {
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
        "stp %[stack0], %[stack1], [sp, #-16]!\n"
        "svc #0\n"
        "add sp, sp, #16\n"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x7),
          [stack0] "r"(s0), [stack1] "r"(s1)
        : "memory");
    return x0;
}

static inline NTSTATUS nt_write_file(HANDLE file, IO_STATUS_BLOCK *iosb, const void *buf, ULONG len) {
    return (NTSTATUS)svc10(
        NR_WRITE_FILE,
        (uint64_t)file,
        0,
        0,
        0,
        (uint64_t)iosb,
        (uint64_t)buf,
        len,
        0,
        0,
        0
    );
}

static inline NTSTATUS nt_terminate_process(HANDLE process, NTSTATUS code) {
    return (NTSTATUS)svc8(NR_TERMINATE_PROCESS, (uint64_t)process, (uint64_t)code, 0, 0, 0, 0, 0, 0);
}

static inline NTSTATUS nt_query_system_information(
    ULONG info_class, void *buf, ULONG len, ULONG *ret_len) {
    return (NTSTATUS)svc8(
        NR_QUERY_SYSTEM_INFORMATION,
        (uint64_t)info_class,
        (uint64_t)buf,
        (uint64_t)len,
        (uint64_t)ret_len,
        0,
        0,
        0,
        0
    );
}

static inline NTSTATUS nt_query_system_time(LARGE_INTEGER *time) {
    return (NTSTATUS)svc8(NR_QUERY_SYSTEM_TIME, (uint64_t)time, 0, 0, 0, 0, 0, 0, 0);
}

static inline NTSTATUS nt_query_performance_counter(LARGE_INTEGER *counter, LARGE_INTEGER *frequency) {
    return (NTSTATUS)svc8(
        NR_QUERY_PERFORMANCE_COUNTER,
        (uint64_t)counter,
        (uint64_t)frequency,
        0,
        0,
        0,
        0,
        0,
        0
    );
}

static inline NTSTATUS nt_delay_execution(BOOLEAN alertable, const LARGE_INTEGER *timeout) {
    return (NTSTATUS)svc8(
        NR_DELAY_EXECUTION,
        (uint64_t)alertable,
        (uint64_t)timeout,
        0,
        0,
        0,
        0,
        0,
        0
    );
}

static uint32_t g_pass = 0;
static uint32_t g_fail = 0;

static void write_str(const char *s) {
    IO_STATUS_BLOCK iosb = {0};
    ULONG len = 0;
    while (s[len]) {
        len++;
    }
    (void)nt_write_file(STDOUT_HANDLE, &iosb, s, len);
}

static void write_u64_hex(uint64_t value) {
    char buf[19];
    const char *hex = "0123456789abcdef";
    int i;
    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 16; i++) {
        buf[2 + i] = hex[(value >> ((15 - i) * 4)) & 0xF];
    }
    buf[18] = '\0';
    write_str(buf);
}

static void check(const char *name, int ok) {
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
    (void)nt_terminate_process(NT_CURRENT_PROCESS, code);
    for (;;) {
        __asm__ volatile("wfi" ::: "memory");
    }
}

void mainCRTStartup(void) {
    LARGE_INTEGER system_time = 0;
    LARGE_INTEGER perf_counter0 = 0;
    LARGE_INTEGER perf_counter1 = 0;
    LARGE_INTEGER perf_frequency = 0;
    LARGE_INTEGER delay_10ms = -100000; /* relative 10ms, 100ns unit */
    ULONG ret_len = 0;
    NTSTATUS st;

    SYSTEM_BASIC_INFORMATION sbi;
    SYSTEM_TIME_OF_DAY_INFORMATION tod;
    uint8_t short_buf[8];

    write_str("== syscall_sysinfo_test ==\r\n");

    st = nt_query_system_time(&system_time);
    check("NtQuerySystemTime returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQuerySystemTime writes non-zero time", system_time > 0);

    st = nt_query_system_time((LARGE_INTEGER *)0);
    check("NtQuerySystemTime(NULL) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    st = nt_query_performance_counter(&perf_counter0, &perf_frequency);
    check("NtQueryPerformanceCounter returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQueryPerformanceCounter frequency is 10,000,000", perf_frequency == 10000000);

    st = nt_delay_execution(0, &delay_10ms);
    check("NtDelayExecution(relative 10ms) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    st = nt_query_performance_counter(&perf_counter1, 0);
    check("NtQueryPerformanceCounter(second read) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("Performance counter advanced >= 8ms", (perf_counter1 - perf_counter0) >= 80000);

    ret_len = 0;
    st = nt_query_system_information(
        SYSTEM_BASIC_INFORMATION_CLASS,
        &sbi,
        (ULONG)sizeof(sbi),
        &ret_len);
    check("NtQuerySystemInformation(SystemBasicInformation) success", st == STATUS_SUCCESS);
    check("SystemBasicInformation return length matches", ret_len == (ULONG)sizeof(sbi));
    check("SystemBasicInformation page size is 4096", sbi.PageSize == 4096);
    check("SystemBasicInformation processor count >= 1", sbi.NumberOfProcessors >= 1);

    ret_len = 0;
    st = nt_query_system_information(
        SYSTEM_TIME_OF_DAY_INFORMATION_CLASS,
        &tod,
        (ULONG)sizeof(tod),
        &ret_len);
    check("NtQuerySystemInformation(SystemTimeOfDayInformation) success", st == STATUS_SUCCESS);
    check("SystemTimeOfDayInformation return length matches", ret_len == (ULONG)sizeof(tod));
    check("SystemTimeOfDayInformation current time >= boot time", tod.CurrentTime >= tod.BootTime);

    ret_len = 0;
    st = nt_query_system_information(
        SYSTEM_BASIC_INFORMATION_CLASS,
        short_buf,
        (ULONG)sizeof(short_buf),
        &ret_len);
    check("SystemBasicInformation short buffer returns STATUS_INFO_LENGTH_MISMATCH", st == STATUS_INFO_LENGTH_MISMATCH);
    check("SystemBasicInformation short buffer returns required size", ret_len == (ULONG)sizeof(SYSTEM_BASIC_INFORMATION));

    st = nt_query_system_information(0xFFFFU, &sbi, (ULONG)sizeof(sbi), &ret_len);
    check("Unknown SystemInformationClass returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    write_str("syscall_sysinfo_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    terminate_current_process(g_fail == 0 ? 0 : 1);
}
