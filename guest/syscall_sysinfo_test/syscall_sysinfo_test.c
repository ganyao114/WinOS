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

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void *apc_routine, void *apc_ctx,
    IO_STATUS_BLOCK *iosb, const void *buf, ULONG len,
    uint64_t *byte_offset, ULONG *key);

__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);

__declspec(dllimport) NTSTATUS NtQuerySystemInformation(
    ULONG info_class, void *buf, ULONG len, ULONG *ret_len);
__declspec(dllimport) NTSTATUS NtQuerySystemTime(LARGE_INTEGER *system_time);
__declspec(dllimport) NTSTATUS NtQueryPerformanceCounter(
    LARGE_INTEGER *counter, LARGE_INTEGER *frequency);
__declspec(dllimport) NTSTATUS NtDelayExecution(
    BOOLEAN alertable, const LARGE_INTEGER *timeout);

static uint32_t g_pass = 0;
static uint32_t g_fail = 0;

static void write_str(const char *s) {
    IO_STATUS_BLOCK iosb = {0};
    ULONG len = 0;
    while (s[len]) {
        len++;
    }
    (void)NtWriteFile(STDOUT_HANDLE, 0, 0, 0, &iosb, s, len, 0, 0);
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
    NtTerminateProcess(NT_CURRENT_PROCESS, code);
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

    st = NtQuerySystemTime(&system_time);
    check("NtQuerySystemTime returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQuerySystemTime writes non-zero time", system_time > 0);

    st = NtQuerySystemTime((LARGE_INTEGER *)0);
    check("NtQuerySystemTime(NULL) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    st = NtQueryPerformanceCounter(&perf_counter0, &perf_frequency);
    check("NtQueryPerformanceCounter returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQueryPerformanceCounter frequency is 10,000,000", perf_frequency == 10000000);

    st = NtDelayExecution(0, &delay_10ms);
    check("NtDelayExecution(relative 10ms) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    st = NtQueryPerformanceCounter(&perf_counter1, 0);
    check("NtQueryPerformanceCounter(second read) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("Performance counter advanced >= 8ms", (perf_counter1 - perf_counter0) >= 80000);

    ret_len = 0;
    st = NtQuerySystemInformation(
        SYSTEM_BASIC_INFORMATION_CLASS,
        &sbi,
        (ULONG)sizeof(sbi),
        &ret_len);
    check("NtQuerySystemInformation(SystemBasicInformation) success", st == STATUS_SUCCESS);
    check("SystemBasicInformation return length matches", ret_len == (ULONG)sizeof(sbi));
    check("SystemBasicInformation page size is 4096", sbi.PageSize == 4096);
    check("SystemBasicInformation processor count >= 1", sbi.NumberOfProcessors >= 1);

    ret_len = 0;
    st = NtQuerySystemInformation(
        SYSTEM_TIME_OF_DAY_INFORMATION_CLASS,
        &tod,
        (ULONG)sizeof(tod),
        &ret_len);
    check("NtQuerySystemInformation(SystemTimeOfDayInformation) success", st == STATUS_SUCCESS);
    check("SystemTimeOfDayInformation return length matches", ret_len == (ULONG)sizeof(tod));
    check("SystemTimeOfDayInformation current time >= boot time", tod.CurrentTime >= tod.BootTime);

    ret_len = 0;
    st = NtQuerySystemInformation(
        SYSTEM_BASIC_INFORMATION_CLASS,
        short_buf,
        (ULONG)sizeof(short_buf),
        &ret_len);
    check("SystemBasicInformation short buffer returns STATUS_INFO_LENGTH_MISMATCH", st == STATUS_INFO_LENGTH_MISMATCH);
    check("SystemBasicInformation short buffer returns required size", ret_len == (ULONG)sizeof(SYSTEM_BASIC_INFORMATION));

    st = NtQuerySystemInformation(0xFFFFU, &sbi, (ULONG)sizeof(sbi), &ret_len);
    check("Unknown SystemInformationClass returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    write_str("syscall_sysinfo_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    terminate_current_process(g_fail == 0 ? 0 : 1);
}
