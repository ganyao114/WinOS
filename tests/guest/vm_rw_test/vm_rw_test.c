#include <stdint.h>
#include <stddef.h>

typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef uint64_t ULONG_PTR;
typedef void *HANDLE;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_INVALID_HANDLE 0xC0000008U

#define MEM_COMMIT 0x1000U
#define MEM_RESERVE 0x2000U
#define MEM_RELEASE 0x8000U
#define PAGE_READWRITE 0x04U

typedef struct {
    uint64_t Status;
    uint64_t Information;
} IO_STATUS_BLOCK;

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void *apc_routine, void *apc_ctx,
    IO_STATUS_BLOCK *iosb, const void *buf, ULONG len,
    uint64_t *byte_offset, ULONG *key);

__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);

__declspec(dllimport) NTSTATUS NtAllocateVirtualMemory(
    HANDLE process, void **base_addr, ULONG_PTR zero_bits,
    size_t *region_size, ULONG alloc_type, ULONG protect);

__declspec(dllimport) NTSTATUS NtFreeVirtualMemory(
    HANDLE process, void **base_addr, size_t *region_size, ULONG free_type);

__declspec(dllimport) NTSTATUS NtReadVirtualMemory(
    HANDLE process, const void *base_addr, void *buffer, size_t size, size_t *bytes_read);

__declspec(dllimport) NTSTATUS NtWriteVirtualMemory(
    HANDLE process, void *base_addr, const void *buffer, size_t size, size_t *bytes_written);

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
    NTSTATUS st;
    void *base = 0;
    size_t size = 0x1000;
    uint64_t direct_value = 0x1122334455667788ULL;
    uint64_t read_back = 0;
    uint64_t write_value = 0x8877665544332211ULL;
    size_t bytes = 0;
    void *free_base = 0;
    size_t free_size = 0;

    write_str("== vm_rw_test ==\r\n");

    st = NtAllocateVirtualMemory(
        NT_CURRENT_PROCESS,
        &base,
        0,
        &size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    check("NtAllocateVirtualMemory success", st == STATUS_SUCCESS);
    check("Allocated base non-null", base != 0);

    if (st == STATUS_SUCCESS && base != 0) {
        *(volatile uint64_t *)base = direct_value;
        bytes = 0;
        st = NtReadVirtualMemory(NT_CURRENT_PROCESS, base, &read_back, sizeof(read_back), &bytes);
        check("NtReadVirtualMemory(self) success", st == STATUS_SUCCESS);
        check("NtReadVirtualMemory bytes_read matches", bytes == sizeof(read_back));
        check("NtReadVirtualMemory data matches", read_back == direct_value);

        bytes = 0;
        st = NtWriteVirtualMemory(NT_CURRENT_PROCESS, base, &write_value, sizeof(write_value), &bytes);
        check("NtWriteVirtualMemory(self) success", st == STATUS_SUCCESS);
        check("NtWriteVirtualMemory bytes_written matches", bytes == sizeof(write_value));
        check("NtWriteVirtualMemory data applied", *(volatile uint64_t *)base == write_value);
    } else {
        check("NtReadVirtualMemory(self) success", 0);
        check("NtReadVirtualMemory bytes_read matches", 0);
        check("NtReadVirtualMemory data matches", 0);
        check("NtWriteVirtualMemory(self) success", 0);
        check("NtWriteVirtualMemory bytes_written matches", 0);
        check("NtWriteVirtualMemory data applied", 0);
    }

    st = NtReadVirtualMemory((HANDLE)(uint64_t)0x12345678ULL, base, &read_back, sizeof(read_back), &bytes);
    check("NtReadVirtualMemory invalid handle returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);

    st = NtWriteVirtualMemory((HANDLE)(uint64_t)0x12345678ULL, base, &write_value, sizeof(write_value), &bytes);
    check("NtWriteVirtualMemory invalid handle returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);

    bytes = 123;
    st = NtReadVirtualMemory(NT_CURRENT_PROCESS, 0, 0, 0, &bytes);
    check("NtReadVirtualMemory zero-size is success", st == STATUS_SUCCESS);
    check("NtReadVirtualMemory zero-size bytes_read is zero", bytes == 0);

    bytes = 123;
    st = NtWriteVirtualMemory(NT_CURRENT_PROCESS, 0, 0, 0, &bytes);
    check("NtWriteVirtualMemory zero-size is success", st == STATUS_SUCCESS);
    check("NtWriteVirtualMemory zero-size bytes_written is zero", bytes == 0);

    if (base != 0) {
        free_base = base;
        free_size = 0;
        st = NtFreeVirtualMemory(NT_CURRENT_PROCESS, &free_base, &free_size, MEM_RELEASE);
        check("NtFreeVirtualMemory(MEM_RELEASE) success", st == STATUS_SUCCESS);
    } else {
        check("NtFreeVirtualMemory(MEM_RELEASE) success", 0);
    }

    write_str("vm_rw_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    terminate_current_process(g_fail == 0 ? 0 : 1);
}
