/*
 * hello_win.c — WinEmu test program (ARM64, C + llvm-mingw)
 * Tests: NtWriteFile, NtCreateSection, NtMapViewOfSection, NtTerminateProcess
 */
#include <stdint.h>
#include <stddef.h>

/* ── ntdll imports ───────────────────────────────────────────── */

typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef uint64_t ULONG_PTR;
typedef void*    HANDLE;

#define STDOUT ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define STATUS_SUCCESS 0

typedef struct { uint64_t Status; uint64_t Information; } IO_STATUS_BLOCK;

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len,
    uint64_t* offset, ULONG* key);

__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);

__declspec(dllimport) NTSTATUS NtAllocateVirtualMemory(
    HANDLE process, void** base, ULONG_PTR zero_bits,
    size_t* size, ULONG type, ULONG protect);

__declspec(dllimport) NTSTATUS NtFreeVirtualMemory(
    HANDLE process, void** base, size_t* size, ULONG free_type);

/* NtCreateSection / NtMapViewOfSection / NtUnmapViewOfSection */
__declspec(dllimport) NTSTATUS NtCreateSection(
    HANDLE* handle_out, ULONG access, void* oa,
    uint64_t* max_size, ULONG page_prot, ULONG alloc_attrs, HANDLE file);

__declspec(dllimport) NTSTATUS NtMapViewOfSection(
    HANDLE section, HANDLE process, void** base, ULONG_PTR zero_bits,
    size_t commit, uint64_t* offset, size_t* view_size,
    ULONG inherit, ULONG alloc_type, ULONG protect);

__declspec(dllimport) NTSTATUS NtUnmapViewOfSection(HANDLE process, void* base);

/* ── helpers ─────────────────────────────────────────────────── */

static void write_str(const char* s) {
    ULONG len = 0;
    while (s[len]) len++;
    IO_STATUS_BLOCK iosb = {0};
    NtWriteFile(STDOUT, NULL, NULL, NULL, &iosb, s, len, NULL, NULL);
}

static __attribute__((noreturn)) void fail(const char* msg) {
    write_str(msg);
    NtTerminateProcess((HANDLE)0, 1);
}

/* ── entry point ─────────────────────────────────────────────── */

void mainCRTStartup(void) {
    write_str("Hello from WinEmu!\r\n");

    /* ── Section test ──────────────────────────────────────── */
    HANDLE sec = NULL;
    uint64_t sz = 4096;
    NTSTATUS st = NtCreateSection(&sec, 0xF, NULL, &sz, 4, 0x8000000, NULL);
    if (st != STATUS_SUCCESS || !sec)
        fail("FAIL: NtCreateSection\r\n");

    void* base = NULL;
    size_t offset = 0, view_size = 4096;
    st = NtMapViewOfSection(sec, (HANDLE)(uint64_t)-1, &base,
                            0, 0, (uint64_t*)&offset, &view_size, 1, 0, 4);
    if (st != STATUS_SUCCESS || !base)
        fail("FAIL: NtMapViewOfSection\r\n");

    volatile uint64_t* ptr = (volatile uint64_t*)base;
    *ptr = 0xDEADBEEFCAFE1234ULL;
    if (*ptr != 0xDEADBEEFCAFE1234ULL)
        fail("FAIL: section readback mismatch\r\n");

    NtUnmapViewOfSection((HANDLE)(uint64_t)-1, base);

    write_str("Section test PASSED\r\n");
    NtTerminateProcess((HANDLE)0, 0);
}
