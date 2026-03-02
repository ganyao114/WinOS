/*
 * Minimal ntdll.dll stub for WinEmu (ARM64)
 * Compiled with aarch64-w64-mingw32-gcc from llvm-mingw
 */
#include <stdint.h>
#include <stddef.h>

/* NT syscall numbers (Windows 11 ARM64) */
#define NR_TERMINATE_PROCESS    0x002C
#define NR_TERMINATE_THREAD     0x0053
#define NR_READ_FILE            0x0006
#define NR_WRITE_FILE           0x0008
#define NR_OPEN_FILE            0x0030
#define NR_CREATE_FILE          0x0055
#define NR_DEVICE_IO_CONTROL_FILE 0x0007
#define NR_QUERY_INFORMATION_FILE 0x0011
#define NR_WAIT_SINGLE          0x0004
#define NR_WAIT_MULTIPLE        0x0040
#define NR_CLOSE                0x000F
#define NR_CREATE_EVENT         0x0048
#define NR_CREATE_MUTANT        0x00A9
#define NR_CREATE_SEMAPHORE     0x00C3
#define NR_SET_EVENT            0x000E
#define NR_RESET_EVENT          0x0034
#define NR_RELEASE_MUTANT       0x001C
#define NR_RELEASE_SEMAPHORE    0x0033
#define NR_QUERY_ATTRIBUTES_FILE 0x0014
#define NR_SET_INFORMATION_FILE 0x0027
#define NR_QUERY_DIRECTORY_FILE 0x004E
#define NR_NOTIFY_CHANGE_DIRECTORY_FILE 0x011F
#define NR_OPEN_KEY            0x0012
#define NR_QUERY_KEY            0x0013
#define NR_CREATE_KEY           0x001D
#define NR_SET_VALUE_KEY        0x003D
#define NR_QUERY_INFORMATION_PROCESS 0x0019
#define NR_QUERY_INFORMATION_THREAD 0x0025
#define NR_SET_INFORMATION_PROCESS 0x001C
#define NR_QUERY_INFORMATION_TOKEN 0x0021
#define NR_QUERY_OBJECT         0x0017
#define NR_OPEN_PROCESS         0x0026
#define NR_OPEN_PROCESS_TOKEN   0x0131
#define NR_DUPLICATE_OBJECT     0x003C
#define NR_YIELD_EXECUTION      0x0046
#define NR_QUERY_PERFORMANCE_COUNTER 0x0031
#define NR_QUERY_SYSTEM_INFORMATION 0x0036
#define NR_DELAY_EXECUTION      0x0034
#define NR_ALLOCATE_VIRTUAL_MEM 0x0015
#define NR_FREE_VIRTUAL_MEM     0x001E
#define NR_QUERY_VIRTUAL_MEM    0x0023
#define NR_PROTECT_VIRTUAL_MEM  0x004D
#define NR_WRITE_VIRTUAL_MEM    0x003A
#define NR_FS_CONTROL_FILE      0x0039
#define NR_READ_VIRTUAL_MEM     0x003F
#define NR_QUERY_SYSTEM_TIME    0x005A
#define NR_QUERY_VOLUME_INFORMATION_FILE 0x0049
#define NR_CREATE_SECTION       0x004A
#define NR_OPEN_SECTION         0x0037
#define NR_CREATE_PROCESS_EX    0x004B
#define NR_MAP_VIEW_OF_SECTION  0x0028
#define NR_UNMAP_VIEW_OF_SECTION 0x002A
#define NR_CREATE_THREAD_EX     0x00C1
#define NR_RESUME_THREAD        0x0052
#define NR_SUSPEND_THREAD       0x01CC
#define NR_DELETE_VALUE_KEY     0x006A

typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef uint64_t ULONG_PTR;
typedef void*    HANDLE;
typedef uint16_t WCHAR;
typedef uint8_t  UCHAR;
typedef uint8_t  BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t DWORD64;
typedef int32_t  LONG;

#define STATUS_SUCCESS 0x00000000U
#define STATUS_NOT_IMPLEMENTED 0xC0000002U
#define STATUS_INVALID_PARAMETER 0xC000000DU
#define STATUS_NO_MEMORY 0xC0000017U
#define STATUS_NONCONTINUABLE_EXCEPTION 0xC0000025U
#define STATUS_INVALID_DISPOSITION 0xC0000026U
#define STATUS_UNWIND 0xC0000027U
#define STATUS_BAD_FUNCTION_TABLE 0xC00000FFU
#define STATUS_UNHANDLED_EXCEPTION 0xC000014BU
#define STATUS_UNWIND_CONSOLIDATE 0x80000029U

#ifdef _MSC_VER
#  define EXPORT __declspec(dllexport)
#else
#  define EXPORT __attribute__((visibility("default")))
#endif

/* ── Syscall helpers ─────────────────────────────────────────── */

static inline NTSTATUS syscall2(uint64_t nr, uint64_t a0, uint64_t a1) {
    register uint64_t x8 asm("x8") = nr;
    register uint64_t x0 asm("x0") = a0;
    register uint64_t x1 asm("x1") = a1;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1) : "memory", "x2","x3","x4","x5","x6","x7");
    return (NTSTATUS)x0;
}

static inline NTSTATUS syscall6(uint64_t nr,
    uint64_t a0, uint64_t a1, uint64_t a2,
    uint64_t a3, uint64_t a4, uint64_t a5)
{
    register uint64_t x8 asm("x8") = nr;
    register uint64_t x0 asm("x0") = a0;
    register uint64_t x1 asm("x1") = a1;
    register uint64_t x2 asm("x2") = a2;
    register uint64_t x3 asm("x3") = a3;
    register uint64_t x4 asm("x4") = a4;
    register uint64_t x5 asm("x5") = a5;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5) : "memory");
    return (NTSTATUS)x0;
}

static inline NTSTATUS syscall4(uint64_t nr,
    uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    register uint64_t x8 asm("x8") = nr;
    register uint64_t x0 asm("x0") = a0;
    register uint64_t x1 asm("x1") = a1;
    register uint64_t x2 asm("x2") = a2;
    register uint64_t x3 asm("x3") = a3;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3) : "memory","x4","x5","x6","x7");
    return (NTSTATUS)x0;
}

EXPORT NTSTATUS NtQueryVirtualMemory(
    HANDLE process_handle, void* base_address, ULONG memory_information_class,
    void* memory_information, size_t memory_information_length, size_t* return_length);

