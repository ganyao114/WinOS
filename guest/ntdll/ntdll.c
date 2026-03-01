/*
 * Minimal ntdll.dll stub for WinEmu (ARM64)
 * Compiled with aarch64-w64-mingw32-gcc from llvm-mingw
 */
#include <stdint.h>
#include <stddef.h>

/* NT syscall numbers (Windows 11 ARM64) */
#define NR_TERMINATE_PROCESS    0x002C
#define NR_TERMINATE_THREAD     0x0053
#define NR_WRITE_FILE           0x0008
#define NR_OPEN_FILE            0x0030
#define NR_CREATE_FILE          0x0055
#define NR_DEVICE_IO_CONTROL_FILE 0x0007
#define NR_WAIT_SINGLE          0x0004
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
typedef int32_t  LONG;

#define STATUS_NOT_IMPLEMENTED 0xC0000002U
#define STATUS_INVALID_PARAMETER 0xC000000DU

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

/* ── Process ─────────────────────────────────────────────────── */

EXPORT NTSTATUS NtTerminateProcess(HANDLE process, NTSTATUS exit_code) {
    return syscall2(NR_TERMINATE_PROCESS, (uint64_t)process, (uint64_t)exit_code);
}

EXPORT __attribute__((noreturn))
void RtlExitUserProcess(NTSTATUS exit_code) {
    (void)NtTerminateProcess((HANDLE)0, exit_code);
    for (;;) {}
}

EXPORT __attribute__((noreturn))
void NtTerminateThread(HANDLE thread, NTSTATUS exit_code) {
    syscall2(NR_TERMINATE_THREAD, (uint64_t)thread, (uint64_t)exit_code);
    __builtin_unreachable();
}

EXPORT NTSTATUS NtYieldExecution(void) {
    return syscall2(NR_YIELD_EXECUTION, 0, 0);
}

EXPORT NTSTATUS NtClose(HANDLE handle) {
    return syscall2(NR_CLOSE, (uint64_t)handle, 0);
}

EXPORT NTSTATUS NtWaitForSingleObject(HANDLE handle, UCHAR alertable, int64_t* timeout) {
    return syscall6(
        NR_WAIT_SINGLE,
        (uint64_t)handle,
        (uint64_t)alertable,
        (uint64_t)timeout,
        0,
        0,
        0
    );
}

EXPORT NTSTATUS NtCreateEvent(
    HANDLE* event_handle, ULONG desired_access, void* object_attributes, ULONG event_type, UCHAR initial_state)
{
    return syscall6(
        NR_CREATE_EVENT,
        (uint64_t)event_handle,
        (uint64_t)desired_access,
        (uint64_t)object_attributes,
        (uint64_t)event_type,
        (uint64_t)initial_state,
        0
    );
}

EXPORT NTSTATUS NtCreateMutant(
    HANDLE* mutant_handle, ULONG desired_access, void* object_attributes, UCHAR initial_owner)
{
    return syscall4(
        NR_CREATE_MUTANT,
        (uint64_t)mutant_handle,
        (uint64_t)desired_access,
        (uint64_t)object_attributes,
        (uint64_t)initial_owner
    );
}

EXPORT NTSTATUS NtReleaseMutant(HANDLE mutant_handle, LONG* previous_count) {
    return syscall2(NR_RELEASE_MUTANT, (uint64_t)mutant_handle, (uint64_t)previous_count);
}

EXPORT NTSTATUS NtCreateSemaphore(
    HANDLE* semaphore_handle, ULONG desired_access, void* object_attributes, LONG initial_count, LONG maximum_count)
{
    return syscall6(
        NR_CREATE_SEMAPHORE,
        (uint64_t)semaphore_handle,
        (uint64_t)desired_access,
        (uint64_t)object_attributes,
        (uint64_t)(int64_t)initial_count,
        (uint64_t)(int64_t)maximum_count,
        0
    );
}

EXPORT NTSTATUS NtReleaseSemaphore(
    HANDLE semaphore_handle, LONG release_count, LONG* previous_count)
{
    return syscall4(
        NR_RELEASE_SEMAPHORE,
        (uint64_t)semaphore_handle,
        (uint64_t)(int64_t)release_count,
        (uint64_t)previous_count,
        0
    );
}

EXPORT NTSTATUS NtSetEvent(HANDLE event_handle, ULONG* previous_state) {
    return syscall2(NR_SET_EVENT, (uint64_t)event_handle, (uint64_t)previous_state);
}

EXPORT NTSTATUS NtResetEvent(HANDLE event_handle, ULONG* previous_state) {
    return syscall2(NR_RESET_EVENT, (uint64_t)event_handle, (uint64_t)previous_state);
}

EXPORT NTSTATUS NtQueryInformationProcess(
    HANDLE process, ULONG info_class, void* buf, ULONG len, ULONG* ret_len)
{
    return syscall6(
        NR_QUERY_INFORMATION_PROCESS,
        (uint64_t)process,
        (uint64_t)info_class,
        (uint64_t)buf,
        (uint64_t)len,
        (uint64_t)ret_len,
        0
    );
}

EXPORT NTSTATUS NtSetInformationProcess(
    HANDLE process, ULONG info_class, void* buf, ULONG len)
{
    return syscall4(
        NR_SET_INFORMATION_PROCESS,
        (uint64_t)process,
        (uint64_t)info_class,
        (uint64_t)buf,
        (uint64_t)len
    );
}

EXPORT NTSTATUS NtOpenProcess(
    HANDLE* process_handle, ULONG desired_access, void* object_attributes, void* client_id)
{
    return syscall4(
        NR_OPEN_PROCESS,
        (uint64_t)process_handle,
        (uint64_t)desired_access,
        (uint64_t)object_attributes,
        (uint64_t)client_id
    );
}

EXPORT NTSTATUS NtOpenProcessToken(
    HANDLE process_handle, ULONG desired_access, HANDLE* token_handle)
{
    return syscall4(
        NR_OPEN_PROCESS_TOKEN,
        (uint64_t)process_handle,
        (uint64_t)desired_access,
        (uint64_t)token_handle,
        0
    );
}

EXPORT NTSTATUS NtQueryInformationToken(
    HANDLE token, ULONG info_class, void* token_info, ULONG token_info_len, ULONG* ret_len)
{
    return syscall6(
        NR_QUERY_INFORMATION_TOKEN,
        (uint64_t)token,
        (uint64_t)info_class,
        (uint64_t)token_info,
        (uint64_t)token_info_len,
        (uint64_t)ret_len,
        0
    );
}

EXPORT NTSTATUS NtQueryObject(
    HANDLE handle, ULONG object_info_class, void* object_info, ULONG object_info_len, ULONG* ret_len)
{
    return syscall6(
        NR_QUERY_OBJECT,
        (uint64_t)handle,
        (uint64_t)object_info_class,
        (uint64_t)object_info,
        (uint64_t)object_info_len,
        (uint64_t)ret_len,
        0
    );
}

__attribute__((naked))
EXPORT NTSTATUS NtCreateProcessEx(
    HANDLE* process_handle, ULONG access, void* object_attributes,
    HANDLE parent_process, ULONG flags, HANDLE section_handle,
    HANDLE debug_port, HANDLE exception_port, ULONG job_member_level)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_CREATE_PROCESS_EX));
}

__attribute__((naked))
EXPORT NTSTATUS NtDuplicateObject(
    HANDLE source_process, HANDLE source_handle,
    HANDLE target_process, HANDLE* target_handle,
    ULONG desired_access, ULONG attributes, ULONG options)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_DUPLICATE_OBJECT));
}

/* ── TEB ─────────────────────────────────────────────────────── */

EXPORT void* NtCurrentTeb(void) {
    void* teb;
    asm("mov %0, x18" : "=r"(teb));
    return teb;
}

/* ── Virtual Memory ──────────────────────────────────────────── */

EXPORT NTSTATUS NtAllocateVirtualMemory(
    HANDLE process, void** base_addr, ULONG_PTR zero_bits,
    size_t* region_size, ULONG alloc_type, ULONG protect)
{
    return syscall6(NR_ALLOCATE_VIRTUAL_MEM,
        (uint64_t)process, (uint64_t)base_addr, zero_bits,
        (uint64_t)region_size, alloc_type, protect);
}

EXPORT NTSTATUS NtFreeVirtualMemory(
    HANDLE process, void** base_addr, size_t* region_size, ULONG free_type)
{
    return syscall4(NR_FREE_VIRTUAL_MEM,
        (uint64_t)process, (uint64_t)base_addr,
        (uint64_t)region_size, free_type);
}

EXPORT NTSTATUS NtReadVirtualMemory(
    HANDLE process, const void* base_addr, void* buffer, size_t size, size_t* bytes_read)
{
    return syscall6(
        NR_READ_VIRTUAL_MEM,
        (uint64_t)process,
        (uint64_t)base_addr,
        (uint64_t)buffer,
        (uint64_t)size,
        (uint64_t)bytes_read,
        0
    );
}

EXPORT NTSTATUS NtWriteVirtualMemory(
    HANDLE process, void* base_addr, const void* buffer, size_t size, size_t* bytes_written)
{
    return syscall6(
        NR_WRITE_VIRTUAL_MEM,
        (uint64_t)process,
        (uint64_t)base_addr,
        (uint64_t)buffer,
        (uint64_t)size,
        (uint64_t)bytes_written,
        0
    );
}

/* ── Heap ────────────────────────────────────────────────────── */

EXPORT void* RtlAllocateHeap(HANDLE heap, ULONG flags, size_t size) {
    (void)heap; (void)flags;
    void* base = NULL;
    size_t sz = size;
    NTSTATUS st = NtAllocateVirtualMemory(
        (HANDLE)(uint64_t)-1, &base, 0, &sz, 0x3000, 4);
    return (st == 0) ? base : NULL;
}

EXPORT int RtlFreeHeap(HANDLE heap, ULONG flags, void* ptr) {
    (void)heap; (void)flags;
    if (!ptr) return 1;
    size_t sz = 0;
    NtFreeVirtualMemory((HANDLE)(uint64_t)-1, &ptr, &sz, 0x8000);
    return 1;
}

EXPORT void* RtlReAllocateHeap(HANDLE heap, ULONG flags, void* ptr, size_t size) {
    void* newp = RtlAllocateHeap(heap, flags, size);
    if (newp && ptr) {
        const uint8_t* src = (const uint8_t*)ptr;
        uint8_t* dst = (uint8_t*)newp;
        for (size_t i = 0; i < size; i++) dst[i] = src[i];
        RtlFreeHeap(heap, flags, ptr);
    }
    return newp;
}

/* ── Critical Section ────────────────────────────────────────── */

typedef struct {
    uint64_t debug_info;
    int32_t  lock_count;
    int32_t  recursion;
    uint64_t owner_thread;
    uint64_t lock_sem;
    uint64_t spin_count;
} RTL_CRITICAL_SECTION;

EXPORT NTSTATUS RtlInitializeCriticalSection(RTL_CRITICAL_SECTION* cs) {
    if (!cs) return STATUS_INVALID_PARAMETER;
    cs->debug_info   = 0;
    cs->lock_count   = -1;
    cs->recursion    = 0;
    cs->owner_thread = 0;
    cs->lock_sem     = 0;
    cs->spin_count   = 0;
    return 0;
}

EXPORT NTSTATUS RtlInitializeCriticalSectionAndSpinCount(RTL_CRITICAL_SECTION* cs, ULONG spin) {
    NTSTATUS r = RtlInitializeCriticalSection(cs);
    if (r == 0) cs->spin_count = spin;
    return r;
}

EXPORT NTSTATUS RtlDeleteCriticalSection(RTL_CRITICAL_SECTION* cs) { (void)cs; return 0; }

EXPORT NTSTATUS RtlEnterCriticalSection(RTL_CRITICAL_SECTION* cs) {
    cs->lock_count++;
    cs->recursion++;
    return 0;
}

EXPORT NTSTATUS RtlLeaveCriticalSection(RTL_CRITICAL_SECTION* cs) {
    cs->lock_count--;
    cs->recursion--;
    return 0;
}

EXPORT int RtlTryEnterCriticalSection(RTL_CRITICAL_SECTION* cs) {
    RtlEnterCriticalSection(cs);
    return 1;
}

/* ── String helpers ──────────────────────────────────────────── */

typedef struct { uint16_t Length, MaximumLength; uint32_t _pad; WCHAR* Buffer; } UNICODE_STRING;
typedef struct { uint16_t Length, MaximumLength; uint32_t _pad; UCHAR* Buffer; } ANSI_STRING;

EXPORT void RtlInitUnicodeString(UNICODE_STRING* dest, const WCHAR* src) {
    if (!src) { dest->Length = dest->MaximumLength = 0; dest->Buffer = NULL; return; }
    size_t len = 0;
    while (src[len]) len++;
    dest->Length        = (uint16_t)(len * 2);
    dest->MaximumLength = (uint16_t)(len * 2 + 2);
    dest->Buffer        = (WCHAR*)src;
}

EXPORT void RtlInitAnsiString(ANSI_STRING* dest, const UCHAR* src) {
    if (!src) { dest->Length = dest->MaximumLength = 0; dest->Buffer = NULL; return; }
    size_t len = 0;
    while (src[len]) len++;
    dest->Length        = (uint16_t)len;
    dest->MaximumLength = (uint16_t)(len + 1);
    dest->Buffer        = (UCHAR*)src;
}

/* ── Misc ────────────────────────────────────────────────────── */

EXPORT NTSTATUS RtlGetVersion(void* osvi) { (void)osvi; return 0; }

EXPORT NTSTATUS NtQuerySystemInformation(ULONG cls, void* buf, ULONG len, ULONG* ret) {
    return syscall4(
        NR_QUERY_SYSTEM_INFORMATION,
        (uint64_t)cls,
        (uint64_t)buf,
        (uint64_t)len,
        (uint64_t)ret
    );
}

EXPORT NTSTATUS NtQuerySystemTime(int64_t* time) {
    return syscall2(NR_QUERY_SYSTEM_TIME, (uint64_t)time, 0);
}

EXPORT NTSTATUS NtQueryPerformanceCounter(int64_t* counter, int64_t* frequency) {
    return syscall2(
        NR_QUERY_PERFORMANCE_COUNTER,
        (uint64_t)counter,
        (uint64_t)frequency
    );
}

EXPORT NTSTATUS NtDelayExecution(UCHAR alertable, const int64_t* timeout) {
    return syscall2(NR_DELAY_EXECUTION, (uint64_t)alertable, (uint64_t)timeout);
}

EXPORT ULONG RtlNtStatusToDosError(NTSTATUS status) {
    switch (status) {
        case 0:            return 0;
        case 0xC0000005:   return 5;
        case 0xC000000D:   return 87;
        case 0xC0000017:   return 14;
        default:           return 317;
    }
}

EXPORT void RtlSetLastWin32Error(ULONG code) {
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    if (teb) *(volatile uint32_t*)(teb + 0x68) = code;
}

EXPORT ULONG RtlGetLastWin32Error(void) {
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    if (!teb) return 0;
    return *(volatile uint32_t*)(teb + 0x68);
}

EXPORT NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    void* io_status, const void* buffer, ULONG length,
    uint64_t* byte_offset, ULONG* key)
{
    register uint64_t x8 asm("x8") = NR_WRITE_FILE;
    register uint64_t x0 asm("x0") = (uint64_t)file;
    register uint64_t x1 asm("x1") = (uint64_t)event;
    register uint64_t x2 asm("x2") = (uint64_t)apc_routine;
    register uint64_t x3 asm("x3") = (uint64_t)apc_ctx;
    register uint64_t x4 asm("x4") = (uint64_t)io_status;
    register uint64_t x5 asm("x5") = (uint64_t)buffer;
    register uint64_t x6 asm("x6") = (uint64_t)length;
    register uint64_t x7 asm("x7") = (uint64_t)byte_offset;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x6),"r"(x7) : "memory");
    return (NTSTATUS)x0;
}

__attribute__((naked))
EXPORT NTSTATUS NtCreateFile(
    HANDLE* file_handle, ULONG desired_access, void* object_attributes, void* io_status_block,
    uint64_t* allocation_size, ULONG file_attributes, ULONG share_access, ULONG create_disposition,
    ULONG create_options, void* ea_buffer, ULONG ea_length)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_CREATE_FILE));
}

EXPORT NTSTATUS NtOpenFile(
    HANDLE* file_handle, ULONG desired_access, void* object_attributes,
    void* io_status_block, ULONG share_access, ULONG open_options)
{
    return syscall6(
        NR_OPEN_FILE,
        (uint64_t)file_handle,
        (uint64_t)desired_access,
        (uint64_t)object_attributes,
        (uint64_t)io_status_block,
        (uint64_t)share_access,
        (uint64_t)open_options
    );
}

EXPORT NTSTATUS NtSetInformationFile(
    HANDLE file_handle, void* io_status_block, void* file_information, ULONG length, ULONG file_information_class)
{
    return syscall6(
        NR_SET_INFORMATION_FILE,
        (uint64_t)file_handle,
        (uint64_t)io_status_block,
        (uint64_t)file_information,
        (uint64_t)length,
        (uint64_t)file_information_class,
        0
    );
}

__attribute__((naked))
EXPORT NTSTATUS NtQueryDirectoryFile(
    HANDLE file_handle, HANDLE event, void* apc_routine, void* apc_context,
    void* io_status_block, void* file_information, ULONG length, ULONG file_information_class,
    UCHAR return_single_entry, void* file_name, UCHAR restart_scan)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_QUERY_DIRECTORY_FILE));
}

__attribute__((naked))
EXPORT NTSTATUS NtNotifyChangeDirectoryFile(
    HANDLE file_handle, HANDLE event, void* apc_routine, void* apc_context,
    void* io_status_block, void* buffer, ULONG length, ULONG completion_filter, UCHAR watch_tree)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_NOTIFY_CHANGE_DIRECTORY_FILE));
}

__attribute__((naked))
EXPORT NTSTATUS NtDeviceIoControlFile(
    HANDLE file_handle, HANDLE event, void* apc_routine, void* apc_context,
    void* io_status_block, ULONG io_control_code, void* input_buffer, ULONG input_buffer_length,
    void* output_buffer, ULONG output_buffer_length)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_DEVICE_IO_CONTROL_FILE));
}

__attribute__((naked))
EXPORT NTSTATUS NtFsControlFile(
    HANDLE file_handle, HANDLE event, void* apc_routine, void* apc_context,
    void* io_status_block, ULONG fs_control_code, void* input_buffer, ULONG input_buffer_length,
    void* output_buffer, ULONG output_buffer_length)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_FS_CONTROL_FILE));
}

EXPORT NTSTATUS NtQueryAttributesFile(void* object_attributes, void* file_information) {
    return syscall2(
        NR_QUERY_ATTRIBUTES_FILE,
        (uint64_t)object_attributes,
        (uint64_t)file_information
    );
}

EXPORT NTSTATUS NtQueryVolumeInformationFile(
    HANDLE file_handle, void* io_status_block, void* fs_information, ULONG length, ULONG fs_information_class)
{
    return syscall6(
        NR_QUERY_VOLUME_INFORMATION_FILE,
        (uint64_t)file_handle,
        (uint64_t)io_status_block,
        (uint64_t)fs_information,
        (uint64_t)length,
        (uint64_t)fs_information_class,
        0
    );
}

/* ── Section ─────────────────────────────────────────────────── */

EXPORT NTSTATUS NtCreateSection(
    void** handle_out, ULONG access, void* oa,
    uint64_t* max_size, ULONG page_prot, ULONG alloc_attrs, void* file)
{
    register uint64_t x8 asm("x8") = NR_CREATE_SECTION;
    register uint64_t x0 asm("x0") = (uint64_t)handle_out;
    register uint64_t x1 asm("x1") = access;
    register uint64_t x2 asm("x2") = (uint64_t)oa;
    register uint64_t x3 asm("x3") = (uint64_t)max_size;
    register uint64_t x4 asm("x4") = page_prot;
    register uint64_t x5 asm("x5") = alloc_attrs;
    register uint64_t x6 asm("x6") = (uint64_t)file;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x6) : "memory");
    return (NTSTATUS)x0;
}

EXPORT NTSTATUS NtOpenSection(void** section_handle, ULONG desired_access, void* object_attributes) {
    return syscall4(
        NR_OPEN_SECTION,
        (uint64_t)section_handle,
        (uint64_t)desired_access,
        (uint64_t)object_attributes,
        0
    );
}

/* NtMapViewOfSection has 10 args. On ARM64 Windows ABI, args 9-10 go on the
 * stack. We use a __attribute__((naked)) trampoline so the compiler never
 * builds a frame around the svc, avoiding sp corruption. */
__attribute__((naked))
EXPORT NTSTATUS NtMapViewOfSection(
    void* section, void* process, void** base, uint64_t zero_bits,
    size_t commit, uint64_t* offset, size_t* view_size,
    ULONG inherit, ULONG alloc_type, ULONG protect)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_MAP_VIEW_OF_SECTION));
}

EXPORT NTSTATUS NtUnmapViewOfSection(void* process, void* base) {
    return syscall2(NR_UNMAP_VIEW_OF_SECTION, (uint64_t)process, (uint64_t)base);
}

__attribute__((naked))
EXPORT NTSTATUS NtCreateThreadEx(
    HANDLE* thread_handle, ULONG access, void* object_attributes,
    HANDLE process_handle, void* start_routine, void* argument,
    ULONG create_flags, size_t zero_bits, size_t stack_size,
    size_t max_stack_size, void* attribute_list)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_CREATE_THREAD_EX));
}

EXPORT NTSTATUS NtSuspendThread(HANDLE thread_handle, ULONG* previous_suspend_count) {
    return syscall2(
        NR_SUSPEND_THREAD,
        (uint64_t)thread_handle,
        (uint64_t)previous_suspend_count
    );
}

EXPORT NTSTATUS NtResumeThread(HANDLE thread_handle, ULONG* previous_suspend_count) {
    return syscall2(
        NR_RESUME_THREAD,
        (uint64_t)thread_handle,
        (uint64_t)previous_suspend_count
    );
}

EXPORT NTSTATUS NtQueryInformationThread(
    HANDLE thread_handle, ULONG thread_information_class, void* thread_information,
    ULONG thread_information_length, ULONG* return_length)
{
    return syscall6(
        NR_QUERY_INFORMATION_THREAD,
        (uint64_t)thread_handle,
        (uint64_t)thread_information_class,
        (uint64_t)thread_information,
        (uint64_t)thread_information_length,
        (uint64_t)return_length,
        0
    );
}

/* ── Registry ────────────────────────────────────────────────── */

EXPORT NTSTATUS NtOpenKey(HANDLE* key_handle, ULONG desired_access, void* object_attributes) {
    return syscall4(
        NR_OPEN_KEY,
        (uint64_t)key_handle,
        (uint64_t)desired_access,
        (uint64_t)object_attributes,
        0
    );
}

__attribute__((naked))
EXPORT NTSTATUS NtCreateKey(
    HANDLE* key_handle, ULONG desired_access, void* object_attributes,
    ULONG title_index, void* class_name, ULONG create_options, ULONG* disposition)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_CREATE_KEY));
}

EXPORT NTSTATUS NtSetValueKey(
    HANDLE key_handle, void* value_name, ULONG title_index,
    ULONG type, const void* data, ULONG data_size)
{
    return syscall6(
        NR_SET_VALUE_KEY,
        (uint64_t)key_handle,
        (uint64_t)value_name,
        (uint64_t)title_index,
        (uint64_t)type,
        (uint64_t)data,
        (uint64_t)data_size
    );
}

EXPORT NTSTATUS NtQueryKey(
    HANDLE key_handle, ULONG key_information_class, void* key_information,
    ULONG length, ULONG* result_length)
{
    return syscall6(
        NR_QUERY_KEY,
        (uint64_t)key_handle,
        (uint64_t)key_information_class,
        (uint64_t)key_information,
        (uint64_t)length,
        (uint64_t)result_length,
        0
    );
}

EXPORT NTSTATUS NtDeleteValueKey(HANDLE key_handle, void* value_name) {
    return syscall2(NR_DELETE_VALUE_KEY, (uint64_t)key_handle, (uint64_t)value_name);
}

/* ── DLL entry point ─────────────────────────────────────────── */

EXPORT int DllMain(HANDLE inst, ULONG reason, void* reserved) {
    (void)inst; (void)reason; (void)reserved;
    return 1;
}

/* Required by linker when using -nostdlib */
int DllMainCRTStartup(HANDLE inst, ULONG reason, void* reserved) {
    return DllMain(inst, reason, reserved);
}
