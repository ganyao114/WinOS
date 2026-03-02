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

EXPORT NTSTATUS NtWaitForMultipleObjects(
    ULONG count, const HANDLE* handles, ULONG wait_type, UCHAR alertable, int64_t* timeout)
{
    return syscall6(
        NR_WAIT_MULTIPLE,
        (uint64_t)count,
        (uint64_t)handles,
        (uint64_t)wait_type,
        (uint64_t)alertable,
        (uint64_t)timeout,
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

/* ── FLS (Fiber Local Storage) ──────────────────────────────── */

typedef void (*PWINEMU_FLS_CALLBACK)(void*);

#define WINEMU_FLS_MAX_SLOTS   128
#define WINEMU_FLS_MAX_THREADS 64

typedef struct {
    uint8_t used;
    PWINEMU_FLS_CALLBACK callback;
} WINEMU_FLS_SLOT;

typedef struct {
    void* teb;
    void* values[WINEMU_FLS_MAX_SLOTS];
} WINEMU_FLS_THREAD;

static WINEMU_FLS_SLOT g_fls_slots[WINEMU_FLS_MAX_SLOTS];
static WINEMU_FLS_THREAD g_fls_threads[WINEMU_FLS_MAX_THREADS];

static WINEMU_FLS_THREAD* fls_thread_entry(int create) {
    void* teb = NtCurrentTeb();
    if (!teb) return NULL;
    for (int i = 0; i < WINEMU_FLS_MAX_THREADS; i++) {
        if (g_fls_threads[i].teb == teb) return &g_fls_threads[i];
    }
    if (!create) return NULL;
    for (int i = 0; i < WINEMU_FLS_MAX_THREADS; i++) {
        if (g_fls_threads[i].teb == NULL) {
            g_fls_threads[i].teb = teb;
            for (int j = 0; j < WINEMU_FLS_MAX_SLOTS; j++) {
                g_fls_threads[i].values[j] = NULL;
            }
            return &g_fls_threads[i];
        }
    }
    return NULL;
}

EXPORT NTSTATUS RtlFlsAlloc(PWINEMU_FLS_CALLBACK callback, ULONG* index_out) {
    if (!index_out) return STATUS_INVALID_PARAMETER;
    for (ULONG i = 0; i < WINEMU_FLS_MAX_SLOTS; i++) {
        if (!g_fls_slots[i].used) {
            g_fls_slots[i].used = 1;
            g_fls_slots[i].callback = callback;
            *index_out = i;
            return 0;
        }
    }
    return STATUS_NO_MEMORY;
}

EXPORT NTSTATUS RtlFlsFree(ULONG index) {
    if (index >= WINEMU_FLS_MAX_SLOTS || !g_fls_slots[index].used) {
        return STATUS_INVALID_PARAMETER;
    }
    g_fls_slots[index].used = 0;
    g_fls_slots[index].callback = NULL;
    for (int i = 0; i < WINEMU_FLS_MAX_THREADS; i++) {
        if (g_fls_threads[i].teb) {
            g_fls_threads[i].values[index] = NULL;
        }
    }
    return 0;
}

EXPORT NTSTATUS RtlFlsSetValue(ULONG index, void* value) {
    if (index >= WINEMU_FLS_MAX_SLOTS || !g_fls_slots[index].used) {
        return STATUS_INVALID_PARAMETER;
    }
    WINEMU_FLS_THREAD* thr = fls_thread_entry(1);
    if (!thr) return STATUS_NO_MEMORY;
    thr->values[index] = value;
    return 0;
}

EXPORT NTSTATUS RtlFlsGetValue(ULONG index, void** value_out) {
    if (!value_out) return STATUS_INVALID_PARAMETER;
    if (index >= WINEMU_FLS_MAX_SLOTS || !g_fls_slots[index].used) {
        return STATUS_INVALID_PARAMETER;
    }
    WINEMU_FLS_THREAD* thr = fls_thread_entry(0);
    *value_out = thr ? thr->values[index] : NULL;
    return 0;
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

EXPORT NTSTATUS NtProtectVirtualMemory(
    HANDLE process_handle, void** base_address, size_t* region_size, ULONG new_protection, ULONG* old_protection)
{
    return syscall6(
        NR_PROTECT_VIRTUAL_MEM,
        (uint64_t)process_handle,
        (uint64_t)base_address,
        (uint64_t)region_size,
        (uint64_t)new_protection,
        (uint64_t)old_protection,
        0
    );
}

EXPORT NTSTATUS NtQueryVirtualMemory(
    HANDLE process_handle, void* base_address, ULONG memory_information_class,
    void* memory_information, size_t memory_information_length, size_t* return_length)
{
    return syscall6(
        NR_QUERY_VIRTUAL_MEM,
        (uint64_t)process_handle,
        (uint64_t)base_address,
        (uint64_t)memory_information_class,
        (uint64_t)memory_information,
        (uint64_t)memory_information_length,
        (uint64_t)return_length
    );
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

typedef struct {
    uint64_t magic;
    uint64_t size;
} WINEMU_HEAP_HDR;

#define WINEMU_HEAP_HDR_MAGIC 0x5748454150484452ULL
#define WINEMU_HEAP_HDR_SIZE  ((size_t)sizeof(WINEMU_HEAP_HDR))

static size_t align_up(size_t v, size_t a) {
    return (v + (a - 1)) & ~(a - 1);
}

/* Minimal process-heap bootstrap for kernelbase/ucrt startup.
 * We keep a single pseudo/default heap handle in PEB.ProcessHeap. */
#define TEB_PEB_OFFSET         0x60
#define PEB_PROCESS_HEAP_OFF   0x30

static void* rtl_query_peb(void) {
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    if (!teb) return NULL;
    return *(void**)(teb + TEB_PEB_OFFSET);
}

static void* rtl_query_process_heap(void) {
    uint8_t* peb = (uint8_t*)rtl_query_peb();
    if (!peb) return NULL;
    return *(void**)(peb + PEB_PROCESS_HEAP_OFF);
}

static void rtl_set_process_heap(void* heap) {
    uint8_t* peb = (uint8_t*)rtl_query_peb();
    if (!peb) return;
    *(void**)(peb + PEB_PROCESS_HEAP_OFF) = heap;
}

EXPORT void* RtlCreateHeap(
    ULONG flags, void* heap_base, size_t reserve_size, size_t commit_size, void* lock, void* params)
{
    (void)flags;
    (void)reserve_size;
    (void)commit_size;
    (void)lock;
    (void)params;

    if (heap_base) {
        rtl_set_process_heap(heap_base);
        return heap_base;
    }
    void* heap = rtl_query_process_heap();
    if (!heap) {
        heap = (void*)0x10000;
        rtl_set_process_heap(heap);
    }
    return heap;
}

EXPORT void* RtlDestroyHeap(void* heap) {
    (void)heap;
    return NULL;
}

EXPORT ULONG RtlGetProcessHeaps(ULONG number_of_heaps, HANDLE* process_heaps) {
    void* heap = rtl_query_process_heap();
    if (!heap) {
        heap = (void*)0x10000;
        rtl_set_process_heap(heap);
    }
    if (number_of_heaps != 0 && process_heaps) {
        process_heaps[0] = heap;
    }
    return 1;
}

EXPORT void* RtlAllocateHeap(HANDLE heap, ULONG flags, size_t size) {
    (void)heap; (void)flags;
    size_t need = align_up(size ? size : 1, 16);
    size_t total = align_up(need + WINEMU_HEAP_HDR_SIZE, 16);
    void* raw = NULL;
    size_t sz = total;
    NTSTATUS st = NtAllocateVirtualMemory(
        (HANDLE)(uint64_t)-1, &raw, 0, &sz, 0x3000, 4);
    if (st != 0 || !raw) return NULL;

    WINEMU_HEAP_HDR* hdr = (WINEMU_HEAP_HDR*)raw;
    hdr->magic = WINEMU_HEAP_HDR_MAGIC;
    hdr->size = size;
    return (void*)((uint8_t*)raw + WINEMU_HEAP_HDR_SIZE);
}

EXPORT int RtlFreeHeap(HANDLE heap, ULONG flags, void* ptr) {
    (void)heap; (void)flags;
    if (!ptr) return 1;
    WINEMU_HEAP_HDR* hdr = (WINEMU_HEAP_HDR*)((uint8_t*)ptr - WINEMU_HEAP_HDR_SIZE);
    if (hdr->magic != WINEMU_HEAP_HDR_MAGIC) return 1;
    size_t sz = 0;
    void* raw = (void*)hdr;
    NTSTATUS st = NtFreeVirtualMemory((HANDLE)(uint64_t)-1, &raw, &sz, 0x8000);
    return st == 0 ? 1 : 0;
}

EXPORT void* RtlReAllocateHeap(HANDLE heap, ULONG flags, void* ptr, size_t size) {
    if (!ptr) return RtlAllocateHeap(heap, flags, size);
    WINEMU_HEAP_HDR* hdr = (WINEMU_HEAP_HDR*)((uint8_t*)ptr - WINEMU_HEAP_HDR_SIZE);
    if (hdr->magic != WINEMU_HEAP_HDR_MAGIC) return NULL;
    size_t old_size = (size_t)hdr->size;

    void* newp = RtlAllocateHeap(heap, flags, size);
    if (!newp) return NULL;

    size_t copy_len = old_size < size ? old_size : size;
    const uint8_t* src = (const uint8_t*)ptr;
    uint8_t* dst = (uint8_t*)newp;
    for (size_t i = 0; i < copy_len; i++) {
        dst[i] = src[i];
    }
    RtlFreeHeap(heap, flags, ptr);
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

EXPORT NTSTATUS RtlInitializeCriticalSectionEx(RTL_CRITICAL_SECTION* cs, ULONG spin, ULONG flags) {
    (void)flags;
    return RtlInitializeCriticalSectionAndSpinCount(cs, spin);
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

EXPORT void RtlInitializeSRWLock(void* lock) {
    if (lock) {
        *(volatile uint64_t*)lock = 0;
    }
}

EXPORT void RtlAcquireSRWLockExclusive(void* lock) {
    (void)lock;
}

EXPORT void RtlAcquireSRWLockShared(void* lock) {
    (void)lock;
}

EXPORT void RtlReleaseSRWLockExclusive(void* lock) {
    (void)lock;
}

EXPORT void RtlReleaseSRWLockShared(void* lock) {
    (void)lock;
}

EXPORT int RtlTryAcquireSRWLockExclusive(void* lock) {
    (void)lock;
    return 1;
}

EXPORT int RtlTryAcquireSRWLockShared(void* lock) {
    (void)lock;
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

/* ── Basic CRT exports required by kernelbase/kernel32 ─────── */

EXPORT ULONG_PTR __chkstk(void) {
    return 0;
}

EXPORT void* memset(void* dst, int c, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    for (size_t i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}

EXPORT void* memcpy(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

EXPORT void* memmove(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    if (d == s || n == 0) return dst;
    if (d < s) {
        for (size_t i = 0; i < n; i++) d[i] = s[i];
    } else {
        size_t i = n;
        while (i != 0) {
            i--;
            d[i] = s[i];
        }
    }
    return dst;
}

EXPORT int memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    for (size_t i = 0; i < n; i++) {
        if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    }
    return 0;
}

static int ascii_tolower(int ch) {
    if (ch >= 'A' && ch <= 'Z') return ch + 32;
    return ch;
}

static int wide_tolower(int ch) {
    if (ch >= L'A' && ch <= L'Z') return ch + 32;
    return ch;
}

EXPORT int tolower(int ch) {
    return ascii_tolower(ch);
}

EXPORT int towupper(int ch) {
    if (ch >= L'a' && ch <= L'z') return ch - 32;
    return ch;
}

EXPORT int isalpha(int ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
}

EXPORT int isalnum(int ch) {
    return isalpha(ch) || (ch >= '0' && ch <= '9');
}

EXPORT int isxdigit(int ch) {
    return (ch >= '0' && ch <= '9')
        || (ch >= 'a' && ch <= 'f')
        || (ch >= 'A' && ch <= 'F');
}

EXPORT size_t strlen(const char* s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

EXPORT int strcmp(const char* a, const char* b) {
    size_t i = 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) return (unsigned char)a[i] - (unsigned char)b[i];
        i++;
    }
    return (unsigned char)a[i] - (unsigned char)b[i];
}

EXPORT int strncmp(const char* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char ac = (unsigned char)a[i];
        unsigned char bc = (unsigned char)b[i];
        if (ac != bc) return ac - bc;
        if (ac == 0) return 0;
    }
    return 0;
}

EXPORT char* strcpy(char* dst, const char* src) {
    size_t i = 0;
    do {
        dst[i] = src[i];
    } while (src[i++] != 0);
    return dst;
}

EXPORT char* strcat(char* dst, const char* src) {
    size_t d = strlen(dst);
    size_t i = 0;
    do {
        dst[d + i] = src[i];
    } while (src[i++] != 0);
    return dst;
}

EXPORT char* strchr(const char* s, int ch) {
    unsigned char c = (unsigned char)ch;
    while (*s) {
        if ((unsigned char)*s == c) return (char*)s;
        s++;
    }
    if (c == 0) return (char*)s;
    return NULL;
}

EXPORT char* strrchr(const char* s, int ch) {
    char* last = NULL;
    unsigned char c = (unsigned char)ch;
    while (*s) {
        if ((unsigned char)*s == c) last = (char*)s;
        s++;
    }
    if (c == 0) return (char*)s;
    return last;
}

EXPORT int _strnicmp(const char* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int ac = ascii_tolower((unsigned char)a[i]);
        int bc = ascii_tolower((unsigned char)b[i]);
        if (ac != bc) return ac - bc;
        if (ac == 0) return 0;
    }
    return 0;
}

EXPORT long strtol(const char* nptr, char** endptr, int base) {
    const char* p = nptr;
    int neg = 0;
    unsigned long v = 0;
    if (!p) {
        if (endptr) *endptr = (char*)nptr;
        return 0;
    }
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '+' || *p == '-') {
        neg = (*p == '-');
        p++;
    }
    if (base == 0) {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
            base = 16;
            p += 2;
        } else if (p[0] == '0') {
            base = 8;
            p++;
        } else {
            base = 10;
        }
    }
    while (*p) {
        int d;
        if (*p >= '0' && *p <= '9') d = *p - '0';
        else if (*p >= 'a' && *p <= 'z') d = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'Z') d = *p - 'A' + 10;
        else break;
        if (d >= base) break;
        v = v * (unsigned)base + (unsigned)d;
        p++;
    }
    if (endptr) *endptr = (char*)p;
    return neg ? -(long)v : (long)v;
}

EXPORT size_t wcslen(const WCHAR* s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

EXPORT size_t wcsnlen(const WCHAR* s, size_t n) {
    size_t i = 0;
    if (!s) return 0;
    while (i < n && s[i]) i++;
    return i;
}

EXPORT int wcscmp(const WCHAR* a, const WCHAR* b) {
    size_t i = 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) return (int)a[i] - (int)b[i];
        i++;
    }
    return (int)a[i] - (int)b[i];
}

EXPORT int wcsncmp(const WCHAR* a, const WCHAR* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)a[i] - (int)b[i];
        if (a[i] == 0) return 0;
    }
    return 0;
}

EXPORT WCHAR* wcscpy(WCHAR* dst, const WCHAR* src) {
    size_t i = 0;
    do {
        dst[i] = src[i];
    } while (src[i++] != 0);
    return dst;
}

EXPORT WCHAR* wcscat(WCHAR* dst, const WCHAR* src) {
    size_t d = wcslen(dst);
    size_t i = 0;
    do {
        dst[d + i] = src[i];
    } while (src[i++] != 0);
    return dst;
}

EXPORT WCHAR* wcschr(const WCHAR* s, WCHAR ch) {
    while (*s) {
        if (*s == ch) return (WCHAR*)s;
        s++;
    }
    if (ch == 0) return (WCHAR*)s;
    return NULL;
}

EXPORT WCHAR* wcsrchr(const WCHAR* s, WCHAR ch) {
    WCHAR* last = NULL;
    while (*s) {
        if (*s == ch) last = (WCHAR*)s;
        s++;
    }
    if (ch == 0) return (WCHAR*)s;
    return last;
}

EXPORT WCHAR* wcspbrk(const WCHAR* s, const WCHAR* accept) {
    for (; *s; s++) {
        for (const WCHAR* a = accept; *a; a++) {
            if (*s == *a) return (WCHAR*)s;
        }
    }
    return NULL;
}

EXPORT size_t wcscspn(const WCHAR* s, const WCHAR* reject) {
    size_t n = 0;
    while (s[n]) {
        for (const WCHAR* r = reject; *r; r++) {
            if (s[n] == *r) return n;
        }
        n++;
    }
    return n;
}

EXPORT size_t wcsspn(const WCHAR* s, const WCHAR* accept) {
    size_t n = 0;
    while (s[n]) {
        int ok = 0;
        for (const WCHAR* a = accept; *a; a++) {
            if (s[n] == *a) {
                ok = 1;
                break;
            }
        }
        if (!ok) break;
        n++;
    }
    return n;
}

EXPORT WCHAR* wcsstr(const WCHAR* haystack, const WCHAR* needle) {
    if (!needle || !needle[0]) return (WCHAR*)haystack;
    for (size_t i = 0; haystack[i]; i++) {
        size_t j = 0;
        while (needle[j] && haystack[i + j] == needle[j]) j++;
        if (!needle[j]) return (WCHAR*)(haystack + i);
    }
    return NULL;
}

EXPORT int _wcsicmp(const WCHAR* a, const WCHAR* b) {
    size_t i = 0;
    while (a[i] && b[i]) {
        int ac = wide_tolower(a[i]);
        int bc = wide_tolower(b[i]);
        if (ac != bc) return ac - bc;
        i++;
    }
    return wide_tolower(a[i]) - wide_tolower(b[i]);
}

EXPORT int _wcsnicmp(const WCHAR* a, const WCHAR* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int ac = wide_tolower(a[i]);
        int bc = wide_tolower(b[i]);
        if (ac != bc) return ac - bc;
        if (ac == 0) return 0;
    }
    return 0;
}

EXPORT long wcstol(const WCHAR* nptr, WCHAR** endptr, int base) {
    const WCHAR* p = nptr;
    int neg = 0;
    unsigned long v = 0;
    if (!p) {
        if (endptr) *endptr = (WCHAR*)nptr;
        return 0;
    }
    while (*p == L' ' || *p == L'\t' || *p == L'\n' || *p == L'\r') p++;
    if (*p == L'+' || *p == L'-') {
        neg = (*p == L'-');
        p++;
    }
    if (base == 0) {
        if (p[0] == L'0' && (p[1] == L'x' || p[1] == L'X')) {
            base = 16;
            p += 2;
        } else if (p[0] == L'0') {
            base = 8;
            p++;
        } else {
            base = 10;
        }
    }
    while (*p) {
        int d;
        if (*p >= L'0' && *p <= L'9') d = *p - L'0';
        else if (*p >= L'a' && *p <= L'z') d = *p - L'a' + 10;
        else if (*p >= L'A' && *p <= L'Z') d = *p - L'A' + 10;
        else break;
        if (d >= base) break;
        v = v * (unsigned)base + (unsigned)d;
        p++;
    }
    if (endptr) *endptr = (WCHAR*)p;
    return neg ? -(long)v : (long)v;
}

EXPORT unsigned long wcstoul(const WCHAR* nptr, WCHAR** endptr, int base) {
    long v = wcstol(nptr, endptr, base);
    return (unsigned long)v;
}

/* ── Misc ────────────────────────────────────────────────────── */

EXPORT NTSTATUS RtlGetVersion(void* osvi) {
    if (!osvi) return STATUS_INVALID_PARAMETER;
    ULONG size = *(ULONG*)osvi;
    if (size < 20) return STATUS_INVALID_PARAMETER;

    uint8_t* p = (uint8_t*)osvi;
    for (ULONG i = 4; i < size; i++) {
        p[i] = 0;
    }

    *(ULONG*)(p + 4) = 10;      // dwMajorVersion
    *(ULONG*)(p + 8) = 0;       // dwMinorVersion
    *(ULONG*)(p + 12) = 19045;  // dwBuildNumber
    *(ULONG*)(p + 16) = 2;      // VER_PLATFORM_WIN32_NT
    return STATUS_SUCCESS;
}

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

EXPORT ULONG NtGetTickCount(void) {
    int64_t now = 0;
    if (NtQuerySystemTime(&now) != 0) return 0;
    return (ULONG)(now / 10000);
}

EXPORT NTSTATUS NtQueryPerformanceCounter(int64_t* counter, int64_t* frequency) {
    return syscall2(
        NR_QUERY_PERFORMANCE_COUNTER,
        (uint64_t)counter,
        (uint64_t)frequency
    );
}

EXPORT int RtlQueryPerformanceCounter(int64_t* counter) {
    return NtQueryPerformanceCounter(counter, NULL) == 0;
}

EXPORT int RtlQueryPerformanceFrequency(int64_t* frequency) {
    return NtQueryPerformanceCounter(NULL, frequency) == 0;
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

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct {
    uint8_t Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550

static IMAGE_NT_HEADERS64* image_nt_headers(void* image_base) {
    if (!image_base) return NULL;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)image_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    if (dos->e_lfanew < 0 || dos->e_lfanew > 0x400000) return NULL;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)image_base + (uint32_t)dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return nt;
}

static IMAGE_SECTION_HEADER* image_first_section(IMAGE_NT_HEADERS64* nt) {
    if (!nt) return NULL;
    return (IMAGE_SECTION_HEADER*)((uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
}

static uint32_t section_span(const IMAGE_SECTION_HEADER* sec) {
    uint32_t v = sec->Misc.VirtualSize;
    uint32_t r = sec->SizeOfRawData;
    return (v > r) ? v : r;
}

EXPORT void* RtlImageNtHeader(void* image_base) {
    return image_nt_headers(image_base);
}

EXPORT void* RtlImageDirectoryEntryToData(
    void* image_base, UCHAR mapped_as_image, ULONG directory_entry, ULONG* size)
{
    if (size) *size = 0;
    IMAGE_NT_HEADERS64* nt = image_nt_headers(image_base);
    if (!nt || directory_entry >= 16) return NULL;
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[directory_entry];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return NULL;
    if (size) *size = dir.Size;

    if (mapped_as_image) {
        return (uint8_t*)image_base + dir.VirtualAddress;
    }

    IMAGE_SECTION_HEADER* sec = image_first_section(nt);
    for (uint32_t i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        uint32_t start = sec->VirtualAddress;
        uint32_t end = start + section_span(sec);
        if (dir.VirtualAddress >= start && dir.VirtualAddress < end) {
            uint32_t delta = dir.VirtualAddress - start;
            return (uint8_t*)image_base + sec->PointerToRawData + delta;
        }
    }
    return NULL;
}

EXPORT void* RtlImageRvaToVa(void* nt_headers, void* image_base, ULONG rva, void** last_rva_section) {
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)nt_headers;
    if (!nt || !image_base) return NULL;

    if (last_rva_section && *last_rva_section) {
        IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)(*last_rva_section);
        uint32_t start = sec->VirtualAddress;
        uint32_t end = start + section_span(sec);
        if (rva >= start && rva < end) {
            return (uint8_t*)image_base + rva;
        }
    }

    IMAGE_SECTION_HEADER* sec = image_first_section(nt);
    for (uint32_t i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        uint32_t start = sec->VirtualAddress;
        uint32_t end = start + section_span(sec);
        if (rva >= start && rva < end) {
            if (last_rva_section) *last_rva_section = sec;
            return (uint8_t*)image_base + rva;
        }
    }

    if (rva < nt->OptionalHeader.SizeOfHeaders) {
        return (uint8_t*)image_base + rva;
    }
    return NULL;
}

EXPORT void* RtlGetCurrentPeb(void) {
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    if (!teb) return NULL;
    return *(void**)(teb + 0x60);
}

EXPORT void* RtlPcToFileHeader(void* pc_value, void** base_of_image) {
    void* base = NULL;
    uint8_t* peb = (uint8_t*)RtlGetCurrentPeb();
    uint64_t pc = (uint64_t)(uintptr_t)pc_value;

    if (peb && pc_value) {
        uint64_t ldr = *(uint64_t*)(peb + 0x18);
        if (ldr != 0) {
            uint64_t head = ldr + 0x10;
            uint64_t link = *(uint64_t*)(uintptr_t)head;
            for (unsigned i = 0; i < 1024 && link != 0 && link != head; i++) {
                uint64_t entry = link; /* InLoadOrderLinks is at +0x0 */
                uint64_t dll_base = *(uint64_t*)(uintptr_t)(entry + 0x30);
                uint32_t size_of_image = *(uint32_t*)(uintptr_t)(entry + 0x40);
                if (size_of_image != 0 &&
                    pc >= dll_base &&
                    pc < dll_base + (uint64_t)size_of_image) {
                    base = (void*)(uintptr_t)dll_base;
                    break;
                }
                link = *(uint64_t*)(uintptr_t)link;
            }
        }
    }
    if (!base) {
        base = peb ? *(void**)(peb + 0x10) : NULL;
    }
    if (base && pc_value) {
        IMAGE_NT_HEADERS64* nt = image_nt_headers(base);
        if (!nt) {
            base = NULL;
        } else {
            uint64_t start = (uint64_t)(uintptr_t)base;
            uint64_t end = start + nt->OptionalHeader.SizeOfImage;
            if (pc < start || pc >= end) {
                base = NULL;
            }
        }
    }
    if (base_of_image) *base_of_image = base;
    return base;
}

typedef struct {
    uint32_t BeginAddress;
    union {
        uint32_t UnwindData;
        struct {
            uint32_t Flag : 2;
            uint32_t FunctionLength : 11;
            uint32_t RegF : 3;
            uint32_t RegI : 4;
            uint32_t H : 1;
            uint32_t CR : 2;
            uint32_t FrameSize : 9;
        };
    };
} RUNTIME_FUNCTION_ARM64;

EXPORT RUNTIME_FUNCTION_ARM64* RtlLookupFunctionEntry(
    uint64_t control_pc, uint64_t* image_base, void* history_table)
{
    (void)history_table;
    void* base = NULL;
    if (!RtlPcToFileHeader((void*)(uintptr_t)control_pc, &base) || !base) {
        if (image_base) *image_base = 0;
        return NULL;
    }
    if (image_base) *image_base = (uint64_t)(uintptr_t)base;
    if (control_pc < (uint64_t)(uintptr_t)base) {
        return NULL;
    }

    ULONG dir_size = 0;
    RUNTIME_FUNCTION_ARM64* table =
        (RUNTIME_FUNCTION_ARM64*)RtlImageDirectoryEntryToData(base, 1, 3, &dir_size);
    if (!table || dir_size < sizeof(RUNTIME_FUNCTION_ARM64)) {
        return NULL;
    }
    uint32_t count = dir_size / (uint32_t)sizeof(RUNTIME_FUNCTION_ARM64);
    if (count == 0) {
        return NULL;
    }

    uint32_t pc_rva = (uint32_t)(control_pc - (uint64_t)(uintptr_t)base);
    uint32_t lo = 0;
    uint32_t hi = count;
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        uint32_t begin = table[mid].BeginAddress;
        if (begin <= pc_rva) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo == 0) {
        return NULL;
    }
    uint32_t idx = lo - 1;
    uint32_t begin = table[idx].BeginAddress;
    if (begin > pc_rva) {
        return NULL;
    }
    uint32_t len_words = 0;
    if (table[idx].Flag) {
        len_words = table[idx].FunctionLength;
    } else {
        uint64_t xdata = (uint64_t)(uintptr_t)base + table[idx].UnwindData;
        if (!xdata) return NULL;
        len_words = *(const uint32_t*)(uintptr_t)xdata & 0x3ffffU;
    }
    uint64_t end = (uint64_t)begin + ((uint64_t)len_words * 4ULL);
    if ((uint64_t)pc_rva >= end) {
        return NULL;
    }
    return &table[idx];
}

EXPORT ULONG RtlRandom(ULONG* seed) {
    if (!seed) return 0;
    *seed = (*seed * 0x343fdU + 0x269ec3U);
    return (*seed >> 16) & 0x7fffU;
}

typedef struct {
    void* ptr;
} RTL_RUN_ONCE;

typedef NTSTATUS (*PRTL_RUN_ONCE_INIT_FN)(RTL_RUN_ONCE*, void*, void**);

EXPORT void RtlRunOnceInitialize(RTL_RUN_ONCE* once) {
    if (once) once->ptr = NULL;
}

EXPORT NTSTATUS RtlRunOnceBeginInitialize(
    RTL_RUN_ONCE* once, ULONG flags, ULONG* pending, void** context)
{
    (void)flags;
    if (!once) return STATUS_INVALID_PARAMETER;
    if (pending) *pending = (once->ptr == NULL) ? 1 : 0;
    if (context) *context = (once->ptr == (void*)1) ? NULL : once->ptr;
    return 0;
}

EXPORT NTSTATUS RtlRunOnceComplete(RTL_RUN_ONCE* once, ULONG flags, void* context) {
    (void)flags;
    if (!once) return STATUS_INVALID_PARAMETER;
    once->ptr = context ? context : (void*)1;
    return 0;
}

EXPORT NTSTATUS RtlRunOnceExecuteOnce(
    RTL_RUN_ONCE* once, PRTL_RUN_ONCE_INIT_FN init_fn, void* parameter, void** context)
{
    if (!once || !init_fn) return STATUS_INVALID_PARAMETER;
    if (once->ptr) {
        if (context) *context = (once->ptr == (void*)1) ? NULL : once->ptr;
        return 0;
    }
    void* local_ctx = NULL;
    NTSTATUS st = init_fn(once, parameter, &local_ctx);
    if (st == 0) {
        once->ptr = local_ctx ? local_ctx : (void*)1;
        if (context) *context = local_ctx;
    }
    return st;
}

EXPORT uint64_t RtlGetEnabledExtendedFeatures(uint64_t feature_mask) {
    (void)feature_mask;
    return 0;
}

EXPORT uint64_t RtlGetExtendedFeaturesMask(void) {
    return 0;
}

EXPORT int RtlIsEcCode(const void* pc) {
    (void)pc;
    return 0;
}

EXPORT void* RtlLocateExtendedFeature(void* feature_info, uint64_t feature_id) {
    (void)feature_info;
    (void)feature_id;
    return NULL;
}

EXPORT void RtlSetExtendedFeaturesMask(uint64_t feature_mask) {
    (void)feature_mask;
}

EXPORT NTSTATUS RtlWow64GetThreadContext(HANDLE thread, void* ctx) {
    (void)thread;
    (void)ctx;
    return STATUS_NOT_IMPLEMENTED;
}

EXPORT NTSTATUS RtlWow64SetThreadContext(HANDLE thread, const void* ctx) {
    (void)thread;
    (void)ctx;
    return STATUS_NOT_IMPLEMENTED;
}

EXPORT ULONG_PTR __chkstk_arm64ec(void) {
    return 0;
}

EXPORT int _setjmp(void* env) {
    (void)env;
    return 0;
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
EXPORT NTSTATUS NtReadFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    void* io_status, void* buffer, ULONG length,
    uint64_t* byte_offset, ULONG* key)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_READ_FILE));
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

EXPORT NTSTATUS NtQueryInformationFile(
    HANDLE file_handle, void* io_status_block, void* file_information, ULONG length, ULONG file_information_class)
{
    return syscall6(
        NR_QUERY_INFORMATION_FILE,
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

typedef struct {
    uint32_t ExceptionCode;
    uint32_t ExceptionFlags;
    void* ExceptionRecord;
    void* ExceptionAddress;
    uint32_t NumberParameters;
    uint32_t __pad;
    uint64_t ExceptionInformation[15];
} EXCEPTION_RECORD64;

typedef union {
    struct {
        uint64_t Low;
        uint64_t High;
    };
    double D[2];
} ARM64_NT_NEON128;

typedef struct {
    uint32_t ContextFlags;
    uint32_t Cpsr;
    uint64_t X[31];
    uint64_t Sp;
    uint64_t Pc;
    ARM64_NT_NEON128 V[32];
    uint32_t Fpcr;
    uint32_t Fpsr;
    uint32_t Bcr[8];
    uint64_t Bvr[8];
    uint32_t Wcr[2];
    uint64_t Wvr[2];
} ARM64_NT_CONTEXT;

typedef uint32_t EXCEPTION_DISPOSITION;

enum {
    ExceptionContinueExecution = 0,
    ExceptionContinueSearch = 1,
    ExceptionNestedException = 2,
    ExceptionCollidedUnwind = 3
};

#define EXCEPTION_NONCONTINUABLE 0x1U
#define EXCEPTION_UNWINDING 0x2U
#define EXCEPTION_EXIT_UNWIND 0x4U
#define EXCEPTION_STACK_INVALID 0x8U
#define EXCEPTION_NESTED_CALL 0x10U
#define EXCEPTION_TARGET_UNWIND 0x20U
#define EXCEPTION_COLLIDED_UNWIND 0x40U

#define UNW_FLAG_NHANDLER 0U
#define UNW_FLAG_EHANDLER 1U
#define UNW_FLAG_UHANDLER 2U

#define CONTEXT_ARM64 0x00400000U
#define CONTEXT_FULL 0x00000007U
#define CONTEXT_UNWOUND_TO_CALL 0x20000000U

typedef struct _DISPATCHER_CONTEXT_ARM64 DISPATCHER_CONTEXT_ARM64;

typedef EXCEPTION_DISPOSITION (*PEXCEPTION_ROUTINE_ARM64)(
    EXCEPTION_RECORD64* record,
    void* frame,
    ARM64_NT_CONTEXT* context,
    DISPATCHER_CONTEXT_ARM64* dispatch
);

struct _DISPATCHER_CONTEXT_ARM64 {
    uint64_t ControlPc;
    uint64_t ImageBase;
    RUNTIME_FUNCTION_ARM64* FunctionEntry;
    uint64_t EstablisherFrame;
    uint64_t TargetPc;
    ARM64_NT_CONTEXT* ContextRecord;
    PEXCEPTION_ROUTINE_ARM64 LanguageHandler;
    void* HandlerData;
    void* HistoryTable;
    uint32_t ScopeIndex;
    uint8_t ControlPcIsUnwound;
    uint8_t Fill0[3];
    uint8_t* NonVolatileRegisters;
};

#define NONVOL_INT_NUMREG_ARM64 11U
#define NONVOL_FP_NUMREG_ARM64 8U
#define NONVOL_INT_SIZE_ARM64 (NONVOL_INT_NUMREG_ARM64 * sizeof(uint64_t))
#define NONVOL_FP_SIZE_ARM64 (NONVOL_FP_NUMREG_ARM64 * sizeof(double))

typedef union {
    uint8_t Buffer[NONVOL_INT_SIZE_ARM64 + NONVOL_FP_SIZE_ARM64];
    struct {
        uint64_t GpNvRegs[NONVOL_INT_NUMREG_ARM64];
        double FpNvRegs[NONVOL_FP_NUMREG_ARM64];
    };
} DISPATCHER_CONTEXT_NONVOLREG_ARM64;

typedef char _winemu_dispatch_nonvol_offset_check[
    (sizeof(void*) == 8 && __builtin_offsetof(DISPATCHER_CONTEXT_ARM64, NonVolatileRegisters) == 0x50)
        ? 1
        : -1
];

typedef char _winemu_dispatch_size_check[
    (sizeof(void*) == 8 && sizeof(DISPATCHER_CONTEXT_ARM64) == 0x58)
        ? 1
        : -1
];

typedef struct {
    uint32_t FunctionLength : 18;
    uint32_t Version : 2;
    uint32_t ExceptionDataPresent : 1;
    uint32_t EpilogInHeader : 1;
    uint32_t EpilogCount : 5;
    uint32_t CodeWords : 5;
} IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA;

struct unwind_info_ext {
    WORD epilog;
    BYTE codes;
    BYTE reserved;
};

struct unwind_info_epilog {
    uint32_t offset : 18;
    uint32_t res : 4;
    uint32_t index : 10;
};

static const BYTE unwind_code_len[256] = {
/* 00 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 20 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 40 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 60 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 80 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* a0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* c0 */ 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
/* e0 */ 4,1,2,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
};

static int max_i(int a, int b) {
    return (a > b) ? a : b;
}

static unsigned int get_sequence_len(BYTE* ptr, BYTE* end) {
    unsigned int ret = 0;
    while (ptr < end) {
        if (*ptr == 0xe4 || *ptr == 0xe5) break;
        if ((*ptr & 0xf8) != 0xe8) ret++;
        ptr += unwind_code_len[*ptr];
    }
    return ret;
}

static void restore_regs(int reg, int count, int pos, ARM64_NT_CONTEXT* context) {
    int i;
    int offset = max_i(0, pos);
    for (i = 0; i < count; i++) {
        context->X[reg + i] = ((DWORD64*)(uintptr_t)context->Sp)[i + offset];
    }
    if (pos < 0) context->Sp += (uint64_t)(-8 * pos);
}

static void restore_fpregs(int reg, int count, int pos, ARM64_NT_CONTEXT* context) {
    int i;
    int offset = max_i(0, pos);
    for (i = 0; i < count; i++) {
        context->V[reg + i].D[0] = ((double*)(uintptr_t)context->Sp)[i + offset];
    }
    if (pos < 0) context->Sp += (uint64_t)(-8 * pos);
}

static void restore_qregs(int reg, int count, int pos, ARM64_NT_CONTEXT* context) {
    int i;
    int offset = max_i(0, pos);
    for (i = 0; i < count; i++) {
        DWORD64* src = ((DWORD64*)(uintptr_t)context->Sp) + 2 * (i + offset);
        context->V[reg + i].Low = src[0];
        context->V[reg + i].High = src[1];
    }
    if (pos < 0) context->Sp += (uint64_t)(-16 * pos);
}

static void restore_any_reg(int reg, int count, int type, int pos, ARM64_NT_CONTEXT* context) {
    if (reg & 0x20) pos = -pos - 1;

    switch (type) {
    case 0:
        if (count > 1 || pos < 0) pos *= 2;
        restore_regs(reg & 0x1f, count, pos, context);
        break;
    case 1:
        if (count > 1 || pos < 0) pos *= 2;
        restore_fpregs(reg & 0x1f, count, pos, context);
        break;
    case 2:
        restore_qregs(reg & 0x1f, count, pos, context);
        break;
    default:
        break;
    }
}

static void do_pac_auth(ARM64_NT_CONTEXT* context) {
    register DWORD64 x17 asm("x17") = context->X[30];
    register DWORD64 x16 asm("x16") = context->Sp;
    asm volatile("hint 0xe" : "+r"(x17) : "r"(x16));
    context->X[30] = x17;
}

static void process_unwind_codes(
    BYTE* ptr, BYTE* end, ARM64_NT_CONTEXT* context, int skip, int* final_pc_from_lr)
{
    unsigned int val;
    unsigned int len;
    unsigned int save_next = 2;

    while (ptr < end && skip) {
        if (*ptr == 0xe4) break;
        ptr += unwind_code_len[*ptr];
        skip--;
    }

    while (ptr < end) {
        if ((len = unwind_code_len[*ptr]) > 1) {
            if (ptr + len > end) break;
            val = (unsigned int)ptr[0] * 0x100U + (unsigned int)ptr[1];
        } else {
            val = *ptr;
        }

        if (*ptr < 0x20) {
            context->Sp += 16U * (val & 0x1fU);
        } else if (*ptr < 0x40) {
            restore_regs(19, (int)save_next, -(int)(val & 0x1fU), context);
        } else if (*ptr < 0x80) {
            restore_regs(29, 2, (int)(val & 0x3fU), context);
        } else if (*ptr < 0xc0) {
            restore_regs(29, 2, -(int)(val & 0x3fU) - 1, context);
        } else if (*ptr < 0xc8) {
            context->Sp += 16U * (val & 0x7ffU);
        } else if (*ptr < 0xcc) {
            restore_regs(19 + ((int)(val >> 6) & 0xf), (int)save_next, (int)(val & 0x3fU), context);
        } else if (*ptr < 0xd0) {
            restore_regs(19 + ((int)(val >> 6) & 0xf), (int)save_next, -(int)(val & 0x3fU) - 1, context);
        } else if (*ptr < 0xd4) {
            restore_regs(19 + ((int)(val >> 6) & 0xf), 1, (int)(val & 0x3fU), context);
        } else if (*ptr < 0xd6) {
            restore_regs(19 + ((int)(val >> 5) & 0xf), 1, -(int)(val & 0x1fU) - 1, context);
        } else if (*ptr < 0xd8) {
            restore_regs(19 + 2 * ((int)(val >> 6) & 0x7), 1, (int)(val & 0x3fU), context);
            restore_regs(30, 1, (int)(val & 0x3fU) + 1, context);
        } else if (*ptr < 0xda) {
            restore_fpregs(8 + ((int)(val >> 6) & 0x7), (int)save_next, (int)(val & 0x3fU), context);
        } else if (*ptr < 0xdc) {
            restore_fpregs(8 + ((int)(val >> 6) & 0x7), (int)save_next, -(int)(val & 0x3fU) - 1, context);
        } else if (*ptr < 0xde) {
            restore_fpregs(8 + ((int)(val >> 6) & 0x7), 1, (int)(val & 0x3fU), context);
        } else if (*ptr == 0xde) {
            restore_fpregs(8 + ((int)(val >> 5) & 0x7), 1, -(int)(val & 0x3fU) - 1, context);
        } else if (*ptr == 0xe0) {
            context->Sp += 16U * ((unsigned int)ptr[1] << 16 | (unsigned int)ptr[2] << 8 | (unsigned int)ptr[3]);
        } else if (*ptr == 0xe1) {
            context->Sp = context->X[29];
        } else if (*ptr == 0xe2) {
            context->Sp = context->X[29] - 8U * (val & 0xffU);
        } else if (*ptr == 0xe3) {
            /* nop */
        } else if (*ptr == 0xe4) {
            break;
        } else if (*ptr == 0xe5) {
            /* end_c */
        } else if (*ptr == 0xe6) {
            save_next += 2;
            ptr += len;
            continue;
        } else if (*ptr == 0xe7) {
            restore_any_reg(ptr[1], (ptr[1] & 0x40) ? (int)save_next : 1, ptr[2] >> 6, ptr[2] & 0x3f, context);
        } else if (*ptr == 0xe9) {
            context->Pc = ((DWORD64*)(uintptr_t)context->Sp)[1];
            context->Sp = ((DWORD64*)(uintptr_t)context->Sp)[0];
            context->ContextFlags &= ~CONTEXT_UNWOUND_TO_CALL;
            *final_pc_from_lr = 0;
        } else if (*ptr == 0xea) {
            uint32_t flags = context->ContextFlags & ~CONTEXT_UNWOUND_TO_CALL;
            ARM64_NT_CONTEXT* src_ctx = (ARM64_NT_CONTEXT*)(uintptr_t)context->Sp;
            *context = *src_ctx;
            context->ContextFlags = flags | (src_ctx->ContextFlags & CONTEXT_UNWOUND_TO_CALL);
            *final_pc_from_lr = 0;
        } else if (*ptr == 0xec) {
            context->Pc = context->X[30];
            context->ContextFlags &= ~CONTEXT_UNWOUND_TO_CALL;
            *final_pc_from_lr = 0;
        } else if (*ptr == 0xfc) {
            do_pac_auth(context);
        } else {
            return;
        }
        save_next = 2;
        ptr += len;
    }
}

static void* unwind_packed_data(ULONG_PTR base, ULONG_PTR pc, RUNTIME_FUNCTION_ARM64* func, ARM64_NT_CONTEXT* context) {
    int i;
    unsigned int len;
    unsigned int offset;
    unsigned int skip = 0;
    unsigned int int_size = func->RegI * 8U;
    unsigned int fp_size = func->RegF * 8U;
    unsigned int h_size = func->H * 4U;
    unsigned int regsave;
    unsigned int local_size;
    unsigned int int_regs;
    unsigned int fp_regs;
    unsigned int saved_regs;
    unsigned int local_size_regs;

    if (func->CR == 1) int_size += 8U;
    if (func->RegF) fp_size += 8U;

    regsave = (unsigned int)(((int_size + fp_size + 8U * 8U * func->H) + 0xfU) & ~0xfU);
    local_size = func->FrameSize * 16U - regsave;

    int_regs = int_size / 8U;
    fp_regs = fp_size / 8U;
    saved_regs = regsave / 8U;
    local_size_regs = local_size / 8U;

    if (func->Flag == 1) {
        offset = (unsigned int)(((pc - base) - func->BeginAddress) / 4U);
        if (offset < 17U || offset >= func->FunctionLength - 15U) {
            len = (int_size + 8U) / 16U + (fp_size + 8U) / 16U;
            switch (func->CR) {
            case 2:
                len++;
                /* fall through */
            case 3:
                len += 2U;
                if (local_size <= 512U) break;
                /* fall through */
            case 0:
            case 1:
                if (local_size) len++;
                if (local_size > 4088U) len++;
                break;
            default:
                break;
            }
            if (offset < len + h_size) {
                skip = len + h_size - offset;
            } else if (offset >= func->FunctionLength - (len + 1U)) {
                skip = offset - (func->FunctionLength - (len + 1U));
                h_size = 0;
            }
        }
    }

    if (!skip) {
        if (func->CR == 3 || func->CR == 2) {
            context->Sp = context->X[29];
            restore_regs(29, 2, 0, context);
        }
        context->Sp += local_size;
        if (fp_size) restore_fpregs(8, (int)fp_regs, (int)int_regs, context);
        if (func->CR == 1) restore_regs(30, 1, (int)int_regs - 1, context);
        restore_regs(19, (int)func->RegI, -(int)saved_regs, context);
    } else {
        unsigned int pos = 0;
        switch (func->CR) {
        case 3:
        case 2:
            if (pos++ >= skip) context->Sp = context->X[29];
            if (local_size <= 512U) {
                if (pos++ >= skip) restore_regs(29, 2, -(int)local_size_regs, context);
                break;
            }
            if (pos++ >= skip) restore_regs(29, 2, 0, context);
            /* fall through */
        case 0:
        case 1:
            if (!local_size) break;
            if (pos++ >= skip) context->Sp += (local_size - 1U) % 4088U + 1U;
            if (local_size > 4088U && pos++ >= skip) context->Sp += 4088U;
            break;
        default:
            break;
        }

        pos += h_size;
        if (fp_size) {
            if (func->RegF % 2 == 0 && pos++ >= skip) {
                restore_fpregs(8 + func->RegF, 1, (int)int_regs + (int)fp_regs - 1, context);
            }
            for (i = (int)((func->RegF + 1U) / 2U) - 1; i >= 0; i--) {
                if (pos++ < skip) continue;
                if (!i && !int_size) {
                    restore_fpregs(8, 2, -(int)saved_regs, context);
                } else {
                    restore_fpregs(8 + 2 * i, 2, (int)int_regs + 2 * i, context);
                }
            }
        }

        if (func->RegI % 2U) {
            if (pos++ >= skip) {
                if (func->CR == 1) restore_regs(30, 1, (int)int_regs - 1, context);
                restore_regs(18 + func->RegI, 1, (func->RegI > 1U) ? (int)func->RegI - 1 : -(int)saved_regs, context);
            }
        } else if (func->CR == 1) {
            if (pos++ >= skip) restore_regs(30, 1, func->RegI ? (int)int_regs - 1 : -(int)saved_regs, context);
        }

        for (i = (int)(func->RegI / 2U) - 1; i >= 0; i--) {
            if (pos++ < skip) continue;
            if (i) {
                restore_regs(19 + 2 * i, 2, 2 * i, context);
            } else {
                restore_regs(19, 2, -(int)saved_regs, context);
            }
        }
    }
    if (func->CR == 2) do_pac_auth(context);
    return NULL;
}

static void* unwind_full_data(
    ULONG_PTR base, ULONG_PTR pc, RUNTIME_FUNCTION_ARM64* func, ARM64_NT_CONTEXT* context,
    void** handler_data, int* final_pc_from_lr)
{
    IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA* info;
    struct unwind_info_epilog* info_epilog;
    unsigned int i;
    unsigned int codes;
    unsigned int epilogs;
    unsigned int len;
    unsigned int offset;
    void* data;
    BYTE* end;

    info = (IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA*)((char*)(uintptr_t)base + func->UnwindData);
    data = info + 1;
    epilogs = info->EpilogCount;
    codes = info->CodeWords;
    if (!codes && !epilogs) {
        struct unwind_info_ext* infoex = (struct unwind_info_ext*)data;
        codes = infoex->codes;
        epilogs = infoex->epilog;
        data = infoex + 1;
    }
    info_epilog = (struct unwind_info_epilog*)data;
    if (!info->EpilogInHeader) data = info_epilog + epilogs;

    offset = (unsigned int)(((pc - base) - func->BeginAddress) / 4U);
    end = (BYTE*)data + codes * 4U;

    if (offset < codes * 4U) {
        len = get_sequence_len((BYTE*)data, end);
        if (offset < len) {
            process_unwind_codes((BYTE*)data, end, context, (int)(len - offset), final_pc_from_lr);
            return NULL;
        }
    }

    if (!info->EpilogInHeader) {
        for (i = 0; i < epilogs; i++) {
            if (offset < info_epilog[i].offset) break;
            if (offset - info_epilog[i].offset < codes * 4U - info_epilog[i].index) {
                BYTE* ptr = (BYTE*)data + info_epilog[i].index;
                len = get_sequence_len(ptr, end);
                if (offset <= info_epilog[i].offset + len) {
                    process_unwind_codes(ptr, end, context, (int)(offset - info_epilog[i].offset), final_pc_from_lr);
                    return NULL;
                }
            }
        }
    } else if (info->FunctionLength - offset <= codes * 4U - epilogs) {
        BYTE* ptr = (BYTE*)data + epilogs;
        len = get_sequence_len(ptr, end) + 1U;
        if (offset >= info->FunctionLength - len) {
            process_unwind_codes(ptr, end, context, (int)(offset - (info->FunctionLength - len)), final_pc_from_lr);
            return NULL;
        }
    }

    process_unwind_codes((BYTE*)data, end, context, 0, final_pc_from_lr);
    if (info->ExceptionDataPresent) {
        DWORD* handler_rva = (DWORD*)data + codes;
        *handler_data = handler_rva + 1;
        return (char*)(uintptr_t)base + *handler_rva;
    }
    return NULL;
}

EXPORT NTSTATUS RtlVirtualUnwind2(
    ULONG type, ULONG_PTR base, ULONG_PTR pc, RUNTIME_FUNCTION_ARM64* func, ARM64_NT_CONTEXT* context,
    uint8_t* mach_frame_unwound, void** handler_data, ULONG_PTR* frame_ret, void* context_pointers,
    ULONG_PTR* limit_low, ULONG_PTR* limit_high, PEXCEPTION_ROUTINE_ARM64* handler_ret, ULONG flags)
{
    int final_pc_from_lr = 1;
    PEXCEPTION_ROUTINE_ARM64 handler = NULL;
    (void)mach_frame_unwound;
    (void)context_pointers;
    (void)limit_low;
    (void)limit_high;
    (void)flags;

    if (!handler_data || !frame_ret || !handler_ret || !context) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!func && pc == context->X[30]) {
        return STATUS_BAD_FUNCTION_TABLE;
    }

    *handler_data = NULL;
    context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;

    if (!func) {
        handler = NULL;
    } else if (func->Flag) {
        handler = (PEXCEPTION_ROUTINE_ARM64)unwind_packed_data(base, pc, func, context);
    } else {
        handler = (PEXCEPTION_ROUTINE_ARM64)unwind_full_data(base, pc, func, context, handler_data, &final_pc_from_lr);
    }

    if (final_pc_from_lr) context->Pc = context->X[30];
    *frame_ret = context->Sp;
    *handler_ret = handler;
    return STATUS_SUCCESS;
}

EXPORT PEXCEPTION_ROUTINE_ARM64 RtlVirtualUnwind(
    ULONG type, ULONG_PTR base, ULONG_PTR pc, RUNTIME_FUNCTION_ARM64* func, ARM64_NT_CONTEXT* context,
    void** handler_data, ULONG_PTR* frame_ret, void* context_pointers)
{
    PEXCEPTION_ROUTINE_ARM64 handler = NULL;
    if (RtlVirtualUnwind2(
            type, base, pc, func, context, NULL, handler_data, frame_ret, context_pointers,
            NULL, NULL, &handler, 0) != STATUS_SUCCESS) {
        context->Pc = 0;
        return NULL;
    }
    return handler;
}

typedef struct {
    EXCEPTION_RECORD64* ExceptionRecord;
    ARM64_NT_CONTEXT* ContextRecord;
} EXCEPTION_POINTERS64;

typedef struct {
    uint32_t Count;
    struct {
        uint32_t BeginAddress;
        uint32_t EndAddress;
        uint32_t HandlerAddress;
        uint32_t JumpTarget;
    } ScopeRecord[1];
} SCOPE_TABLE64;

#define EXCEPTION_CONTINUE_SEARCH 0
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_EXECUTION (-1)

typedef LONG (*PEXCEPTION_FILTER64)(EXCEPTION_POINTERS64* ptrs, void* frame);
typedef void (*PTERMINATION_HANDLER64)(int abnormal, void* frame);
typedef struct _EXCEPTION_REGISTRATION_RECORD64 {
    struct _EXCEPTION_REGISTRATION_RECORD64* Prev;
    void* Handler;
} EXCEPTION_REGISTRATION_RECORD64;

EXPORT void RtlUnwindEx(
    void* end_frame, void* target_ip, EXCEPTION_RECORD64* rec, void* retval,
    ARM64_NT_CONTEXT* context, void* history_table);

__attribute__((naked))
static LONG winemu_execute_exception_filter(
    EXCEPTION_POINTERS64* ptrs, void* frame, PEXCEPTION_FILTER64 filter, uint8_t* nonvol_regs)
{
    asm volatile(
        "stp x29, x30, [sp, #-96]!\n\t"
        "stp x19, x20, [sp, #16]\n\t"
        "stp x21, x22, [sp, #32]\n\t"
        "stp x23, x24, [sp, #48]\n\t"
        "stp x25, x26, [sp, #64]\n\t"
        "stp x27, x28, [sp, #80]\n\t"
        "ldp x19, x20, [x3, #0]\n\t"
        "ldp x21, x22, [x3, #16]\n\t"
        "ldp x23, x24, [x3, #32]\n\t"
        "ldp x25, x26, [x3, #48]\n\t"
        "ldp x27, x28, [x3, #64]\n\t"
        "ldr x1, [x3, #80]\n\t"
        "blr x2\n\t"
        "ldp x19, x20, [sp, #16]\n\t"
        "ldp x21, x22, [sp, #32]\n\t"
        "ldp x23, x24, [sp, #48]\n\t"
        "ldp x25, x26, [sp, #64]\n\t"
        "ldp x27, x28, [sp, #80]\n\t"
        "ldp x29, x30, [sp], #96\n\t"
        "ret\n\t"
    );
}

__attribute__((naked))
static EXCEPTION_DISPOSITION winemu_call_seh_handler(
    EXCEPTION_RECORD64* rec,
    uint64_t frame,
    ARM64_NT_CONTEXT* context,
    DISPATCHER_CONTEXT_ARM64* dispatch,
    PEXCEPTION_ROUTINE_ARM64 handler)
{
    asm volatile(
        "stp x29, x30, [sp, #-16]!\n\t"
        "blr x4\n\t"
        "ldp x29, x30, [sp], #16\n\t"
        "ret\n\t"
    );
}

EXPORT EXCEPTION_DISPOSITION __C_specific_handler(
    EXCEPTION_RECORD64* rec,
    void* frame,
    ARM64_NT_CONTEXT* context,
    DISPATCHER_CONTEXT_ARM64* dispatch)
{
    const SCOPE_TABLE64* table = (const SCOPE_TABLE64*)dispatch->HandlerData;
    ULONG_PTR base = dispatch->ImageBase;
    ULONG_PTR pc = dispatch->ControlPc;
    unsigned int i;

    if (!table) return ExceptionContinueSearch;
    if (dispatch->ControlPcIsUnwound && pc >= 4) pc -= 4;

    if (rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) {
        for (i = dispatch->ScopeIndex; i < table->Count; i++) {
            ULONG_PTR begin = base + table->ScopeRecord[i].BeginAddress;
            ULONG_PTR end = base + table->ScopeRecord[i].EndAddress;
            if (pc < begin || pc >= end) continue;
            if (table->ScopeRecord[i].JumpTarget) continue;

            if ((rec->ExceptionFlags & EXCEPTION_TARGET_UNWIND) &&
                dispatch->TargetPc >= begin &&
                dispatch->TargetPc < end) {
                break;
            }

            PTERMINATION_HANDLER64 handler =
                (PTERMINATION_HANDLER64)((char*)(uintptr_t)base + table->ScopeRecord[i].HandlerAddress);
            dispatch->ScopeIndex = i + 1;
            handler(1, frame);
        }
    } else {
        for (i = dispatch->ScopeIndex; i < table->Count; i++) {
            ULONG_PTR begin = base + table->ScopeRecord[i].BeginAddress;
            ULONG_PTR end = base + table->ScopeRecord[i].EndAddress;
            if (pc < begin || pc >= end) continue;
            if (!table->ScopeRecord[i].JumpTarget) continue;

            if (table->ScopeRecord[i].HandlerAddress != EXCEPTION_EXECUTE_HANDLER) {
                EXCEPTION_POINTERS64 ptrs = { rec, context };
                PEXCEPTION_FILTER64 filter =
                    (PEXCEPTION_FILTER64)((char*)(uintptr_t)base + table->ScopeRecord[i].HandlerAddress);
                LONG result = dispatch->NonVolatileRegisters
                    ? winemu_execute_exception_filter(&ptrs, frame, filter, dispatch->NonVolatileRegisters)
                    : filter(&ptrs, frame);
                if (result == EXCEPTION_CONTINUE_SEARCH) continue;
                if (result == EXCEPTION_CONTINUE_EXECUTION) return ExceptionContinueExecution;
            }

            RtlUnwindEx(
                frame,
                (char*)(uintptr_t)base + table->ScopeRecord[i].JumpTarget,
                rec,
                NULL,
                dispatch->ContextRecord,
                dispatch->HistoryTable);
        }
    }

    return ExceptionContinueSearch;
}

static NTSTATUS virtual_unwind(ULONG type, DISPATCHER_CONTEXT_ARM64* dispatch, ARM64_NT_CONTEXT* context) {
    ULONG_PTR pc = context->Pc;
    ULONG_PTR frame = 0;
    void* handler_data = NULL;
    PEXCEPTION_ROUTINE_ARM64 handler = NULL;
    DISPATCHER_CONTEXT_NONVOLREG_ARM64* nonvol_regs =
        (DISPATCHER_CONTEXT_NONVOLREG_ARM64*)(void*)dispatch->NonVolatileRegisters;

    dispatch->ScopeIndex = 0;
    dispatch->ControlPc = pc;
    dispatch->ControlPcIsUnwound = (context->ContextFlags & CONTEXT_UNWOUND_TO_CALL) != 0;
    if (dispatch->ControlPcIsUnwound && pc >= 4) pc -= 4;
    if (nonvol_regs) {
        for (unsigned i = 0; i < NONVOL_INT_NUMREG_ARM64; i++) {
            nonvol_regs->GpNvRegs[i] = context->X[19 + i];
        }
        for (unsigned i = 0; i < NONVOL_FP_NUMREG_ARM64; i++) {
            nonvol_regs->FpNvRegs[i] = context->V[8 + i].D[0];
        }
    }

    dispatch->FunctionEntry = RtlLookupFunctionEntry(pc, &dispatch->ImageBase, dispatch->HistoryTable);
    NTSTATUS st = RtlVirtualUnwind2(
        type,
        dispatch->ImageBase,
        pc,
        dispatch->FunctionEntry,
        context,
        NULL,
        &handler_data,
        &frame,
        NULL,
        NULL,
        NULL,
        &handler,
        0
    );
    if (st != STATUS_SUCCESS) {
        return st;
    }
    dispatch->LanguageHandler = handler;
    dispatch->HandlerData = handler_data;
    dispatch->EstablisherFrame = frame;
    return STATUS_SUCCESS;
}

__attribute__((naked))
EXPORT void RtlCaptureContext(ARM64_NT_CONTEXT* context) {
    asm volatile(
        "str xzr, [x0, #0x8]\n\t"
        "stp x1, x2, [x0, #0x10]\n\t"
        "stp x3, x4, [x0, #0x20]\n\t"
        "stp x5, x6, [x0, #0x30]\n\t"
        "stp x7, x8, [x0, #0x40]\n\t"
        "stp x9, x10, [x0, #0x50]\n\t"
        "stp x11, x12, [x0, #0x60]\n\t"
        "stp x13, x14, [x0, #0x70]\n\t"
        "stp x15, x16, [x0, #0x80]\n\t"
        "stp x17, x18, [x0, #0x90]\n\t"
        "stp x19, x20, [x0, #0xa0]\n\t"
        "stp x21, x22, [x0, #0xb0]\n\t"
        "stp x23, x24, [x0, #0xc0]\n\t"
        "stp x25, x26, [x0, #0xd0]\n\t"
        "stp x27, x28, [x0, #0xe0]\n\t"
        "stp x29, xzr, [x0, #0xf0]\n\t"
        "mov x1, sp\n\t"
        "stp x1, x30, [x0, #0x100]\n\t"
        "stp q0, q1, [x0, #0x110]\n\t"
        "stp q2, q3, [x0, #0x130]\n\t"
        "stp q4, q5, [x0, #0x150]\n\t"
        "stp q6, q7, [x0, #0x170]\n\t"
        "stp q8, q9, [x0, #0x190]\n\t"
        "stp q10, q11, [x0, #0x1b0]\n\t"
        "stp q12, q13, [x0, #0x1d0]\n\t"
        "stp q14, q15, [x0, #0x1f0]\n\t"
        "stp q16, q17, [x0, #0x210]\n\t"
        "stp q18, q19, [x0, #0x230]\n\t"
        "stp q20, q21, [x0, #0x250]\n\t"
        "stp q22, q23, [x0, #0x270]\n\t"
        "stp q24, q25, [x0, #0x290]\n\t"
        "stp q26, q27, [x0, #0x2b0]\n\t"
        "stp q28, q29, [x0, #0x2d0]\n\t"
        "stp q30, q31, [x0, #0x2f0]\n\t"
        "mov w1, #0x400000\n\t"
        "movk w1, #0x7\n\t"
        "str w1, [x0]\n\t"
        "mrs x1, NZCV\n\t"
        "str w1, [x0, #0x4]\n\t"
        "mrs x1, FPCR\n\t"
        "str w1, [x0, #0x310]\n\t"
        "mrs x1, FPSR\n\t"
        "str w1, [x0, #0x314]\n\t"
        "ret\n\t");
}

__attribute__((naked, noreturn))
static void winemu_restore_context(ARM64_NT_CONTEXT* context) {
    asm volatile(
        "mov x9, x0\n\t"
        "ldr w12, [x9, #0x310]\n\t"
        "msr fpcr, x12\n\t"
        "ldr w12, [x9, #0x314]\n\t"
        "msr fpsr, x12\n\t"
        "ldp d8, d9, [x9, #0x190]\n\t"
        "ldp d10, d11, [x9, #0x1b0]\n\t"
        "ldp d12, d13, [x9, #0x1d0]\n\t"
        "ldp d14, d15, [x9, #0x1f0]\n\t"
        "ldp x19, x20, [x9, #0xa0]\n\t"
        "ldp x21, x22, [x9, #0xb0]\n\t"
        "ldp x23, x24, [x9, #0xc0]\n\t"
        "ldp x25, x26, [x9, #0xd0]\n\t"
        "ldp x27, x28, [x9, #0xe0]\n\t"
        "ldp x29, x30, [x9, #0xf0]\n\t"
        "ldr x0, [x9, #0x8]\n\t"
        "ldr x1, [x9, #0x10]\n\t"
        "ldr x2, [x9, #0x18]\n\t"
        "ldr x3, [x9, #0x20]\n\t"
        "ldr x4, [x9, #0x28]\n\t"
        "ldr x5, [x9, #0x30]\n\t"
        "ldr x6, [x9, #0x38]\n\t"
        "ldr x7, [x9, #0x40]\n\t"
        "ldr x8, [x9, #0x48]\n\t"
        "ldr x10, [x9, #0x100]\n\t"
        "ldr x11, [x9, #0x108]\n\t"
        "mov sp, x10\n\t"
        "br x11\n\t");
}

EXPORT void RtlRestoreContext(ARM64_NT_CONTEXT* context, EXCEPTION_RECORD64* rec) {
    (void)rec;
    winemu_restore_context(context);
}

static int is_valid_teb_frame(uint64_t frame) {
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    if (!teb || frame == 0 || frame == UINT64_MAX) {
        return 0;
    }
    uint64_t stack_base = *(uint64_t*)(teb + 0x08);
    uint64_t stack_limit = *(uint64_t*)(teb + 0x10);
    if (frame < stack_limit || frame >= stack_base) {
        return 0;
    }
    if ((frame & 0x0fU) != 0) {
        return 0;
    }
    return 1;
}

static NTSTATUS dispatch_exception(EXCEPTION_RECORD64* rec, ARM64_NT_CONTEXT* orig_context) {
    ARM64_NT_CONTEXT context = *orig_context;
    DISPATCHER_CONTEXT_ARM64 dispatch;
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 nonvol_regs;
    EXCEPTION_REGISTRATION_RECORD64* teb_frame = NULL;
    uint64_t prev_sp = context.Sp;
    uint64_t prev_pc = context.Pc;
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    if (teb) {
        teb_frame = (EXCEPTION_REGISTRATION_RECORD64*)(uintptr_t)(*(uint64_t*)(teb + 0x00));
    }

    for (;;) {
        memset(&dispatch, 0, sizeof(dispatch));
        dispatch.TargetPc = 0;
        dispatch.ContextRecord = &context;
        dispatch.HistoryTable = NULL;
        dispatch.NonVolatileRegisters = nonvol_regs.Buffer;

        NTSTATUS status = virtual_unwind(UNW_FLAG_EHANDLER, &dispatch, &context);
        if (status != STATUS_SUCCESS) {
            *orig_context = context;
            return status;
        }
        if (!dispatch.EstablisherFrame) break;

        if (dispatch.LanguageHandler) {
            EXCEPTION_DISPOSITION res = dispatch.LanguageHandler(
                rec,
                (void*)(uintptr_t)dispatch.EstablisherFrame,
                orig_context,
                &dispatch
            );
            rec->ExceptionFlags &= EXCEPTION_NONCONTINUABLE;

            if (res == ExceptionContinueExecution) {
                if (rec->ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
                    *orig_context = context;
                    return STATUS_NONCONTINUABLE_EXCEPTION;
                }
                *orig_context = context;
                return STATUS_SUCCESS;
            }
            if (res == ExceptionContinueSearch) {
                /* continue searching */
            } else if (res == ExceptionNestedException || res == ExceptionCollidedUnwind) {
                rec->ExceptionFlags |= EXCEPTION_NESTED_CALL;
            } else {
                *orig_context = context;
                return STATUS_INVALID_DISPOSITION;
            }
        } else {
            while (is_valid_teb_frame((uint64_t)(uintptr_t)teb_frame) &&
                   (uint64_t)(uintptr_t)teb_frame < context.Sp) {
                EXCEPTION_DISPOSITION res = winemu_call_seh_handler(
                    rec,
                    (uint64_t)(uintptr_t)teb_frame,
                    orig_context,
                    &dispatch,
                    (PEXCEPTION_ROUTINE_ARM64)(uintptr_t)teb_frame->Handler
                );
                if (res == ExceptionContinueExecution) {
                    if (rec->ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
                        *orig_context = context;
                        return STATUS_NONCONTINUABLE_EXCEPTION;
                    }
                    *orig_context = context;
                    return STATUS_SUCCESS;
                }
                if (res == ExceptionNestedException || res == ExceptionCollidedUnwind) {
                    rec->ExceptionFlags |= EXCEPTION_NESTED_CALL;
                } else if (res != ExceptionContinueSearch) {
                    *orig_context = context;
                    return STATUS_INVALID_DISPOSITION;
                }
                teb_frame = teb_frame->Prev;
            }
        }

        if (!context.Pc) break;
        if (context.Sp < prev_sp) break;
        if (context.Sp == prev_sp && context.Pc == prev_pc) break;
        prev_sp = context.Sp;
        prev_pc = context.Pc;
    }
    *orig_context = context;
    return STATUS_UNHANDLED_EXCEPTION;
}

EXPORT void RtlUnwindEx(
    void* end_frame, void* target_ip, EXCEPTION_RECORD64* rec, void* retval,
    ARM64_NT_CONTEXT* context, void* history_table)
{
    EXCEPTION_RECORD64 record;
    ARM64_NT_CONTEXT captured;
    ARM64_NT_CONTEXT walk;
    DISPATCHER_CONTEXT_ARM64 dispatch;
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 nonvol_regs;
    uint64_t prev_sp;
    uint64_t prev_pc;

    if (!context) {
        context = &captured;
    }
    RtlCaptureContext(context);
    walk = *context;
    prev_sp = walk.Sp;
    prev_pc = walk.Pc;

    if (!rec) {
        record.ExceptionCode = STATUS_UNWIND;
        record.ExceptionFlags = 0;
        record.ExceptionRecord = NULL;
        record.ExceptionAddress = (void*)(uintptr_t)context->Pc;
        record.NumberParameters = 0;
        rec = &record;
    }
    rec->ExceptionFlags |= EXCEPTION_UNWINDING | (end_frame ? 0 : EXCEPTION_EXIT_UNWIND);

    for (;;) {
        memset(&dispatch, 0, sizeof(dispatch));
        dispatch.TargetPc = (uint64_t)(uintptr_t)target_ip;
        dispatch.ContextRecord = context;
        dispatch.HistoryTable = history_table;
        dispatch.NonVolatileRegisters = nonvol_regs.Buffer;

        NTSTATUS status = virtual_unwind(UNW_FLAG_UHANDLER, &dispatch, &walk);
        if (status != STATUS_SUCCESS) break;
        if (!dispatch.EstablisherFrame) break;

        if (dispatch.LanguageHandler) {
            if (end_frame && dispatch.EstablisherFrame > (uint64_t)(uintptr_t)end_frame) {
                break;
            }
            if (dispatch.EstablisherFrame == (uint64_t)(uintptr_t)end_frame) {
                rec->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
            }

            EXCEPTION_DISPOSITION res = dispatch.LanguageHandler(
                rec,
                (void*)(uintptr_t)dispatch.EstablisherFrame,
                dispatch.ContextRecord,
                &dispatch
            );

            if (res == ExceptionContinueSearch) {
                rec->ExceptionFlags &= ~EXCEPTION_COLLIDED_UNWIND;
            } else if (res == ExceptionCollidedUnwind) {
                rec->ExceptionFlags |= EXCEPTION_COLLIDED_UNWIND;
            } else {
                break;
            }
        }

        if (dispatch.EstablisherFrame == (uint64_t)(uintptr_t)end_frame) break;
        *context = walk;
        if (!walk.Pc) break;
        if (walk.Sp < prev_sp) break;
        if (walk.Sp == prev_sp && walk.Pc == prev_pc) break;
        prev_sp = walk.Sp;
        prev_pc = walk.Pc;
    }

    if (rec->ExceptionCode != STATUS_UNWIND_CONSOLIDATE) {
        context->Pc = (uint64_t)(uintptr_t)target_ip;
    }
    context->X[0] = (uint64_t)(uintptr_t)retval;
    RtlRestoreContext(context, rec);
}

EXPORT void RtlUnwind(void* frame, void* target_ip, EXCEPTION_RECORD64* rec, void* retval) {
    ARM64_NT_CONTEXT context;
    RtlUnwindEx(frame, target_ip, rec, retval, &context, NULL);
}

__attribute__((noreturn))
void winemu_raise_exception_dispatch(EXCEPTION_RECORD64* record, ARM64_NT_CONTEXT* context) {
    uint64_t code = 0xE06D7363ULL;
    EXCEPTION_RECORD64 fallback;
    if (!record) {
        memset(&fallback, 0, sizeof(fallback));
        fallback.ExceptionCode = (uint32_t)code;
        record = &fallback;
    }
    if (context && context->Pc == 0) {
        if (record && record->ExceptionAddress) {
            context->Pc = (uint64_t)(uintptr_t)record->ExceptionAddress;
        } else {
            context->Pc = context->X[30];
        }
        record->ExceptionAddress = (void*)(uintptr_t)context->Pc;
    }
    NTSTATUS dispatch_status = dispatch_exception(record, context);
    if (dispatch_status == STATUS_SUCCESS) {
        RtlRestoreContext(context, record);
    }

    if (record) {
        code = record->ExceptionCode;
    }
    (void)dispatch_status;
    (void)syscall2(
        NR_TERMINATE_PROCESS,
        (uint64_t)(HANDLE)(uint64_t)-1,
        (uint64_t)(NTSTATUS)code
    );
    for (;;) {}
}

__attribute__((naked))
EXPORT void RtlRaiseException(EXCEPTION_RECORD64* record) {
    asm volatile(
        "sub sp, sp, #0x3b0\n\t"      // 0x390 context + 0x20 scratch
        "stp x29, x30, [sp]\n\t"
        "mov x29, sp\n\t"
        "str x0, [sp, #0x10]\n\t"     // save record pointer
        "add x0, sp, #0x20\n\t"       // x0 = context
        "bl RtlCaptureContext\n\t"
        "add x1, sp, #0x20\n\t"       // x1 = context
        "add x2, sp, #0x3b0\n\t"      // original sp before frame allocation
        "str x2, [x1, #0x100]\n\t"    // context->Sp
        "ldr x0, [sp, #0x10]\n\t"     // x0 = record
        "str x0, [x1, #0x08]\n\t"     // context->X0
        "ldp x4, x5, [sp]\n\t"        // caller fp/lr
        "stp x4, x5, [x1, #0xf0]\n\t" // context->X29/X30
        "str x5, [x1, #0x108]\n\t"    // context->Pc
        "cbz x0, 1f\n\t"
        "str x5, [x0, #0x10]\n\t"     // rec->ExceptionAddress
        "1:\tldr w2, [x1]\n\t"
        "orr w2, w2, #0x20000000\n\t" // CONTEXT_UNWOUND_TO_CALL
        "str w2, [x1]\n\t"
        "ldr x0, [sp, #0x10]\n\t"
        "bl winemu_raise_exception_dispatch\n\t"
        "brk #1\n\t"
    );
}

#include "ntdll_missing_exports.generated.h"

/* ── DLL entry point ─────────────────────────────────────────── */

EXPORT int DllMain(HANDLE inst, ULONG reason, void* reserved) {
    (void)inst; (void)reason; (void)reserved;
    return 1;
}

/* Required by linker when using -nostdlib */
int DllMainCRTStartup(HANDLE inst, ULONG reason, void* reserved) {
    return DllMain(inst, reason, reserved);
}
