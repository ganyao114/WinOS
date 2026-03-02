/* ── Heap ────────────────────────────────────────────────────── */

typedef struct {
    uint64_t magic;
    uint64_t size;
} WINEMU_HEAP_HDR;

#define WINEMU_HEAP_HDR_MAGIC 0x5748454150484452ULL
#define WINEMU_HEAP_HDR_SIZE  ((size_t)sizeof(WINEMU_HEAP_HDR))

static uint64_t g_heap_alloc_fail_count = 0;
static uint64_t g_heap_last_fail_size = 0;
static uint32_t g_heap_last_fail_status = STATUS_SUCCESS;

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
    if (st != 0 || !raw) {
        g_heap_alloc_fail_count++;
        g_heap_last_fail_size = total;
        g_heap_last_fail_status = (uint32_t)st;
        return NULL;
    }

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

EXPORT size_t RtlSizeHeap(HANDLE heap, ULONG flags, const void* ptr) {
    (void)heap; (void)flags;
    if (!ptr) return (size_t)-1;
    const WINEMU_HEAP_HDR* hdr =
        (const WINEMU_HEAP_HDR*)((const uint8_t*)ptr - WINEMU_HEAP_HDR_SIZE);
    if (hdr->magic != WINEMU_HEAP_HDR_MAGIC) return (size_t)-1;
    return (size_t)hdr->size;
}

EXPORT int RtlValidateHeap(HANDLE heap, ULONG flags, const void* ptr) {
    (void)heap; (void)flags;
    if (!ptr) return 1;
    const WINEMU_HEAP_HDR* hdr =
        (const WINEMU_HEAP_HDR*)((const uint8_t*)ptr - WINEMU_HEAP_HDR_SIZE);
    return hdr->magic == WINEMU_HEAP_HDR_MAGIC ? 1 : 0;
}

