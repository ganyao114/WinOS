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

