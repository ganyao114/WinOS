/* ── Global/Local memory APIs ─────────────────────────────────── */

typedef struct {
    uint64_t magic;
    uint32_t flags;
    uint32_t lock_count;
    size_t size;
    void* data_base;
    void* user_ptr;
} WINEMU_GMEM_HDR;

#define WINEMU_GMEM_MAGIC 0x57474D454D484452ULL
#define WINEMU_GMEM_PREFIX_SIZE ((size_t)sizeof(void*))

#define GMEM_FIXED     0x0000U
#define GMEM_MOVEABLE  0x0002U
#define GMEM_ZEROINIT  0x0040U
#define GMEM_MODIFY    0x0080U

static void gmem_zero(void* ptr, size_t n) {
    uint8_t* p = (uint8_t*)ptr;
    for (size_t i = 0; i < n; i++) {
        p[i] = 0;
    }
}

static int gmem_valid_hdr(const WINEMU_GMEM_HDR* hdr) {
    return hdr
        && hdr->magic == WINEMU_GMEM_MAGIC
        && hdr->data_base
        && hdr->user_ptr
        && (hdr->user_ptr == (void*)((uint8_t*)hdr->data_base + WINEMU_GMEM_PREFIX_SIZE));
}

static WINEMU_GMEM_HDR* gmem_hdr_from_handle(const void* handle) {
    const WINEMU_GMEM_HDR* hdr = (const WINEMU_GMEM_HDR*)handle;
    return gmem_valid_hdr(hdr) ? (WINEMU_GMEM_HDR*)hdr : NULL;
}

static WINEMU_GMEM_HDR* gmem_hdr_from_ptr(const void* ptr) {
    if (!ptr) return NULL;
    const uint8_t* p = (const uint8_t*)ptr;
    if ((uintptr_t)p < WINEMU_GMEM_PREFIX_SIZE) return NULL;
    WINEMU_GMEM_HDR* hdr = *(WINEMU_GMEM_HDR**)(p - WINEMU_GMEM_PREFIX_SIZE);
    if (!gmem_valid_hdr(hdr)) return NULL;
    if (hdr->user_ptr != ptr) return NULL;
    return hdr;
}

static WINEMU_GMEM_HDR* gmem_resolve(const void* mem, int* from_handle) {
    WINEMU_GMEM_HDR* hdr = gmem_hdr_from_handle(mem);
    if (hdr) {
        if (from_handle) *from_handle = 1;
        return hdr;
    }
    hdr = gmem_hdr_from_ptr(mem);
    if (hdr) {
        if (from_handle) *from_handle = 0;
        return hdr;
    }
    return NULL;
}

static int gmem_is_moveable(const WINEMU_GMEM_HDR* hdr) {
    return (hdr->flags & GMEM_MOVEABLE) != 0;
}

static int gmem_alloc_data(WINEMU_GMEM_HDR* hdr, size_t size, int zero_init) {
    size_t need = align_up(size ? size : 1, 16);
    size_t total = align_up(need + WINEMU_GMEM_PREFIX_SIZE, 16);
    void* data_base = RtlAllocateHeap(NULL, 0, total);
    if (!data_base) {
        return 0;
    }
    *(WINEMU_GMEM_HDR**)data_base = hdr;
    void* user = (void*)((uint8_t*)data_base + WINEMU_GMEM_PREFIX_SIZE);
    if (zero_init && need) {
        gmem_zero(user, need);
    }
    hdr->data_base = data_base;
    hdr->user_ptr = user;
    hdr->size = size;
    return 1;
}

static HANDLE gmem_handle_for(const WINEMU_GMEM_HDR* hdr) {
    if (gmem_is_moveable(hdr)) {
        return (HANDLE)hdr;
    }
    return (HANDLE)hdr->user_ptr;
}

EXPORT HANDLE GlobalAlloc(ULONG flags, size_t bytes) {
    WINEMU_GMEM_HDR* hdr = (WINEMU_GMEM_HDR*)RtlAllocateHeap(NULL, 0, sizeof(WINEMU_GMEM_HDR));
    if (!hdr) return NULL;

    hdr->magic = WINEMU_GMEM_MAGIC;
    hdr->flags = flags;
    hdr->lock_count = 0;
    hdr->size = 0;
    hdr->data_base = NULL;
    hdr->user_ptr = NULL;
    if (!gmem_alloc_data(hdr, bytes, (flags & GMEM_ZEROINIT) != 0)) {
        (void)RtlFreeHeap(NULL, 0, hdr);
        return NULL;
    }
    return gmem_handle_for(hdr);
}

EXPORT HANDLE GlobalFree(HANDLE mem) {
    if (!mem) return NULL;
    WINEMU_GMEM_HDR* hdr = gmem_resolve(mem, NULL);
    if (!hdr) return mem;
    void* data_base = hdr->data_base;
    hdr->magic = 0;
    hdr->data_base = NULL;
    hdr->user_ptr = NULL;
    if (data_base) {
        (void)RtlFreeHeap(NULL, 0, data_base);
    }
    (void)RtlFreeHeap(NULL, 0, hdr);
    return NULL;
}

EXPORT HANDLE GlobalHandle(const void* mem) {
    WINEMU_GMEM_HDR* hdr = gmem_resolve(mem, NULL);
    if (!hdr) return NULL;
    return gmem_handle_for(hdr);
}

EXPORT void* GlobalLock(HANDLE mem) {
    WINEMU_GMEM_HDR* hdr = gmem_resolve(mem, NULL);
    if (!hdr) return NULL;
    if (gmem_is_moveable(hdr) && hdr->lock_count != 0xFFFFFFFFU) {
        hdr->lock_count++;
    }
    return hdr->user_ptr;
}

EXPORT int GlobalUnlock(HANDLE mem) {
    WINEMU_GMEM_HDR* hdr = gmem_resolve(mem, NULL);
    if (!hdr) return 0;
    if (!gmem_is_moveable(hdr)) return 1;
    if (hdr->lock_count == 0) return 0;
    hdr->lock_count--;
    return hdr->lock_count != 0 ? 1 : 0;
}

EXPORT size_t GlobalSize(HANDLE mem) {
    WINEMU_GMEM_HDR* hdr = gmem_resolve(mem, NULL);
    if (!hdr) return 0;
    return hdr->size;
}

EXPORT ULONG GlobalFlags(HANDLE mem) {
    WINEMU_GMEM_HDR* hdr = gmem_resolve(mem, NULL);
    if (!hdr) return 0xFFFFU;
    ULONG out = 0;
    if (gmem_is_moveable(hdr)) out |= GMEM_MOVEABLE;
    out |= (hdr->lock_count & 0xFFU);
    return out;
}

EXPORT HANDLE GlobalReAlloc(HANDLE mem, size_t bytes, ULONG flags) {
    if (!mem) {
        return GlobalAlloc(flags, bytes);
    }
    int from_handle = 0;
    WINEMU_GMEM_HDR* hdr = gmem_resolve(mem, &from_handle);
    if (!hdr) return NULL;

    if (flags & GMEM_MODIFY) {
        if (flags & GMEM_MOVEABLE) {
            hdr->flags |= GMEM_MOVEABLE;
        } else {
            hdr->flags &= ~GMEM_MOVEABLE;
        }
        return gmem_handle_for(hdr);
    }

    size_t old_size = hdr->size;
    size_t need = align_up(bytes ? bytes : 1, 16);
    size_t total = align_up(need + WINEMU_GMEM_PREFIX_SIZE, 16);
    void* new_data = RtlReAllocateHeap(NULL, 0, hdr->data_base, total);
    if (!new_data) return NULL;

    *(WINEMU_GMEM_HDR**)new_data = hdr;
    hdr->data_base = new_data;
    hdr->user_ptr = (void*)((uint8_t*)new_data + WINEMU_GMEM_PREFIX_SIZE);
    hdr->size = bytes;
    if ((flags & GMEM_ZEROINIT) && bytes > old_size) {
        gmem_zero((uint8_t*)hdr->user_ptr + old_size, bytes - old_size);
    }

    if (!from_handle && !gmem_is_moveable(hdr)) {
        return (HANDLE)hdr->user_ptr;
    }
    return gmem_handle_for(hdr);
}

EXPORT HANDLE LocalAlloc(ULONG flags, size_t bytes) {
    return GlobalAlloc(flags, bytes);
}

EXPORT HANDLE LocalReAlloc(HANDLE mem, size_t bytes, ULONG flags) {
    return GlobalReAlloc(mem, bytes, flags);
}

EXPORT HANDLE LocalFree(HANDLE mem) {
    return GlobalFree(mem);
}

EXPORT void* LocalLock(HANDLE mem) {
    return GlobalLock(mem);
}

EXPORT int LocalUnlock(HANDLE mem) {
    return GlobalUnlock(mem);
}

EXPORT HANDLE LocalHandle(const void* mem) {
    return GlobalHandle(mem);
}

EXPORT size_t LocalSize(HANDLE mem) {
    return GlobalSize(mem);
}

EXPORT ULONG LocalFlags(HANDLE mem) {
    return GlobalFlags(mem);
}

