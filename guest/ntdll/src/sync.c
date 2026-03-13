/* ── Critical Section ────────────────────────────────────────── */

typedef struct {
    uint64_t debug_info;
    int32_t  lock_count;
    int32_t  recursion;
    uint64_t owner_thread;
    uint64_t lock_sem;
    uint64_t spin_count;
} RTL_CRITICAL_SECTION;

typedef struct {
    uint64_t owner_cs;
    uint8_t storage[0x40];
} CS_DEBUG_SLOT;

#define CS_DEBUG_SLOTS 256
static CS_DEBUG_SLOT g_cs_debug_slots[CS_DEBUG_SLOTS];
static uint32_t g_cs_debug_next;

static void cs_debug_zero(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = 0;
    }
}

static uint64_t cs_debug_info_acquire(RTL_CRITICAL_SECTION* cs) {
    uint64_t key = (uint64_t)(uintptr_t)cs;
    for (uint32_t i = 0; i < CS_DEBUG_SLOTS; i++) {
        if (g_cs_debug_slots[i].owner_cs == key) {
            return (uint64_t)(uintptr_t)g_cs_debug_slots[i].storage;
        }
    }
    for (uint32_t i = 0; i < CS_DEBUG_SLOTS; i++) {
        if (g_cs_debug_slots[i].owner_cs == 0) {
            g_cs_debug_slots[i].owner_cs = key;
            cs_debug_zero(g_cs_debug_slots[i].storage, sizeof(g_cs_debug_slots[i].storage));
            return (uint64_t)(uintptr_t)g_cs_debug_slots[i].storage;
        }
    }
    uint32_t idx = g_cs_debug_next++ % CS_DEBUG_SLOTS;
    g_cs_debug_slots[idx].owner_cs = key;
    cs_debug_zero(g_cs_debug_slots[idx].storage, sizeof(g_cs_debug_slots[idx].storage));
    return (uint64_t)(uintptr_t)g_cs_debug_slots[idx].storage;
}

static void cs_debug_info_release(RTL_CRITICAL_SECTION* cs) {
    uint64_t key = (uint64_t)(uintptr_t)cs;
    for (uint32_t i = 0; i < CS_DEBUG_SLOTS; i++) {
        if (g_cs_debug_slots[i].owner_cs == key) {
            g_cs_debug_slots[i].owner_cs = 0;
            cs_debug_zero(g_cs_debug_slots[i].storage, sizeof(g_cs_debug_slots[i].storage));
            return;
        }
    }
}

static inline uint64_t cs_current_owner_id(void) {
    uint8_t *teb = (uint8_t *)NtCurrentTeb();
    uint64_t tid;

    if (!teb) return 1;
    tid = *(uint64_t *)(teb + 0x48);
    if (tid) return tid;
    return (uint64_t)(uintptr_t)teb;
}

static inline void cs_cpu_relax(void) {
#if defined(__aarch64__)
    asm volatile("yield" ::: "memory");
#else
    asm volatile("" ::: "memory");
#endif
}

EXPORT NTSTATUS RtlInitializeCriticalSection(RTL_CRITICAL_SECTION* cs) {
    if (!cs) return STATUS_INVALID_PARAMETER;
    cs->debug_info   = cs_debug_info_acquire(cs);
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

EXPORT NTSTATUS RtlDeleteCriticalSection(RTL_CRITICAL_SECTION* cs) {
    if (!cs) return STATUS_INVALID_PARAMETER;
    cs_debug_info_release(cs);
    cs->debug_info = 0;
    return 0;
}

EXPORT NTSTATUS RtlEnterCriticalSection(RTL_CRITICAL_SECTION* cs) {
    uint64_t self;
    uint64_t unlocked = 0;
    uint32_t spin = 0;

    if (!cs) return STATUS_INVALID_PARAMETER;

    self = cs_current_owner_id();
    if (__atomic_load_n(&cs->owner_thread, __ATOMIC_RELAXED) == self) {
        cs->lock_count++;
        cs->recursion++;
        return 0;
    }

    for (;;) {
        unlocked = 0;
        if (__atomic_compare_exchange_n(
                &cs->owner_thread,
                &unlocked,
                self,
                0,
                __ATOMIC_ACQUIRE,
                __ATOMIC_RELAXED)) {
            cs->lock_count = 0;
            cs->recursion = 1;
            return 0;
        }

        if (unlocked == self) {
            cs->lock_count++;
            cs->recursion++;
            return 0;
        }

        if (++spin >= 256) {
            spin = 0;
            NtYieldExecution();
        } else {
            cs_cpu_relax();
        }
    }
    return 0;
}

EXPORT NTSTATUS RtlLeaveCriticalSection(RTL_CRITICAL_SECTION* cs) {
    uint64_t self;

    if (!cs) return STATUS_INVALID_PARAMETER;

    self = cs_current_owner_id();
    if (__atomic_load_n(&cs->owner_thread, __ATOMIC_RELAXED) != self || cs->recursion <= 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (--cs->recursion == 0) {
        cs->lock_count = -1;
        __atomic_store_n(&cs->owner_thread, 0, __ATOMIC_RELEASE);
    } else {
        cs->lock_count--;
    }
    return 0;
}

EXPORT int RtlTryEnterCriticalSection(RTL_CRITICAL_SECTION* cs) {
    uint64_t self;
    uint64_t unlocked = 0;

    if (!cs) return 0;

    self = cs_current_owner_id();
    if (__atomic_load_n(&cs->owner_thread, __ATOMIC_RELAXED) == self) {
        cs->lock_count++;
        cs->recursion++;
        return 1;
    }

    if (__atomic_compare_exchange_n(
            &cs->owner_thread,
            &unlocked,
            self,
            0,
            __ATOMIC_ACQUIRE,
            __ATOMIC_RELAXED)) {
        cs->lock_count = 0;
        cs->recursion = 1;
        return 1;
    }
    return 0;
}

EXPORT int RtlIsCriticalSectionLocked(RTL_CRITICAL_SECTION* cs) {
    if (!cs) return 0;
    return __atomic_load_n(&cs->owner_thread, __ATOMIC_RELAXED) != 0;
}

EXPORT int RtlIsCriticalSectionLockedByThread(RTL_CRITICAL_SECTION* cs) {
    if (!cs) return 0;
    return __atomic_load_n(&cs->owner_thread, __ATOMIC_RELAXED) == cs_current_owner_id();
}

EXPORT ULONG_PTR RtlSetCriticalSectionSpinCount(RTL_CRITICAL_SECTION* cs, ULONG_PTR spin_count) {
    ULONG_PTR prev;

    if (!cs) return 0;
    prev = cs->spin_count;
    cs->spin_count = spin_count;
    return prev;
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

typedef struct {
    unsigned char flags;
    char name[15];
} WINE_DEBUG_CHANNEL;

EXPORT unsigned char __wine_dbg_get_channel_flags(WINE_DEBUG_CHANNEL* channel) {
    if (!channel) return 0;
    channel->flags = 0;
    return 0;
}

EXPORT int __wine_dbg_header(int cls, WINE_DEBUG_CHANNEL* channel, const char* function) {
    (void)cls;
    (void)function;
    if (channel) channel->flags = 0;
    return -1;
}

EXPORT int __wine_dbg_output(const char* str) {
    if (!str) return 0;
    int n = 0;
    while (str[n]) n++;
    return n;
}

EXPORT const char* __wine_dbg_strdup(const char* str) {
    return str ? str : "";
}
