/* ── Minimal threadpool / work-item support ─────────────────── */

typedef uint8_t BOOLEAN;
typedef void (*PRTL_WORK_ITEM_ROUTINE)(void *);
typedef void (*PTP_SIMPLE_CALLBACK)(void *instance, void *context);

typedef struct {
    uint64_t Status;
    uint64_t Information;
} WINEMU_TP_IO_STATUS_BLOCK64;

typedef struct {
    PRTL_WORK_ITEM_ROUTINE function;
    void *context;
} WINEMU_RTL_WORK_ITEM;

typedef struct {
    PTP_SIMPLE_CALLBACK callback;
    void *context;
} WINEMU_TP_SIMPLE_WORK;

EXPORT void *RtlAllocateHeap(HANDLE heap, ULONG flags, size_t size);
EXPORT int RtlFreeHeap(HANDLE heap, ULONG flags, void *ptr);
EXPORT NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void *apc_routine, void *apc_ctx,
    void *io_status, const void *buffer, ULONG length,
    uint64_t *byte_offset, ULONG *key);
EXPORT NTSTATUS NtCreateThreadEx(
    HANDLE *thread_handle, ULONG access, void *object_attributes,
    HANDLE process_handle, void *start_routine, void *argument,
    ULONG create_flags, size_t zero_bits, size_t stack_size,
    size_t max_stack_size, void *attribute_list);

static volatile ULONG g_winemu_tp_trace_budget = 32;

static void winemu_tp_write_buf(const char *buf, ULONG len) {
    WINEMU_TP_IO_STATUS_BLOCK64 iosb;

    iosb.Status = 0;
    iosb.Information = 0;
    (void)NtWriteFile(
        (HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL,
        0,
        0,
        0,
        &iosb,
        buf,
        len,
        0,
        0);
}

static void winemu_tp_write_str(const char *str) {
    ULONG len = 0;
    while (str && str[len]) len++;
    if (len) winemu_tp_write_buf(str, len);
}

static void winemu_tp_write_hex_u64(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    char buf[18];
    int i;

    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 16; ++i) {
        buf[2 + i] = digits[(value >> ((15 - i) * 4)) & 0xf];
    }
    winemu_tp_write_buf(buf, (ULONG)sizeof(buf));
}

static void winemu_tp_trace_triplet(const char *tag, uint64_t a, uint64_t b, uint64_t c) {
    if (__atomic_fetch_sub(&g_winemu_tp_trace_budget, 1, __ATOMIC_ACQ_REL) == 0) {
        __atomic_store_n(&g_winemu_tp_trace_budget, 0, __ATOMIC_RELEASE);
        return;
    }
    winemu_tp_write_str("[ntdll-tp] ");
    winemu_tp_write_str(tag);
    winemu_tp_write_str(" a=");
    winemu_tp_write_hex_u64(a);
    winemu_tp_write_str(" b=");
    winemu_tp_write_hex_u64(b);
    winemu_tp_write_str(" c=");
    winemu_tp_write_hex_u64(c);
    winemu_tp_write_str("\r\n");
}

static ULONG winemu_rtl_work_item_start(void *arg) {
    WINEMU_RTL_WORK_ITEM *item = (WINEMU_RTL_WORK_ITEM *)arg;
    PRTL_WORK_ITEM_ROUTINE function = item ? item->function : NULL;
    void *context = item ? item->context : NULL;

    winemu_tp_trace_triplet(
        "rtl-start",
        (uint64_t)(uintptr_t)item,
        (uint64_t)(uintptr_t)function,
        (uint64_t)(uintptr_t)context);
    if (item) RtlFreeHeap(0, 0, item);
    if (function) function(context);
    return 0;
}

static ULONG winemu_tp_simple_work_start(void *arg) {
    WINEMU_TP_SIMPLE_WORK *work = (WINEMU_TP_SIMPLE_WORK *)arg;
    PTP_SIMPLE_CALLBACK callback = work ? work->callback : NULL;
    void *context = work ? work->context : NULL;

    winemu_tp_trace_triplet(
        "tp-start",
        (uint64_t)(uintptr_t)work,
        (uint64_t)(uintptr_t)callback,
        (uint64_t)(uintptr_t)context);
    if (work) RtlFreeHeap(0, 0, work);
    if (callback) callback(NULL, context);
    return 0;
}

static NTSTATUS winemu_spawn_worker(void *start_routine, void *arg) {
    HANDLE thread = 0;
    NTSTATUS status = NtCreateThreadEx(
        &thread,
        0x001fffffU,
        NULL,
        (HANDLE)(uintptr_t)-1,
        start_routine,
        arg,
        0,
        0,
        0,
        0,
        NULL);
    if (!status && thread) NtClose(thread);
    return status;
}

EXPORT NTSTATUS RtlQueueWorkItem(PRTL_WORK_ITEM_ROUTINE function, void *context, ULONG flags) {
    WINEMU_RTL_WORK_ITEM *item;

    (void)flags;
    if (!function) return STATUS_INVALID_PARAMETER;

    item = (WINEMU_RTL_WORK_ITEM *)RtlAllocateHeap(0, 0, sizeof(*item));
    if (!item) return STATUS_NO_MEMORY;
    item->function = function;
    item->context = context;
    winemu_tp_trace_triplet(
        "rtl-queue",
        (uint64_t)(uintptr_t)function,
        (uint64_t)(uintptr_t)context,
        (uint64_t)(uintptr_t)item);

    if (winemu_spawn_worker((void *)winemu_rtl_work_item_start, item) != STATUS_SUCCESS) {
        RtlFreeHeap(0, 0, item);
        return STATUS_NO_MEMORY;
    }
    return STATUS_SUCCESS;
}

EXPORT NTSTATUS TpSimpleTryPost(
    PTP_SIMPLE_CALLBACK callback,
    void *userdata,
    void *environment)
{
    WINEMU_TP_SIMPLE_WORK *work;

    (void)environment;
    if (!callback) return STATUS_INVALID_PARAMETER;

    work = (WINEMU_TP_SIMPLE_WORK *)RtlAllocateHeap(0, 0, sizeof(*work));
    if (!work) return STATUS_NO_MEMORY;
    work->callback = callback;
    work->context = userdata;
    winemu_tp_trace_triplet(
        "tp-queue",
        (uint64_t)(uintptr_t)callback,
        (uint64_t)(uintptr_t)userdata,
        (uint64_t)(uintptr_t)work);

    if (winemu_spawn_worker((void *)winemu_tp_simple_work_start, work) != STATUS_SUCCESS) {
        RtlFreeHeap(0, 0, work);
        return STATUS_NO_MEMORY;
    }
    return STATUS_SUCCESS;
}
