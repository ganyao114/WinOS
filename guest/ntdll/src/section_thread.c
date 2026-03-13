/* ── Section ─────────────────────────────────────────────────── */

typedef uint8_t BOOLEAN;
typedef uint64_t SIZE_T;
typedef struct _SECURITY_DESCRIPTOR SECURITY_DESCRIPTOR;
typedef void (*PRTL_THREAD_START_ROUTINE)(void *);

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    void *TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION;

enum {
    ThreadBasicInformation = 0,
};

#define THREAD_ALL_ACCESS 0x001fffffU

EXPORT NTSTATUS NtQueryInformationThread(
    HANDLE thread_handle,
    ULONG thread_information_class,
    void *thread_information,
    ULONG thread_information_length,
    ULONG *return_length);

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

EXPORT NTSTATUS RtlCreateUserThread(
    HANDLE process,
    SECURITY_DESCRIPTOR *security_descriptor,
    BOOLEAN create_suspended,
    ULONG zero_bits,
    SIZE_T stack_reserve,
    SIZE_T stack_commit,
    PRTL_THREAD_START_ROUTINE start,
    void *param,
    HANDLE *thread_handle,
    CLIENT_ID *client_id)
{
    HANDLE local_handle = 0;
    HANDLE *create_out = thread_handle ? thread_handle : &local_handle;
    NTSTATUS status;

    (void)security_descriptor;

    if (!start || (!thread_handle && !client_id)) return STATUS_INVALID_PARAMETER;

    status = NtCreateThreadEx(
        create_out,
        THREAD_ALL_ACCESS,
        NULL,
        process,
        (void *)start,
        param,
        create_suspended ? 0x1u : 0u,
        zero_bits,
        stack_commit,
        stack_reserve,
        NULL);
    if (status) return status;

    if (client_id)
    {
        THREAD_BASIC_INFORMATION basic_info;
        ULONG ret_len = 0;

        status = NtQueryInformationThread(
            *create_out,
            ThreadBasicInformation,
            &basic_info,
            sizeof(basic_info),
            &ret_len);
        if (!status) *client_id = basic_info.ClientId;
    }

    if (!thread_handle && local_handle) NtClose(local_handle);
    return status;
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
