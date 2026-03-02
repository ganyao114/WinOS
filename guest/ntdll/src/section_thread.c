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

