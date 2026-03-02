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

