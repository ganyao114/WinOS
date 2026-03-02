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

