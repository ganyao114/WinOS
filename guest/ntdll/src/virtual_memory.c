/* ── Virtual Memory ──────────────────────────────────────────── */

EXPORT NTSTATUS NtAllocateVirtualMemory(
    HANDLE process, void** base_addr, ULONG_PTR zero_bits,
    size_t* region_size, ULONG alloc_type, ULONG protect)
{
    return syscall6(NR_ALLOCATE_VIRTUAL_MEMORY,
        (uint64_t)process, (uint64_t)base_addr, zero_bits,
        (uint64_t)region_size, alloc_type, protect);
}

EXPORT NTSTATUS NtFreeVirtualMemory(
    HANDLE process, void** base_addr, size_t* region_size, ULONG free_type)
{
    return syscall4(NR_FREE_VIRTUAL_MEMORY,
        (uint64_t)process, (uint64_t)base_addr,
        (uint64_t)region_size, free_type);
}

EXPORT NTSTATUS NtProtectVirtualMemory(
    HANDLE process_handle, void** base_address, size_t* region_size, ULONG new_protection, ULONG* old_protection)
{
    return syscall6(
        NR_PROTECT_VIRTUAL_MEMORY,
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
        NR_QUERY_VIRTUAL_MEMORY,
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
        NR_READ_VIRTUAL_MEMORY,
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
        NR_WRITE_VIRTUAL_MEMORY,
        (uint64_t)process,
        (uint64_t)base_addr,
        (uint64_t)buffer,
        (uint64_t)size,
        (uint64_t)bytes_written,
        0
    );
}

