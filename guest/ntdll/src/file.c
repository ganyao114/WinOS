EXPORT NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    void* io_status, const void* buffer, ULONG length,
    uint64_t* byte_offset, ULONG* key)
{
    register uint64_t x8 asm("x8") = NR_WRITE_FILE;
    register uint64_t x0 asm("x0") = (uint64_t)file;
    register uint64_t x1 asm("x1") = (uint64_t)event;
    register uint64_t x2 asm("x2") = (uint64_t)apc_routine;
    register uint64_t x3 asm("x3") = (uint64_t)apc_ctx;
    register uint64_t x4 asm("x4") = (uint64_t)io_status;
    register uint64_t x5 asm("x5") = (uint64_t)buffer;
    register uint64_t x6 asm("x6") = (uint64_t)length;
    register uint64_t x7 asm("x7") = (uint64_t)byte_offset;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x6),"r"(x7) : "memory");
    return (NTSTATUS)x0;
}

__attribute__((naked))
EXPORT NTSTATUS NtReadFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    void* io_status, void* buffer, ULONG length,
    uint64_t* byte_offset, ULONG* key)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_READ_FILE));
}

__attribute__((naked))
EXPORT NTSTATUS NtCreateFile(
    HANDLE* file_handle, ULONG desired_access, void* object_attributes, void* io_status_block,
    uint64_t* allocation_size, ULONG file_attributes, ULONG share_access, ULONG create_disposition,
    ULONG create_options, void* ea_buffer, ULONG ea_length)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_CREATE_FILE));
}

EXPORT NTSTATUS NtOpenFile(
    HANDLE* file_handle, ULONG desired_access, void* object_attributes,
    void* io_status_block, ULONG share_access, ULONG open_options)
{
    return syscall6(
        NR_OPEN_FILE,
        (uint64_t)file_handle,
        (uint64_t)desired_access,
        (uint64_t)object_attributes,
        (uint64_t)io_status_block,
        (uint64_t)share_access,
        (uint64_t)open_options
    );
}

EXPORT NTSTATUS NtSetInformationFile(
    HANDLE file_handle, void* io_status_block, void* file_information, ULONG length, ULONG file_information_class)
{
    return syscall6(
        NR_SET_INFORMATION_FILE,
        (uint64_t)file_handle,
        (uint64_t)io_status_block,
        (uint64_t)file_information,
        (uint64_t)length,
        (uint64_t)file_information_class,
        0
    );
}

EXPORT NTSTATUS NtQueryInformationFile(
    HANDLE file_handle, void* io_status_block, void* file_information, ULONG length, ULONG file_information_class)
{
    return syscall6(
        NR_QUERY_INFORMATION_FILE,
        (uint64_t)file_handle,
        (uint64_t)io_status_block,
        (uint64_t)file_information,
        (uint64_t)length,
        (uint64_t)file_information_class,
        0
    );
}

__attribute__((naked))
EXPORT NTSTATUS NtQueryDirectoryFile(
    HANDLE file_handle, HANDLE event, void* apc_routine, void* apc_context,
    void* io_status_block, void* file_information, ULONG length, ULONG file_information_class,
    UCHAR return_single_entry, void* file_name, UCHAR restart_scan)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_QUERY_DIRECTORY_FILE));
}

__attribute__((naked))
EXPORT NTSTATUS NtNotifyChangeDirectoryFile(
    HANDLE file_handle, HANDLE event, void* apc_routine, void* apc_context,
    void* io_status_block, void* buffer, ULONG length, ULONG completion_filter, UCHAR watch_tree)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_NOTIFY_CHANGE_DIRECTORY_FILE));
}

__attribute__((naked))
EXPORT NTSTATUS NtDeviceIoControlFile(
    HANDLE file_handle, HANDLE event, void* apc_routine, void* apc_context,
    void* io_status_block, ULONG io_control_code, void* input_buffer, ULONG input_buffer_length,
    void* output_buffer, ULONG output_buffer_length)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_DEVICE_IO_CONTROL_FILE));
}

__attribute__((naked))
EXPORT NTSTATUS NtFsControlFile(
    HANDLE file_handle, HANDLE event, void* apc_routine, void* apc_context,
    void* io_status_block, ULONG fs_control_code, void* input_buffer, ULONG input_buffer_length,
    void* output_buffer, ULONG output_buffer_length)
{
    asm volatile(
        "mov x8, %0\n"
        "svc #0\n"
        "ret\n"
        :: "i"(NR_FS_CONTROL_FILE));
}

EXPORT NTSTATUS NtQueryAttributesFile(void* object_attributes, void* file_information) {
    return syscall2(
        NR_QUERY_ATTRIBUTES_FILE,
        (uint64_t)object_attributes,
        (uint64_t)file_information
    );
}

EXPORT NTSTATUS NtQueryVolumeInformationFile(
    HANDLE file_handle, void* io_status_block, void* fs_information, ULONG length, ULONG fs_information_class)
{
    return syscall6(
        NR_QUERY_VOLUME_INFORMATION_FILE,
        (uint64_t)file_handle,
        (uint64_t)io_status_block,
        (uint64_t)fs_information,
        (uint64_t)length,
        (uint64_t)fs_information_class,
        0
    );
}

