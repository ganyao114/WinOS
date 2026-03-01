#include <stdint.h>
#include <stddef.h>

typedef uint16_t WCHAR;
typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef void* HANDLE;

typedef struct {
    uint64_t Status;
    uint64_t Information;
} IO_STATUS_BLOCK;

typedef struct {
    uint32_t DeviceType;
    uint32_t Characteristics;
} FILE_FS_DEVICE_INFORMATION;

typedef struct {
    uint32_t FileSystemAttributes;
    int32_t MaximumComponentNameLength;
    uint32_t FileSystemNameLength;
    WCHAR FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION_PREFIX;

typedef struct {
    int64_t TotalAllocationUnits;
    int64_t AvailableAllocationUnits;
    uint32_t SectorsPerAllocationUnit;
    uint32_t BytesPerSector;
} FILE_FS_SIZE_INFORMATION;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_INVALID_HANDLE 0xC0000008U
#define STATUS_INVALID_PARAMETER 0xC000000DU
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004U

#define FILE_FS_SIZE_INFORMATION_CLASS 3U
#define FILE_FS_DEVICE_INFORMATION_CLASS 4U
#define FILE_FS_ATTRIBUTE_INFORMATION_CLASS 5U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);
__declspec(dllimport) NTSTATUS NtQueryVolumeInformationFile(
    HANDLE file_handle, IO_STATUS_BLOCK* io_status_block, void* fs_information,
    ULONG length, ULONG fs_information_class);

static uint32_t g_pass = 0;
static uint32_t g_fail = 0;

static void write_str(const char* s) {
    IO_STATUS_BLOCK iosb = {0};
    ULONG len = 0;
    while (s[len]) {
        len++;
    }
    (void)NtWriteFile(STDOUT_HANDLE, 0, 0, 0, &iosb, s, len, 0, 0);
}

static void write_u64_hex(uint64_t value) {
    char buf[19];
    const char* hex = "0123456789abcdef";
    int i;
    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 16; i++) {
        buf[2 + i] = hex[(value >> ((15 - i) * 4)) & 0xF];
    }
    buf[18] = '\0';
    write_str(buf);
}

static void check(const char* name, int ok) {
    if (ok) {
        g_pass++;
        write_str("[PASS] ");
    } else {
        g_fail++;
        write_str("[FAIL] ");
    }
    write_str(name);
    write_str("\r\n");
}

static __attribute__((noreturn)) void terminate_current_process(uint32_t code) {
    NtTerminateProcess(NT_CURRENT_PROCESS, code);
    for (;;) {
        __asm__ volatile("wfi" ::: "memory");
    }
}

static int equal_utf16_ascii(const WCHAR* wstr, ULONG wbytes, const char* ascii) {
    ULONG count = wbytes / 2;
    ULONG i = 0;
    for (; i < count; i++) {
        if (!ascii[i] || wstr[i] != (WCHAR)ascii[i]) {
            return 0;
        }
    }
    return ascii[count] == '\0';
}

void mainCRTStartup(void) {
    NTSTATUS st;
    IO_STATUS_BLOCK iosb;
    uint8_t buf[128];
    FILE_FS_DEVICE_INFORMATION* dev_info = (FILE_FS_DEVICE_INFORMATION*)buf;
    FILE_FS_ATTRIBUTE_INFORMATION_PREFIX* attr_info = (FILE_FS_ATTRIBUTE_INFORMATION_PREFIX*)buf;
    FILE_FS_SIZE_INFORMATION* size_info = (FILE_FS_SIZE_INFORMATION*)buf;
    uint8_t short_buf[4];

    write_str("== syscall_file_volume_test ==\r\n");

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtQueryVolumeInformationFile(
        STDOUT_HANDLE, &iosb, buf, (ULONG)sizeof(FILE_FS_DEVICE_INFORMATION),
        FILE_FS_DEVICE_INFORMATION_CLASS);
    check("NtQueryVolumeInformationFile(Device) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("DeviceInfo io_status is STATUS_SUCCESS", (NTSTATUS)iosb.Status == STATUS_SUCCESS);
    check("DeviceInfo returns 8 bytes", iosb.Information == sizeof(FILE_FS_DEVICE_INFORMATION));
    check("DeviceInfo device type is non-zero", dev_info->DeviceType != 0);

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtQueryVolumeInformationFile(
        STDOUT_HANDLE, &iosb, buf, (ULONG)sizeof(buf),
        FILE_FS_ATTRIBUTE_INFORMATION_CLASS);
    check("NtQueryVolumeInformationFile(Attribute) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("AttributeInfo io_status is STATUS_SUCCESS", (NTSTATUS)iosb.Status == STATUS_SUCCESS);
    if (st == STATUS_SUCCESS && attr_info->FileSystemNameLength > 0) {
        check("AttributeInfo fs name is WinEmuFS",
              equal_utf16_ascii(attr_info->FileSystemName, attr_info->FileSystemNameLength, "WinEmuFS"));
    }

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtQueryVolumeInformationFile(
        STDOUT_HANDLE, &iosb, buf, (ULONG)sizeof(FILE_FS_SIZE_INFORMATION),
        FILE_FS_SIZE_INFORMATION_CLASS);
    check("NtQueryVolumeInformationFile(Size) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("SizeInfo bytes per sector is 4096", size_info->BytesPerSector == 4096);
    check("SizeInfo total allocation units > 0", size_info->TotalAllocationUnits > 0);

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtQueryVolumeInformationFile(
        STDOUT_HANDLE, &iosb, short_buf, (ULONG)sizeof(short_buf),
        FILE_FS_DEVICE_INFORMATION_CLASS);
    check("NtQueryVolumeInformationFile(short) returns STATUS_INFO_LENGTH_MISMATCH", st == STATUS_INFO_LENGTH_MISMATCH);
    check("short io_status is STATUS_INFO_LENGTH_MISMATCH", (NTSTATUS)iosb.Status == STATUS_INFO_LENGTH_MISMATCH);

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtQueryVolumeInformationFile(
        (HANDLE)(uint64_t)0x7fffffffULL, &iosb, buf, (ULONG)sizeof(buf),
        FILE_FS_DEVICE_INFORMATION_CLASS);
    check("NtQueryVolumeInformationFile(invalid handle) returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);

    iosb.Status = 0;
    iosb.Information = 0;
    st = NtQueryVolumeInformationFile(
        STDOUT_HANDLE, &iosb, buf, (ULONG)sizeof(buf),
        0xFFFFU);
    check("NtQueryVolumeInformationFile(unknown class) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);
    check("unknown class io_status is STATUS_INVALID_PARAMETER", (NTSTATUS)iosb.Status == STATUS_INVALID_PARAMETER);

    write_str("syscall_file_volume_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    terminate_current_process(g_fail == 0 ? 0 : 1);
}
