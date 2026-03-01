#include <stdint.h>
#include <stddef.h>

typedef uint16_t USHORT;
typedef uint16_t WCHAR;
typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef void* HANDLE;

typedef struct {
    uint64_t Status;
    uint64_t Information;
} IO_STATUS_BLOCK;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    uint32_t _pad;
    WCHAR* Buffer;
} UNICODE_STRING;

typedef struct {
    uint32_t Length;
    uint32_t _pad0;
    HANDLE RootDirectory;
    UNICODE_STRING* ObjectName;
    uint32_t Attributes;
    uint32_t _pad1;
    void* SecurityDescriptor;
    void* SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_INVALID_HANDLE 0xC0000008U
#define STATUS_INVALID_PARAMETER 0xC000000DU
#define STATUS_BUFFER_TOO_SMALL 0xC0000023U
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004U
#define STATUS_ACCESS_DENIED 0xC0000022U

#define KEY_BASIC_INFORMATION_CLASS 0U
#define KEY_FULL_INFORMATION_CLASS 2U
#define KEY_NAME_INFORMATION_CLASS 3U
#define OBJECT_NAME_INFORMATION_CLASS 1U

#define REG_DWORD 4U
#define OBJ_CASE_INSENSITIVE 0x40U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);
__declspec(dllimport) NTSTATUS NtOpenKey(
    HANDLE* key_handle, ULONG desired_access, OBJECT_ATTRIBUTES* object_attributes);
__declspec(dllimport) NTSTATUS NtCreateKey(
    HANDLE* key_handle, ULONG desired_access, OBJECT_ATTRIBUTES* object_attributes,
    ULONG title_index, UNICODE_STRING* class_name, ULONG create_options, ULONG* disposition);
__declspec(dllimport) NTSTATUS NtSetValueKey(
    HANDLE key_handle, UNICODE_STRING* value_name, ULONG title_index,
    ULONG type, const void* data, ULONG data_size);
__declspec(dllimport) NTSTATUS NtQueryKey(
    HANDLE key_handle, ULONG key_information_class, void* key_information,
    ULONG length, ULONG* result_length);
__declspec(dllimport) NTSTATUS NtQueryObject(
    HANDLE handle, ULONG object_info_class, void* object_info, ULONG object_info_len, ULONG* ret_len);
__declspec(dllimport) NTSTATUS NtClose(HANDLE handle);

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

static void init_unicode(UNICODE_STRING* us, WCHAR* storage, const char* ascii) {
    uint32_t n = 0;
    while (ascii[n]) {
        storage[n] = (WCHAR)ascii[n];
        n++;
    }
    storage[n] = 0;
    us->Length = (USHORT)(n * 2);
    us->MaximumLength = (USHORT)((n + 1) * 2);
    us->Buffer = storage;
}

static void init_oa(OBJECT_ATTRIBUTES* oa, UNICODE_STRING* name, HANDLE root) {
    oa->Length = (ULONG)sizeof(OBJECT_ATTRIBUTES);
    oa->_pad0 = 0;
    oa->RootDirectory = root;
    oa->ObjectName = name;
    oa->Attributes = OBJ_CASE_INSENSITIVE;
    oa->_pad1 = 0;
    oa->SecurityDescriptor = 0;
    oa->SecurityQualityOfService = 0;
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

static int utf16_ends_with_ascii(const WCHAR* wstr, ULONG wbytes, const char* ascii) {
    ULONG count = wbytes / 2;
    ULONG ascii_len = 0;
    while (ascii[ascii_len]) {
        ascii_len++;
    }
    if (count < ascii_len) {
        return 0;
    }
    ULONG i = 0;
    ULONG start = count - ascii_len;
    for (; i < ascii_len; i++) {
        if (wstr[start + i] != (WCHAR)ascii[i]) {
            return 0;
        }
    }
    return 1;
}

void mainCRTStartup(void) {
    NTSTATUS st;
    HANDLE parent_key = 0;
    HANDLE sub_key = 0;
    HANDLE opened_key = 0;
    HANDLE denied_key = 0;
    ULONG disp = 0;
    ULONG ret_len = 0;
    uint32_t value = 0x12345678U;
    uint8_t key_info[256];
    uint8_t short_buf[8];

    WCHAR parent_buf[96];
    WCHAR sub_buf[32];
    WCHAR value_buf[32];
    UNICODE_STRING parent_name;
    UNICODE_STRING sub_name;
    UNICODE_STRING value_name;
    OBJECT_ATTRIBUTES parent_oa;
    OBJECT_ATTRIBUTES sub_oa;

    write_str("== syscall_registry_key_test ==\r\n");

    init_unicode(&parent_name, parent_buf, "\\Registry\\Machine\\Software\\WinEmuQueryKeyTest");
    init_oa(&parent_oa, &parent_name, 0);
    st = NtCreateKey(&denied_key, 0x80000000U, &parent_oa, 0, 0, 0, &disp);
    check("NtCreateKey(invalid desired access) returns STATUS_ACCESS_DENIED", st == STATUS_ACCESS_DENIED);
    check("NtCreateKey(invalid desired access) returns no handle", denied_key == 0);

    st = NtCreateKey(&parent_key, 0, &parent_oa, 0, 0, 0, &disp);
    check("NtCreateKey(parent) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateKey(parent) returns non-zero handle", parent_key != 0);
    check("NtCreateKey(parent) disposition is create/opened", disp == 1 || disp == 2);

    st = NtOpenKey(&opened_key, 0, &parent_oa);
    check("NtOpenKey(valid desired access) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtOpenKey(valid desired access) returns non-zero handle", opened_key != 0);

    denied_key = 0;
    st = NtOpenKey(&denied_key, 0x80000000U, &parent_oa);
    check("NtOpenKey(invalid desired access) returns STATUS_ACCESS_DENIED", st == STATUS_ACCESS_DENIED);
    check("NtOpenKey(invalid desired access) returns no handle", denied_key == 0);

    init_unicode(&sub_name, sub_buf, "SubKeyA");
    init_oa(&sub_oa, &sub_name, parent_key);
    disp = 0;
    st = NtCreateKey(&sub_key, 0, &sub_oa, 0, 0, 0, &disp);
    check("NtCreateKey(subkey) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateKey(subkey) returns non-zero handle", sub_key != 0);

    init_unicode(&value_name, value_buf, "ValueA");
    st = NtSetValueKey(parent_key, &value_name, 0, REG_DWORD, &value, sizeof(value));
    check("NtSetValueKey(parent) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    ret_len = 0;
    st = NtQueryKey(parent_key, KEY_BASIC_INFORMATION_CLASS, key_info, (ULONG)sizeof(key_info), &ret_len);
    check("NtQueryKey(KeyBasicInformation) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQueryKey(KeyBasicInformation) return length >= 16", ret_len >= 16);
    if (st == STATUS_SUCCESS && ret_len >= 16) {
        uint32_t name_len = *(uint32_t*)(key_info + 12);
        check("KeyBasicInformation name is WinEmuQueryKeyTest",
              equal_utf16_ascii((const WCHAR*)(key_info + 16), name_len, "WinEmuQueryKeyTest"));
    }

    ret_len = 0;
    st = NtQueryKey(parent_key, KEY_BASIC_INFORMATION_CLASS, short_buf, (ULONG)sizeof(short_buf), &ret_len);
    check("NtQueryKey(KeyBasicInformation, short) returns STATUS_BUFFER_TOO_SMALL", st == STATUS_BUFFER_TOO_SMALL);
    check("NtQueryKey(KeyBasicInformation, short) reports required length >= 16", ret_len >= 16);

    ret_len = 0;
    st = NtQueryKey(parent_key, KEY_NAME_INFORMATION_CLASS, key_info, (ULONG)sizeof(key_info), &ret_len);
    check("NtQueryKey(KeyNameInformation) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    if (st == STATUS_SUCCESS && ret_len >= 4) {
        uint32_t name_len = *(uint32_t*)key_info;
        check("KeyNameInformation full name ends with WinEmuQueryKeyTest",
              utf16_ends_with_ascii((const WCHAR*)(key_info + 4), name_len, "WinEmuQueryKeyTest"));
    }

    ret_len = 0;
    st = NtQueryKey(parent_key, KEY_FULL_INFORMATION_CLASS, key_info, (ULONG)sizeof(key_info), &ret_len);
    check("NtQueryKey(KeyFullInformation) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQueryKey(KeyFullInformation) return length >= 44", ret_len >= 44);
    if (st == STATUS_SUCCESS && ret_len >= 44) {
        uint32_t subkeys = *(uint32_t*)(key_info + 20);
        uint32_t values = *(uint32_t*)(key_info + 32);
        uint32_t max_value_data = *(uint32_t*)(key_info + 40);
        check("KeyFullInformation subkeys >= 1", subkeys >= 1);
        check("KeyFullInformation values >= 1", values >= 1);
        check("KeyFullInformation max value data >= 4", max_value_data >= 4);
    }

    ret_len = 0;
    st = NtQueryObject(parent_key, OBJECT_NAME_INFORMATION_CLASS, key_info, (ULONG)sizeof(key_info), &ret_len);
    check("NtQueryObject(key, ObjectNameInformation) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    if (st == STATUS_SUCCESS && ret_len >= 16) {
        USHORT name_len = *(USHORT*)(key_info + 0);
        uint64_t name_ptr = *(uint64_t*)(key_info + 8);
        check("ObjectNameInformation(key) name length is non-zero", name_len != 0);
        check("ObjectNameInformation(key) buffer pointer is non-zero", name_ptr != 0);
        check("ObjectNameInformation(key) ends with WinEmuQueryKeyTest",
              utf16_ends_with_ascii((const WCHAR*)(key_info + 16), (ULONG)name_len, "WinEmuQueryKeyTest"));
    }

    ret_len = 0;
    st = NtQueryObject(parent_key, OBJECT_NAME_INFORMATION_CLASS, short_buf, (ULONG)sizeof(short_buf), &ret_len);
    check("NtQueryObject(ObjectNameInformation, short) returns STATUS_INFO_LENGTH_MISMATCH",
          st == STATUS_INFO_LENGTH_MISMATCH);
    check("NtQueryObject(ObjectNameInformation, short) reports required length > 16", ret_len > 16);

    st = NtQueryKey((HANDLE)(uint64_t)0x7fffffffULL, KEY_BASIC_INFORMATION_CLASS, key_info, (ULONG)sizeof(key_info), &ret_len);
    check("NtQueryKey(invalid handle) returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);

    st = NtQueryKey(parent_key, 0xFFFFU, key_info, (ULONG)sizeof(key_info), &ret_len);
    check("NtQueryKey(unknown class) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    st = NtClose(sub_key);
    check("NtClose(sub key) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    st = NtClose(opened_key);
    check("NtClose(opened key) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    st = NtClose(parent_key);
    check("NtClose(parent key) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    write_str("syscall_registry_key_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    terminate_current_process(g_fail == 0 ? 0 : 1);
}
