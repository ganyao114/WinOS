#include <stddef.h>
#include <stdint.h>

typedef uint8_t BOOLEAN;
typedef uint16_t USHORT;
typedef uint16_t WCHAR;
typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef uint64_t ULONG_PTR;
typedef void *HANDLE;

typedef struct {
    uint64_t Status;
    uint64_t Information;
} IO_STATUS_BLOCK;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    uint32_t _pad;
    WCHAR *Buffer;
} UNICODE_STRING;

typedef struct {
    UNICODE_STRING TypeName;
} OBJECT_TYPE_INFORMATION_PREFIX;

typedef struct {
    uint8_t Revision;
    uint8_t SubAuthorityCount;
    uint8_t IdentifierAuthority[6];
    uint32_t SubAuthority[1];
} SID;

typedef struct {
    SID *Sid;
    ULONG Attributes;
} SID_AND_ATTRIBUTES;

typedef struct {
    SID_AND_ATTRIBUTES User;
} TOKEN_USER;

typedef struct {
    HANDLE LinkedToken;
} TOKEN_LINKED_TOKEN;

typedef struct {
    ULONG TokenIsElevated;
} TOKEN_ELEVATION;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_INVALID_HANDLE 0xC0000008U
#define STATUS_INVALID_PARAMETER 0xC000000DU
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004U
#define STATUS_BUFFER_TOO_SMALL 0xC0000023U
#define STATUS_NOT_IMPLEMENTED 0xC0000002U
#define STATUS_ACCESS_DENIED 0xC0000022U

#define PROCESS_DEFAULT_HARD_ERROR_MODE 12U
#define PROCESS_AFFINITY_MASK 21U

#define OBJECT_TYPE_INFORMATION_CLASS 2U

#define TOKEN_USER_CLASS 1U
#define TOKEN_TYPE_CLASS 8U
#define TOKEN_ELEVATION_TYPE_CLASS 18U
#define TOKEN_LINKED_TOKEN_CLASS 19U
#define TOKEN_ELEVATION_CLASS 20U
#define TOKEN_VIRTUALIZATION_ENABLED_CLASS 24U
#define TOKEN_IS_APP_CONTAINER_CLASS 29U
#define DUPLICATE_CLOSE_SOURCE 0x00000001U
#define DUPLICATE_SAME_ACCESS 0x00000002U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void *apc_routine, void *apc_ctx,
    IO_STATUS_BLOCK *iosb, const void *buf, ULONG len, uint64_t *byte_offset, ULONG *key);
__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);
__declspec(dllimport) NTSTATUS NtOpenProcessToken(
    HANDLE process_handle, ULONG desired_access, HANDLE *token_handle);
__declspec(dllimport) NTSTATUS NtQueryInformationToken(
    HANDLE token, ULONG info_class, void *token_info, ULONG token_info_len, ULONG *ret_len);
__declspec(dllimport) NTSTATUS NtSetInformationProcess(
    HANDLE process, ULONG info_class, void *buf, ULONG len);
__declspec(dllimport) NTSTATUS NtQueryObject(
    HANDLE handle, ULONG object_info_class, void *object_info, ULONG object_info_len, ULONG *ret_len);
__declspec(dllimport) NTSTATUS NtDuplicateObject(
    HANDLE source_process, HANDLE source_handle,
    HANDLE target_process, HANDLE *target_handle,
    ULONG desired_access, ULONG attributes, ULONG options);
__declspec(dllimport) NTSTATUS NtClose(HANDLE handle);

static uint32_t g_pass = 0;
static uint32_t g_fail = 0;

static void write_str(const char *s) {
    IO_STATUS_BLOCK iosb = {0};
    ULONG len = 0;
    while (s[len]) {
        len++;
    }
    (void)NtWriteFile(STDOUT_HANDLE, 0, 0, 0, &iosb, s, len, 0, 0);
}

static void write_u64_hex(uint64_t value) {
    char buf[19];
    const char *hex = "0123456789abcdef";
    int i;
    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 16; i++) {
        buf[2 + i] = hex[(value >> ((15 - i) * 4)) & 0xF];
    }
    buf[18] = '\0';
    write_str(buf);
}

static void check(const char *name, int ok) {
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

static int equal_utf16_ascii(const WCHAR *wstr, USHORT wbytes, const char *ascii) {
    USHORT count = (USHORT)(wbytes / 2);
    USHORT i = 0;
    for (; i < count; i++) {
        char c = ascii[i];
        if (!c) {
            return 0;
        }
        if ((WCHAR)c != wstr[i]) {
            return 0;
        }
    }
    return ascii[count] == '\0';
}

static uint32_t read_u32_le(const uint8_t *buf, size_t off) {
    return (uint32_t)buf[off] |
           ((uint32_t)buf[off + 1] << 8) |
           ((uint32_t)buf[off + 2] << 16) |
           ((uint32_t)buf[off + 3] << 24);
}

void mainCRTStartup(void) {
    NTSTATUS st;
    HANDLE token = 0;
    ULONG ret_len = 0;
    ULONG u32 = 0;
    ULONG small_ret = 0;
    ULONG_PTR affinity = 1;
    uint8_t user_buf[128];
    uint8_t obj_buf[256];
    uint8_t small_buf[8];
    TOKEN_LINKED_TOKEN linked = {0};
    TOKEN_ELEVATION elevation = {0};
    OBJECT_TYPE_INFORMATION_PREFIX *obj_type = (OBJECT_TYPE_INFORMATION_PREFIX *)obj_buf;

    write_str("== syscall_process_token_test ==\r\n");

    st = NtOpenProcessToken(NT_CURRENT_PROCESS, 0x0008, &token);
    check("NtOpenProcessToken(current) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtOpenProcessToken returns non-zero handle", token != 0);

    ret_len = 0;
    st = NtQueryInformationToken(token, TOKEN_USER_CLASS, user_buf, (ULONG)sizeof(user_buf), &ret_len);
    check("NtQueryInformationToken(TokenUser) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("TokenUser return length >= TOKEN_USER + SID", ret_len >= (ULONG)(sizeof(TOKEN_USER) + 12));
    if (st == STATUS_SUCCESS) {
        TOKEN_USER *tu = (TOKEN_USER *)user_buf;
        check("TokenUser SID pointer is non-null", tu->User.Sid != 0);
        if (tu->User.Sid != 0) {
            check("TokenUser SID revision is 1", tu->User.Sid->Revision == 1);
        }
    }

    small_ret = 0;
    st = NtQueryInformationToken(token, TOKEN_USER_CLASS, small_buf, (ULONG)sizeof(small_buf), &small_ret);
    check("TokenUser short buffer returns STATUS_BUFFER_TOO_SMALL", st == STATUS_BUFFER_TOO_SMALL);
    check("TokenUser short buffer reports required length", small_ret >= (ULONG)(sizeof(TOKEN_USER) + 12));

    ret_len = 0;
    u32 = 0;
    st = NtQueryInformationToken(token, TOKEN_TYPE_CLASS, &u32, sizeof(u32), &ret_len);
    check("NtQueryInformationToken(TokenType) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("TokenType return length is 4", ret_len == sizeof(u32));
    check("TokenType is primary(1)", u32 == 1);

    ret_len = 0;
    u32 = 0;
    st = NtQueryInformationToken(token, TOKEN_ELEVATION_TYPE_CLASS, &u32, sizeof(u32), &ret_len);
    check("NtQueryInformationToken(TokenElevationType) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("TokenElevationType is default(1)", u32 == 1);

    ret_len = 0;
    elevation.TokenIsElevated = 0xFFFFFFFFU;
    st = NtQueryInformationToken(token, TOKEN_ELEVATION_CLASS, &elevation, sizeof(elevation), &ret_len);
    check("NtQueryInformationToken(TokenElevation) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("TokenElevation return length is 4", ret_len == sizeof(elevation));
    check("TokenElevation TokenIsElevated is 0", elevation.TokenIsElevated == 0);

    ret_len = 0;
    u32 = 0xFFFFFFFFU;
    st = NtQueryInformationToken(token, TOKEN_VIRTUALIZATION_ENABLED_CLASS, &u32, sizeof(u32), &ret_len);
    check("NtQueryInformationToken(TokenVirtualizationEnabled) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("TokenVirtualizationEnabled is 0", u32 == 0);

    ret_len = 0;
    u32 = 0xFFFFFFFFU;
    st = NtQueryInformationToken(token, TOKEN_IS_APP_CONTAINER_CLASS, &u32, sizeof(u32), &ret_len);
    check("NtQueryInformationToken(TokenIsAppContainer) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("TokenIsAppContainer is 0", u32 == 0);

    ret_len = 0;
    linked.LinkedToken = 0;
    st = NtQueryInformationToken(token, TOKEN_LINKED_TOKEN_CLASS, &linked, sizeof(linked), &ret_len);
    check("NtQueryInformationToken(TokenLinkedToken) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("TokenLinkedToken handle is non-zero", linked.LinkedToken != 0);
    if (linked.LinkedToken) {
        st = NtClose(linked.LinkedToken);
        check("NtClose(linked token) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    }

    ret_len = 0;
    st = NtQueryInformationToken((HANDLE)(ULONG_PTR)0x7fffffffULL, TOKEN_USER_CLASS, user_buf, (ULONG)sizeof(user_buf), &ret_len);
    check("NtQueryInformationToken(invalid handle) returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);

    HANDLE dup = 0;
    st = NtDuplicateObject(
        NT_CURRENT_PROCESS, token, NT_CURRENT_PROCESS, &dup,
        0x80000000U, 0, 0);
    check("NtDuplicateObject(token, invalid desired access) returns STATUS_ACCESS_DENIED", st == STATUS_ACCESS_DENIED);
    check("NtDuplicateObject(token, invalid desired access) does not return handle", dup == 0);

    dup = 0;
    st = NtDuplicateObject(
        NT_CURRENT_PROCESS, token, NT_CURRENT_PROCESS, &dup,
        0x80000000U, 0, DUPLICATE_SAME_ACCESS);
    check("NtDuplicateObject(token, DUPLICATE_SAME_ACCESS) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtDuplicateObject(token, DUPLICATE_SAME_ACCESS) returns non-zero handle", dup != 0);
    if (dup) {
        st = NtClose(dup);
        check("NtClose(duplicate token) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    }

    u32 = 0;
    st = NtSetInformationProcess(NT_CURRENT_PROCESS, PROCESS_DEFAULT_HARD_ERROR_MODE, &u32, sizeof(u32));
    check("NtSetInformationProcess(ProcessDefaultHardErrorMode) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    st = NtSetInformationProcess(NT_CURRENT_PROCESS, PROCESS_AFFINITY_MASK, &affinity, sizeof(affinity));
    check("NtSetInformationProcess(ProcessAffinityMask) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    st = NtSetInformationProcess(NT_CURRENT_PROCESS, PROCESS_DEFAULT_HARD_ERROR_MODE, &u32, 0);
    check("NtSetInformationProcess(invalid len) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    st = NtSetInformationProcess(NT_CURRENT_PROCESS, 0xFFFFU, &u32, sizeof(u32));
    check("NtSetInformationProcess(unknown class) returns STATUS_NOT_IMPLEMENTED", st == STATUS_NOT_IMPLEMENTED);

    ret_len = 0;
    st = NtQueryObject(NT_CURRENT_PROCESS, OBJECT_TYPE_INFORMATION_CLASS, obj_buf, (ULONG)sizeof(obj_buf), &ret_len);
    check("NtQueryObject(process, ObjectTypeInformation) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    if (st == STATUS_SUCCESS) {
        check("ObjectTypeInformation(process) name is Process",
              obj_type->TypeName.Buffer &&
              equal_utf16_ascii(obj_type->TypeName.Buffer, obj_type->TypeName.Length, "Process"));
        check("ObjectTypeInformation(process) total objects >= 1",
              read_u32_le(obj_buf, 16) >= 1);
        check("ObjectTypeInformation(process) total handles >= 1",
              read_u32_le(obj_buf, 20) >= 1);
        check("ObjectTypeInformation(process) high-water objects >= total objects",
              read_u32_le(obj_buf, 40) >= read_u32_le(obj_buf, 16));
        check("ObjectTypeInformation(process) high-water handles >= total handles",
              read_u32_le(obj_buf, 44) >= read_u32_le(obj_buf, 20));
    }

    ret_len = 0;
    st = NtQueryObject(token, OBJECT_TYPE_INFORMATION_CLASS, obj_buf, (ULONG)sizeof(obj_buf), &ret_len);
    check("NtQueryObject(token, ObjectTypeInformation) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    if (st == STATUS_SUCCESS) {
        check("ObjectTypeInformation(token) name is Token",
              obj_type->TypeName.Buffer &&
              equal_utf16_ascii(obj_type->TypeName.Buffer, obj_type->TypeName.Length, "Token"));
        check("ObjectTypeInformation(token) total objects >= 1",
              read_u32_le(obj_buf, 16) >= 1);
        check("ObjectTypeInformation(token) total handles >= 1",
              read_u32_le(obj_buf, 20) >= 1);
        check("ObjectTypeInformation(token) high-water objects >= total objects",
              read_u32_le(obj_buf, 40) >= read_u32_le(obj_buf, 16));
        check("ObjectTypeInformation(token) high-water handles >= total handles",
              read_u32_le(obj_buf, 44) >= read_u32_le(obj_buf, 20));
    }

    ret_len = 0;
    st = NtQueryObject(token, OBJECT_TYPE_INFORMATION_CLASS, small_buf, (ULONG)sizeof(small_buf), &ret_len);
    check("NtQueryObject(ObjectTypeInformation, short) returns STATUS_INFO_LENGTH_MISMATCH", st == STATUS_INFO_LENGTH_MISMATCH);
    check("NtQueryObject(ObjectTypeInformation, short) has non-zero required length", ret_len > 0);

    HANDLE moved = 0;
    st = NtDuplicateObject(
        NT_CURRENT_PROCESS, token, NT_CURRENT_PROCESS, &moved,
        0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
    check("NtDuplicateObject(token, DUPLICATE_CLOSE_SOURCE) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtDuplicateObject(token, DUPLICATE_CLOSE_SOURCE) returns non-zero handle", moved != 0);

    st = NtClose(token);
    check("NtClose(original token after DUPLICATE_CLOSE_SOURCE) returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);

    token = moved;
    st = NtClose(token);
    check("NtClose(token) returns STATUS_SUCCESS", st == STATUS_SUCCESS);

    write_str("syscall_process_token_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    terminate_current_process(g_fail == 0 ? 0 : 1);
}
