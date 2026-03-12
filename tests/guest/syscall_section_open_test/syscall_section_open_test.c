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

typedef struct {
    uint64_t BaseAddress;
    uint32_t AllocationAttributes;
    uint32_t _pad;
    uint64_t MaximumSize;
} SECTION_BASIC_INFORMATION;

typedef struct {
    uint64_t Attributes;
    uint32_t HandleCount;
    uint32_t PointerCount;
    uint8_t Reserved[40];
} OBJECT_BASIC_INFORMATION;

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define NT_CURRENT_PROCESS ((HANDLE)(uint64_t)-1)

#define STATUS_SUCCESS 0x00000000U
#define STATUS_INVALID_PARAMETER 0xC000000DU
#define STATUS_INVALID_HANDLE 0xC0000008U
#define STATUS_BUFFER_TOO_SMALL 0xC0000023U
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035U
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034U
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004U
#define STATUS_ACCESS_DENIED 0xC0000022U

#define PAGE_READWRITE 0x04U
#define SEC_COMMIT 0x08000000U
#define OBJ_CASE_INSENSITIVE 0x40U
#define OBJECT_BASIC_INFORMATION_CLASS 0U
#define OBJECT_NAME_INFORMATION_CLASS 1U
#define NR_QUERY_SECTION 0x0051U
#define DUPLICATE_SAME_ACCESS 0x00000002U

__declspec(dllimport) NTSTATUS NtWriteFile(
    HANDLE file, HANDLE event, void* apc_routine, void* apc_ctx,
    IO_STATUS_BLOCK* iosb, const void* buf, ULONG len, uint64_t* byte_offset, ULONG* key);
__declspec(dllimport) __attribute__((noreturn))
void NtTerminateProcess(HANDLE process, NTSTATUS code);
__declspec(dllimport) NTSTATUS NtCreateSection(
    HANDLE* section_handle, ULONG desired_access, OBJECT_ATTRIBUTES* object_attributes,
    uint64_t* max_size, ULONG page_prot, ULONG alloc_attrs, HANDLE file_handle);
__declspec(dllimport) NTSTATUS NtOpenSection(
    HANDLE* section_handle, ULONG desired_access, OBJECT_ATTRIBUTES* object_attributes);
__declspec(dllimport) NTSTATUS NtQueryObject(
    HANDLE handle, ULONG object_info_class, void* object_info, ULONG object_info_len, ULONG* ret_len);
__declspec(dllimport) NTSTATUS NtDuplicateObject(
    HANDLE source_process, HANDLE source_handle, HANDLE target_process, HANDLE* target_handle,
    ULONG desired_access, ULONG handle_attributes, ULONG options);
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

static WCHAR wchar_lower_ascii(WCHAR ch) {
    if (ch >= (WCHAR)'A' && ch <= (WCHAR)'Z') {
        return (WCHAR)(ch + ((WCHAR)'a' - (WCHAR)'A'));
    }
    return ch;
}

static int utf16_ends_with_ascii_ci(const WCHAR* wstr, ULONG wbytes, const char* ascii) {
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
        WCHAR wc = wchar_lower_ascii(wstr[start + i]);
        char ac = ascii[i];
        if (ac >= 'A' && ac <= 'Z') {
            ac = (char)(ac + ('a' - 'A'));
        }
        if (wc != (WCHAR)ac) {
            return 0;
        }
    }
    return 1;
}

static NTSTATUS raw_nt_query_section(
    HANDLE section_handle,
    ULONG info_class,
    void* info,
    ULONG info_len,
    ULONG* ret_len
) {
    register uint64_t x0 __asm__("x0") = (uint64_t)(uintptr_t)section_handle;
    register uint64_t x1 __asm__("x1") = (uint64_t)info_class;
    register uint64_t x2 __asm__("x2") = (uint64_t)(uintptr_t)info;
    register uint64_t x3 __asm__("x3") = (uint64_t)info_len;
    register uint64_t x4 __asm__("x4") = (uint64_t)(uintptr_t)ret_len;
    register uint64_t x8 __asm__("x8") = NR_QUERY_SECTION;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "x5", "x6", "x7", "memory"
    );
    return (NTSTATUS)x0;
}

void mainCRTStartup(void) {
    NTSTATUS st;
    HANDLE section_a = 0;
    HANDLE section_b = 0;
    HANDLE section_c = 0;
    HANDLE section_dup = 0;
    ULONG ret_len = 0;
    SECTION_BASIC_INFORMATION sbi = {0};
    OBJECT_BASIC_INFORMATION obi = {0};
    uint8_t section_image_info[40];
    uint64_t section_size = 0x2000;
    uint8_t obj_name_info[256];
    uint8_t short_obj_name_info[8];
    WCHAR named_buf[96];
    WCHAR missing_buf[96];
    UNICODE_STRING named_name;
    UNICODE_STRING missing_name;
    OBJECT_ATTRIBUTES named_oa;
    OBJECT_ATTRIBUTES missing_oa;

    write_str("== syscall_section_open_test ==\r\n");

    init_unicode(&named_name, named_buf, "\\BaseNamedObjects\\WinEmuOpenSectionTest");
    init_oa(&named_oa, &named_name, 0);

    st = NtCreateSection((HANDLE*)0, 0, &named_oa, &section_size, PAGE_READWRITE, SEC_COMMIT, 0);
    check("NtCreateSection(NULL out handle) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    st = NtCreateSection(&section_a, 0, &named_oa, &section_size, PAGE_READWRITE, SEC_COMMIT, 0);
    check("NtCreateSection(named) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtCreateSection(named) returns non-zero handle", section_a != 0);

    section_c = 0;
    st = NtCreateSection(&section_c, 0x80000000U, &named_oa, &section_size, PAGE_READWRITE, SEC_COMMIT, 0);
    check("NtCreateSection(invalid desired access) returns STATUS_ACCESS_DENIED", st == STATUS_ACCESS_DENIED);
    check("NtCreateSection(invalid desired access) returns no handle", section_c == 0);

    st = NtOpenSection(&section_b, 0, &named_oa);
    check("NtOpenSection(existing name) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtOpenSection(existing name) returns non-zero handle", section_b != 0);

    st = NtOpenSection((HANDLE*)0, 0, &named_oa);
    check("NtOpenSection(NULL out handle) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    ret_len = 0;
    sbi.AllocationAttributes = 0;
    sbi.MaximumSize = 0;
    st = raw_nt_query_section(section_a, 0, &sbi, (ULONG)sizeof(sbi), &ret_len);
    check("NtQuerySection(SectionBasicInformation) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQuerySection(SectionBasicInformation) reports expected length", ret_len == (ULONG)sizeof(sbi));
    check("NtQuerySection(SectionBasicInformation) allocation attrs match SEC_COMMIT",
          sbi.AllocationAttributes == SEC_COMMIT);
    check("NtQuerySection(SectionBasicInformation) maximum size is 0x2000", sbi.MaximumSize == section_size);

    ret_len = 0;
    st = raw_nt_query_section(section_a, 0, &sbi, 8, &ret_len);
    check("NtQuerySection(SectionBasicInformation, short) returns STATUS_BUFFER_TOO_SMALL",
          st == STATUS_BUFFER_TOO_SMALL);
    check("NtQuerySection(SectionBasicInformation, short) reports expected length",
          ret_len == (ULONG)sizeof(sbi));

    ret_len = 0;
    section_image_info[0] = 0xAA;
    st = raw_nt_query_section(section_a, 1, section_image_info, (ULONG)sizeof(section_image_info), &ret_len);
    check("NtQuerySection(SectionImageInformation) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtQuerySection(SectionImageInformation) reports expected length", ret_len == (ULONG)sizeof(section_image_info));
    check("NtQuerySection(SectionImageInformation) zero-fills output", section_image_info[0] == 0);

    ret_len = 0;
    st = raw_nt_query_section(section_a, 0xFFFFU, &sbi, (ULONG)sizeof(sbi), &ret_len);
    check("NtQuerySection(unknown class) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    ret_len = 0;
    st = raw_nt_query_section((HANDLE)(uint64_t)0x7fffffffULL, 0, &sbi, (ULONG)sizeof(sbi), &ret_len);
    check("NtQuerySection(invalid handle) returns STATUS_INVALID_HANDLE", st == STATUS_INVALID_HANDLE);

    section_c = 0;
    st = NtOpenSection(&section_c, 0x80000000U, &named_oa);
    check("NtOpenSection(invalid desired access) returns STATUS_ACCESS_DENIED", st == STATUS_ACCESS_DENIED);
    check("NtOpenSection(invalid desired access) returns no handle", section_c == 0);

    st = NtClose(section_b);
    check("NtClose(opened section) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    section_b = 0;

    ret_len = 0;
    sbi.AllocationAttributes = 0;
    sbi.MaximumSize = 0;
    st = raw_nt_query_section(section_a, 0, &sbi, (ULONG)sizeof(sbi), &ret_len);
    check(
        "NtQuerySection(created handle remains valid after closing sibling handle)",
        st == STATUS_SUCCESS
    );

    st = NtOpenSection(&section_b, 0, &named_oa);
    check("NtOpenSection(reopen after sibling close) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtOpenSection(reopen after sibling close) returns non-zero handle", section_b != 0);

    st = NtDuplicateObject(
        NT_CURRENT_PROCESS,
        section_a,
        NT_CURRENT_PROCESS,
        &section_dup,
        0,
        0,
        DUPLICATE_SAME_ACCESS
    );
    check("NtDuplicateObject(section) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("NtDuplicateObject(section) returns non-zero handle", section_dup != 0);

    st = NtClose(section_a);
    check("NtClose(created section) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    section_a = 0;

    ret_len = 0;
    sbi.AllocationAttributes = 0;
    sbi.MaximumSize = 0;
    st = raw_nt_query_section(section_dup, 0, &sbi, (ULONG)sizeof(sbi), &ret_len);
    check(
        "NtQuerySection(duplicate handle remains valid after closing source handle)",
        st == STATUS_SUCCESS
    );

    ret_len = 0;
    obi.HandleCount = 0;
    obi.PointerCount = 0;
    st = NtQueryObject(
        section_dup,
        OBJECT_BASIC_INFORMATION_CLASS,
        &obi,
        (ULONG)sizeof(obi),
        &ret_len
    );
    check("NtQueryObject(section, ObjectBasicInformation) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    check("ObjectBasicInformation(section) handle count is 2 after closing source handle", obi.HandleCount == 2);
    check("ObjectBasicInformation(section) pointer count is 2 after closing source handle", obi.PointerCount == 2);

    ret_len = 0;
    st = NtQueryObject(section_dup, OBJECT_NAME_INFORMATION_CLASS, obj_name_info, (ULONG)sizeof(obj_name_info), &ret_len);
    check("NtQueryObject(section, ObjectNameInformation) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
    if (st == STATUS_SUCCESS && ret_len >= 16) {
        USHORT name_len = *(USHORT*)(obj_name_info + 0);
        uint64_t name_ptr = *(uint64_t*)(obj_name_info + 8);
        check("ObjectNameInformation(section) name length is non-zero", name_len != 0);
        check("ObjectNameInformation(section) buffer pointer is non-zero", name_ptr != 0);
        check("ObjectNameInformation(section) ends with WinEmuOpenSectionTest",
              utf16_ends_with_ascii_ci((const WCHAR*)(obj_name_info + 16), (ULONG)name_len, "WinEmuOpenSectionTest"));
    }

    ret_len = 0;
    st = NtQueryObject(section_dup, OBJECT_NAME_INFORMATION_CLASS, short_obj_name_info, (ULONG)sizeof(short_obj_name_info), &ret_len);
    check("NtQueryObject(ObjectNameInformation, short) returns STATUS_INFO_LENGTH_MISMATCH",
          st == STATUS_INFO_LENGTH_MISMATCH);
    check("NtQueryObject(ObjectNameInformation, short) reports required length > 16", ret_len > 16);

    section_c = 0;
    st = NtCreateSection(&section_c, 0, &named_oa, &section_size, PAGE_READWRITE, SEC_COMMIT, 0);
    check("NtCreateSection(duplicate name) returns STATUS_OBJECT_NAME_COLLISION", st == STATUS_OBJECT_NAME_COLLISION);

    init_unicode(&missing_name, missing_buf, "\\BaseNamedObjects\\WinEmuOpenSectionMissing");
    init_oa(&missing_oa, &missing_name, 0);
    section_c = 0;
    st = NtOpenSection(&section_c, 0, &missing_oa);
    check("NtOpenSection(missing name) returns STATUS_OBJECT_NAME_NOT_FOUND", st == STATUS_OBJECT_NAME_NOT_FOUND);

    section_c = 0;
    st = NtOpenSection(&section_c, 0, 0);
    check("NtOpenSection(NULL oa) returns STATUS_INVALID_PARAMETER", st == STATUS_INVALID_PARAMETER);

    if (section_b != 0) {
        st = NtClose(section_b);
        check("NtClose(reopened section) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
        section_b = 0;
    }
    if (section_dup != 0) {
        st = NtClose(section_dup);
        check("NtClose(duplicate section) returns STATUS_SUCCESS", st == STATUS_SUCCESS);
        section_dup = 0;
    }

    write_str("syscall_section_open_test summary: pass=");
    write_u64_hex(g_pass);
    write_str(" fail=");
    write_u64_hex(g_fail);
    write_str("\r\n");

    terminate_current_process(g_fail == 0 ? 0 : 1);
}
