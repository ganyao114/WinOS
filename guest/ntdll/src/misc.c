/* ── Misc ────────────────────────────────────────────────────── */

EXPORT NTSTATUS RtlGetVersion(void* osvi) {
    if (!osvi) return STATUS_INVALID_PARAMETER;
    ULONG size = *(ULONG*)osvi;
    if (size < 20) return STATUS_INVALID_PARAMETER;

    uint8_t* p = (uint8_t*)osvi;
    for (ULONG i = 4; i < size; i++) {
        p[i] = 0;
    }

    *(ULONG*)(p + 4) = 10;      // dwMajorVersion
    *(ULONG*)(p + 8) = 0;       // dwMinorVersion
    *(ULONG*)(p + 12) = 19045;  // dwBuildNumber
    *(ULONG*)(p + 16) = 2;      // VER_PLATFORM_WIN32_NT
    return STATUS_SUCCESS;
}

EXPORT NTSTATUS NtQuerySystemInformation(ULONG cls, void* buf, ULONG len, ULONG* ret) {
    return syscall4(
        NR_QUERY_SYSTEM_INFORMATION,
        (uint64_t)cls,
        (uint64_t)buf,
        (uint64_t)len,
        (uint64_t)ret
    );
}

EXPORT NTSTATUS NtQuerySystemTime(int64_t* time) {
    return syscall2(NR_QUERY_SYSTEM_TIME, (uint64_t)time, 0);
}

EXPORT ULONG NtGetTickCount(void) {
    int64_t now = 0;
    if (NtQuerySystemTime(&now) != 0) return 0;
    return (ULONG)(now / 10000);
}

EXPORT NTSTATUS NtQueryPerformanceCounter(int64_t* counter, int64_t* frequency) {
    return syscall2(
        NR_QUERY_PERFORMANCE_COUNTER,
        (uint64_t)counter,
        (uint64_t)frequency
    );
}

EXPORT int RtlQueryPerformanceCounter(int64_t* counter) {
    return NtQueryPerformanceCounter(counter, NULL) == 0;
}

EXPORT int RtlQueryPerformanceFrequency(int64_t* frequency) {
    return NtQueryPerformanceCounter(NULL, frequency) == 0;
}

EXPORT NTSTATUS NtDelayExecution(UCHAR alertable, const int64_t* timeout) {
    return syscall2(NR_DELAY_EXECUTION, (uint64_t)alertable, (uint64_t)timeout);
}

EXPORT ULONG RtlNtStatusToDosError(NTSTATUS status) {
    switch (status) {
        case 0:            return 0;
        case 0xC0000005:   return 5;
        case 0xC000000D:   return 87;
        case 0xC0000017:   return 14;
        case 0xC0000034:   return 2;
        case 0xC0000035:   return 183;
        case 0xC000003A:   return 3;
        default:           return 317;
    }
}

EXPORT ULONG RtlNtStatusToDosErrorNoTeb(NTSTATUS status) {
    return RtlNtStatusToDosError(status);
}

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct {
    uint8_t Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550

static IMAGE_NT_HEADERS64* image_nt_headers(void* image_base) {
    if (!image_base) return NULL;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)image_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    if (dos->e_lfanew < 0 || dos->e_lfanew > 0x400000) return NULL;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)image_base + (uint32_t)dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return nt;
}

static IMAGE_SECTION_HEADER* image_first_section(IMAGE_NT_HEADERS64* nt) {
    if (!nt) return NULL;
    return (IMAGE_SECTION_HEADER*)((uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
}

static uint32_t section_span(const IMAGE_SECTION_HEADER* sec) {
    uint32_t v = sec->Misc.VirtualSize;
    uint32_t r = sec->SizeOfRawData;
    return (v > r) ? v : r;
}

EXPORT void* RtlImageNtHeader(void* image_base) {
    return image_nt_headers(image_base);
}

EXPORT void* RtlImageDirectoryEntryToData(
    void* image_base, UCHAR mapped_as_image, ULONG directory_entry, ULONG* size)
{
    if (size) *size = 0;
    IMAGE_NT_HEADERS64* nt = image_nt_headers(image_base);
    if (!nt || directory_entry >= 16) return NULL;
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[directory_entry];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return NULL;
    if (size) *size = dir.Size;

    if (mapped_as_image) {
        return (uint8_t*)image_base + dir.VirtualAddress;
    }

    IMAGE_SECTION_HEADER* sec = image_first_section(nt);
    for (uint32_t i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        uint32_t start = sec->VirtualAddress;
        uint32_t end = start + section_span(sec);
        if (dir.VirtualAddress >= start && dir.VirtualAddress < end) {
            uint32_t delta = dir.VirtualAddress - start;
            return (uint8_t*)image_base + sec->PointerToRawData + delta;
        }
    }
    return NULL;
}

EXPORT void* RtlImageRvaToVa(void* nt_headers, void* image_base, ULONG rva, void** last_rva_section) {
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)nt_headers;
    if (!nt || !image_base) return NULL;

    if (last_rva_section && *last_rva_section) {
        IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)(*last_rva_section);
        uint32_t start = sec->VirtualAddress;
        uint32_t end = start + section_span(sec);
        if (rva >= start && rva < end) {
            return (uint8_t*)image_base + rva;
        }
    }

    IMAGE_SECTION_HEADER* sec = image_first_section(nt);
    for (uint32_t i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        uint32_t start = sec->VirtualAddress;
        uint32_t end = start + section_span(sec);
        if (rva >= start && rva < end) {
            if (last_rva_section) *last_rva_section = sec;
            return (uint8_t*)image_base + rva;
        }
    }

    if (rva < nt->OptionalHeader.SizeOfHeaders) {
        return (uint8_t*)image_base + rva;
    }
    return NULL;
}

EXPORT void* RtlGetCurrentPeb(void) {
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    if (!teb) return NULL;
    return *(void**)(teb + 0x60);
}

EXPORT void* RtlPcToFileHeader(void* pc_value, void** base_of_image) {
    void* base = NULL;
    uint8_t* peb = (uint8_t*)RtlGetCurrentPeb();
    uint64_t pc = (uint64_t)(uintptr_t)pc_value;

    if (peb && pc_value) {
        uint64_t ldr = *(uint64_t*)(peb + 0x18);
        if (ldr != 0) {
            uint64_t head = ldr + 0x10;
            uint64_t link = *(uint64_t*)(uintptr_t)head;
            for (unsigned i = 0; i < 1024 && link != 0 && link != head; i++) {
                uint64_t entry = link; /* InLoadOrderLinks is at +0x0 */
                uint64_t dll_base = *(uint64_t*)(uintptr_t)(entry + 0x30);
                uint32_t size_of_image = *(uint32_t*)(uintptr_t)(entry + 0x40);
                if (size_of_image != 0 &&
                    pc >= dll_base &&
                    pc < dll_base + (uint64_t)size_of_image) {
                    base = (void*)(uintptr_t)dll_base;
                    break;
                }
                link = *(uint64_t*)(uintptr_t)link;
            }
        }
    }
    if (!base) {
        base = peb ? *(void**)(peb + 0x10) : NULL;
    }
    if (base && pc_value) {
        IMAGE_NT_HEADERS64* nt = image_nt_headers(base);
        if (!nt) {
            base = NULL;
        } else {
            uint64_t start = (uint64_t)(uintptr_t)base;
            uint64_t end = start + nt->OptionalHeader.SizeOfImage;
            if (pc < start || pc >= end) {
                base = NULL;
            }
        }
    }
    if (base_of_image) *base_of_image = base;
    return base;
}

typedef struct {
    uint32_t BeginAddress;
    union {
        uint32_t UnwindData;
        struct {
            uint32_t Flag : 2;
            uint32_t FunctionLength : 11;
            uint32_t RegF : 3;
            uint32_t RegI : 4;
            uint32_t H : 1;
            uint32_t CR : 2;
            uint32_t FrameSize : 9;
        };
    };
} RUNTIME_FUNCTION_ARM64;

EXPORT RUNTIME_FUNCTION_ARM64* RtlLookupFunctionEntry(
    uint64_t control_pc, uint64_t* image_base, void* history_table)
{
    (void)history_table;
    void* base = NULL;
    if (!RtlPcToFileHeader((void*)(uintptr_t)control_pc, &base) || !base) {
        if (image_base) *image_base = 0;
        return NULL;
    }
    if (image_base) *image_base = (uint64_t)(uintptr_t)base;
    if (control_pc < (uint64_t)(uintptr_t)base) {
        return NULL;
    }

    ULONG dir_size = 0;
    RUNTIME_FUNCTION_ARM64* table =
        (RUNTIME_FUNCTION_ARM64*)RtlImageDirectoryEntryToData(base, 1, 3, &dir_size);
    if (!table || dir_size < sizeof(RUNTIME_FUNCTION_ARM64)) {
        return NULL;
    }
    uint32_t count = dir_size / (uint32_t)sizeof(RUNTIME_FUNCTION_ARM64);
    if (count == 0) {
        return NULL;
    }

    uint32_t pc_rva = (uint32_t)(control_pc - (uint64_t)(uintptr_t)base);
    uint32_t lo = 0;
    uint32_t hi = count;
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        uint32_t begin = table[mid].BeginAddress;
        if (begin <= pc_rva) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo == 0) {
        return NULL;
    }
    uint32_t idx = lo - 1;
    uint32_t begin = table[idx].BeginAddress;
    if (begin > pc_rva) {
        return NULL;
    }
    uint32_t len_words = 0;
    if (table[idx].Flag) {
        len_words = table[idx].FunctionLength;
    } else {
        uint64_t xdata = (uint64_t)(uintptr_t)base + table[idx].UnwindData;
        if (!xdata) return NULL;
        len_words = *(const uint32_t*)(uintptr_t)xdata & 0x3ffffU;
    }
    uint64_t end = (uint64_t)begin + ((uint64_t)len_words * 4ULL);
    if ((uint64_t)pc_rva >= end) {
        return NULL;
    }
    return &table[idx];
}

EXPORT ULONG RtlRandom(ULONG* seed) {
    if (!seed) return 0;
    *seed = (*seed * 0x343fdU + 0x269ec3U);
    return (*seed >> 16) & 0x7fffU;
}

typedef struct {
    void* ptr;
} RTL_RUN_ONCE;

typedef NTSTATUS (*PRTL_RUN_ONCE_INIT_FN)(RTL_RUN_ONCE*, void*, void**);

EXPORT void RtlRunOnceInitialize(RTL_RUN_ONCE* once) {
    if (once) once->ptr = NULL;
}

EXPORT NTSTATUS RtlRunOnceBeginInitialize(
    RTL_RUN_ONCE* once, ULONG flags, ULONG* pending, void** context)
{
    (void)flags;
    if (!once) return STATUS_INVALID_PARAMETER;
    if (pending) *pending = (once->ptr == NULL) ? 1 : 0;
    if (context) *context = (once->ptr == (void*)1) ? NULL : once->ptr;
    return 0;
}

EXPORT NTSTATUS RtlRunOnceComplete(RTL_RUN_ONCE* once, ULONG flags, void* context) {
    (void)flags;
    if (!once) return STATUS_INVALID_PARAMETER;
    once->ptr = context ? context : (void*)1;
    return 0;
}

EXPORT NTSTATUS RtlRunOnceExecuteOnce(
    RTL_RUN_ONCE* once, PRTL_RUN_ONCE_INIT_FN init_fn, void* parameter, void** context)
{
    if (!once || !init_fn) return STATUS_INVALID_PARAMETER;
    if (once->ptr) {
        if (context) *context = (once->ptr == (void*)1) ? NULL : once->ptr;
        return 0;
    }
    void* local_ctx = NULL;
    NTSTATUS st = init_fn(once, parameter, &local_ctx);
    if (st == 0) {
        once->ptr = local_ctx ? local_ctx : (void*)1;
        if (context) *context = local_ctx;
    }
    return st;
}

EXPORT uint64_t RtlGetEnabledExtendedFeatures(uint64_t feature_mask) {
    (void)feature_mask;
    return 0;
}

EXPORT uint64_t RtlGetExtendedFeaturesMask(void) {
    return 0;
}

EXPORT int RtlIsEcCode(const void* pc) {
    (void)pc;
    return 0;
}

EXPORT void* RtlLocateExtendedFeature(void* feature_info, uint64_t feature_id) {
    (void)feature_info;
    (void)feature_id;
    return NULL;
}

EXPORT void RtlSetExtendedFeaturesMask(uint64_t feature_mask) {
    (void)feature_mask;
}

EXPORT NTSTATUS RtlWow64GetThreadContext(HANDLE thread, void* ctx) {
    (void)thread;
    (void)ctx;
    return STATUS_NOT_IMPLEMENTED;
}

EXPORT NTSTATUS RtlWow64SetThreadContext(HANDLE thread, const void* ctx) {
    (void)thread;
    (void)ctx;
    return STATUS_NOT_IMPLEMENTED;
}

__attribute__((naked))
EXPORT ULONG_PTR __chkstk_arm64ec(void) {
    asm volatile(
        "b __chkstk\n\t");
}

typedef struct {
    uint64_t frame;
    uint64_t reserved;
    uint64_t x19;
    uint64_t x20;
    uint64_t x21;
    uint64_t x22;
    uint64_t x23;
    uint64_t x24;
    uint64_t x25;
    uint64_t x26;
    uint64_t x27;
    uint64_t x28;
    uint64_t fp;
    uint64_t lr;
    uint64_t sp;
    uint32_t fpcr;
    uint32_t fpsr;
    double d[8];
} WINEMU_JUMP_BUFFER_ARM64;

typedef struct {
    uint32_t ExceptionCode;
    uint32_t ExceptionFlags;
    void* ExceptionRecord;
    void* ExceptionAddress;
    uint32_t NumberParameters;
    uint32_t __pad;
    uint64_t ExceptionInformation[15];
} WINEMU_EXCEPTION_RECORD64;

#define STATUS_LONGJUMP ((NTSTATUS)0x80000026U)

EXPORT void RtlUnwind();

__attribute__((naked))
EXPORT int _setjmpex(void* env, void* frame) {
    asm volatile(
        "cbz x0, 2f\n\t"
        "str x1, [x0, #0x00]\n\t"
        "str xzr, [x0, #0x08]\n\t"
        "stp x19, x20, [x0, #0x10]\n\t"
        "stp x21, x22, [x0, #0x20]\n\t"
        "stp x23, x24, [x0, #0x30]\n\t"
        "stp x25, x26, [x0, #0x40]\n\t"
        "stp x27, x28, [x0, #0x50]\n\t"
        "stp x29, x30, [x0, #0x60]\n\t"
        "mov x2, sp\n\t"
        "str x2, [x0, #0x70]\n\t"
        "mrs x2, fpcr\n\t"
        "str w2, [x0, #0x78]\n\t"
        "mrs x2, fpsr\n\t"
        "str w2, [x0, #0x7c]\n\t"
        "stp d8, d9, [x0, #0x80]\n\t"
        "stp d10, d11, [x0, #0x90]\n\t"
        "stp d12, d13, [x0, #0xa0]\n\t"
        "stp d14, d15, [x0, #0xb0]\n\t"
        "2:\n\t"
        "mov w0, #0\n\t"
        "ret\n\t");
}

EXPORT int _setjmp(void* env) {
    return _setjmpex(env, NULL);
}

EXPORT void longjmp(void* env, int value) {
    WINEMU_JUMP_BUFFER_ARM64* buf = (WINEMU_JUMP_BUFFER_ARM64*)env;
    WINEMU_EXCEPTION_RECORD64 rec;

    if (!buf) {
        (void)syscall2(NR_TERMINATE_PROCESS, (uint64_t)(HANDLE)(uint64_t)-1, 0);
        for (;;) {}
    }

    if (!value) value = 1;

    rec.ExceptionCode = STATUS_LONGJUMP;
    rec.ExceptionFlags = 0;
    rec.ExceptionRecord = NULL;
    rec.ExceptionAddress = NULL;
    rec.NumberParameters = 1;
    rec.__pad = 0;
    rec.ExceptionInformation[0] = (uint64_t)(uintptr_t)buf;
    for (size_t i = 1; i < 15; ++i) rec.ExceptionInformation[i] = 0;
    RtlUnwind((void*)(uintptr_t)buf->frame, (void*)(uintptr_t)buf->lr, &rec, (void*)(uintptr_t)value);
    for (;;) {}
}

EXPORT void RtlSetLastWin32Error(ULONG code) {
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    if (teb) *(volatile uint32_t*)(teb + 0x68) = code;
}

EXPORT ULONG RtlGetLastWin32Error(void) {
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    if (!teb) return 0;
    return *(volatile uint32_t*)(teb + 0x68);
}
