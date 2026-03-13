typedef struct {
    uint32_t ExceptionCode;
    uint32_t ExceptionFlags;
    void* ExceptionRecord;
    void* ExceptionAddress;
    uint32_t NumberParameters;
    uint32_t __pad;
    uint64_t ExceptionInformation[15];
} EXCEPTION_RECORD64;

typedef union {
    struct {
        uint64_t Low;
        uint64_t High;
    };
    double D[2];
} ARM64_NT_NEON128;

typedef struct {
    uint32_t ContextFlags;
    uint32_t Cpsr;
    uint64_t X[31];
    uint64_t Sp;
    uint64_t Pc;
    ARM64_NT_NEON128 V[32];
    uint32_t Fpcr;
    uint32_t Fpsr;
    uint32_t Bcr[8];
    uint64_t Bvr[8];
    uint32_t Wcr[2];
    uint64_t Wvr[2];
} ARM64_NT_CONTEXT;

typedef struct {
    uint64_t frame;
    uint64_t lr;
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
    uint64_t sp;
    uint32_t fpcr;
    uint32_t fpsr;
    double d[8];
} WINEMU_RESTORE_JUMP_BUFFER_ARM64;

typedef uint32_t EXCEPTION_DISPOSITION;

enum {
    ExceptionContinueExecution = 0,
    ExceptionContinueSearch = 1,
    ExceptionNestedException = 2,
    ExceptionCollidedUnwind = 3
};

#define EXCEPTION_NONCONTINUABLE 0x1U
#define EXCEPTION_UNWINDING 0x2U
#define EXCEPTION_EXIT_UNWIND 0x4U
#define EXCEPTION_STACK_INVALID 0x8U
#define EXCEPTION_NESTED_CALL 0x10U
#define EXCEPTION_TARGET_UNWIND 0x20U
#define EXCEPTION_COLLIDED_UNWIND 0x40U

#define UNW_FLAG_NHANDLER 0U
#define UNW_FLAG_EHANDLER 1U
#define UNW_FLAG_UHANDLER 2U

#define CONTEXT_ARM64 0x00400000U
#define CONTEXT_FULL 0x00000007U
#define CONTEXT_UNWOUND_TO_CALL 0x20000000U
#ifndef STATUS_LONGJUMP
#define STATUS_LONGJUMP 0x80000026U
#endif

typedef struct _DISPATCHER_CONTEXT_ARM64 DISPATCHER_CONTEXT_ARM64;

typedef EXCEPTION_DISPOSITION (*PEXCEPTION_ROUTINE_ARM64)(
    EXCEPTION_RECORD64* record,
    void* frame,
    ARM64_NT_CONTEXT* context,
    DISPATCHER_CONTEXT_ARM64* dispatch
);

struct _DISPATCHER_CONTEXT_ARM64 {
    uint64_t ControlPc;
    uint64_t ImageBase;
    RUNTIME_FUNCTION_ARM64* FunctionEntry;
    uint64_t EstablisherFrame;
    uint64_t TargetPc;
    ARM64_NT_CONTEXT* ContextRecord;
    PEXCEPTION_ROUTINE_ARM64 LanguageHandler;
    void* HandlerData;
    void* HistoryTable;
    uint32_t ScopeIndex;
    uint8_t ControlPcIsUnwound;
    uint8_t Fill0[3];
    uint8_t* NonVolatileRegisters;
};

#define NONVOL_INT_NUMREG_ARM64 11U
#define NONVOL_FP_NUMREG_ARM64 8U
#define NONVOL_INT_SIZE_ARM64 (NONVOL_INT_NUMREG_ARM64 * sizeof(uint64_t))
#define NONVOL_FP_SIZE_ARM64 (NONVOL_FP_NUMREG_ARM64 * sizeof(double))

typedef union {
    uint8_t Buffer[NONVOL_INT_SIZE_ARM64 + NONVOL_FP_SIZE_ARM64];
    struct {
        uint64_t GpNvRegs[NONVOL_INT_NUMREG_ARM64];
        double FpNvRegs[NONVOL_FP_NUMREG_ARM64];
    };
} DISPATCHER_CONTEXT_NONVOLREG_ARM64;

typedef char _winemu_dispatch_nonvol_offset_check[
    (sizeof(void*) == 8 && __builtin_offsetof(DISPATCHER_CONTEXT_ARM64, NonVolatileRegisters) == 0x50)
        ? 1
        : -1
];

typedef char _winemu_dispatch_size_check[
    (sizeof(void*) == 8 && sizeof(DISPATCHER_CONTEXT_ARM64) == 0x58)
        ? 1
        : -1
];

#define STDOUT_HANDLE ((HANDLE)(uint64_t)0xFFFFFFFFFFFFFFF5ULL)
#define EXCEPTION_WINE_STUB 0x80000100U

typedef struct {
    uint64_t Status;
    uint64_t Information;
} WINEMU_IO_STATUS_BLOCK64;

static void winemu_exc_write_buf(const char* buf, ULONG len) {
    WINEMU_IO_STATUS_BLOCK64 iosb;
    iosb.Status = 0;
    iosb.Information = 0;
    (void)NtWriteFile(STDOUT_HANDLE, 0, 0, 0, &iosb, buf, len, 0, 0);
}

static void winemu_exc_write_str(const char* s) {
    ULONG len = 0;
    if (!s) return;
    while (s[len]) len++;
    winemu_exc_write_buf(s, len);
}

static void winemu_exc_write_hex32(uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    char buf[10];
    int i;

    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 8; ++i) {
        buf[2 + i] = digits[(value >> ((7 - i) * 4)) & 0xf];
    }
    winemu_exc_write_buf(buf, (ULONG)sizeof(buf));
}

static void winemu_exc_write_hex64(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    char buf[18];
    int i;

    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 16; ++i) {
        buf[2 + i] = digits[(value >> ((15 - i) * 4)) & 0xf];
    }
    winemu_exc_write_buf(buf, (ULONG)sizeof(buf));
}

static void winemu_exc_write_cstr_trunc(const char* s, ULONG cap) {
    ULONG len = 0;

    if (!s) {
        winemu_exc_write_str("<null>");
        return;
    }
    while (len < cap && s[len]) len++;
    winemu_exc_write_buf(s, len);
    if (s[len]) winemu_exc_write_str("...");
}

static uint64_t winemu_exc_image_rel_or_abs(uint64_t image_base, uint32_t value) {
    if (!value) return 0;
    if (image_base && value < 0x10000000U) {
        return image_base + (uint64_t)value;
    }
    return (uint64_t)value;
}

static int winemu_exc_read_ascii_cstr(uint64_t ptr, char* out, ULONG cap) {
    ULONG len = 0;

    if (!ptr || !out || !cap) return 0;
    while (len + 1 < cap) {
        char ch = *(const char*)(uintptr_t)(ptr + len);
        if (!ch) {
            out[len] = '\0';
            return len != 0;
        }
        if ((unsigned char)ch < 0x20 || (unsigned char)ch > 0x7e) return 0;
        out[len++] = ch;
    }
    out[cap - 1] = '\0';
    return 0;
}

static int winemu_exc_copy_cpp_type_name(EXCEPTION_RECORD64* rec, char* out, ULONG cap) {
    static const uint64_t name_offsets[] = {16, 8, 24, 0, 32};
    uint64_t throw_info;
    uint64_t image_base;
    uint64_t cta;
    uint32_t count;
    uint32_t i;

    if (!rec || rec->ExceptionCode != 0xE06D7363U || rec->NumberParameters < 4) return 0;
    throw_info = rec->ExceptionInformation[2];
    image_base = rec->ExceptionInformation[3];
    if (!throw_info || !image_base) return 0;

    cta = winemu_exc_image_rel_or_abs(
        image_base,
        *(const uint32_t*)(uintptr_t)(throw_info + 0x0c)
    );
    if (!cta) return 0;
    count = *(const uint32_t*)(uintptr_t)cta;
    if (!count || count > 32) return 0;

    for (i = 0; i < count; ++i) {
        uint64_t ct = winemu_exc_image_rel_or_abs(
            image_base,
            *(const uint32_t*)(uintptr_t)(cta + 4 + ((uint64_t)i * 4))
        );
        uint64_t td;
        uint32_t j;

        if (!ct) continue;
        td = winemu_exc_image_rel_or_abs(
            image_base,
            *(const uint32_t*)(uintptr_t)(ct + 4)
        );
        if (!td) continue;
        for (j = 0; j < sizeof(name_offsets) / sizeof(name_offsets[0]); ++j) {
            if (winemu_exc_read_ascii_cstr(td + name_offsets[j], out, cap)) {
                return 1;
            }
        }
    }
    return 0;
}

static void winemu_exc_log_cpp_diagnostics(EXCEPTION_RECORD64* rec) {
    char type_name[128];

    if (!winemu_exc_copy_cpp_type_name(rec, type_name, sizeof(type_name))) return;
    winemu_exc_write_str(" cpp_type=");
    winemu_exc_write_cstr_trunc(type_name, 96);
    if (strcmp(type_name, ".?AV_com_error@@") == 0 && rec->NumberParameters > 1) {
        uint64_t object_ptr = rec->ExceptionInformation[1];
        uint32_t com_hr = *(const uint32_t*)(uintptr_t)(object_ptr + 8);
        winemu_exc_write_str(" com_obj=");
        winemu_exc_write_hex64(object_ptr);
        winemu_exc_write_str(" com_hr=");
        winemu_exc_write_hex32(com_hr);
    }
}

static void winemu_exc_log_exception(
    const char* stage,
    EXCEPTION_RECORD64* rec,
    NTSTATUS dispatch_status,
    uint64_t first_unwound_pc,
    uint64_t second_unwound_pc,
    uint64_t third_unwound_pc)
{
    winemu_exc_write_str("ntdll-exc: ");
    winemu_exc_write_str(stage);
    if (rec) {
        winemu_exc_write_str(" code=");
        winemu_exc_write_hex32(rec->ExceptionCode);
        winemu_exc_write_str(" flags=");
        winemu_exc_write_hex32(rec->ExceptionFlags);
        winemu_exc_write_str(" addr=");
        winemu_exc_write_hex64((uint64_t)(uintptr_t)rec->ExceptionAddress);
        winemu_exc_write_str(" params=");
        winemu_exc_write_hex32(rec->NumberParameters);
        if (rec->NumberParameters > 0) {
            winemu_exc_write_str(" info0=");
            winemu_exc_write_hex64(rec->ExceptionInformation[0]);
        }
        if (rec->NumberParameters > 1) {
            winemu_exc_write_str(" info1=");
            winemu_exc_write_hex64(rec->ExceptionInformation[1]);
        }
        if (rec->NumberParameters > 2) {
            winemu_exc_write_str(" info2=");
            winemu_exc_write_hex64(rec->ExceptionInformation[2]);
        }
        if (rec->NumberParameters > 3) {
            winemu_exc_write_str(" info3=");
            winemu_exc_write_hex64(rec->ExceptionInformation[3]);
        }
        if (rec->ExceptionCode == EXCEPTION_WINE_STUB && rec->NumberParameters >= 2) {
            winemu_exc_write_str(" wine_stub=");
            winemu_exc_write_cstr_trunc((const char*)(uintptr_t)rec->ExceptionInformation[0], 64);
            winemu_exc_write_str(".");
            if ((rec->ExceptionInformation[1] >> 16) != 0) {
                winemu_exc_write_cstr_trunc(
                    (const char*)(uintptr_t)rec->ExceptionInformation[1],
                    96
                );
            } else {
                winemu_exc_write_str("#");
                winemu_exc_write_hex64(rec->ExceptionInformation[1]);
            }
        }
        winemu_exc_log_cpp_diagnostics(rec);
    }
    winemu_exc_write_str(" dispatch_status=");
    winemu_exc_write_hex32((uint32_t)dispatch_status);
    winemu_exc_write_str(" unwind1=");
    winemu_exc_write_hex64(first_unwound_pc);
    winemu_exc_write_str(" unwind2=");
    winemu_exc_write_hex64(second_unwound_pc);
    winemu_exc_write_str(" unwind3=");
    winemu_exc_write_hex64(third_unwound_pc);
    winemu_exc_write_str("\r\n");
}

static volatile uint32_t g_winemu_sp_diag_budget = 128;

static int winemu_exc_query_stack_bounds(uint64_t* stack_limit_out, uint64_t* stack_base_out) {
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    uint64_t stack_base;
    uint64_t stack_limit;

    if (!teb) return 0;
    stack_base = *(const uint64_t*)(uintptr_t)(teb + 0x08);
    stack_limit = *(const uint64_t*)(uintptr_t)(teb + 0x10);
    if (!stack_base || stack_limit >= stack_base) return 0;
    if (stack_limit_out) *stack_limit_out = stack_limit;
    if (stack_base_out) *stack_base_out = stack_base;
    return 1;
}

static int winemu_exc_sp_in_current_stack(uint64_t sp, uint64_t* stack_limit_out, uint64_t* stack_base_out) {
    uint64_t stack_limit = 0;
    uint64_t stack_base = 0;

    if (!winemu_exc_query_stack_bounds(&stack_limit, &stack_base)) return 0;
    if (stack_limit_out) *stack_limit_out = stack_limit;
    if (stack_base_out) *stack_base_out = stack_base;
    return sp >= stack_limit && sp < stack_base;
}

static void winemu_exc_log_sp_event(
    const char* stage,
    ARM64_NT_CONTEXT* context,
    uint64_t prev_sp,
    uint64_t aux0,
    uint64_t aux1,
    EXCEPTION_RECORD64* rec)
{
    uint64_t stack_limit = 0;
    uint64_t stack_base = 0;
    uint64_t current_sp = 0;
    int target_in_stack;
    int prev_in_stack;

    if (!context) return;
    target_in_stack = winemu_exc_sp_in_current_stack(context->Sp, &stack_limit, &stack_base);
    prev_in_stack = prev_sp ? winemu_exc_sp_in_current_stack(prev_sp, NULL, NULL) : 1;
    if (target_in_stack && prev_in_stack) return;
    if (!g_winemu_sp_diag_budget) return;
    g_winemu_sp_diag_budget--;

    asm volatile("mov %0, sp" : "=r"(current_sp));
    winemu_exc_write_str("ntdll-sp: ");
    winemu_exc_write_str(stage);
    winemu_exc_write_str(" pc=");
    winemu_exc_write_hex64(context->Pc);
    winemu_exc_write_str(" sp=");
    winemu_exc_write_hex64(context->Sp);
    winemu_exc_write_str(" prev_sp=");
    winemu_exc_write_hex64(prev_sp);
    winemu_exc_write_str(" cur_sp=");
    winemu_exc_write_hex64(current_sp);
    winemu_exc_write_str(" stack_limit=");
    winemu_exc_write_hex64(stack_limit);
    winemu_exc_write_str(" stack_base=");
    winemu_exc_write_hex64(stack_base);
    winemu_exc_write_str(" aux0=");
    winemu_exc_write_hex64(aux0);
    winemu_exc_write_str(" aux1=");
    winemu_exc_write_hex64(aux1);
    if (rec) {
        winemu_exc_write_str(" code=");
        winemu_exc_write_hex32(rec->ExceptionCode);
        winemu_exc_write_str(" flags=");
        winemu_exc_write_hex32(rec->ExceptionFlags);
    }
    winemu_exc_write_str("\r\n");
}

typedef struct {
    uint32_t FunctionLength : 18;
    uint32_t Version : 2;
    uint32_t ExceptionDataPresent : 1;
    uint32_t EpilogInHeader : 1;
    uint32_t EpilogCount : 5;
    uint32_t CodeWords : 5;
} IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA;

struct unwind_info_ext {
    WORD epilog;
    BYTE codes;
    BYTE reserved;
};

struct unwind_info_epilog {
    uint32_t offset : 18;
    uint32_t res : 4;
    uint32_t index : 10;
};

static const BYTE unwind_code_len[256] = {
/* 00 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 20 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 40 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 60 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 80 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* a0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* c0 */ 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
/* e0 */ 4,1,2,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
};

static int max_i(int a, int b) {
    return (a > b) ? a : b;
}

static unsigned int get_sequence_len(BYTE* ptr, BYTE* end) {
    unsigned int ret = 0;
    while (ptr < end) {
        if (*ptr == 0xe4 || *ptr == 0xe5) break;
        if ((*ptr & 0xf8) != 0xe8) ret++;
        ptr += unwind_code_len[*ptr];
    }
    return ret;
}

static void restore_regs(int reg, int count, int pos, ARM64_NT_CONTEXT* context) {
    int i;
    int offset = max_i(0, pos);
    for (i = 0; i < count; i++) {
        context->X[reg + i] = ((DWORD64*)(uintptr_t)context->Sp)[i + offset];
    }
    if (pos < 0) context->Sp += (uint64_t)(-8 * pos);
}

static void restore_fpregs(int reg, int count, int pos, ARM64_NT_CONTEXT* context) {
    int i;
    int offset = max_i(0, pos);
    for (i = 0; i < count; i++) {
        context->V[reg + i].D[0] = ((double*)(uintptr_t)context->Sp)[i + offset];
    }
    if (pos < 0) context->Sp += (uint64_t)(-8 * pos);
}

static void restore_qregs(int reg, int count, int pos, ARM64_NT_CONTEXT* context) {
    int i;
    int offset = max_i(0, pos);
    for (i = 0; i < count; i++) {
        DWORD64* src = ((DWORD64*)(uintptr_t)context->Sp) + 2 * (i + offset);
        context->V[reg + i].Low = src[0];
        context->V[reg + i].High = src[1];
    }
    if (pos < 0) context->Sp += (uint64_t)(-16 * pos);
}

static void restore_any_reg(int reg, int count, int type, int pos, ARM64_NT_CONTEXT* context) {
    if (reg & 0x20) pos = -pos - 1;

    switch (type) {
    case 0:
        if (count > 1 || pos < 0) pos *= 2;
        restore_regs(reg & 0x1f, count, pos, context);
        break;
    case 1:
        if (count > 1 || pos < 0) pos *= 2;
        restore_fpregs(reg & 0x1f, count, pos, context);
        break;
    case 2:
        restore_qregs(reg & 0x1f, count, pos, context);
        break;
    default:
        break;
    }
}

static void do_pac_auth(ARM64_NT_CONTEXT* context) {
    register DWORD64 x17 asm("x17") = context->X[30];
    register DWORD64 x16 asm("x16") = context->Sp;
    asm volatile("hint 0xe" : "+r"(x17) : "r"(x16));
    context->X[30] = x17;
}

static void process_unwind_codes(
    BYTE* ptr, BYTE* end, ARM64_NT_CONTEXT* context, int skip, int* final_pc_from_lr)
{
    unsigned int val;
    unsigned int len;
    unsigned int save_next = 2;

    while (ptr < end && skip) {
        if (*ptr == 0xe4) break;
        ptr += unwind_code_len[*ptr];
        skip--;
    }

    while (ptr < end) {
        if ((len = unwind_code_len[*ptr]) > 1) {
            if (ptr + len > end) break;
            val = (unsigned int)ptr[0] * 0x100U + (unsigned int)ptr[1];
        } else {
            val = *ptr;
        }

        if (*ptr < 0x20) {
            context->Sp += 16U * (val & 0x1fU);
        } else if (*ptr < 0x40) {
            restore_regs(19, (int)save_next, -(int)(val & 0x1fU), context);
        } else if (*ptr < 0x80) {
            restore_regs(29, 2, (int)(val & 0x3fU), context);
        } else if (*ptr < 0xc0) {
            restore_regs(29, 2, -(int)(val & 0x3fU) - 1, context);
        } else if (*ptr < 0xc8) {
            context->Sp += 16U * (val & 0x7ffU);
        } else if (*ptr < 0xcc) {
            restore_regs(19 + ((int)(val >> 6) & 0xf), (int)save_next, (int)(val & 0x3fU), context);
        } else if (*ptr < 0xd0) {
            restore_regs(19 + ((int)(val >> 6) & 0xf), (int)save_next, -(int)(val & 0x3fU) - 1, context);
        } else if (*ptr < 0xd4) {
            restore_regs(19 + ((int)(val >> 6) & 0xf), 1, (int)(val & 0x3fU), context);
        } else if (*ptr < 0xd6) {
            restore_regs(19 + ((int)(val >> 5) & 0xf), 1, -(int)(val & 0x1fU) - 1, context);
        } else if (*ptr < 0xd8) {
            restore_regs(19 + 2 * ((int)(val >> 6) & 0x7), 1, (int)(val & 0x3fU), context);
            restore_regs(30, 1, (int)(val & 0x3fU) + 1, context);
        } else if (*ptr < 0xda) {
            restore_fpregs(8 + ((int)(val >> 6) & 0x7), (int)save_next, (int)(val & 0x3fU), context);
        } else if (*ptr < 0xdc) {
            restore_fpregs(8 + ((int)(val >> 6) & 0x7), (int)save_next, -(int)(val & 0x3fU) - 1, context);
        } else if (*ptr < 0xde) {
            restore_fpregs(8 + ((int)(val >> 6) & 0x7), 1, (int)(val & 0x3fU), context);
        } else if (*ptr == 0xde) {
            restore_fpregs(8 + ((int)(val >> 5) & 0x7), 1, -(int)(val & 0x3fU) - 1, context);
        } else if (*ptr == 0xe0) {
            context->Sp += 16U * ((unsigned int)ptr[1] << 16 | (unsigned int)ptr[2] << 8 | (unsigned int)ptr[3]);
        } else if (*ptr == 0xe1) {
            context->Sp = context->X[29];
        } else if (*ptr == 0xe2) {
            context->Sp = context->X[29] - 8U * (val & 0xffU);
        } else if (*ptr == 0xe3) {
            /* nop */
        } else if (*ptr == 0xe4) {
            break;
        } else if (*ptr == 0xe5) {
            /* end_c */
        } else if (*ptr == 0xe6) {
            save_next += 2;
            ptr += len;
            continue;
        } else if (*ptr == 0xe7) {
            restore_any_reg(ptr[1], (ptr[1] & 0x40) ? (int)save_next : 1, ptr[2] >> 6, ptr[2] & 0x3f, context);
        } else if (*ptr == 0xe9) {
            context->Pc = ((DWORD64*)(uintptr_t)context->Sp)[1];
            context->Sp = ((DWORD64*)(uintptr_t)context->Sp)[0];
            context->ContextFlags &= ~CONTEXT_UNWOUND_TO_CALL;
            *final_pc_from_lr = 0;
        } else if (*ptr == 0xea) {
            uint32_t flags = context->ContextFlags & ~CONTEXT_UNWOUND_TO_CALL;
            ARM64_NT_CONTEXT* src_ctx = (ARM64_NT_CONTEXT*)(uintptr_t)context->Sp;
            *context = *src_ctx;
            context->ContextFlags = flags | (src_ctx->ContextFlags & CONTEXT_UNWOUND_TO_CALL);
            *final_pc_from_lr = 0;
        } else if (*ptr == 0xec) {
            context->Pc = context->X[30];
            context->ContextFlags &= ~CONTEXT_UNWOUND_TO_CALL;
            *final_pc_from_lr = 0;
        } else if (*ptr == 0xfc) {
            do_pac_auth(context);
        } else {
            return;
        }
        save_next = 2;
        ptr += len;
    }
}

static void* unwind_packed_data(ULONG_PTR base, ULONG_PTR pc, RUNTIME_FUNCTION_ARM64* func, ARM64_NT_CONTEXT* context) {
    int i;
    unsigned int len;
    unsigned int offset;
    unsigned int skip = 0;
    unsigned int int_size = func->RegI * 8U;
    unsigned int fp_size = func->RegF * 8U;
    unsigned int h_size = func->H * 4U;
    unsigned int regsave;
    unsigned int local_size;
    unsigned int int_regs;
    unsigned int fp_regs;
    unsigned int saved_regs;
    unsigned int local_size_regs;

    if (func->CR == 1) int_size += 8U;
    if (func->RegF) fp_size += 8U;

    regsave = (unsigned int)(((int_size + fp_size + 8U * 8U * func->H) + 0xfU) & ~0xfU);
    local_size = func->FrameSize * 16U - regsave;

    int_regs = int_size / 8U;
    fp_regs = fp_size / 8U;
    saved_regs = regsave / 8U;
    local_size_regs = local_size / 8U;

    if (func->Flag == 1) {
        offset = (unsigned int)(((pc - base) - func->BeginAddress) / 4U);
        if (offset < 17U || offset >= func->FunctionLength - 15U) {
            len = (int_size + 8U) / 16U + (fp_size + 8U) / 16U;
            switch (func->CR) {
            case 2:
                len++;
                /* fall through */
            case 3:
                len += 2U;
                if (local_size <= 512U) break;
                /* fall through */
            case 0:
            case 1:
                if (local_size) len++;
                if (local_size > 4088U) len++;
                break;
            default:
                break;
            }
            if (offset < len + h_size) {
                skip = len + h_size - offset;
            } else if (offset >= func->FunctionLength - (len + 1U)) {
                skip = offset - (func->FunctionLength - (len + 1U));
                h_size = 0;
            }
        }
    }

    if (!skip) {
        if (func->CR == 3 || func->CR == 2) {
            context->Sp = context->X[29];
            restore_regs(29, 2, 0, context);
        }
        context->Sp += local_size;
        if (fp_size) restore_fpregs(8, (int)fp_regs, (int)int_regs, context);
        if (func->CR == 1) restore_regs(30, 1, (int)int_regs - 1, context);
        restore_regs(19, (int)func->RegI, -(int)saved_regs, context);
    } else {
        unsigned int pos = 0;
        switch (func->CR) {
        case 3:
        case 2:
            if (pos++ >= skip) context->Sp = context->X[29];
            if (local_size <= 512U) {
                if (pos++ >= skip) restore_regs(29, 2, -(int)local_size_regs, context);
                break;
            }
            if (pos++ >= skip) restore_regs(29, 2, 0, context);
            /* fall through */
        case 0:
        case 1:
            if (!local_size) break;
            if (pos++ >= skip) context->Sp += (local_size - 1U) % 4088U + 1U;
            if (local_size > 4088U && pos++ >= skip) context->Sp += 4088U;
            break;
        default:
            break;
        }

        pos += h_size;
        if (fp_size) {
            if (func->RegF % 2 == 0 && pos++ >= skip) {
                restore_fpregs(8 + func->RegF, 1, (int)int_regs + (int)fp_regs - 1, context);
            }
            for (i = (int)((func->RegF + 1U) / 2U) - 1; i >= 0; i--) {
                if (pos++ < skip) continue;
                if (!i && !int_size) {
                    restore_fpregs(8, 2, -(int)saved_regs, context);
                } else {
                    restore_fpregs(8 + 2 * i, 2, (int)int_regs + 2 * i, context);
                }
            }
        }

        if (func->RegI % 2U) {
            if (pos++ >= skip) {
                if (func->CR == 1) restore_regs(30, 1, (int)int_regs - 1, context);
                restore_regs(18 + func->RegI, 1, (func->RegI > 1U) ? (int)func->RegI - 1 : -(int)saved_regs, context);
            }
        } else if (func->CR == 1) {
            if (pos++ >= skip) restore_regs(30, 1, func->RegI ? (int)int_regs - 1 : -(int)saved_regs, context);
        }

        for (i = (int)(func->RegI / 2U) - 1; i >= 0; i--) {
            if (pos++ < skip) continue;
            if (i) {
                restore_regs(19 + 2 * i, 2, 2 * i, context);
            } else {
                restore_regs(19, 2, -(int)saved_regs, context);
            }
        }
    }
    if (func->CR == 2) do_pac_auth(context);
    return NULL;
}

static void* unwind_full_data(
    ULONG_PTR base, ULONG_PTR pc, RUNTIME_FUNCTION_ARM64* func, ARM64_NT_CONTEXT* context,
    void** handler_data, int* final_pc_from_lr)
{
    IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA* info;
    struct unwind_info_epilog* info_epilog;
    unsigned int i;
    unsigned int codes;
    unsigned int epilogs;
    unsigned int len;
    unsigned int offset;
    void* data;
    BYTE* end;

    info = (IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA*)((char*)(uintptr_t)base + func->UnwindData);
    data = info + 1;
    epilogs = info->EpilogCount;
    codes = info->CodeWords;
    if (!codes && !epilogs) {
        struct unwind_info_ext* infoex = (struct unwind_info_ext*)data;
        codes = infoex->codes;
        epilogs = infoex->epilog;
        data = infoex + 1;
    }
    info_epilog = (struct unwind_info_epilog*)data;
    if (!info->EpilogInHeader) data = info_epilog + epilogs;

    offset = (unsigned int)(((pc - base) - func->BeginAddress) / 4U);
    end = (BYTE*)data + codes * 4U;

    if (offset < codes * 4U) {
        len = get_sequence_len((BYTE*)data, end);
        if (offset < len) {
            process_unwind_codes((BYTE*)data, end, context, (int)(len - offset), final_pc_from_lr);
            return NULL;
        }
    }

    if (!info->EpilogInHeader) {
        for (i = 0; i < epilogs; i++) {
            if (offset < info_epilog[i].offset) break;
            if (offset - info_epilog[i].offset < codes * 4U - info_epilog[i].index) {
                BYTE* ptr = (BYTE*)data + info_epilog[i].index;
                len = get_sequence_len(ptr, end);
                if (offset <= info_epilog[i].offset + len) {
                    process_unwind_codes(ptr, end, context, (int)(offset - info_epilog[i].offset), final_pc_from_lr);
                    return NULL;
                }
            }
        }
    } else if (info->FunctionLength - offset <= codes * 4U - epilogs) {
        BYTE* ptr = (BYTE*)data + epilogs;
        len = get_sequence_len(ptr, end) + 1U;
        if (offset >= info->FunctionLength - len) {
            process_unwind_codes(ptr, end, context, (int)(offset - (info->FunctionLength - len)), final_pc_from_lr);
            return NULL;
        }
    }

    process_unwind_codes((BYTE*)data, end, context, 0, final_pc_from_lr);
    if (info->ExceptionDataPresent) {
        DWORD* handler_rva = (DWORD*)data + codes;
        *handler_data = handler_rva + 1;
        return (char*)(uintptr_t)base + *handler_rva;
    }
    return NULL;
}

EXPORT NTSTATUS RtlVirtualUnwind2(
    ULONG type, ULONG_PTR base, ULONG_PTR pc, RUNTIME_FUNCTION_ARM64* func, ARM64_NT_CONTEXT* context,
    uint8_t* mach_frame_unwound, void** handler_data, ULONG_PTR* frame_ret, void* context_pointers,
    ULONG_PTR* limit_low, ULONG_PTR* limit_high, PEXCEPTION_ROUTINE_ARM64* handler_ret, ULONG flags)
{
    int final_pc_from_lr = 1;
    PEXCEPTION_ROUTINE_ARM64 handler = NULL;
    (void)mach_frame_unwound;
    (void)context_pointers;
    (void)limit_low;
    (void)limit_high;
    (void)flags;

    if (!handler_data || !frame_ret || !handler_ret || !context) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!func && pc == context->X[30]) {
        return STATUS_BAD_FUNCTION_TABLE;
    }

    *handler_data = NULL;
    context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;

    if (!func) {
        handler = NULL;
    } else if (func->Flag) {
        handler = (PEXCEPTION_ROUTINE_ARM64)unwind_packed_data(base, pc, func, context);
    } else {
        handler = (PEXCEPTION_ROUTINE_ARM64)unwind_full_data(base, pc, func, context, handler_data, &final_pc_from_lr);
    }

    if (final_pc_from_lr) context->Pc = context->X[30];
    *frame_ret = context->Sp;
    *handler_ret = handler;
    return STATUS_SUCCESS;
}

EXPORT PEXCEPTION_ROUTINE_ARM64 RtlVirtualUnwind(
    ULONG type, ULONG_PTR base, ULONG_PTR pc, RUNTIME_FUNCTION_ARM64* func, ARM64_NT_CONTEXT* context,
    void** handler_data, ULONG_PTR* frame_ret, void* context_pointers)
{
    PEXCEPTION_ROUTINE_ARM64 handler = NULL;
    if (RtlVirtualUnwind2(
            type, base, pc, func, context, NULL, handler_data, frame_ret, context_pointers,
            NULL, NULL, &handler, 0) != STATUS_SUCCESS) {
        context->Pc = 0;
        return NULL;
    }
    return handler;
}

typedef struct {
    EXCEPTION_RECORD64* ExceptionRecord;
    ARM64_NT_CONTEXT* ContextRecord;
} EXCEPTION_POINTERS64;

typedef struct {
    uint32_t Count;
    struct {
        uint32_t BeginAddress;
        uint32_t EndAddress;
        uint32_t HandlerAddress;
        uint32_t JumpTarget;
    } ScopeRecord[1];
} SCOPE_TABLE64;

#define EXCEPTION_CONTINUE_SEARCH 0
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_EXECUTION (-1)

typedef LONG (*PEXCEPTION_FILTER64)(EXCEPTION_POINTERS64* ptrs, void* frame);
typedef void (*PTERMINATION_HANDLER64)(int abnormal, void* frame);
typedef struct _EXCEPTION_REGISTRATION_RECORD64 {
    struct _EXCEPTION_REGISTRATION_RECORD64* Prev;
    void* Handler;
} EXCEPTION_REGISTRATION_RECORD64;

EXPORT void RtlUnwindEx(
    void* end_frame, void* target_ip, EXCEPTION_RECORD64* rec, void* retval,
    ARM64_NT_CONTEXT* context, void* history_table);
EXPORT NTSTATUS NtContinue(void* context, uint8_t test_alert);
static int is_valid_teb_frame(uint64_t frame);

__attribute__((naked))
static LONG winemu_execute_exception_filter(
    EXCEPTION_POINTERS64* ptrs, void* frame, PEXCEPTION_FILTER64 filter, uint8_t* nonvol_regs)
{
    asm volatile(
        "stp x29, x30, [sp, #-96]!\n\t"
        "stp x19, x20, [sp, #16]\n\t"
        "stp x21, x22, [sp, #32]\n\t"
        "stp x23, x24, [sp, #48]\n\t"
        "stp x25, x26, [sp, #64]\n\t"
        "stp x27, x28, [sp, #80]\n\t"
        "ldp x19, x20, [x3, #0]\n\t"
        "ldp x21, x22, [x3, #16]\n\t"
        "ldp x23, x24, [x3, #32]\n\t"
        "ldp x25, x26, [x3, #48]\n\t"
        "ldp x27, x28, [x3, #64]\n\t"
        "ldr x1, [x3, #80]\n\t"
        "blr x2\n\t"
        "ldp x19, x20, [sp, #16]\n\t"
        "ldp x21, x22, [sp, #32]\n\t"
        "ldp x23, x24, [sp, #48]\n\t"
        "ldp x25, x26, [sp, #64]\n\t"
        "ldp x27, x28, [sp, #80]\n\t"
        "ldp x29, x30, [sp], #96\n\t"
        "ret\n\t"
    );
}

__attribute__((naked))
static EXCEPTION_DISPOSITION winemu_call_seh_handler(
    EXCEPTION_RECORD64* rec,
    uint64_t frame,
    ARM64_NT_CONTEXT* context,
    DISPATCHER_CONTEXT_ARM64* dispatch,
    PEXCEPTION_ROUTINE_ARM64 handler)
{
    asm volatile(
        "stp x29, x30, [sp, #-16]!\n\t"
        "blr x4\n\t"
        "ldp x29, x30, [sp], #16\n\t"
        "ret\n\t"
    );
}

EXPORT EXCEPTION_DISPOSITION __C_specific_handler(
    EXCEPTION_RECORD64* rec,
    void* frame,
    ARM64_NT_CONTEXT* context,
    DISPATCHER_CONTEXT_ARM64* dispatch)
{
    const SCOPE_TABLE64* table = (const SCOPE_TABLE64*)dispatch->HandlerData;
    ULONG_PTR base = dispatch->ImageBase;
    ULONG_PTR pc = dispatch->ControlPc;
    unsigned int i;

    if (!table) return ExceptionContinueSearch;
    if (dispatch->ControlPcIsUnwound && pc >= 4) pc -= 4;

    if (rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) {
        for (i = dispatch->ScopeIndex; i < table->Count; i++) {
            ULONG_PTR begin = base + table->ScopeRecord[i].BeginAddress;
            ULONG_PTR end = base + table->ScopeRecord[i].EndAddress;
            if (pc < begin || pc >= end) continue;
            if (table->ScopeRecord[i].JumpTarget) continue;

            if ((rec->ExceptionFlags & EXCEPTION_TARGET_UNWIND) &&
                dispatch->TargetPc >= begin &&
                dispatch->TargetPc < end) {
                break;
            }

            PTERMINATION_HANDLER64 handler =
                (PTERMINATION_HANDLER64)((char*)(uintptr_t)base + table->ScopeRecord[i].HandlerAddress);
            dispatch->ScopeIndex = i + 1;
            handler(1, frame);
        }
    } else {
        for (i = dispatch->ScopeIndex; i < table->Count; i++) {
            ULONG_PTR begin = base + table->ScopeRecord[i].BeginAddress;
            ULONG_PTR end = base + table->ScopeRecord[i].EndAddress;
            if (pc < begin || pc >= end) continue;
            if (!table->ScopeRecord[i].JumpTarget) continue;

            if (table->ScopeRecord[i].HandlerAddress != EXCEPTION_EXECUTE_HANDLER) {
                EXCEPTION_POINTERS64 ptrs = { rec, context };
                PEXCEPTION_FILTER64 filter =
                    (PEXCEPTION_FILTER64)((char*)(uintptr_t)base + table->ScopeRecord[i].HandlerAddress);
                LONG result = dispatch->NonVolatileRegisters
                    ? winemu_execute_exception_filter(&ptrs, frame, filter, dispatch->NonVolatileRegisters)
                    : filter(&ptrs, frame);
                if (result == EXCEPTION_CONTINUE_SEARCH) continue;
                if (result == EXCEPTION_CONTINUE_EXECUTION) return ExceptionContinueExecution;
            }

            RtlUnwindEx(
                frame,
                (char*)(uintptr_t)base + table->ScopeRecord[i].JumpTarget,
                rec,
                NULL,
                dispatch->ContextRecord,
                dispatch->HistoryTable);
        }
    }

    return ExceptionContinueSearch;
}

static NTSTATUS virtual_unwind(ULONG type, DISPATCHER_CONTEXT_ARM64* dispatch, ARM64_NT_CONTEXT* context) {
    ULONG_PTR pc = context->Pc;
    ULONG_PTR frame = 0;
    uint64_t orig_sp = context->Sp;
    void* handler_data = NULL;
    PEXCEPTION_ROUTINE_ARM64 handler = NULL;
    DISPATCHER_CONTEXT_NONVOLREG_ARM64* nonvol_regs =
        (DISPATCHER_CONTEXT_NONVOLREG_ARM64*)(void*)dispatch->NonVolatileRegisters;

    dispatch->ScopeIndex = 0;
    dispatch->ControlPc = pc;
    dispatch->ControlPcIsUnwound = (context->ContextFlags & CONTEXT_UNWOUND_TO_CALL) != 0;
    if (dispatch->ControlPcIsUnwound && pc >= 4) pc -= 4;
    if (nonvol_regs) {
        for (unsigned i = 0; i < NONVOL_INT_NUMREG_ARM64; i++) {
            nonvol_regs->GpNvRegs[i] = context->X[19 + i];
        }
        for (unsigned i = 0; i < NONVOL_FP_NUMREG_ARM64; i++) {
            nonvol_regs->FpNvRegs[i] = context->V[8 + i].D[0];
        }
    }

    dispatch->FunctionEntry = RtlLookupFunctionEntry(pc, &dispatch->ImageBase, dispatch->HistoryTable);
    NTSTATUS st = RtlVirtualUnwind2(
        type,
        dispatch->ImageBase,
        pc,
        dispatch->FunctionEntry,
        context,
        NULL,
        &handler_data,
        &frame,
        NULL,
        NULL,
        NULL,
        &handler,
        0
    );
    if (st != STATUS_SUCCESS) {
        return st;
    }
    winemu_exc_log_sp_event(
        "virtual_unwind",
        context,
        orig_sp,
        frame,
        (uint64_t)(uintptr_t)handler,
        NULL
    );
    dispatch->LanguageHandler = handler;
    dispatch->HandlerData = handler_data;
    dispatch->EstablisherFrame = frame;
    return STATUS_SUCCESS;
}

__attribute__((naked))
EXPORT void RtlCaptureContext(ARM64_NT_CONTEXT* context) {
    asm volatile(
        "str xzr, [x0, #0x8]\n\t"
        "stp x1, x2, [x0, #0x10]\n\t"
        "stp x3, x4, [x0, #0x20]\n\t"
        "stp x5, x6, [x0, #0x30]\n\t"
        "stp x7, x8, [x0, #0x40]\n\t"
        "stp x9, x10, [x0, #0x50]\n\t"
        "stp x11, x12, [x0, #0x60]\n\t"
        "stp x13, x14, [x0, #0x70]\n\t"
        "stp x15, x16, [x0, #0x80]\n\t"
        "stp x17, x18, [x0, #0x90]\n\t"
        "stp x19, x20, [x0, #0xa0]\n\t"
        "stp x21, x22, [x0, #0xb0]\n\t"
        "stp x23, x24, [x0, #0xc0]\n\t"
        "stp x25, x26, [x0, #0xd0]\n\t"
        "stp x27, x28, [x0, #0xe0]\n\t"
        "stp x29, xzr, [x0, #0xf0]\n\t"
        "mov x1, sp\n\t"
        "stp x1, x30, [x0, #0x100]\n\t"
        "stp q0, q1, [x0, #0x110]\n\t"
        "stp q2, q3, [x0, #0x130]\n\t"
        "stp q4, q5, [x0, #0x150]\n\t"
        "stp q6, q7, [x0, #0x170]\n\t"
        "stp q8, q9, [x0, #0x190]\n\t"
        "stp q10, q11, [x0, #0x1b0]\n\t"
        "stp q12, q13, [x0, #0x1d0]\n\t"
        "stp q14, q15, [x0, #0x1f0]\n\t"
        "stp q16, q17, [x0, #0x210]\n\t"
        "stp q18, q19, [x0, #0x230]\n\t"
        "stp q20, q21, [x0, #0x250]\n\t"
        "stp q22, q23, [x0, #0x270]\n\t"
        "stp q24, q25, [x0, #0x290]\n\t"
        "stp q26, q27, [x0, #0x2b0]\n\t"
        "stp q28, q29, [x0, #0x2d0]\n\t"
        "stp q30, q31, [x0, #0x2f0]\n\t"
        "mov w1, #0x400000\n\t"
        "movk w1, #0x7\n\t"
        "str w1, [x0]\n\t"
        "mrs x1, NZCV\n\t"
        "str w1, [x0, #0x4]\n\t"
        "mrs x1, FPCR\n\t"
        "str w1, [x0, #0x310]\n\t"
        "mrs x1, FPSR\n\t"
        "str w1, [x0, #0x314]\n\t"
        "ret\n\t");
}

EXPORT void RtlRestoreContext(ARM64_NT_CONTEXT* context, EXCEPTION_RECORD64* rec) {
    if (context && rec && rec->ExceptionCode == STATUS_LONGJUMP && rec->NumberParameters >= 1) {
        WINEMU_RESTORE_JUMP_BUFFER_ARM64* jmp =
            (WINEMU_RESTORE_JUMP_BUFFER_ARM64*)(uintptr_t)rec->ExceptionInformation[0];
        if (jmp) {
            context->X[19] = jmp->x19;
            context->X[20] = jmp->x20;
            context->X[21] = jmp->x21;
            context->X[22] = jmp->x22;
            context->X[23] = jmp->x23;
            context->X[24] = jmp->x24;
            context->X[25] = jmp->x25;
            context->X[26] = jmp->x26;
            context->X[27] = jmp->x27;
            context->X[28] = jmp->x28;
            context->X[29] = jmp->fp;
            context->X[30] = jmp->lr;
            context->Sp = jmp->sp;
            context->Pc = jmp->lr;
            context->Fpcr = jmp->fpcr;
            context->Fpsr = jmp->fpsr;
            for (int i = 0; i < 8; ++i) context->V[8 + i].D[0] = jmp->d[i];
        }
    }
    if (context) {
        winemu_exc_log_sp_event("restore_target", context, 0, context->X[30], context->X[0], rec);
    }
    if (context) {
        uint8_t* teb = (uint8_t*)NtCurrentTeb();
        EXCEPTION_REGISTRATION_RECORD64* teb_frame = teb
            ? (EXCEPTION_REGISTRATION_RECORD64*)(uintptr_t)(*(uint64_t*)(teb + 0x00))
            : NULL;

        while (teb && is_valid_teb_frame((uint64_t)(uintptr_t)teb_frame) &&
               (uint64_t)(uintptr_t)teb_frame < context->Sp) {
            winemu_exc_log_sp_event(
                "restore_pop_teb",
                context,
                (uint64_t)(uintptr_t)teb_frame,
                (uint64_t)(uintptr_t)teb_frame->Prev,
                0,
                rec
            );
            teb_frame = teb_frame->Prev;
            *(uint64_t*)(teb + 0x00) = (uint64_t)(uintptr_t)teb_frame;
        }
    }
    (void)NtContinue(context, 0);
    for (;;) {}
}

static int is_valid_teb_frame(uint64_t frame) {
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    if (!teb || frame == 0 || frame == UINT64_MAX) {
        return 0;
    }
    uint64_t stack_base = *(uint64_t*)(teb + 0x08);
    uint64_t stack_limit = *(uint64_t*)(teb + 0x10);
    if (frame < stack_limit || frame >= stack_base) {
        return 0;
    }
    if ((frame & 0x0fU) != 0) {
        return 0;
    }
    return 1;
}

static uint64_t g_dispatch_handler_count = 0;
static uint64_t g_dispatch_last_result = 0;
static uint64_t g_dispatch_last_handler = 0;
static uint64_t g_dispatch_first_unwound_pc = 0;
static uint64_t g_dispatch_second_unwound_pc = 0;
static uint64_t g_dispatch_third_unwound_pc = 0;

static NTSTATUS dispatch_exception(EXCEPTION_RECORD64* rec, ARM64_NT_CONTEXT* orig_context) {
    ARM64_NT_CONTEXT context = *orig_context;
    DISPATCHER_CONTEXT_ARM64 dispatch;
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 nonvol_regs;
    EXCEPTION_REGISTRATION_RECORD64* teb_frame = NULL;
    uint64_t prev_sp = context.Sp;
    uint64_t prev_pc = context.Pc;
    uint64_t handler_count = 0;
    uint64_t last_result = 0;
    uint64_t last_handler = 0;
    uint64_t first_unwound_pc = 0;
    uint64_t second_unwound_pc = 0;
    uint64_t third_unwound_pc = 0;
    uint64_t unwind_step = 0;
    uint8_t* teb = (uint8_t*)NtCurrentTeb();

#define FINISH_DISPATCH(st) do { \
    g_dispatch_handler_count = handler_count; \
    g_dispatch_last_result = last_result; \
    g_dispatch_last_handler = last_handler; \
    g_dispatch_first_unwound_pc = first_unwound_pc; \
    g_dispatch_second_unwound_pc = second_unwound_pc; \
    g_dispatch_third_unwound_pc = third_unwound_pc; \
    *orig_context = context; \
    return (st); \
} while (0)

    if (teb) {
        teb_frame = (EXCEPTION_REGISTRATION_RECORD64*)(uintptr_t)(*(uint64_t*)(teb + 0x00));
    }

    for (;;) {
        memset(&dispatch, 0, sizeof(dispatch));
        dispatch.TargetPc = 0;
        dispatch.ContextRecord = &context;
        dispatch.HistoryTable = NULL;
        dispatch.NonVolatileRegisters = nonvol_regs.Buffer;

        NTSTATUS status = virtual_unwind(UNW_FLAG_EHANDLER, &dispatch, &context);
        if (status != STATUS_SUCCESS) {
            winemu_exc_log_exception(
                "virtual_unwind_fail",
                rec,
                status,
                first_unwound_pc,
                second_unwound_pc,
                third_unwound_pc
            );
            FINISH_DISPATCH(status);
        }
        unwind_step++;
        if (!first_unwound_pc && context.Pc) {
            first_unwound_pc = context.Pc;
        }
        if (unwind_step == 2 && !second_unwound_pc && context.Pc) {
            second_unwound_pc = context.Pc;
        }
        if (unwind_step == 3 && !third_unwound_pc && context.Pc) {
            third_unwound_pc = context.Pc;
        }
        if (!dispatch.EstablisherFrame) break;

        if (dispatch.LanguageHandler) {
            handler_count++;
            last_handler = (uint64_t)(uintptr_t)dispatch.LanguageHandler;
            EXCEPTION_DISPOSITION res = dispatch.LanguageHandler(
                rec,
                (void*)(uintptr_t)dispatch.EstablisherFrame,
                &context,
                &dispatch
            );
            last_result = (uint64_t)res;
            rec->ExceptionFlags &= EXCEPTION_NONCONTINUABLE;

            if (res == ExceptionContinueExecution) {
                if (rec->ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
                    FINISH_DISPATCH(STATUS_NONCONTINUABLE_EXCEPTION);
                }
                FINISH_DISPATCH(STATUS_SUCCESS);
            }
            if (res == ExceptionContinueSearch) {
                /* continue searching */
            } else if (res == ExceptionNestedException || res == ExceptionCollidedUnwind) {
                rec->ExceptionFlags |= EXCEPTION_NESTED_CALL;
            } else {
                FINISH_DISPATCH(STATUS_INVALID_DISPOSITION);
            }
        } else {
            while (is_valid_teb_frame((uint64_t)(uintptr_t)teb_frame) &&
                   (uint64_t)(uintptr_t)teb_frame < context.Sp) {
                handler_count++;
                last_handler = (uint64_t)(uintptr_t)teb_frame->Handler;
                EXCEPTION_DISPOSITION res = winemu_call_seh_handler(
                    rec,
                    (uint64_t)(uintptr_t)teb_frame,
                    &context,
                    &dispatch,
                    (PEXCEPTION_ROUTINE_ARM64)(uintptr_t)teb_frame->Handler
                );
                last_result = (uint64_t)res;
                if (res == ExceptionContinueExecution) {
                    if (rec->ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
                        FINISH_DISPATCH(STATUS_NONCONTINUABLE_EXCEPTION);
                    }
                    FINISH_DISPATCH(STATUS_SUCCESS);
                }
                if (res == ExceptionNestedException || res == ExceptionCollidedUnwind) {
                    rec->ExceptionFlags |= EXCEPTION_NESTED_CALL;
                } else if (res != ExceptionContinueSearch) {
                    FINISH_DISPATCH(STATUS_INVALID_DISPOSITION);
                }
                teb_frame = teb_frame->Prev;
            }
        }

        if (!context.Pc) break;
        if (context.Sp < prev_sp) break;
        if (context.Sp == prev_sp && context.Pc == prev_pc) break;
        prev_sp = context.Sp;
        prev_pc = context.Pc;
    }
    FINISH_DISPATCH(STATUS_UNHANDLED_EXCEPTION);

#undef FINISH_DISPATCH
}

EXPORT void RtlUnwindEx(
    void* end_frame, void* target_ip, EXCEPTION_RECORD64* rec, void* retval,
    ARM64_NT_CONTEXT* context, void* history_table)
{
    EXCEPTION_RECORD64 record;
    ARM64_NT_CONTEXT captured;
    ARM64_NT_CONTEXT walk;
    DISPATCHER_CONTEXT_ARM64 dispatch;
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 nonvol_regs;
    uint64_t prev_sp;
    uint64_t prev_pc;

    if (!context) {
        context = &captured;
    }
    RtlCaptureContext(context);
    walk = *context;
    prev_sp = walk.Sp;
    prev_pc = walk.Pc;

    if (!rec) {
        record.ExceptionCode = STATUS_UNWIND;
        record.ExceptionFlags = 0;
        record.ExceptionRecord = NULL;
        record.ExceptionAddress = (void*)(uintptr_t)context->Pc;
        record.NumberParameters = 0;
        rec = &record;
    }
    rec->ExceptionFlags |= EXCEPTION_UNWINDING | (end_frame ? 0 : EXCEPTION_EXIT_UNWIND);

    for (;;) {
        memset(&dispatch, 0, sizeof(dispatch));
        dispatch.TargetPc = (uint64_t)(uintptr_t)target_ip;
        dispatch.ContextRecord = context;
        dispatch.HistoryTable = history_table;
        dispatch.NonVolatileRegisters = nonvol_regs.Buffer;

        NTSTATUS status = virtual_unwind(UNW_FLAG_UHANDLER, &dispatch, &walk);
        if (status != STATUS_SUCCESS) break;
        if (!dispatch.EstablisherFrame) break;

        if (dispatch.LanguageHandler) {
            if (end_frame && dispatch.EstablisherFrame > (uint64_t)(uintptr_t)end_frame) {
                break;
            }
            if (dispatch.EstablisherFrame == (uint64_t)(uintptr_t)end_frame) {
                rec->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
            }

            EXCEPTION_DISPOSITION res = dispatch.LanguageHandler(
                rec,
                (void*)(uintptr_t)dispatch.EstablisherFrame,
                dispatch.ContextRecord,
                &dispatch
            );

            if (res == ExceptionContinueSearch) {
                rec->ExceptionFlags &= ~EXCEPTION_COLLIDED_UNWIND;
            } else if (res == ExceptionCollidedUnwind) {
                rec->ExceptionFlags |= EXCEPTION_COLLIDED_UNWIND;
            } else {
                break;
            }
        }

        if (dispatch.EstablisherFrame == (uint64_t)(uintptr_t)end_frame) break;
        *context = walk;
        winemu_exc_log_sp_event(
            "unwind_step",
            context,
            prev_sp,
            dispatch.EstablisherFrame,
            (uint64_t)(uintptr_t)target_ip,
            rec
        );
        if (!walk.Pc) break;
        if (walk.Sp < prev_sp) break;
        if (walk.Sp == prev_sp && walk.Pc == prev_pc) break;
        prev_sp = walk.Sp;
        prev_pc = walk.Pc;
    }

    if (rec->ExceptionCode != STATUS_UNWIND_CONSOLIDATE) {
        context->Pc = (uint64_t)(uintptr_t)target_ip;
    }
    context->X[0] = (uint64_t)(uintptr_t)retval;
    RtlRestoreContext(context, rec);
}

EXPORT void RtlUnwind(void* frame, void* target_ip, EXCEPTION_RECORD64* rec, void* retval) {
    ARM64_NT_CONTEXT context;
    RtlUnwindEx(frame, target_ip, rec, retval, &context, NULL);
}

__attribute__((noreturn))
void winemu_raise_exception_dispatch(EXCEPTION_RECORD64* record, ARM64_NT_CONTEXT* context) {
    uint64_t code = 0xE06D7363ULL;
    uint64_t info2 = 0;
    uint64_t info3 = 0;
    uint64_t exaddr = 0;
    EXCEPTION_RECORD64 fallback;
    if (!record) {
        memset(&fallback, 0, sizeof(fallback));
        fallback.ExceptionCode = (uint32_t)code;
        record = &fallback;
    }
    if (context && context->Pc == 0) {
        if (record && record->ExceptionAddress) {
            context->Pc = (uint64_t)(uintptr_t)record->ExceptionAddress;
        } else {
            context->Pc = context->X[30];
        }
        record->ExceptionAddress = (void*)(uintptr_t)context->Pc;
    }
    NTSTATUS dispatch_status = dispatch_exception(record, context);
    if (dispatch_status == STATUS_SUCCESS) {
        RtlRestoreContext(context, record);
    }
    winemu_exc_log_exception(
        "terminate",
        record,
        dispatch_status,
        g_dispatch_first_unwound_pc,
        g_dispatch_second_unwound_pc,
        g_dispatch_third_unwound_pc
    );

    if (record) {
        code = record->ExceptionCode;
        exaddr = (uint64_t)(uintptr_t)record->ExceptionAddress;
        if (record->NumberParameters > 2) {
            info2 = record->ExceptionInformation[2];
        }
        if (record->NumberParameters > 3) {
            info3 = record->ExceptionInformation[3];
        }
    }
    uint64_t dispatch_diag = ((g_dispatch_handler_count & 0xFFFFULL) << 48)
        | ((g_dispatch_last_result & 0xFFULL) << 40)
        | ((g_heap_alloc_fail_count & 0xFFULL) << 32)
        | (uint64_t)(uint32_t)dispatch_status;
    uint64_t diag4 = exaddr;
    if (g_heap_last_fail_size) {
        diag4 = g_heap_last_fail_size;
    }
    if (g_dispatch_last_handler) {
        diag4 = g_dispatch_last_handler;
    }
    if (g_dispatch_first_unwound_pc) {
        diag4 = g_dispatch_first_unwound_pc;
    }
    if (g_dispatch_second_unwound_pc) {
        diag4 = g_dispatch_second_unwound_pc;
    }
    if (g_dispatch_third_unwound_pc) {
        diag4 = g_dispatch_third_unwound_pc;
    }
    (void)syscall6(
        NR_TERMINATE_PROCESS,
        (uint64_t)(HANDLE)(uint64_t)-1,
        (uint64_t)(NTSTATUS)code,
        info2,
        info3,
        diag4,
        dispatch_diag
    );
    for (;;) {}
}

__attribute__((naked))
EXPORT void RtlRaiseException(EXCEPTION_RECORD64* record) {
    asm volatile(
        "sub sp, sp, #0x3b0\n\t"      // 0x390 context + 0x20 scratch
        "stp x29, x30, [sp]\n\t"
        "mov x29, sp\n\t"
        "str x0, [sp, #0x10]\n\t"     // save record pointer
        "add x0, sp, #0x20\n\t"       // x0 = context
        "bl RtlCaptureContext\n\t"
        "add x1, sp, #0x20\n\t"       // x1 = context
        "add x2, sp, #0x3b0\n\t"      // original sp before frame allocation
        "str x2, [x1, #0x100]\n\t"    // context->Sp
        "ldr x0, [sp, #0x10]\n\t"     // x0 = record
        "str x0, [x1, #0x08]\n\t"     // context->X0
        "ldp x4, x5, [sp]\n\t"        // caller fp/lr
        "stp x4, x5, [x1, #0xf0]\n\t" // context->X29/X30
        "str x5, [x1, #0x108]\n\t"    // context->Pc
        "cbz x0, 1f\n\t"
        "str x5, [x0, #0x10]\n\t"     // rec->ExceptionAddress
        "1:\tldr w2, [x1]\n\t"
        "orr w2, w2, #0x20000000\n\t" // CONTEXT_UNWOUND_TO_CALL
        "str w2, [x1]\n\t"
        "ldr x0, [sp, #0x10]\n\t"
        "bl winemu_raise_exception_dispatch\n\t"
        "brk #1\n\t"
    );
}
