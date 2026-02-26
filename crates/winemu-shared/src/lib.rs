#![no_std]

pub mod pe;

/// Hypercall ABI — 所有编号和参数约定的唯一来源
/// 同时被 winemu-kernel (bare-metal) 和 winemu-core (host) 使用

pub mod nr {
    // ── 系统: 0x0000 - 0x000F ────────────────────────────────
    /// Guest kernel 启动完成，传入 PE 入口点和栈
    /// args: [entry_va, stack_va, teb_gva, 0, 0, 0]
    pub const KERNEL_READY:       u64 = 0x0000;
    /// 调试打印
    /// args: [gpa_of_str, len, 0, 0, 0, 0]
    pub const DEBUG_PRINT:        u64 = 0x0001;
    /// 加载 syscall 表 TOML
    /// args: [dst_gpa, max_len, write(1)/query(0), 0, 0, 0]
    pub const LOAD_SYSCALL_TABLE: u64 = 0x0002;

    // ── 进程/线程: 0x0010 - 0x001F ───────────────────────────
    /// args: [image_base_gva, 0, 0, 0, 0, 0]
    pub const PROCESS_CREATE:     u64 = 0x0010;
    /// args: [exit_code, 0, 0, 0, 0, 0]
    pub const PROCESS_EXIT:       u64 = 0x0011;
    /// args: [entry_va, stack_va, arg_x0, teb_gva, 0, 0]
    pub const THREAD_CREATE:      u64 = 0x0012;
    /// args: [exit_code, 0, 0, 0, 0, 0]
    pub const THREAD_EXIT:        u64 = 0x0013;

    // ── DLL 加载: 0x0300 ─────────────────────────────────────
    /// args: [name_gpa, name_len, dst_gpa(0=query), dst_size, 0, 0]
    pub const LOAD_DLL_IMAGE:     u64 = 0x0300;
    /// args: [dll_base, name_gpa, name_len, 0, 0, 0] → returns fn VA or 0
    pub const GET_PROC_ADDRESS:   u64 = 0x0301;

    // ── NT 文件 I/O: 0x0400 - 0x04FF ────────────────────────
    /// args: [path_gpa, path_len, access, disposition, 0, 0]
    pub const NT_CREATE_FILE:     u64 = 0x0400;
    /// args: [path_gpa, path_len, access, 0, 0, 0]
    pub const NT_OPEN_FILE:       u64 = 0x0401;
    /// args: [handle, buf_gpa, len, offset(MAX=cur), 0, 0]
    pub const NT_READ_FILE:       u64 = 0x0402;
    /// args: [handle, buf_gpa, len, offset(MAX=cur), 0, 0]
    pub const NT_WRITE_FILE:      u64 = 0x0403;
    /// args: [handle, 0, 0, 0, 0, 0]
    pub const NT_CLOSE:           u64 = 0x0404;
    /// args: [handle, 0, 0, 0, 0, 0] → returns file size
    pub const NT_QUERY_INFO_FILE: u64 = 0x0405;
    /// args: [handle, buf_gpa, buf_len, 0, 0, 0]
    pub const NT_QUERY_DIR_FILE:  u64 = 0x0406;

    // ── NT Section/映射: 0x0510 - 0x051F ────────────────────
    /// NtCreateSection
    /// args: [file_handle(0=pagefile), size, prot, 0, 0, 0]
    /// returns: section_handle
    pub const NT_CREATE_SECTION:    u64 = 0x0510;
    /// NtMapViewOfSection
    /// args: [section_handle, base_hint(0=any), size, offset, prot, 0]
    /// returns: mapped_va (0 on error)
    pub const NT_MAP_VIEW_OF_SECTION: u64 = 0x0511;
    /// NtUnmapViewOfSection
    /// args: [base_va, 0, 0, 0, 0, 0]
    pub const NT_UNMAP_VIEW_OF_SECTION: u64 = 0x0512;

    // ── NT 虚拟内存: 0x0500 - 0x05FF ────────────────────────
    /// args: [hint_va(0=any), size, prot, 0, 0, 0]
    pub const NT_ALLOC_VIRTUAL:   u64 = 0x0500;
    /// args: [base_va, 0, 0, 0, 0, 0]
    pub const NT_FREE_VIRTUAL:    u64 = 0x0501;
    /// args: [base_va, size, new_prot, 0, 0, 0]
    pub const NT_PROTECT_VIRTUAL: u64 = 0x0502;
    /// args: [addr, 0, 0, 0, 0, 0]
    pub const NT_QUERY_VIRTUAL:   u64 = 0x0503;

    // ── NT 同步: 0x0600 - 0x06FF ─────────────────────────────
    /// args: [manual_reset, initial_state, 0, 0, 0, 0]
    pub const NT_CREATE_EVENT:      u64 = 0x0600;
    /// args: [handle, 0, 0, 0, 0, 0]
    pub const NT_SET_EVENT:         u64 = 0x0601;
    /// args: [handle, 0, 0, 0, 0, 0]
    pub const NT_RESET_EVENT:       u64 = 0x0602;
    /// args: [handle, timeout_100ns(i64), 0, 0, 0, 0]
    pub const NT_WAIT_SINGLE:       u64 = 0x0603;
    /// args: [handles_gpa, count, wait_all, timeout_100ns(i64), 0, 0]
    pub const NT_WAIT_MULTIPLE:     u64 = 0x0604;
    /// args: [initial_owner, 0, 0, 0, 0, 0]
    pub const NT_CREATE_MUTEX:      u64 = 0x0605;
    /// args: [handle, 0, 0, 0, 0, 0]
    pub const NT_RELEASE_MUTEX:     u64 = 0x0606;
    /// args: [initial_count, maximum_count, 0, 0, 0, 0]
    pub const NT_CREATE_SEMAPHORE:  u64 = 0x0607;
    /// args: [handle, release_count, 0, 0, 0, 0]
    pub const NT_RELEASE_SEMAPHORE: u64 = 0x0608;
    /// args: [handle, 0, 0, 0, 0, 0]
    pub const NT_CLOSE_HANDLE:      u64 = 0x0609;
    /// args: [0, 0, 0, 0, 0, 0]
    pub const NT_YIELD_EXECUTION:   u64 = 0x060A;

    // ── NT syscall 分发: 0x0700 ───────────────────────────────
    /// Guest syscall 分发入口
    /// args: [syscall_nr, table_nr, arg0, arg1, arg2, arg3]
    /// 超过4个参数时 VMM 从 guest sp 读取
    pub const NT_SYSCALL:           u64 = 0x0700;

    // ── 图形: 0x0100 - 0x01FF ────────────────────────────────
    pub const WIN32U_CREATE_WINDOW:  u64 = 0x0100;
    pub const WIN32U_SHOW_WINDOW:    u64 = 0x0101;
    pub const WIN32U_DESTROY_WINDOW: u64 = 0x0102;
    pub const WIN32U_MSG_CALL:       u64 = 0x0103;
    pub const WIN32U_GDI_BITBLT:     u64 = 0x0110;
    pub const VULKAN_CALL:           u64 = 0x0120;

    // ── 音频: 0x0200 - 0x02FF ────────────────────────────────
    pub const WAVE_OUT_OPEN:  u64 = 0x0200;
    pub const WAVE_OUT_WRITE: u64 = 0x0201;
    pub const WAVE_OUT_CLOSE: u64 = 0x0202;
}

/// NT 超时常量（100ns 单位）
pub mod timeout {
    pub const INFINITE: i64 = i64::MIN;
    pub const NOW:      i64 = 0;

}

/// NT 状态码（hypercall 返回值高 32 位）
pub mod status {
    pub const SUCCESS:                u32 = 0x0000_0000;
    pub const WAIT_0:                 u32 = 0x0000_0000;
    pub const TIMEOUT:                u32 = 0x0000_0102;
    pub const ABANDONED_WAIT_0:       u32 = 0x0000_0080;
    pub const OBJECT_NOT_FOUND:       u32 = 0xC000_0034;
    pub const OBJECT_NAME_COLLISION:  u32 = 0xC000_0035;
    pub const ACCESS_DENIED:          u32 = 0xC000_0022;
    pub const INVALID_HANDLE:         u32 = 0xC000_0008;
    pub const END_OF_FILE:            u32 = 0xC000_011B;
    pub const INVALID_PARAMETER:      u32 = 0xC000_000D;
    pub const MUTANT_NOT_OWNED:       u32 = 0xC000_0046;
    pub const SEMAPHORE_LIMIT_EXCEEDED: u32 = 0xC000_0047;
    pub const NO_MEMORY:              u32 = 0xC000_0017;
    pub const INFO_LENGTH_MISMATCH:   u32 = 0xC000_0004;
    pub const OBJECT_NAME_NOT_FOUND:  u32 = 0xC000_0034;
    pub const NO_MORE_ENTRIES:        u32 = 0x8000_001A;
    pub const BUFFER_TOO_SMALL:       u32 = 0xC000_0023;
    pub const NO_MORE_FILES:          u32 = 0x8000_0006;
    pub const NOT_IMPLEMENTED:        u32 = 0xC000_0002;
}

/// NT TEB 字段偏移（64-bit，参考 Wine winternl.h + signal_arm64.c）
pub mod teb {
    pub const EXCEPTION_LIST:  usize = 0x0000;
    pub const STACK_BASE:      usize = 0x0008;
    pub const STACK_LIMIT:     usize = 0x0010;
    pub const SUBSYSTEM_TIB:   usize = 0x0018;
    pub const FIBER_DATA:      usize = 0x0020;
    pub const ARBITRARY_USER:  usize = 0x0028;
    pub const SELF:            usize = 0x0030;
    pub const ENV_POINTER:     usize = 0x0038;
    pub const CLIENT_ID:       usize = 0x0040; // [pid(8), tid(8)]
    pub const ACTIVE_RPC:      usize = 0x0050;
    pub const TLS_POINTER:     usize = 0x0058;
    pub const PEB:             usize = 0x0060;
    pub const SYSCALL_FRAME:   usize = 0x02f0; // Wine ARM64 private
    pub const SYSCALL_TABLE:   usize = 0x02f8;
    pub const SIZE:            usize = 0x1000;
}

/// NT PEB 字段偏移（64-bit）
pub mod peb {
    pub const IMAGE_BASE_ADDRESS: usize = 0x0010;
    pub const LDR:                usize = 0x0018;
    pub const PROCESS_PARAMETERS: usize = 0x0020;
    pub const PROCESS_HEAP:       usize = 0x0030;
    pub const OS_MAJOR_VERSION:   usize = 0x0118;
    pub const OS_MINOR_VERSION:   usize = 0x011c;
    pub const OS_BUILD_NUMBER:    usize = 0x0120;
    pub const OS_PLATFORM_ID:     usize = 0x0124;
    pub const IMAGE_SUBSYSTEM:    usize = 0x012c;
    pub const SIZE:               usize = 0x1000;
}

/// PE OptionalHeader64 字段偏移（相对于 OptionalHeader 起始）
pub mod pe_opt {
    pub const MAGIC:             usize = 0;
    pub const ENTRY_POINT:       usize = 16;
    pub const IMAGE_BASE:        usize = 24;
    pub const SECTION_ALIGNMENT: usize = 32;
    pub const SIZE_OF_IMAGE:     usize = 56;
    pub const SIZE_OF_HEADERS:   usize = 60;
    pub const STACK_RESERVE:     usize = 72;
    pub const STACK_COMMIT:      usize = 80;
    pub const NUM_DIRS:          usize = 92;
    pub const DIRS:              usize = 96;
}
