#![no_std]

pub mod pe;
pub mod win32k_sysno;
pub mod nt_sysno;

/// Hypercall ABI — 所有编号和参数约定的唯一来源
/// 同时被 winemu-kernel (bare-metal) 和 winemu-core (host) 使用

pub mod nr {
    // ── 系统: 0x0000 - 0x000F ────────────────────────────────
    /// Guest kernel 启动完成，传入 PE 入口点和栈
    /// args: [entry_va, stack_va, teb_gva, 0, 0, 0]
    pub const KERNEL_READY: u64 = 0x0000;
    /// 调试打印
    /// args: [gpa_of_str, len, 0, 0, 0, 0]
    pub const DEBUG_PRINT: u64 = 0x0001;
    /// 加载 syscall 表 TOML
    /// args: [dst_gpa, max_len, write(1)/query(0), 0, 0, 0]
    pub const LOAD_SYSCALL_TABLE: u64 = 0x0002;
    /// 按 vCPU mask 精确唤醒宿主调度线程
    /// args: [vcpu_mask, 0, 0, 0, 0, 0]
    pub const KICK_VCPU_MASK: u64 = 0x0003;
    /// 查询 guest Windows build 号
    /// args: [0, 0, 0, 0, 0, 0] → windows_build (u32)
    pub const QUERY_WINDOWS_BUILD: u64 = 0x0004;
    // ── 进程/线程: 0x0010 - 0x001F ───────────────────────────
    /// args: [image_base_gva, 0, 0, 0, 0, 0]
    pub const PROCESS_CREATE: u64 = 0x0010;
    /// args: [exit_code, 0, 0, 0, 0, 0]
    pub const PROCESS_EXIT: u64 = 0x0011;

    // ── DLL 加载: 0x0300 ─────────────────────────────────────
    /// args: [name_gpa, name_len, dst_gpa(0=query), dst_size, 0, 0]
    pub const LOAD_DLL_IMAGE: u64 = 0x0300;
    /// args: [dll_base, name_gpa, name_len, 0, 0, 0] → returns fn VA or 0
    pub const GET_PROC_ADDRESS: u64 = 0x0301;

    // ── NT 文件 I/O: 0x0400 - 0x04FF ────────────────────────
    /// args: [path_gpa, path_len, access, disposition, 0, 0]
    pub const NT_CREATE_FILE: u64 = 0x0400;
    /// args: [path_gpa, path_len, access, 0, 0, 0]
    pub const NT_OPEN_FILE: u64 = 0x0401;
    /// args: [handle, buf_gpa, len, offset(MAX=cur), 0, 0]
    pub const NT_READ_FILE: u64 = 0x0402;
    /// args: [handle, buf_gpa, len, offset(MAX=cur), 0, 0]
    pub const NT_WRITE_FILE: u64 = 0x0403;
    /// args: [handle, 0, 0, 0, 0, 0]
    pub const NT_CLOSE: u64 = 0x0404;
    /// args: [handle, 0, 0, 0, 0, 0] → returns file size
    pub const NT_QUERY_INFO_FILE: u64 = 0x0405;
    /// args: [handle, buf_gpa, buf_len, 0, 0, 0]
    pub const NT_QUERY_DIR_FILE: u64 = 0x0406;

    // ── NT Section/映射: 0x0510 - 0x051F ────────────────────
    /// NtCreateSection
    /// args: [file_handle(0=pagefile), size, prot, 0, 0, 0]
    /// returns: section_handle
    pub const NT_CREATE_SECTION: u64 = 0x0510;
    /// NtMapViewOfSection
    /// args: [section_handle, base_hint(0=any), size, offset, prot, 0]
    /// returns: mapped_va (0 on error)
    pub const NT_MAP_VIEW_OF_SECTION: u64 = 0x0511;
    /// NtUnmapViewOfSection
    /// args: [base_va, 0, 0, 0, 0, 0]
    pub const NT_UNMAP_VIEW_OF_SECTION: u64 = 0x0512;

    // ── NT 虚拟内存: 0x0500 - 0x05FF ────────────────────────
    /// args: [hint_va(0=any), size, prot, 0, 0, 0]
    pub const NT_ALLOC_VIRTUAL: u64 = 0x0500;
    /// args: [base_va, 0, 0, 0, 0, 0]
    pub const NT_FREE_VIRTUAL: u64 = 0x0501;
    /// args: [base_va, size, new_prot, 0, 0, 0]
    pub const NT_PROTECT_VIRTUAL: u64 = 0x0502;
    /// args: [addr, 0, 0, 0, 0, 0]
    pub const NT_QUERY_VIRTUAL: u64 = 0x0503;

    // ── NT 同步: 0x0600 - 0x06FF ─────────────────────────────
    /// args: [manual_reset, initial_state, 0, 0, 0, 0]
    pub const NT_CREATE_EVENT: u64 = 0x0600;
    /// args: [handle, 0, 0, 0, 0, 0]
    pub const NT_SET_EVENT: u64 = 0x0601;
    /// args: [handle, 0, 0, 0, 0, 0]
    pub const NT_RESET_EVENT: u64 = 0x0602;
    /// args: [handle, timeout_100ns(i64), 0, 0, 0, 0]
    pub const NT_WAIT_SINGLE: u64 = 0x0603;
    /// args: [handles_gpa, count, wait_all, timeout_100ns(i64), 0, 0]
    pub const NT_WAIT_MULTIPLE: u64 = 0x0604;
    /// args: [initial_owner, 0, 0, 0, 0, 0]
    pub const NT_CREATE_MUTEX: u64 = 0x0605;
    /// args: [handle, 0, 0, 0, 0, 0]
    pub const NT_RELEASE_MUTEX: u64 = 0x0606;
    /// args: [initial_count, maximum_count, 0, 0, 0, 0]
    pub const NT_CREATE_SEMAPHORE: u64 = 0x0607;
    /// args: [handle, release_count, 0, 0, 0, 0]
    pub const NT_RELEASE_SEMAPHORE: u64 = 0x0608;
    /// args: [handle, 0, 0, 0, 0, 0]
    pub const NT_CLOSE_HANDLE: u64 = 0x0609;
    /// args: [0, 0, 0, 0, 0, 0]
    pub const NT_YIELD_EXECUTION: u64 = 0x060A;

    // ── NT syscall 分发: 0x0700 ───────────────────────────────
    /// Guest syscall 分发入口
    /// args: [syscall_nr, table_nr, arg0, arg1, arg2, arg3]
    /// 超过4个参数时 VMM 从 guest sp 读取
    pub const NT_SYSCALL: u64 = 0x0700;

    // ── 图形: 0x0100 - 0x01FF ────────────────────────────────
    pub const WIN32U_CREATE_WINDOW: u64 = 0x0100;
    pub const WIN32U_SHOW_WINDOW: u64 = 0x0101;
    pub const WIN32U_DESTROY_WINDOW: u64 = 0x0102;
    pub const WIN32U_MSG_CALL: u64 = 0x0103;
    pub const WIN32U_GDI_BITBLT: u64 = 0x0110;
    pub const VULKAN_CALL: u64 = 0x0120;

    // ── 音频: 0x0200 - 0x02FF ────────────────────────────────
    pub const WAVE_OUT_OPEN: u64 = 0x0200;
    pub const WAVE_OUT_WRITE: u64 = 0x0201;
    pub const WAVE_OUT_CLOSE: u64 = 0x0202;

    // ── 物理内存管理: 0x0800 - 0x080F ──────────────────────
    /// 分配连续物理页框
    /// args: [num_pages, 0, 0, 0, 0, 0] → 首页 GPA（失败返回 0）
    pub const ALLOC_PHYS_PAGES: u64 = 0x0800;
    /// 释放连续物理页框
    /// args: [gpa, num_pages, 0, 0, 0, 0]
    pub const FREE_PHYS_PAGES: u64 = 0x0801;

    // ── Host 文件操作: 0x0810 - 0x081F ─────────────────────
    /// 打开宿主文件
    /// args: [path_gpa, path_len, flags(0=RD,1=WR,2=RW,3=CREATE), 0, 0, 0]
    /// 返回: host_fd (失败返回 u64::MAX)
    pub const HOST_OPEN: u64 = 0x0810;
    /// 读取文件内容到 guest 内存
    /// args: [host_fd, dst_gpa, len, offset(u64::MAX=current), 0, 0]
    /// 返回: 实际读取字节数
    pub const HOST_READ: u64 = 0x0811;
    /// 写入 guest 内存到文件
    /// args: [host_fd, src_gpa, len, offset(u64::MAX=current), 0, 0]
    /// 返回: 实际写入字节数
    pub const HOST_WRITE: u64 = 0x0812;
    /// 关闭文件
    /// args: [host_fd, 0, 0, 0, 0, 0]
    pub const HOST_CLOSE: u64 = 0x0813;
    /// 查询文件大小
    /// args: [host_fd, 0, 0, 0, 0, 0] → 文件大小（字节）
    pub const HOST_STAT: u64 = 0x0814;
    /// mmap 宿主文件到 guest 物理地址空间（零拷贝）
    /// args: [host_fd, offset, size, prot, 0, 0] → gpa (失败返回 0)
    pub const HOST_MMAP: u64 = 0x0815;
    /// 解除文件映射
    /// args: [gpa, size, 0, 0, 0, 0]
    pub const HOST_MUNMAP: u64 = 0x0816;
    /// 查询 EXE 文件信息（VMM 打开 exe 并返回 host_fd + size）
    /// args: [0, 0, 0, 0, 0, 0] → packed (size<<32 | fd)
    pub const QUERY_EXE_INFO: u64 = 0x0817;
    /// 查询单调时钟（100ns 单位）
    /// args: [0, 0, 0, 0, 0, 0] → elapsed_100ns
    pub const QUERY_MONO_TIME: u64 = 0x0818;
    /// 查询系统墙钟时间（NT epoch 1601 起的 100ns）
    /// args: [0, 0, 0, 0, 0, 0] → system_time_100ns
    pub const QUERY_SYSTEM_TIME: u64 = 0x0819;
    /// 枚举目录下一项（按 host 端游标）
    /// args: [host_fd, dst_gpa, dst_len, restart(0/1), 0, 0]
    /// 返回:
    ///   - 0: no more files
    ///   - u64::MAX: invalid / not a directory
    ///   - 其他: bit63=is_dir, low32=name_len
    pub const HOST_READDIR: u64 = 0x081A;
    /// 目录变更通知（非阻塞）
    /// args: [host_fd, dst_gpa, dst_len, watch_tree(0/1), completion_filter, 0]
    /// 返回:
    ///   - 0: no change
    ///   - u64::MAX: invalid / not a directory
    ///   - 其他: bits[39:32]=action, low32=name_len
    pub const HOST_NOTIFY_DIR: u64 = 0x081B;
    /// 以固定字节填充 guest 物理内存区间
    /// args: [dst_gpa, len, value(u8), 0, 0, 0]
    /// 返回: 0=ok, u64::MAX=invalid
    pub const HOST_MEMSET: u64 = 0x081C;
    /// guest 物理内存区间复制
    /// args: [dst_gpa, src_gpa, len, 0, 0, 0]
    /// 返回: 0=ok, u64::MAX=invalid
    pub const HOST_MEMCPY: u64 = 0x081D;

    // ── HostCall IPC: 0x0820 - 0x082F ──────────────────────
    /// HostCall 通道初始化（预留）
    pub const HOSTCALL_SETUP: u64 = 0x0820;
    /// 统一 HostCall 提交入口
    /// args: [opcode, flags, arg0, arg1, arg2, arg3]
    /// returns: x0=host_result, x1=aux(request_id or opcode-defined value)
    pub const HOSTCALL_SUBMIT: u64 = 0x0821;
    /// 取消异步请求
    /// args: [request_id, 0, 0, 0, 0, 0]
    /// returns: host_result
    pub const HOSTCALL_CANCEL: u64 = 0x0822;
    /// 拉取一个 completion
    /// args: [dst_gpa, dst_cap, 0, 0, 0, 0]
    /// returns: 写入条目数（0/1）
    pub const HOSTCALL_POLL: u64 = 0x0823;
    /// 批量拉取 completion
    /// args: [dst_gpa, dst_cap_entries, 0, 0, 0, 0]
    /// returns: 写入条目数
    pub const HOSTCALL_POLL_BATCH: u64 = 0x0824;
    /// 查询 hostcall 统计快照
    /// args: [dst_gpa, dst_len, flags(bit0=reset_after_read), 0, 0, 0]
    /// returns: 实际写入字节数
    pub const HOSTCALL_QUERY_STATS: u64 = 0x0825;
    /// 查询 VMM 调度唤醒统计快照
    /// args: [dst_gpa, dst_len, flags(bit0=reset_after_read), 0, 0, 0]
    /// returns: 实际写入字节数
    pub const HOSTCALL_QUERY_SCHED_WAKE_STATS: u64 = 0x0826;
}

pub mod hostcall {
    // Submit flags
    pub const FLAG_ALLOW_ASYNC: u64 = 1 << 0;
    pub const FLAG_FORCE_ASYNC: u64 = 1 << 1;
    pub const FLAG_EXT_BUF: u64 = 1 << 2;
    pub const FLAG_MAIN_THREAD: u64 = 1 << 3;

    // Submit return sentinel
    pub const PENDING_RESULT: u64 = 0xFFFF_FFFF_FFFF_FFFEu64;

    // HostCall result codes (host-domain, non-NT)
    pub const HC_OK: u64 = 0;
    pub const HC_INVALID: u64 = 1;
    pub const HC_BUSY: u64 = 2;
    pub const HC_NO_MEMORY: u64 = 3;
    pub const HC_CANCELED: u64 = 4;
    pub const HC_IO_ERROR: u64 = 5;

    // Opcodes
    pub const OP_OPEN: u64 = 1;
    pub const OP_READ: u64 = 2;
    pub const OP_WRITE: u64 = 3;
    pub const OP_CLOSE: u64 = 4;
    pub const OP_STAT: u64 = 5;
    pub const OP_READDIR: u64 = 6;
    pub const OP_NOTIFY_DIR: u64 = 7;
    pub const OP_MMAP: u64 = 8;
    pub const OP_MUNMAP: u64 = 9;
    pub const OP_WIN32K_CALL: u64 = 10;

    pub const WIN32K_CALL_PACKET_VERSION: u32 = 1;
    pub const WIN32K_CALL_MAX_ARGS: usize = 16;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Win32kCallPacket {
        pub version: u32,
        pub table: u32,
        pub syscall_nr: u32,
        pub arg_count: u32,
        pub owner_pid: u32,
        pub owner_tid: u32,
        pub reserved0: u32,
        pub reserved1: u32,
        pub args: [u64; WIN32K_CALL_MAX_ARGS],
    }

    impl Win32kCallPacket {
        pub const fn new() -> Self {
            Self {
                version: WIN32K_CALL_PACKET_VERSION,
                table: 0,
                syscall_nr: 0,
                arg_count: 0,
                owner_pid: 0,
                owner_tid: 0,
                reserved0: 0,
                reserved1: 0,
                args: [0; WIN32K_CALL_MAX_ARGS],
            }
        }
    }

    pub const WIN32K_CALL_PACKET_SIZE: usize = core::mem::size_of::<Win32kCallPacket>();

    // HostCallCpl binary layout size (u64 + i32 + u32 + u64 + u64 + u64)
    pub const CPL_SIZE: usize = 40;
    pub const CPLF_MAIN_THREAD: u32 = 1 << 0;
    pub const CPLF_CANCELED: u32 = 1 << 1;
    pub const STATS_RESET_AFTER_READ: u64 = 1 << 0;
    pub const STATS_VERSION: u64 = 1;
    pub const STATS_HEADER_SIZE: usize = 9 * core::mem::size_of::<u64>();
    pub const STATS_OP_SIZE: usize = 7 * core::mem::size_of::<u64>();
    pub const SCHED_WAKE_STATS_VERSION: u64 = 1;
    pub const SCHED_WAKE_STATS_SIZE: usize = 11 * core::mem::size_of::<u64>();

    // EXT_BUF payload layout for HOSTCALL_SUBMIT:
    // [u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 user_tag]
    pub const EXT_SUBMIT_WORDS: usize = 5;
    pub const EXT_SUBMIT_SIZE: usize = EXT_SUBMIT_WORDS * core::mem::size_of::<u64>();
}

/// NT 超时常量（100ns 单位）
pub mod timeout {
    pub const INFINITE: i64 = i64::MIN;
    pub const NOW: i64 = 0;
}

/// NT 状态码（hypercall 返回值高 32 位）
pub mod status {
    pub const SUCCESS: u32 = 0x0000_0000;
    pub const WAIT_0: u32 = 0x0000_0000;
    pub const TIMEOUT: u32 = 0x0000_0102;
    pub const ABANDONED_WAIT_0: u32 = 0x0000_0080;
    pub const OBJECT_NOT_FOUND: u32 = 0xC000_0034;
    pub const OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
    pub const OBJECT_NAME_EXISTS: u32 = 0x4000_0000;
    pub const ACCESS_DENIED: u32 = 0xC000_0022;
    pub const INVALID_HANDLE: u32 = 0xC000_0008;
    pub const END_OF_FILE: u32 = 0xC000_011B;
    pub const INVALID_PARAMETER: u32 = 0xC000_000D;
    pub const NOT_COMMITTED: u32 = 0xC000_0021;
    pub const MUTANT_NOT_OWNED: u32 = 0xC000_0046;
    pub const SEMAPHORE_LIMIT_EXCEEDED: u32 = 0xC000_0047;
    pub const NO_MEMORY: u32 = 0xC000_0017;
    pub const INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
    pub const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    pub const NO_MORE_ENTRIES: u32 = 0x8000_001A;
    pub const BUFFER_TOO_SMALL: u32 = 0xC000_0023;
    pub const NO_MORE_FILES: u32 = 0x8000_0006;
    pub const THREAD_IS_TERMINATING: u32 = 0xC000_004B;
    pub const CANCELLED: u32 = 0xC000_0120;
    pub const NOT_IMPLEMENTED: u32 = 0xC000_0002;
    pub const STILL_ACTIVE: u32 = 0x0000_0103; // STATUS_PENDING — thread still running
    pub const ALERTED: u32 = 0x0000_0101;
}

/// NT TEB 字段偏移（64-bit，参考 Wine winternl.h + signal_arm64.c）
pub mod teb {
    pub const EXCEPTION_LIST: usize = 0x0000;
    pub const STACK_BASE: usize = 0x0008;
    pub const STACK_LIMIT: usize = 0x0010;
    pub const SUBSYSTEM_TIB: usize = 0x0018;
    pub const FIBER_DATA: usize = 0x0020;
    pub const ARBITRARY_USER: usize = 0x0028;
    pub const SELF: usize = 0x0030;
    pub const ENV_POINTER: usize = 0x0038;
    pub const CLIENT_ID: usize = 0x0040; // [pid(8), tid(8)]
    pub const ACTIVE_RPC: usize = 0x0050;
    pub const TLS_POINTER: usize = 0x0058;
    pub const PEB: usize = 0x0060;
    pub const SYSCALL_FRAME: usize = 0x02f0; // Wine ARM64 private
    pub const SYSCALL_TABLE: usize = 0x02f8;
    pub const SIZE: usize = 0x1000;
}

/// NT PEB 字段偏移（64-bit）
pub mod peb {
    pub const IMAGE_BASE_ADDRESS: usize = 0x0010;
    pub const LDR: usize = 0x0018;
    pub const PROCESS_PARAMETERS: usize = 0x0020;
    pub const PROCESS_HEAP: usize = 0x0030;
    pub const OS_MAJOR_VERSION: usize = 0x0118;
    pub const OS_MINOR_VERSION: usize = 0x011c;
    pub const OS_BUILD_NUMBER: usize = 0x0120;
    pub const OS_PLATFORM_ID: usize = 0x0124;
    pub const IMAGE_SUBSYSTEM: usize = 0x012c;
    pub const SIZE: usize = 0x1000;
}

/// PE OptionalHeader64 字段偏移（相对于 OptionalHeader 起始）
pub mod pe_opt {
    pub const MAGIC: usize = 0;
    pub const ENTRY_POINT: usize = 16;
    pub const IMAGE_BASE: usize = 24;
    pub const SECTION_ALIGNMENT: usize = 32;
    pub const SIZE_OF_IMAGE: usize = 56;
    pub const SIZE_OF_HEADERS: usize = 60;
    pub const STACK_RESERVE: usize = 72;
    pub const STACK_COMMIT: usize = 80;
    pub const NUM_DIRS: usize = 92;
    pub const DIRS: usize = 96;
}
