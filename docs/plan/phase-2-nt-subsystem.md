# Phase 2 — NT 子系统 + Wine DLL 集成 (第 9-16 周)

## 目标

在 Guest 内加载并运行一个简单的 Windows PE 控制台程序（Hello World）。

---

## P2-1: PE 加载器 (第 9-10 周)

在 Guest Kernel 内实现 PE32+ 加载器。

### 解析流程

```
MZ Header → PE Signature → COFF Header → Optional Header → Section Headers
```

### 核心结构

```rust
// winemu-kernel/src/ldr/pe.rs

pub struct PeImage {
    pub base: Gva,
    pub size: usize,
    pub entry_point: Gva,
    pub exports: ExportTable,
    pub imports: Vec<ImportDescriptor>,
}

pub fn load(data: &[u8], preferred_base: Option<Gva>) -> Result<PeImage> {
    let dos = parse_dos_header(data)?;
    let pe = parse_pe_header(data, dos.e_lfanew as usize)?;
    let opt = parse_optional_header(data, &pe)?;

    let base = preferred_base.unwrap_or(Gva(opt.image_base));
    let base = if is_address_free(base, opt.size_of_image as usize) {
        base
    } else {
        // ASLR: 随机选择基地址
        aslr_alloc(opt.size_of_image as usize)?
    };

    map_sections(data, &pe, base)?;
    apply_relocations(base, &opt)?;
    resolve_imports(base, &opt)?;

    Ok(PeImage {
        base,
        size: opt.size_of_image as usize,
        entry_point: Gva(base.0 + opt.address_of_entry_point as u64),
        exports: parse_exports(base, &opt)?,
        imports: vec![],
    })
}
```

### 重定位处理

```rust
fn apply_relocations(base: Gva, opt: &OptionalHeader) -> Result<()> {
    let delta = base.0.wrapping_sub(opt.image_base);
    if delta == 0 { return Ok(()); }

    let reloc_dir = &opt.data_directories[5]; // IMAGE_DIRECTORY_ENTRY_BASERELOC
    // 遍历 reloc block，处理 IMAGE_REL_BASED_DIR64 (type=10)
    for block in reloc_blocks(base, reloc_dir) {
        for entry in block.entries {
            if entry.type_ == 10 {
                let addr = Gva(base.0 + block.virtual_address as u64
                               + entry.offset as u64);
                let val = read_u64(addr);
                write_u64(addr, val.wrapping_add(delta));
            }
        }
    }
    Ok(())
}
```

### 导入表解析

```rust
fn resolve_imports(base: Gva, opt: &OptionalHeader) -> Result<()> {
    let import_dir = &opt.data_directories[1];
    for desc in import_descriptors(base, import_dir) {
        // 通过 hypercall 从 Host 读取 DLL 文件
        let dll_data = hypercall::load_dll(&desc.name)?;
        let dll = load(&dll_data, None)?;

        // 填充 IAT
        for thunk in iat_thunks(base, &desc) {
            let proc_addr = dll.exports.find(&thunk.name)?;
            write_u64(thunk.iat_entry, proc_addr.0);
        }
    }
    Ok(())
}
```

### DLL 搜索路径（通过 hypercall）

```
1. 应用程序目录
2. %WINDIR%\system32  → Host Wine DLL 目录
3. %WINDIR%           → 同上
4. PATH 目录
```

### P2-1 验收

- [ ] 能加载静态链接的 PE32+ 二进制（无导入表）
- [ ] 重定位正确（ASLR 基地址下运行）
- [ ] 能解析并填充 IAT（依赖 ntdll.dll）

---

## P2-2: NT 对象管理器 (第 10-11 周)

### 核心结构

```rust
// winemu-kernel/src/ob/mod.rs

pub struct ObjectManager {
    handle_tables: BTreeMap<ProcessId, HandleTable>,
    named_objects: BTreeMap<String, Arc<dyn KernelObject>>,
    next_handle: AtomicU64,
}

pub trait KernelObject: Send + Sync {
    fn object_type(&self) -> ObjectType;
    fn ref_count(&self) -> u32;
    fn close(&self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Process, Thread, Event, Mutex, Semaphore,
    Section, File, Directory, Token, Timer,
}
```

### 句柄表

```rust
// winemu-kernel/src/ob/handle_table.rs

pub struct HandleTable {
    entries: Vec<Option<HandleEntry>>,
}

pub struct HandleEntry {
    pub object: Arc<dyn KernelObject>,
    pub access: u32,
    pub inherit: bool,
}

impl HandleTable {
    pub fn insert(&mut self, obj: Arc<dyn KernelObject>,
                  access: u32, inherit: bool) -> Handle {
        // 找第一个空槽，句柄值 = index * 4 + 4（Windows 句柄对齐到 4）
        let idx = self.entries.iter().position(|e| e.is_none())
            .unwrap_or_else(|| { self.entries.push(None); self.entries.len() - 1 });
        self.entries[idx] = Some(HandleEntry { object: obj, access, inherit });
        Handle((idx as u64 + 1) * 4)
    }

    pub fn get(&self, handle: Handle) -> Option<&HandleEntry> {
        let idx = (handle.0 / 4) as usize - 1;
        self.entries.get(idx)?.as_ref()
    }

    pub fn remove(&mut self, handle: Handle) -> Option<HandleEntry> {
        let idx = (handle.0 / 4) as usize - 1;
        self.entries.get_mut(idx)?.take()
    }
}
```

### 实现的对象类型

```rust
// winemu-kernel/src/ob/objects.rs

pub struct EventObject {
    pub manual_reset: bool,
    pub signaled: AtomicBool,
    pub waiters: Mutex<Vec<ThreadId>>,
}

pub struct MutexObject {
    pub owner: AtomicU64,   // ThreadId，0 表示未持有
    pub recursion: AtomicU32,
    pub waiters: Mutex<Vec<ThreadId>>,
}

pub struct SemaphoreObject {
    pub count: AtomicI32,
    pub max_count: i32,
    pub waiters: Mutex<Vec<ThreadId>>,
}

pub struct SectionObject {
    pub size: u64,
    pub prot: MemProt,
    pub backing: SectionBacking,
}

pub enum SectionBacking {
    Anonymous(Vec<u8>),
    File(Arc<FileObject>),
}
```

### P2-2 验收

- [ ] `NtCreateEvent` / `NtSetEvent` / `NtResetEvent` 正确
- [ ] `NtCreateMutex` / `NtReleaseMutex` 正确
- [ ] 句柄继承（`DuplicateHandle`）正确
- [ ] 引用计数：最后一个句柄关闭后对象销毁

---

## P2-3: 进程与线程管理 (第 11-12 周)

### 进程结构

```rust
// winemu-kernel/src/ps/process.rs

pub struct Process {
    pub pid: ProcessId,
    pub parent_pid: ProcessId,
    pub address_space: AddressSpace,
    pub handle_table: HandleTable,
    pub peb_gva: Gva,
    pub threads: Vec<Arc<Thread>>,
    pub exit_code: AtomicI32,
    pub state: AtomicU8, // Running / Terminating / Terminated
}

#[repr(C)]
pub struct Peb {
    pub image_base: u64,
    pub ldr: u64,           // PEB_LDR_DATA
    pub process_params: u64, // RTL_USER_PROCESS_PARAMETERS
    pub tls_bitmap: u64,
    pub number_of_processors: u32,
    pub nt_global_flag: u32,
}
```

### 线程结构

```rust
// winemu-kernel/src/ps/thread.rs

pub struct Thread {
    pub tid: ThreadId,
    pub pid: ProcessId,
    pub priority: u8,           // 0-31
    pub state: ThreadState,
    pub context: ThreadContext, // 保存的寄存器
    pub teb_gva: Gva,
    pub stack_base: Gva,
    pub stack_limit: Gva,
    pub wait_reason: Option<WaitReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Waiting,
    Terminated,
}

#[repr(C)]
pub struct Teb {
    pub exception_list: u64,    // SEH chain
    pub stack_base: u64,
    pub stack_limit: u64,
    pub tls_slots: [u64; 64],
    pub peb: u64,
    pub thread_id: u32,
    pub process_id: u32,
    pub last_error: u32,
    pub _pad: u32,
}
```

### N:M 调度器

```rust
// winemu-kernel/src/ps/scheduler.rs

pub struct Scheduler {
    // 32 级优先级队列，每级一个 FIFO
    ready_queues: [VecDeque<Arc<Thread>>; 32],
    // 当前各 vCPU 上运行的线程
    running: [Option<Arc<Thread>>; MAX_VCPUS],
}

impl Scheduler {
    pub fn pick_next(&mut self, vcpu_id: usize) -> Option<Arc<Thread>> {
        // 从最高优先级开始找
        for q in self.ready_queues.iter_mut().rev() {
            if let Some(t) = q.pop_front() {
                return Some(t);
            }
        }
        None
    }

    pub fn enqueue(&mut self, thread: Arc<Thread>) {
        let prio = thread.priority as usize;
        self.ready_queues[prio].push_back(thread);
    }

    pub fn block_current(&mut self, vcpu_id: usize, reason: WaitReason) {
        if let Some(t) = self.running[vcpu_id].take() {
            t.set_state(ThreadState::Waiting);
            t.set_wait_reason(reason);
        }
        // 切换到下一个就绪线程
        if let Some(next) = self.pick_next(vcpu_id) {
            self.switch_to(vcpu_id, next);
        }
    }
}
```

### 抢占定时器

Host 每 15ms 向 vCPU 注入虚拟定时器中断，触发 Guest 调度器抢占：

```rust
// crates/winemu-vmm/src/preempt_timer.rs

pub fn start_preempt_timer(vm: Arc<dyn Vm>, vcpu_ids: Vec<u32>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(15));
            for &id in &vcpu_ids {
                // 注入虚拟定时器中断
                vm.inject_irq(id, VIRTUAL_TIMER_IRQ).ok();
            }
        }
    });
}
```

### 进程创建流程

```
1. Host hypercall: HC_NT_CREATE_PROCESS (传入 EXE 路径)
2. Guest Kernel: 分配 Process 结构，创建地址空间
3. PE 加载器: 加载 EXE + 依赖 DLL
4. 创建主线程: 分配栈 (1MB)，初始化 TEB/PEB
5. 设置初始寄存器: PC = entry_point, SP = stack_top
6. 将主线程加入就绪队列 (优先级 8)
7. 调度器选择空闲 vCPU 执行
```

### P2-3 验收

- [ ] `NtCreateProcess` / `NtTerminateProcess` 正确
- [ ] `NtCreateThread` / `NtTerminateThread` 正确
- [ ] 调度器能在多个线程间切换
- [ ] 抢占定时器触发上下文切换
- [ ] TEB/PEB 结构正确初始化

---

## P2-4: NT Syscall 分发层 (第 12-13 周)

NT syscall 使用真实 Windows 系统调用号，Guest Kernel 在 EL1（ARM64）或 Ring 0（x86）拦截 `SVC`/`SYSCALL` 指令并分发。ntdll.dll PE 层**无需任何修改**，直接复用 Wine 的 ntdll PE 二进制。

### 架构说明

```
Windows App
    │ 调用 NtCreateFile (通过 ntdll.dll PE 层)
    ▼
ntdll.dll (Wine PE，不修改)
    │ SVC #0 / x8 = 0x0055 (NT_CREATE_FILE，真实 Windows 调用号)
    ▼
Guest Kernel EL1 — SVC 向量
    │ 按调用号分发
    ▼
winemu-kernel::syscall::nt_create_file()
    │ 在 Guest 内处理（内存管理、对象管理等）
    │ 需要 Host 资源时（文件 I/O）→ 异步 hypercall
    ▼
Host VMM（仅 I/O 类操作）
```

### ARM64 SVC 向量安装

```rust
// winemu-kernel/src/syscall/mod.rs

static SYSCALL_TABLE: OnceCell<SyscallTable> = OnceCell::new();

pub fn init() {
    // 1. 通过 hypercall 从 Host 读取调用号表 TOML
    let toml_len = hypercall(nr::LOAD_SYSCALL_TABLE, 0, 0, 0);
    let mut buf = vec![0u8; toml_len as usize];
    hypercall(nr::LOAD_SYSCALL_TABLE, buf.as_mut_ptr() as u64,
              toml_len, 1 /* read */);

    // 2. 解析并存入全局表
    let toml_str = core::str::from_utf8(&buf).expect("invalid syscall table");
    let table = SyscallTable::load_from_toml(toml_str)
        .expect("failed to parse syscall table");
    SYSCALL_TABLE.set(table).ok();

    // 3. 安装 SVC/SYSCALL 异常向量
    install_exception_vectors();
}

pub fn dispatch(nr: u32, args: &[u64; 8]) -> u32 {
    let id = SYSCALL_TABLE.get().unwrap().lookup(nr);
    handlers::dispatch(id, args)
}
```

```asm
// winemu-kernel/src/arch/arm64/vectors.S
.align 11
.global exception_vector_table
exception_vector_table:
    // Current EL with SP0
    .align 7; b unexpected_exception   // Synchronous
    .align 7; b unexpected_exception   // IRQ
    .align 7; b unexpected_exception   // FIQ
    .align 7; b unexpected_exception   // SError

    // Current EL with SPx (kernel mode)
    .align 7; b handle_sync_el1        // Synchronous (timer, etc.)
    .align 7; b handle_irq_el1         // IRQ
    .align 7; b unexpected_exception   // FIQ
    .align 7; b unexpected_exception   // SError

    // Lower EL AArch64 (user mode — Windows apps)
    .align 7; b handle_sync_el0        // Synchronous (SVC = syscall)
    .align 7; b handle_irq_el0         // IRQ
    .align 7; b unexpected_exception   // FIQ
    .align 7; b unexpected_exception   // SError

    // Lower EL AArch32 (不支持)
    .align 7; b unexpected_exception
    .align 7; b unexpected_exception
    .align 7; b unexpected_exception
    .align 7; b unexpected_exception
```

### SVC 处理入口

```asm
// winemu-kernel/src/arch/arm64/vectors.S
handle_sync_el0:
    // 保存用户寄存器
    stp x0,  x1,  [sp, #-16]!
    stp x2,  x3,  [sp, #-16]!
    stp x4,  x5,  [sp, #-16]!
    stp x6,  x7,  [sp, #-16]!
    stp x8,  x30, [sp, #-16]!

    // 读取 ESR_EL1 判断异常类型
    mrs x9, esr_el1
    lsr x10, x9, #26        // EC field
    cmp x10, #0x15          // EC=0x15: SVC from AArch64
    b.eq do_syscall
    // 其他异常（Data Abort 等）→ 异常分发
    b handle_exception_el0

do_syscall:
    // x8 = syscall number (Windows convention)
    // x0-x7 = arguments
    bl syscall_dispatch
    // 恢复寄存器，返回用户态
    ldp x8,  x30, [sp], #16
    ldp x6,  x7,  [sp], #16
    ldp x4,  x5,  [sp], #16
    ldp x2,  x3,  [sp], #16
    ldp x0,  x1,  [sp], #16  // x0 = NTSTATUS return
    eret
```

### Syscall 分发表

```rust
// winemu-kernel/src/syscall/dispatch.rs
use winemu_core::syscall::nt;

#[no_mangle]
pub extern "C" fn syscall_dispatch(
    nr: u32,
    a0: u64, a1: u64, a2: u64, a3: u64,
    a4: u64, a5: u64, a6: u64, a7: u64,
) -> u32 {
    match nr {
        // 文件 I/O
        nt::NT_CREATE_FILE            => io::nt_create_file(a0, a1, a2, a3, a4, a5, a6),
        nt::NT_OPEN_FILE              => io::nt_open_file(a0, a1, a2, a3, a4),
        nt::NT_READ_FILE              => io::nt_read_file(a0, a1, a2, a3, a4, a5, a6),
        nt::NT_WRITE_FILE             => io::nt_write_file(a0, a1, a2, a3, a4, a5, a6),
        nt::NT_CLOSE                  => ob::nt_close(a0),
        nt::NT_QUERY_INFORMATION_FILE => io::nt_query_information_file(a0, a1, a2, a3, a4),
        nt::NT_QUERY_DIRECTORY_FILE   => io::nt_query_directory_file(a0, a1, a2, a3, a4, a5, a6, a7),

        // 虚拟内存
        nt::NT_ALLOCATE_VIRTUAL_MEMORY => mm::nt_allocate_virtual_memory(a0, a1, a2, a3, a4, a5),
        nt::NT_FREE_VIRTUAL_MEMORY     => mm::nt_free_virtual_memory(a0, a1, a2, a3),
        nt::NT_PROTECT_VIRTUAL_MEMORY  => mm::nt_protect_virtual_memory(a0, a1, a2, a3, a4),
        nt::NT_MAP_VIEW_OF_SECTION     => mm::nt_map_view_of_section(a0, a1, a2, a3, a4, a5, a6, a7),
        nt::NT_UNMAP_VIEW_OF_SECTION   => mm::nt_unmap_view_of_section(a0, a1),

        // 进程/线程
        nt::NT_CREATE_PROCESS_EX      => ps::nt_create_process_ex(a0, a1, a2, a3, a4, a5, a6, a7),
        nt::NT_CREATE_THREAD_EX       => ps::nt_create_thread_ex(a0, a1, a2, a3, a4, a5, a6, a7),
        nt::NT_TERMINATE_PROCESS      => ps::nt_terminate_process(a0, a1),
        nt::NT_TERMINATE_THREAD       => ps::nt_terminate_thread(a0, a1),

        // 同步
        nt::NT_WAIT_FOR_SINGLE_OBJECT  => ex::nt_wait_for_single_object(a0, a1, a2),
        nt::NT_WAIT_FOR_MULTIPLE_OBJECTS => ex::nt_wait_for_multiple_objects(a0, a1, a2, a3, a4),
        nt::NT_CREATE_EVENT            => ob::nt_create_event(a0, a1, a2, a3, a4),
        nt::NT_SET_EVENT               => ob::nt_set_event(a0, a1),
        nt::NT_RESET_EVENT             => ob::nt_reset_event(a0, a1),
        nt::NT_CREATE_MUTEX            => ob::nt_create_mutex(a0, a1, a2, a3),
        nt::NT_RELEASE_MUTEX           => ob::nt_release_mutex(a0, a1),

        // 注册表
        nt::NT_OPEN_KEY               => reg::nt_open_key(a0, a1, a2),
        nt::NT_CREATE_KEY             => reg::nt_create_key(a0, a1, a2, a3, a4, a5, a6),
        nt::NT_QUERY_VALUE_KEY        => reg::nt_query_value_key(a0, a1, a2, a3, a4),
        nt::NT_SET_VALUE_KEY          => reg::nt_set_value_key(a0, a1, a2, a3, a4),

        // win32k (图形，0x1000+)
        nr if nr >= 0x1000            => win32k::dispatch(nr, a0, a1, a2, a3, a4, a5, a6, a7),

        _ => {
            log::warn!("unimplemented syscall {:#06x}", nr);
            NtStatus::NotImplemented as u32
        }
    }
}
```

### win32k 分发（图形 syscall）

win32u.dll 发出的 win32k syscall（0x1000+）由 Guest Kernel 拦截后，通过 **hypercall** 转发到 Host 原生窗口系统：

```rust
// winemu-kernel/src/syscall/win32k.rs

pub fn dispatch(nr: u32, a0: u64, a1: u64, a2: u64, a3: u64,
                a4: u64, a5: u64, a6: u64, a7: u64) -> u32 {
    use winemu_core::hypercall::nr as hc;
    match nr {
        nt::NT_USER_CREATE_WINDOW_EX => hypercall(hc::WIN32U_CREATE_WINDOW, a0, a1, a2) as u32,
        nt::NT_USER_SHOW_WINDOW      => hypercall(hc::WIN32U_SHOW_WINDOW, a0, a1, 0) as u32,
        nt::NT_USER_MESSAGE_CALL     => hypercall(hc::WIN32U_MSG_CALL, a0, a1, a2) as u32,
        nt::NT_GDI_CREATE_DC         => hypercall(hc::WIN32U_GDI_BITBLT, a0, a1, a2) as u32,
        _ => NtStatus::NotImplemented as u32,
    }
}
```

### P2-4 验收

- [ ] SVC 向量表正确安装，用户态 `SVC #0` 进入 `syscall_dispatch`
- [ ] 未修改的 Wine ntdll.dll PE 能正常发出 syscall 并被拦截
- [ ] `NtCreateFile` / `NtReadFile` / `NtWriteFile` / `NtClose` 分发正确
- [ ] win32k syscall（0x1000+）正确转发到 hypercall

---

## P2-5: 同步原语 (第 13-14 周)

### Guest 内快速路径（无 hypercall）

```rust
// winemu-kernel/src/ex/sync.rs

// 无竞争 Mutex：用 guest 内存原子变量
pub struct FastMutex {
    owner: AtomicU64,   // 0 = free, else ThreadId
}

impl FastMutex {
    pub fn try_lock(&self, tid: ThreadId) -> bool {
        self.owner.compare_exchange(0, tid.0,
            Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    pub fn unlock(&self) {
        self.owner.store(0, Ordering::Release);
        // 如有等待者，唤醒（通过调度器）
    }
}

// Event：ARM64 WFE/SEV
pub struct FastEvent {
    signaled: AtomicBool,
}

impl FastEvent {
    pub fn wait(&self) {
        while !self.signaled.load(Ordering::Acquire) {
            unsafe { core::arch::asm!("wfe") };
        }
    }

    pub fn signal(&self) {
        self.signaled.store(true, Ordering::Release);
        unsafe { core::arch::asm!("sev") };
    }
}
```

### 跨进程 / 超时路径（需要 hypercall）

```rust
// winemu-kernel/src/ex/wait.rs

pub fn nt_wait_for_single_object(
    handle: Handle,
    alertable: bool,
    timeout: Option<i64>,  // 100ns 单位，负数=相对时间
) -> NtStatus {
    let obj = ob::get_object(handle)?;

    // 先尝试快速路径
    if obj.try_satisfy() {
        return NtStatus::Success;
    }

    // 需要阻塞：切换线程，通过 hypercall 让 Host 等待
    ps::block_current_thread(WaitReason::Object(handle));
    let ret = hypercall::wait_single(handle.0, alertable as u64,
                                      timeout.unwrap_or(i64::MIN) as u64);
    NtStatus::from(ret as u32)
}
```

### Host 侧等待实现

```rust
// crates/winemu-vmm/src/hypercall/sync.rs

pub async fn handle_wait_single(
    handle: u64,
    timeout_100ns: i64,
    completion_tx: oneshot::Sender<u64>,
) {
    let duration = if timeout_100ns < 0 {
        Duration::from_nanos((-timeout_100ns) as u64 * 100)
    } else {
        Duration::MAX
    };

    let result = tokio::time::timeout(duration, async {
        // 等待对应的 Host 对象就绪
        wait_host_object(handle).await
    }).await;

    let status = match result {
        Ok(_) => NtStatus::Success as u64,
        Err(_) => NtStatus::Timeout as u64,
    };
    completion_tx.send(status).ok();
    // 完成后通过虚拟中断唤醒 Guest 线程
}
```

### P2-5 验收

- [ ] 无竞争 Mutex 不触发 hypercall
- [ ] `NtWaitForSingleObject` 超时正确返回 `STATUS_TIMEOUT`
- [ ] 多线程等待同一 Event，`NtSetEvent` 后全部唤醒（Manual Reset）

---

## P2-6: 基础文件 I/O (第 14-15 周)

### 实现的 NT API

| API | Hypercall 编号 | 说明 |
|-----|--------------|------|
| `NtCreateFile` | 0x0100 | 创建/打开文件 |
| `NtOpenFile` | 0x0101 | 打开已有文件 |
| `NtReadFile` | 0x0102 | 读文件（异步） |
| `NtWriteFile` | 0x0103 | 写文件（异步） |
| `NtClose` | 0x0104 | 关闭句柄 |
| `NtQueryInformationFile` | 0x0105 | 查询文件信息 |
| `NtQueryDirectoryFile` | 0x0106 | 枚举目录 |
| `NtSetInformationFile` | 0x0107 | 设置文件信息 |

### 异步 I/O 流程

```
Guest: NtReadFile(handle, buf, len, &iosb)
  │
  ▼ hypercall (异步)
Guest Kernel: 当前线程 → Waiting，切换到其他线程
  │
  ▼
Host: tokio::fs::read → 完成
  │
  ▼
Host: 将结果写入 Guest IOSB，注入虚拟中断
  │
  ▼
Guest Kernel: 线程 → Ready，返回 STATUS_SUCCESS
```

### Host 侧实现

```rust
// crates/winemu-vmm/src/hypercall/nt_file.rs

pub async fn handle_nt_read_file(
    guest_mem: Arc<GuestMemory>,
    args: [u64; 6],
    irq_injector: Arc<IrqInjector>,
) {
    let params = guest_mem.read_struct::<NtReadFileParams>(Gpa(args[0]));
    let host_fd = handle_table::get_host_fd(params.file_handle);

    let mut buf = vec![0u8; params.length as usize];
    match tokio::fs::read_at(host_fd, &mut buf, params.byte_offset).await {
        Ok(n) => {
            guest_mem.write_bytes(Gpa(params.buffer), &buf[..n]);
            guest_mem.write_struct(Gpa(params.io_status_block), IoStatusBlock {
                status: NtStatus::Success as u32,
                information: n as u64,
            });
        }
        Err(e) => {
            guest_mem.write_struct(Gpa(params.io_status_block), IoStatusBlock {
                status: io_error_to_nt_status(&e) as u32,
                information: 0,
            });
        }
    }
    // 唤醒等待的 Guest 线程
    irq_injector.inject(IO_COMPLETION_IRQ);
}
```

### P2-6 验收

- [ ] 能读写 Host 文件系统上的文件
- [ ] 路径转换正确（`C:\Windows\System32\` → Wine prefix）
- [ ] 异步 I/O 不阻塞 vCPU
- [ ] `NtQueryDirectoryFile` 能枚举目录

---

## P2-7: Hello World 验收 (第 15-16 周)

### 验收程序

```c
// test/hello.c (用 mingw-w64 编译为 ARM64 Windows PE)
#include <windows.h>

int main(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    WriteFile(h, "Hello from WinEmu!\n", 19, &written, NULL);
    return 0;
}
```

编译：
```bash
aarch64-w64-mingw32-gcc -o hello.exe test/hello.c
```

### 运行

```bash
cargo run --bin winemu -- run hello.exe
# 期望输出: Hello from WinEmu!
# 期望退出码: 0
```

### 验收标准

- [ ] `winemu run hello.exe` 输出 "Hello from WinEmu!"
- [ ] 进程正常退出，返回码 0
- [ ] 无内存错误（AddressSanitizer 检查）
- [ ] `cargo test --workspace` 全绿

