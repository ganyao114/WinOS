# Phase 4 — 兼容性提升 + 跨架构 DBT (持续)

## 目标

提升 Wine 测试套件通过率，实现跨架构运行（ARM64 Host 运行 x86_64 Windows 程序），探索 iOS 移植路径。

---

## P4-1: 兼容性提升

### 测试驱动流程

```bash
# 运行 Wine 测试套件
winemu run winetest.exe -q > winetest_results.txt

# 分析失败项
grep "FAIL" winetest_results.txt | sort | uniq -c | sort -rn
```

### 优先补全的 NT API

按 winetest 失败频率排序：

**注册表**

注册表 API 通过真实 Windows syscall 号进入 Guest Kernel，在 Guest 内处理后通过异步 hypercall 代理到 Host Wine 注册表文件：

```rust
// winemu-kernel/src/syscall/registry.rs

pub fn nt_open_key(handle_out: u64, access: u32, obj_attr: u64) -> u32 {
    let key_path = ob::read_unicode_string(Gva(obj_attr));
    // 通过 hypercall 让 Host 打开 Wine 注册表文件
    // HKLM → $WINEPREFIX/system.reg
    // HKCU → $WINEPREFIX/user.reg
    let result = hypercall::reg_open_key(&key_path, access);
    ob::insert_handle(result.handle, ObjectType::Key, access) as u32
}
```

| API | 真实 Windows syscall 号（ARM64 Win11） |
|-----|--------------------------------------|
| `NtOpenKey` | 0x0012 |
| `NtCreateKey` | 0x001D |
| `NtQueryValueKey` | 0x0016 |
| `NtSetValueKey` | 0x003D |
| `NtDeleteKey` | 0x000C |
| `NtEnumerateKey` | 0x0032 |
| `NtEnumerateValueKey` | 0x0010 |

**网络**

网络 API 同样通过真实 Windows syscall 号进入 Guest Kernel，Guest Kernel 通过异步 hypercall 代理到 Host socket：

```rust
// winemu-kernel/src/syscall/network.rs

pub fn nt_create_socket(handle_out: u64, access: u32,
                         domain: u32, sock_type: u32, protocol: u32) -> u32 {
    // hypercall 到 Host 创建真实 socket，返回 Host fd
    let host_fd = hypercall::socket(domain, sock_type, protocol);
    let sock_obj = SocketObject::new(host_fd);
    ob::insert_handle(Arc::new(sock_obj), access) as u32
}
```

| API | 说明 |
|-----|------|
| `NtCreateFile` (socket) | Winsock 通过 NtCreateFile 创建 socket |
| `NtDeviceIoControlFile` | connect / send / recv / bind 等操作 |
| `NtReadFile` / `NtWriteFile` | socket 数据收发 |

**异常处理 (SEH / VEH)**

```rust
// winemu-kernel/src/ex/exception.rs

pub fn dispatch_exception(vcpu_id: usize, exception: CpuException) {
    let thread = ps::current_thread(vcpu_id);
    let record = ExceptionRecord::from_cpu(exception);

    // 1. 尝试 VEH 处理器链
    if let Some(handler) = veh::find_handler(&record) {
        if handler.call(&record) == EXCEPTION_CONTINUE_EXECUTION {
            return;
        }
    }

    // 2. 展开 SEH 链 (TEB.ExceptionList)
    let teb = ps::get_teb(thread.tid);
    let mut seh = teb.exception_list;
    while seh != 0xFFFFFFFFFFFFFFFF {
        let frame = read_seh_frame(Gva(seh));
        match frame.handler.call(&record, &frame) {
            EXCEPTION_EXECUTE_HANDLER => {
                unwind_to_frame(&frame);
                return;
            }
            EXCEPTION_CONTINUE_SEARCH => {
                seh = frame.prev;
            }
            _ => {}
        }
    }

    // 3. 未处理异常 → 终止进程
    ps::terminate_process(thread.pid, 0xC0000005);
}
```

**COM 基础支持**

- `CoInitialize` / `CoCreateInstance` → 通过 Wine 的 `ole32.dll` PE 层处理
- 只需确保 `NtCreateFile`、注册表 API 正确，ole32 PE 层可直接复用

### 兼容性目标

| 阶段 | winetest 通过率目标 |
|------|-------------------|
| Phase 2 完成 | ~20%（仅文件 I/O、基础进程） |
| P4-1 完成 | ~60%（注册表、网络、SEH） |
| P4-1 持续 | ~80%（COM、更多 NT API） |

---

## P4-2: 性能优化

### Hypercall 批处理

对于高频小 hypercall（如 `NtQueryPerformanceCounter`），使用批处理减少 VM exit：

```rust
// winemu-kernel/src/hypercall/batch.rs

pub struct HypercallBatch {
    buf: [HypercallEntry; 64],
    count: usize,
}

pub struct HypercallEntry {
    pub nr: u64,
    pub args: [u64; 4],
    pub result_slot: u32,
}

pub fn flush_batch(batch: &HypercallBatch) {
    // 单次 hypercall 提交整个 batch
    hypercall(HC_BATCH_SUBMIT,
              batch.buf.as_ptr() as u64,
              batch.count as u64, 0);
}
```

### 共享内存替换高频 hypercall

```
替换前: NtQuerySystemTime → hypercall → VM exit → Host 读时间 → 返回
替换后: Host 每 1ms 更新共享内存中的系统时间，Guest 直接读取，无 VM exit
```

```rust
// crates/winemu-vmm/src/shared_state.rs

#[repr(C)]
pub struct SharedState {
    pub system_time: AtomicU64,      // FILETIME (100ns since 1601)
    pub tick_count: AtomicU64,       // GetTickCount64
    pub perf_counter: AtomicU64,     // QueryPerformanceCounter
    pub perf_frequency: u64,         // QueryPerformanceFrequency (固定值)
}

pub fn start_time_updater(state: Arc<SharedState>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(1));
            let now = filetime_now();
            state.system_time.store(now, Ordering::Relaxed);
            state.tick_count.store(tick_count_now(), Ordering::Relaxed);
        }
    });
}
```

### vCPU 亲和性优化

```rust
// crates/winemu-vmm/src/vcpu.rs

pub fn set_vcpu_affinity(vcpu_thread: &std::thread::JoinHandle<()>, core_id: usize) {
    #[cfg(target_os = "linux")]
    {
        use libc::{cpu_set_t, sched_setaffinity, CPU_SET};
        let mut set = unsafe { std::mem::zeroed::<cpu_set_t>() };
        unsafe { CPU_SET(core_id, &mut set) };
        unsafe { sched_setaffinity(0, std::mem::size_of::<cpu_set_t>(), &set) };
    }
    #[cfg(target_os = "macos")]
    {
        // macOS 不支持强制亲和性，使用 thread_policy_set 设置偏好
        // thread_affinity_policy_data_t
        todo!()
    }
}
```

### 性能目标

| 指标 | 目标 |
|------|------|
| Hypercall 往返延迟 | < 2μs (同步) |
| 文件读吞吐 | > 500MB/s (本地 SSD) |
| Vulkan 帧率 (triangle) | > 1000fps |
| 输入延迟 | < 5ms |

---

## P4-3: FEX 集成 (跨架构 DBT)

在 Guest VM 内集成 FEX-Emu，实现 ARM64 Host 运行 x86_64 Windows 程序。

### 架构

```
ARM64 Host
    │
    ▼
WinEmu VMM (ARM64 native)
    │
    ▼
Guest VM (ARM64 EL0/EL1)
    │
    ├── ARM64 Windows App → 直接执行（无翻译）
    │
    └── x86_64 Windows App
            │
        FEX-Emu (guest 内运行，ARM64 二进制)
            │ JIT: x86_64 → ARM64
            ▼
        ARM64 指令流 → 直接执行
```

### FEX 集成方式

FEX 在 Guest 内作为普通进程运行，其 syscall 被 Guest Kernel 拦截：

```rust
// winemu-kernel/src/ps/fex_loader.rs

pub fn load_x86_exe(exe_path: &str) -> Result<()> {
    // 1. 检测 PE 机器类型
    let machine = pe::get_machine_type(exe_path)?;
    if machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(WinemuError::UnsupportedArch);
    }

    // 2. 启动 FEX-Emu 进程，传入 x86_64 EXE 路径
    let fex_path = "/usr/bin/FEXInterpreter"; // Guest 内的 FEX 二进制
    ps::create_process(fex_path, &[exe_path])
}
```

### FEX syscall 拦截

FEX 在 Guest 内发出 Linux syscall，Guest Kernel 需要处理：

```rust
// winemu-kernel/src/ps/fex_syscall.rs

// FEX 使用 Linux syscall ABI，Guest Kernel 拦截并转换为 NT 语义
pub fn handle_fex_syscall(nr: u64, args: [u64; 6]) -> u64 {
    match nr {
        libc::SYS_mmap => handle_mmap(args),
        libc::SYS_mprotect => handle_mprotect(args),
        libc::SYS_read => handle_read(args),
        libc::SYS_write => handle_write(args),
        libc::SYS_exit_group => handle_exit(args),
        _ => {
            log::warn!("unhandled FEX syscall {}", nr);
            (-libc::ENOSYS) as u64
        }
    }
}
```

### 构建 FEX Guest 二进制

```bash
# 交叉编译 FEX 为 ARM64 Linux 静态二进制，嵌入 Guest rootfs
cmake -DCMAKE_BUILD_TYPE=Release \
      -DENABLE_STATIC=ON \
      -DCMAKE_TOOLCHAIN_FILE=aarch64-linux-gnu.cmake \
      ../FEX
make -j$(nproc) FEXInterpreter
```

### P4-3 验收

- [ ] ARM64 Host 能运行 x86_64 Hello World PE
- [ ] FEX JIT 正确翻译基础 x86_64 指令
- [ ] x86_64 Wine DLL 在 FEX 下能加载

---

## P4-4: iOS 移植路径

### 约束

| 约束 | 说明 |
|------|------|
| 无 JIT（App Store） | 不能在运行时生成可执行代码 |
| 无多进程 | 只能单进程 |
| 无 HVF | iOS 不暴露 Hypervisor.framework |
| 内存限制 | 前台 ~1.5GB，后台更少 |

### 软件 Hypervisor 后端

当无 HVF/KVM 时，降级为软件模拟：

```rust
// crates/winemu-hypervisor/src/software/mod.rs

pub struct SoftwareHypervisor;

impl Hypervisor for SoftwareHypervisor {
    fn create_vm(&self, config: VmConfig) -> Result<Box<dyn Vm>> {
        // 使用软件 CPU 模拟（类似 QEMU TCG）
        Ok(Box::new(SoftwareVm::new(config)))
    }
}

pub struct SoftwareVcpu {
    regs: Regs,
    memory: Arc<GuestMemory>,
    // 简单解释器，不做 JIT（iOS 限制）
}

impl Vcpu for SoftwareVcpu {
    fn run(&mut self) -> Result<VmExit> {
        loop {
            let insn = self.fetch_insn()?;
            match self.execute(insn)? {
                StepResult::Continue => {}
                StepResult::Exit(exit) => return Ok(exit),
            }
        }
    }
}
```

### AOT 编译模式

绕过 iOS JIT 限制：在构建时将 Guest Kernel 和常用 DLL 预编译为 ARM64：

```
构建时:
  Guest Kernel (Rust) → ARM64 机器码 → 嵌入 app bundle

运行时:
  直接执行预编译的 ARM64 代码，无需 JIT
  动态加载的 DLL → 软件解释器（性能较低，但可用）
```

### 单进程架构验证

WinEmu 本身已是单进程架构（所有 Windows 进程运行在同一 VMM 进程内），天然适配 iOS：

```
iOS App Process
    └── WinEmu VMM
            ├── Guest VM (软件模拟)
            │       ├── Windows Process A
            │       ├── Windows Process B
            │       └── Windows Process C
            └── Host 资源管理
```

### P4-4 验收

- [ ] 软件 Hypervisor 后端能运行 Hello World（无 HVF/KVM）
- [ ] 单进程架构在 iOS 模拟器上验证
- [ ] 内存占用 < 500MB（基础运行时）

---

## 持续工作项

### 兼容性追踪

```bash
# 每周运行，追踪回归
winemu run winetest.exe -q 2>&1 | tee winetest_$(date +%Y%m%d).txt
diff winetest_prev.txt winetest_$(date +%Y%m%d).txt
```

### Fuzzing

```rust
// 对 PE 加载器、hypercall handler 进行 fuzzing
// 使用 cargo-fuzz + libFuzzer
#[no_mangle]
pub fn fuzz_pe_loader(data: &[u8]) {
    let _ = winemu_kernel::ldr::pe::load(data, None);
}
```

### 性能 Profiling

```bash
# macOS
cargo instruments --template "Time Profiler" -- winemu run benchmark.exe

# Linux
perf record -g cargo run --bin winemu -- run benchmark.exe
perf report
```
