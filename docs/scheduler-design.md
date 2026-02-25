# WinEmu 调度器与同步机制设计

## 1. 背景与目标

WinEmu 采用 **N:M 协作式调度**：M 个 vCPU pthread 运行 N 个 Guest 线程。
Guest 线程不直接对应 OS 线程，调度完全由 VMM 控制。

设计目标：
- 高性能：最小化上下文切换开销（延迟 FP 保存、无不必要的锁竞争）
- 正确性：完整实现 NT `WaitForSingleObject` / `WaitForMultipleObjects` 语义
- 可扩展：vCPU 数量可配置，锁粒度细化（分片锁）

---

## 2. 核心数据结构

### 2.1 ThreadId

```
ThreadId(u32)  — 全局唯一，从 1 开始单调递增
```

### 2.2 ThreadContext — 寄存器快照

保存 Guest 线程被换出时的完整 CPU 状态。

```
struct ThreadContext {
    // 通用寄存器 x0-x30 + sp + pc + pstate
    gpr:      [u64; 33],   // [0..30]=x0-x30, [31]=sp, [32]=pc
    pstate:   u64,

    // 浮点寄存器（延迟保存）
    fp_regs:  [u128; 32],  // Q0-Q31
    fp_dirty: bool,        // true = fp_regs 有效，需要恢复
    fpcr:     u64,
    fpsr:     u64,
}
```

**延迟 FP 保存策略**：
- 换出时：仅当 `fp_dirty == true` 才保存 Q0-Q31（4KB 拷贝）
- 换入时：仅当 `fp_dirty == true` 才恢复 Q0-Q31
- vCPU 检测到 Guest 执行了浮点指令（CPSR.V/FPCR 变化）时置 `fp_dirty = true`
- 大多数纯整数路径（syscall dispatch、字符串操作）无需触碰 FP 寄存器

### 2.3 ThreadState

```
enum ThreadState {
    Ready,                          // 在 ready 队列中，等待 vCPU
    Running { vcpu_id: u32 },       // 正在某 vCPU 上执行
    Waiting(WaitRequest),           // 阻塞在同步对象上
    Terminated(u32),                // 已退出，退出码
}
```

### 2.4 WaitRequest — 等待描述符

```
struct WaitRequest {
    kind:       WaitKind,
    deadline:   Option<Instant>,    // None = 无限等待
    wake_index: Option<usize>,      // WaitMultiple 时，哪个对象触发了唤醒
}

enum WaitKind {
    Single(SyncHandle),
    Multiple { handles: Vec<SyncHandle>, wait_all: bool },
}
```

### 2.5 GuestThread

```
struct GuestThread {
    id:      ThreadId,
    state:   ThreadState,
    ctx:     ThreadContext,         // 换出时保存的寄存器
    teb_gva: u64,                   // Guest TEB 地址（NT 线程环境块）
}
```

---

## 3. 同步对象

### 3.1 SyncHandle

```
SyncHandle(u32)  — Guest 可见的句柄，映射到 VMM 内部 SyncObject
```

### 3.2 SyncObject

```
enum SyncObject {
    Event(EventObj),
    Mutex(MutexObj),
    Semaphore(SemaphoreObj),
    Thread(ThreadId),               // 等待线程退出（WaitForSingleObject(hThread)）
}
```

#### Event

```
struct EventObj {
    manual_reset: bool,
    signaled:     bool,
    waiters:      VecDeque<ThreadId>,
}
```

- `SetEvent`：`signaled = true`；若 auto-reset，唤醒一个 waiter 并立即清除；若 manual-reset，唤醒所有 waiter
- `ResetEvent`：`signaled = false`
- `WaitForSingleObject`：若已 signaled 且 auto-reset → 消费信号立即返回；否则入队等待

#### Mutex

```
struct MutexObj {
    owner:     Option<ThreadId>,
    rec_count: u32,                 // 递归计数
    waiters:   VecDeque<ThreadId>,
}
```

- 支持递归获取（同一线程可多次 acquire，`rec_count++`）
- `ReleaseMutex`：`rec_count--`；归零时唤醒队首 waiter

#### Semaphore

```
struct SemaphoreObj {
    count:   i64,
    maximum: i64,
    waiters: VecDeque<ThreadId>,
}
```

- `ReleaseSemaphore(n)`：`count += n`（不超过 maximum），唤醒 min(n, waiters.len()) 个线程

---

## 4. 调度器结构

### 4.1 分片锁设计

避免单一全局锁成为瓶颈：

```
struct Scheduler {
    // 就绪队列（FIFO）
    ready:    Mutex<VecDeque<ThreadId>>,

    // 线程表：分片，减少竞争
    // 分片数 = THREAD_SHARDS（默认 16）
    threads:  [Mutex<HashMap<ThreadId, GuestThread>>; THREAD_SHARDS],

    // 同步对象表：分片
    // 分片数 = SYNC_SHARDS（默认 16）
    objects:  [Mutex<HashMap<SyncHandle, SyncObject>>; SYNC_SHARDS],

    // 全局计数器
    next_tid:    AtomicU32,
    next_handle: AtomicU32,

    // vCPU 数量
    vcpu_count: u32,
}
```

分片索引：
```
thread_shard(tid)   = tid.0 as usize % THREAD_SHARDS
object_shard(handle) = handle.0 as usize % SYNC_SHARDS
```

### 4.2 就绪队列（FIFO）

- `push_ready(tid)`：加入队尾
- `pop_ready() -> Option<ThreadId>`：取队首
- 简单 FIFO，公平调度，无优先级（NT 优先级在 Phase 3 扩展）

---

## 5. vCPU 主循环

每个 vCPU pthread 运行以下循环：

```
fn vcpu_thread(vcpu_id, vcpu, scheduler, hc_mgr):
    current_tid = None

    loop:
        // 1. 若当前无线程，从就绪队列取一个
        if current_tid is None:
            current_tid = scheduler.pop_ready()
            if None:
                yield_or_park()   // 短暂 spin 后 park，等待 unpark 信号
                continue

        tid = current_tid.unwrap()

        // 2. 恢复 Guest 寄存器
        ctx = scheduler.get_ctx(tid)
        vcpu.set_regs(ctx.gpr, ctx.pstate)
        if ctx.fp_dirty:
            vcpu.set_fp_regs(ctx.fp_regs, ctx.fpcr, ctx.fpsr)

        // 3. 运行 Guest 直到 VM-exit
        exit = vcpu.run()

        // 4. 处理 VM-exit
        match exit:
            Hypercall { nr, args } =>
                result = hc_mgr.dispatch(nr, args, tid)
                match result:
                    Sync(ret) =>
                        vcpu.set_x0(ret)
                        vcpu.advance_pc(4)
                        // 线程继续运行，不切换

                    Yield =>
                        // 线程主动让出（NT_YIELD_EXECUTION）
                        save_ctx(tid, vcpu)
                        scheduler.push_ready(tid)
                        current_tid = None

                    Block(wait_req) =>
                        // 线程阻塞在同步对象上
                        save_ctx(tid, vcpu)
                        scheduler.set_waiting(tid, wait_req)
                        current_tid = None

                    Exit(code) =>
                        scheduler.terminate(tid, code)
                        current_tid = None

            Halt | Shutdown => break

            _ => log::warn!(...)

// 保存上下文（含延迟 FP）
fn save_ctx(tid, vcpu):
    gpr    = vcpu.get_regs()
    pstate = vcpu.get_pstate()
    fp_dirty = vcpu.fp_accessed_since_last_clear()
    if fp_dirty:
        fp_regs = vcpu.get_fp_regs()
    scheduler.update_ctx(tid, gpr, pstate, fp_dirty, fp_regs)
```

---

## 6. 同步操作流程

### 6.1 WaitForSingleObject

```
hypercall NT_WAIT_SINGLE(handle, timeout_100ns):
    obj = scheduler.get_object(handle)

    // 快路径：对象已 signaled，直接消费
    if obj.try_acquire(tid):
        return STATUS_SUCCESS   // Sync(STATUS_SUCCESS)

    // 慢路径：入队等待
    deadline = if timeout == INFINITE: None else: now() + timeout
    wait_req = WaitRequest { Single(handle), deadline }
    return Block(wait_req)      // vCPU 换出当前线程
```

### 6.2 WaitForMultipleObjects

```
hypercall NT_WAIT_MULTIPLE(handles[], wait_all, timeout_100ns):
    if wait_all:
        // 检查所有对象是否全部 signaled
        if all signaled: acquire all, return STATUS_WAIT_0
    else:
        // 检查任意一个 signaled
        for (i, h) in handles:
            if obj.try_acquire(tid): return STATUS_WAIT_0 + i

    // 慢路径：注册到所有对象的 waiter 列表
    wait_req = WaitRequest { Multiple(handles, wait_all), deadline }
    return Block(wait_req)
```

### 6.3 唤醒流程

当 `SetEvent` / `ReleaseMutex` / `ReleaseSemaphore` 触发唤醒：

```
fn wake_waiter(tid):
    thread = scheduler.get_thread(tid)
    // 从 Waiting → Ready
    scheduler.set_ready(tid)
    scheduler.push_ready(tid)
    // 若有 vCPU 在 park，unpark 一个
    scheduler.unpark_one_vcpu()
```

### 6.4 超时检查

独立的 timeout 线程（或 vCPU 空闲时检查）：

```
fn check_timeouts():
    now = Instant::now()
    for each Waiting thread with deadline <= now:
        // 从所有等待对象的 waiter 列表中移除
        remove_from_waiters(tid)
        // 设置返回值为 STATUS_TIMEOUT
        thread.ctx.gpr[0] = STATUS_TIMEOUT
        scheduler.push_ready(tid)
```

---

## 7. 超时精度说明

NT 超时单位：100 纳秒（负值 = 相对时间，正值 = 绝对时间）。

macOS 上使用 `std::time::Instant` + `thread::park_timeout`，精度约 1ms，
对大多数应用场景足够。高精度定时器（multimedia timer）留 Phase 3。

---

## 8. 与 hypercall 层的接口

`HypercallManager::dispatch` 返回值扩展：

```
enum HypercallResult {
    Sync(u64),              // 立即返回，x0 = 值
    Block(WaitRequest),     // 线程阻塞，vCPU 换出
    Yield,                  // 线程让出 CPU
    Exit(u32),              // 线程退出
}
```

`HypercallManager` 持有 `Arc<Scheduler>`，同步 hypercall 直接操作调度器。

---

## 9. 实现顺序

1. `winemu-vmm/src/sched/mod.rs` — 核心数据结构 + `Scheduler`
2. `winemu-vmm/src/sched/sync.rs` — `SyncObject` 实现（Event/Mutex/Semaphore）
3. `winemu-vmm/src/sched/wait.rs` — `wait_single` / `wait_multiple` / `check_timeouts`
4. 修改 `vcpu.rs` — 新 vCPU 主循环（含 `save_ctx` / `restore_ctx`）
5. 修改 `hypercall/mod.rs` — 接入 `Scheduler`，实现 sync hypercall handlers
6. 修改 `lib.rs` — `Vmm::new` 创建 `Scheduler`，`KERNEL_READY` 创建 Thread 0

---

## 10. 不在本阶段实现的内容

| 功能 | 原因 |
|------|------|
| NT 线程优先级 | 需要多级队列，Phase 3 |
| 异步文件 I/O（kqueue + POSIX AIO） | 当前同步 I/O 足够，Phase 3 |
| APC / 可警告等待 | 复杂度高，Phase 4 |
| NT Timer 对象 | Phase 3 |
| 进程间同步（跨进程句柄） | 单进程模型，暂不需要 |
