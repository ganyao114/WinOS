# WinEmu 线程与调度系统技术架构

## 1. 设计目标与约束

### 1.1 硬约束

| 约束 | 说明 |
|------|------|
| **多 vCPU** | macOS HVF 要求每个 vCPU 绑定一个宿主线程；支持 N 个 vCPU 并发运行 |
| **EL1 guest kernel** | 调度器运行在 EL1，用户线程运行在 EL0 |
| **HVC 开销** | 每次 VM exit ~1–5 μs，调度热路径必须完全在 guest 内完成 |
| **Windows NT 语义** | 必须兼容 NT 的优先级模型（0–31）、等待语义、APC 等 |
| **用户线程 : 内核线程 = 1:1** | 与 yuzu/HOS 相同，每个用户线程对应一个内核线程，调度对象是内核线程 |

### 1.2 设计目标

- 调度器、同步原语状态机全部在 guest kernel（EL1）内实现，不走 HVC
- 只有真正需要 host 资源（文件 I/O、定时器、跨进程事件）时才触发 hypercall
- 借鉴 yuzu 的"全局调度锁 + 延迟更新"模式，保证正确性
- 上下文切换开销目标：< 500 ns（纯 guest 内寄存器保存/恢复 + ERET）
- vCPU 空闲时通过 WFI 触发 VM exit，让 VMM 暂停对应宿主线程，不空转

---

## 2. 与 yuzu 的对比与借鉴

yuzu 模拟 Nintendo HOS（多核 ARM64），WinEmu 模拟 Windows NT（多 vCPU ARM64）。
两者约束相似，核心调度思想可以直接借鉴：

| 概念 | yuzu | WinEmu 借鉴方式 |
|------|------|----------------|
| `KThread` 统一调度对象 | 用户/内核/dummy 线程统一表示 | 同样用 `KThread` 统一表示所有 guest 内核线程 |
| 全局调度锁 + 延迟更新 | `KAbstractSchedulerLock`，最终解锁时批量计算 | `SchedLock`，解锁时调用 `pick_next_thread()` |
| `disable_count` 细粒度不可抢占 | `KScopedDisableDispatch` | 同样在 guest kernel 内维护 `disable_count` |
| 优先级队列 + bitset O(1) 查找 | `KSchedulerPriorityQueue` | 32 级优先级 + `u32` bitset，`clz` 指令 O(1) |
| Fiber 切换 | 每核一个 scheduler fiber；多个宿主线程并发运行 guest fiber，Fiber 是宿主线程上的调度单元 | vCPU 是 WinEmu 的 Fiber 等价物：每个 vCPU 绑定一个宿主线程，guest kernel 在 vCPU 上调度内核线程，VMM 在宿主线程上调度 vCPU |
| Dummy 线程桥接 | 宿主 HLE 线程通过条件变量阻塞 | vCPU 执行 WFI → VM exit → VMM 暂停宿主线程（condvar/park），等待唤醒信号 |
| 多核迁移 | `suggested queue` 填补空闲核 | guest kernel 全局就绪队列，空闲 vCPU 通过 WFI 退出后由 VMM 重新调度到有就绪线程的 vCPU |
| 每核 `KScheduler` | 每核独立调度器，`needs_scheduling` flag | 每 vCPU 一个 `KScheduler`，共享全局就绪队列，`needs_scheduling` 触发跨 vCPU 重调度 |

**关键对应关系**：
- yuzu Fiber ↔ WinEmu vCPU（都是宿主线程上的执行单元）
- yuzu 宿主线程 ↔ WinEmu vCPU 宿主线程
- yuzu `YieldTo(fiber)` ↔ WinEmu guest kernel `context_switch` + ERET
- yuzu condvar 阻塞宿主线程 ↔ WinEmu WFI → VM exit → VMM park 宿主线程

---

## 3. 线程模型

### 3.1 KThread 结构

```
struct KThread {
    // 调度状态
    state:        ThreadState,   // Ready / Running / Waiting / Terminated
    priority:     u8,            // NT 优先级 0–31（31 最高）
    base_priority: u8,           // 基础优先级（优先级继承用）
    disable_count: u32,          // > 0 时不可抢占

    // 执行上下文（EL0 寄存器快照）
    ctx: ThreadContext {
        x: [u64; 31],            // x0–x30
        sp: u64,                 // SP_EL0
        pc: u64,                 // ELR_EL1（返回地址）
        pstate: u64,             // SPSR_EL1
        tpidr_el0: u64,          // TEB 指针
    },

    // 等待信息
    wait_queue:   *mut WaitQueue,  // 当前阻塞在哪个等待队列
    wait_result:  NtStatus,        // 唤醒时的结果码
    wait_deadline: u64,            // 超时时间（FILETIME，0 = 无超时）

    // 链表节点（侵入式，零分配）
    sched_node:   ListNode,        // 就绪队列节点
    wait_node:    ListNode,        // 等待队列节点

    // 标识
    tid:          u32,
    teb:          u64,             // TEB guest VA
}
```

### 3.2 线程状态机

```
                  create
                    │
                    ▼
              ┌─────────┐
    unblock   │  Ready  │◄──────────────────┐
    ──────────►         │                   │
              └────┬────┘                   │
                   │ pick_next              │ signal /
                   ▼                        │ timeout
              ┌─────────┐   wait()   ┌──────┴──────┐
              │ Running ├───────────►│   Waiting   │
              └────┬────┘            └─────────────┘
                   │ exit()
                   ▼
              ┌────────────┐
              │ Terminated │
              └────────────┘
```

### 3.3 线程存储

- guest kernel 内静态数组：`static THREADS: [KThread; MAX_THREADS]`（MAX_THREADS = 64）
- 当前运行线程：`CURRENT_TID: u32`（存在 `TPIDR_EL1` 系统寄存器，零开销读取）
- 线程 ID 分配：简单递增计数器

---

## 4. 调度器设计

### 4.1 两级调度架构

```
┌─────────────────────────────────────────────────────────┐
│                    Guest Kernel (EL1)                    │
│                                                          │
│  全局就绪队列 ReadyQueue (32优先级 bitset)                │
│       ↑ push/pop                                         │
│  KScheduler[0]   KScheduler[1]  ...  KScheduler[N-1]    │
│  current_tid=A   current_tid=B       current_tid=C       │
│       │                │                   │             │
│      vCPU 0           vCPU 1             vCPU N-1        │
└───────│────────────────│───────────────────│─────────────┘
        │ HVF run        │ HVF run           │ HVF run
┌───────▼────────────────▼───────────────────▼─────────────┐
│                    VMM (host)                             │
│  vcpu_thread[0]  vcpu_thread[1]  ...  vcpu_thread[N-1]   │
│  (park/unpark)   (park/unpark)        (park/unpark)       │
└──────────────────────────────────────────────────────────┘
```

- **Guest kernel 调度器**：管理 `KThread`，在 vCPU 上做上下文切换（保存/恢复寄存器 + ERET）
- **VMM vCPU 调度器**：管理宿主线程，决定哪个宿主线程运行哪个 vCPU；vCPU 空闲时 park 宿主线程

### 4.2 优先级队列

借鉴 yuzu 的 bitset 优化，全局共享，多 vCPU 并发访问需在调度锁保护下进行：

```
struct ReadyQueue {
    // 每个优先级一个侵入式链表头
    heads: [Option<*mut KThread>; 32],
    // bitset：第 i 位为 1 表示优先级 i 有就绪线程
    // NT 优先级 0–31，31 最高 → clz(bitset) 找最高优先级
    present: u32,
}

impl ReadyQueue {
    fn push(&mut self, t: *mut KThread) {
        let p = t.priority as usize;
        // 插入链表尾（FIFO within same priority）
        self.present |= 1 << p;
    }

    fn pop_highest(&mut self) -> Option<*mut KThread> {
        if self.present == 0 { return None; }
        let p = 31 - self.present.leading_zeros() as usize;  // clz → O(1)
        let t = self.heads[p].take()?;
        // 更新链表头
        if self.heads[p].is_none() { self.present &= !(1 << p); }
        Some(t)
    }
}
```

### 4.3 调度锁（借鉴 yuzu KAbstractSchedulerLock）

```
struct SchedLock {
    owner_tid:   u32,    // 持锁线程 TID（0 = 未持有）
    lock_count:  u32,    // 可重入计数
    // 多 vCPU：底层用自旋锁保护（EL1 内持锁时间极短，自旋开销可接受）
}

// 加锁：若已持有则仅递增计数；否则获取自旋锁，disable_count++
// 解锁：递减计数；降为 0 时调用 schedule()，释放自旋锁
```

**关键设计**：所有对线程状态、等待队列的修改都在 `SchedLock` 保护下进行。
解锁时统一调用 `schedule()`，决定是否切换线程。这与 yuzu 的"延迟更新"完全一致。

### 4.4 调度入口 schedule()

```
// 在当前 vCPU 上执行
fn schedule(vcpu_id: usize) {
    let sched = &mut SCHEDULERS[vcpu_id];
    let cur   = sched.current_tid;

    // 检查超时
    check_timeouts(now_filetime());

    let next = READY_QUEUE.pop_highest();

    if next == 0 {
        // 无就绪线程 → WFI → VM exit → VMM park 宿主线程
        wfi();
        return;
    }

    if next == cur {
        // 当前线程仍最高优先级，重新入队继续运行
        READY_QUEUE.push(cur);
        return;
    }

    // 切换：cur 回就绪队列，next 上 CPU
    if cur != 0 && THREADS[cur].state == Running {
        THREADS[cur].state = Ready;
        READY_QUEUE.push(cur);
    }
    THREADS[next].state = Running;
    sched.current_tid   = next;
    context_switch(cur, next);   // 保存 cur.ctx，恢复 next.ctx，ERET
}
```

### 4.5 跨 vCPU 重调度

当线程被唤醒（`wake(tid)`）时，若存在空闲 vCPU（正在 WFI），需要通知它：

```
fn wake(tid: u32, result: u32) {
    THREADS[tid].state       = Ready;
    THREADS[tid].wait_result = result;
    READY_QUEUE.push(tid);

    // 若有 vCPU 正在 WFI（VMM 侧 park），发送 IPI 等价信号唤醒它
    // VMM 实现：向对应 vcpu_thread 发 unpark()，让它重新进入 hv_vcpu_run
    hvc_wake_idle_vcpu();   // 可选优化，避免延迟
}
```

---

## 5. 上下文切换

### 5.1 切换机制

多 vCPU 下，每个 vCPU 独立执行上下文切换，不需要跨核协调（全局调度锁保证互斥）：

```
// 在 EL1 SVC handler 内执行（已有 SVC 栈）
fn context_switch(from_tid: u32, to_tid: u32) {
    let from = &mut THREADS[from_tid];
    let to   = &THREADS[to_tid];

    // 1. 保存 from 的 EL0 上下文（SVC 入口时已保存到 SvcFrame）
    from.ctx.x      = svc_frame.x;       // x0–x30
    from.ctx.sp     = svc_frame.sp_el0;
    from.ctx.pc     = svc_frame.elr;     // ELR_EL1（返回地址）
    from.ctx.pstate = svc_frame.spsr;    // SPSR_EL1
    from.ctx.tpidr  = read_tpidr_el0();  // TEB 指针

    // 2. 恢复 to 的 EL0 上下文到 SvcFrame（ERET 时生效）
    svc_frame.x      = to.ctx.x;
    svc_frame.sp_el0 = to.ctx.sp;
    svc_frame.elr    = to.ctx.pc;
    svc_frame.spsr   = to.ctx.pstate;
    write_tpidr_el0(to.ctx.tpidr);       // 切换 TEB

    // 3. 从 SVC handler 返回时 ERET → 跳转到 to 线程的 PC
}
```

### 5.2 新线程首次运行

新线程创建时，`ctx.pc` 指向线程入口，`ctx.sp` 指向用户栈顶，`ctx.x[0]` 为参数。
首次被调度时，`context_switch` 直接 ERET 到入口地址，与普通恢复路径完全一致。

---

## 6. 同步原语

所有同步原语状态机在 guest kernel 内实现，不走 HVC。

### 6.1 等待队列（WaitQueue）

```
struct WaitQueue {
    // 侵入式链表，按优先级排序（高优先级在前）
    head: Option<*mut KThread>,
}

impl WaitQueue {
    // 将线程加入等待队列（按优先级插入）
    fn enqueue(&mut self, t: *mut KThread) { ... }

    // 唤醒队首线程（最高优先级）
    fn wake_one(&mut self) -> Option<*mut KThread> { ... }

    // 唤醒所有线程
    fn wake_all(&mut self) { ... }
}
```

### 6.2 KEvent

```
struct KEvent {
    signaled:    bool,
    auto_reset:  bool,   // true = auto-reset event
    waiters:     WaitQueue,
}

fn set_event(ev: &mut KEvent) {
    let _lock = SchedLock::acquire();
    if let Some(t) = ev.waiters.wake_one() {
        t.wait_result = STATUS_SUCCESS;
        t.state = Ready;
        READY_QUEUE.push(t);
        if !ev.auto_reset { ev.signaled = true; }
        // SchedLock 解锁时自动调用 schedule()
    } else {
        ev.signaled = true;
    }
}

fn wait_event(ev: &mut KEvent, timeout: u64) -> NtStatus {
    let _lock = SchedLock::acquire();
    if ev.signaled {
        if ev.auto_reset { ev.signaled = false; }
        return STATUS_SUCCESS;   // 快路径，不切换
    }
    // 慢路径：加入等待队列，让出 CPU
    let cur = current_thread();
    cur.state = Waiting;
    cur.wait_deadline = timeout;
    ev.waiters.enqueue(cur);
    // 解锁 → schedule() → ERET 到下一个线程
    // 当前线程被唤醒后从这里继续
    cur.wait_result
}
```

### 6.3 KMutex（含优先级继承）

```
struct KMutex {
    owner:    Option<*mut KThread>,
    waiters:  WaitQueue,
}

fn acquire_mutex(m: &mut KMutex) -> NtStatus {
    let _lock = SchedLock::acquire();
    if m.owner.is_none() {
        m.owner = Some(current_thread());
        return STATUS_SUCCESS;
    }
    // 优先级继承：若当前线程优先级高于 owner，临时提升 owner 优先级
    let cur = current_thread();
    if let Some(owner) = m.owner {
        if cur.priority > owner.priority {
            boost_priority(owner, cur.priority);
        }
    }
    cur.state = Waiting;
    m.waiters.enqueue(cur);
    cur.wait_result
}

fn release_mutex(m: &mut KMutex) {
    let _lock = SchedLock::acquire();
    // 恢复 owner 的基础优先级
    restore_base_priority(current_thread());
    if let Some(next) = m.waiters.wake_one() {
        m.owner = Some(next);
        next.wait_result = STATUS_SUCCESS;
        next.state = Ready;
        READY_QUEUE.push(next);
    } else {
        m.owner = None;
    }
}
```

### 6.4 KSemaphore

```
struct KSemaphore {
    count:    i32,
    max:      i32,
    waiters:  WaitQueue,
}
// release: count += n，唤醒 min(n, waiters) 个线程
// wait:    count > 0 → count--（快路径）；否则阻塞
```

### 6.5 NtWaitForMultipleObjects

```
fn wait_multiple(handles: &[Handle], wait_all: bool, timeout: u64) -> NtStatus {
    let _lock = SchedLock::acquire();
    // 检查是否所有/任一对象已 signaled（快路径）
    // 若不满足：将当前线程注册到所有对象的等待队列
    // 唤醒时：检查 wait_all 条件，若未满足则重新入队
}
```

---

## 7. 超时处理

超时不依赖 host 定时器中断（EL1 无中断），而是在调度循环中检查：

```
fn schedule() {
    // 检查所有 Waiting 线程的 deadline
    let now = hvc_query_system_time();   // 一次 HVC，读 host 时钟
    for t in waiting_threads() {
        if t.wait_deadline != 0 && now >= t.wait_deadline {
            t.wait_result = STATUS_TIMEOUT;
            dequeue_from_wait_queue(t);
            t.state = Ready;
            READY_QUEUE.push(t);
        }
    }
    // 然后正常选取下一个线程
}
```

**优化**：维护一个按 deadline 排序的最小堆，避免每次遍历所有等待线程。

---

## 8. vCPU 空闲与宿主线程暂停

当 guest kernel 的就绪队列为空时，vCPU 没有可运行的线程。此时不能空转（浪费 CPU），
而是通过 WFI 指令触发 VM exit，让 VMM 暂停对应宿主线程：

```
// Guest kernel (EL1) — schedule() 无就绪线程时
wfi   // → VM exit (WFI exit reason)

// VMM (host) — vcpu_thread 处理 WFI exit
match vm_exit {
    VmExit::Wfi => {
        // 宿主线程 park（条件变量等待）
        vcpu.parked.wait();
        // 被唤醒后重新进入 hv_vcpu_run，guest 从 WFI 后继续执行
    }
}

// VMM — 当有新线程就绪时（I/O 完成、定时器到期）
// 唤醒所有 parked vCPU 宿主线程
for vcpu in parked_vcpus {
    vcpu.parked.notify();
}
```

**与 yuzu Dummy 线程的对应关系**：
- yuzu：宿主 HLE 线程通过 `std::condition_variable::wait()` 阻塞，等待 guest 线程就绪
- WinEmu：vCPU 宿主线程通过 WFI → VM exit → `park()` 阻塞，等待 guest 线程就绪
- 语义完全等价，实现路径不同（yuzu 在 host 用户态，WinEmu 经过 hypervisor 层）

**不再需要 BLOCK_THREAD hypercall**（用于 idle 的那个）：WFI 本身就是 idle 信号，
VMM 在 WFI exit handler 里直接 park 宿主线程，无需额外 hypercall 协议。
BLOCK_THREAD hypercall 仅保留用于需要 host 资源的等待（文件 I/O、跨进程事件）。

---

## 9. 完整调用链示例

### 场景：线程 A 等待 Event，线程 B 触发 Event

```
线程 B 调用 NtSetEvent:
  1. SVC → EL1 SVC handler
  2. 识别为 NtSetEvent，调用 set_event()
  3. SchedLock::acquire()
  4. ev.waiters.wake_one() → 线程 A 出队
  5. A.state = Ready，READY_QUEUE.push(A)
  6. SchedLock::release() → schedule()
  7. A.priority > B.priority？
     是 → context_switch(B, A)，ERET 到 A
     否 → B 继续运行，A 在就绪队列等待

线程 A 被唤醒:
  8. A 从 wait_event() 的阻塞点继续执行
  9. 返回 STATUS_SUCCESS 给用户态
```

---

## 10. 数据结构内存布局

全部静态分配在 guest kernel BSS，不依赖动态堆：

```
// guest kernel BSS
static THREADS:    [KThread; 64]          // ~64 * 256 bytes = 16 KB
static READY_QUEUE: ReadyQueue            // 32 * 8 bytes = 256 bytes
static EVENTS:     [KEvent; 256]          // 对象池
static MUTEXES:    [KMutex; 256]
static SEMAPHORES: [KSemaphore; 128]
static HANDLES:    HandleTable            // TID/对象 映射表
```

对象句柄（HANDLE）= 对象类型（4 bit）+ 对象池索引（12 bit），直接数组索引，O(1)。

---

## 11. 实现路径

按依赖顺序：

1. **KThread + ReadyQueue**：基础数据结构，静态分配
2. **SchedLock + schedule()**：调度锁和调度入口
3. **context_switch()**：寄存器保存/恢复 + ERET
4. **KEvent**：最简单的同步原语，验证调度正确性
5. **KMutex + 优先级继承**：NT 语义要求
6. **KSemaphore**
7. **NtWaitForMultipleObjects**
8. **超时最小堆**
9. **WFI idle 处理**（VMM WFI exit handler park 宿主线程）+ **BLOCK_THREAD hypercall**（I/O / 跨进程等待）
10. **删除 VMM 侧对应 hypercall**（NT_CREATE_EVENT 等）

---

## 12. 性能预期

| 操作 | 当前（走 HVC） | 目标（guest 内） |
|------|--------------|----------------|
| NtCreateEvent | ~2 μs | ~20 ns（对象池分配） |
| NtSetEvent（已有等待者） | ~2 μs | ~100 ns（队列操作 + schedule） |
| NtWaitForSingleObject（已 signal） | ~2 μs | ~30 ns（原子检查） |
| 线程上下文切换 | ~2 μs（HVC） | ~200 ns（寄存器保存/恢复） |
| NtYieldExecution | ~2 μs | ~200 ns（schedule） |
| NtWriteFile（stdout） | ~2 μs | ~2 μs（仍需 HVC） |
