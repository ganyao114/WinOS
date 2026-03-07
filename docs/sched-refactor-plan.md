# WinEmu Kernel Scheduler 实现计划

## 一、目标

参考 Horizon OS (libmesosphere) 的设计，对调度器进行完全重构：

参考对象：/Users/swift/Downloads/Atmosphere-master/libraries/libmesosphere

- 清晰的模块边界，每个文件是真正的 Rust module（消除 `include!` 模式）
- 全局调度结构体 `KGlobalScheduler` + 每 CPU 结构体 `KScheduler`
- 调度器只切换内核栈（kctx），不切换用户栈
- Lock/Unlock Edge 作为调度入口，RAII 调度锁
- 同步对象（KEvent / KMutex / KSemaphore）逻辑收敛，方法实现在结构体内
- 消除所有 `unsafe` 裸指针访问的隐式契约，用类型系统表达

---

## 二、新模块结构

```
sched/
├── mod.rs              # pub use 汇总，无 include!
├── types.rs            # ThreadState, ThreadContext, KernelContext, KThread
├── global.rs           # KGlobalScheduler 定义 + 全局静态
├── per_cpu.rs          # KScheduler (per-vCPU) 定义
├── priority_queue.rs   # ReadyQueue: scheduled/suggested 双队列 + BitSet
├── lock.rs             # KSchedulerLock (RAII) + spinlock
├── thread_store.rs     # ObjectStore<KThread> 封装，with_thread / with_thread_mut
├── context.rs          # KernelContext switch/enter，kstack 管理
├── schedule.rs         # scheduler_round, schedule(), idle_thread_fn
├── threads.rs          # spawn, create_user_thread, terminate
├── wait.rs             # block_current, end_wait, check_timeouts
└── sync/
    ├── mod.rs          # pub use
    ├── object.rs       # KSyncObject trait (is_signaled, notify, consume)
    ├── event.rs        # KEvent { impl KSyncObject }
    ├── mutex.rs        # KMutex { impl KSyncObject, priority inheritance }
    ├── semaphore.rs    # KSemaphore { impl KSyncObject }
    └── wait_queue.rs   # WaitQueue (priority-sorted intrusive list)
```

---

## 三、核心数据结构设计

### 3.1 KGlobalScheduler（全局，单例）

```rust
pub struct KGlobalScheduler {
    /// 线程对象存储
    threads: SpinLock<ObjectStore<KThread>>,

    /// 全局就绪队列（scheduled + suggested 双队列）
    ready_queue: UnsafeCell<KReadyQueue>,

    /// 每 vCPU 调度器
    per_cpu: UnsafeCell<[KScheduler; MAX_VCPUS]>,

    /// 在线 vCPU 掩码
    online_mask: UnsafeCell<u32>,

    /// 空闲 vCPU 掩码
    idle_mask: UnsafeCell<u32>,

    /// 待调度掩码（需要 reschedule 的 vCPU）
    pending_resched_mask: UnsafeCell<u32>,

    /// 延迟释放的内核栈队列
    deferred_kstacks: UnsafeCell<DeferredKstackQueue>,

    /// 调度器锁（reentrant spinlock）
    lock: KSchedulerLockState,
}
```

### 3.2 KScheduler（每 vCPU）

```rust
pub struct KScheduler {
    pub vcpu_id: usize,
    pub current_tid: u32,
    pub idle_tid: u32,
    pub needs_scheduling: bool,
    pub last_context_switch_ticks: u64,
    pub switch_count: u64,
}
```

### 3.3 KReadyQueue（双队列）

参考 libmesosphere 的 scheduled/suggested 分离：

```rust
pub struct KReadyQueue {
    /// 已分配到特定 vCPU 的线程（按 vCPU 分桶）
    scheduled: PerVcpuPriorityQueue,

    /// 可迁移到任意 vCPU 的线程
    suggested: PerVcpuPriorityQueue,
}

struct PerVcpuPriorityQueue {
    /// heads[vcpu][priority] = TID 链表头
    heads: [[u32; 32]; MAX_VCPUS],
    tails: [[u32; 32]; MAX_VCPUS],
    /// present[vcpu] = BitSet32，bit i = priority i 有线程
    present: [u32; MAX_VCPUS],
}
```

**关键操作：**
- `push_scheduled(tid, vcpu, priority)` — 加入 scheduled 队列
- `push_suggested(tid, priority)` — 加入所有允许 vCPU 的 suggested 队列
- `pop_scheduled(vcpu) -> u32` — O(1) 取最高优先级（CLZ on present bitmap）
- `pop_suggested(vcpu) -> u32` — 从其他 vCPU 的 suggested 队列迁移
- `remove(tid)` — 从 scheduled 或 suggested 中移除

### 3.4 KThread（精简）

```rust
pub struct KThread {
    // --- 身份 ---
    pub tid: u32,
    pub pid: u32,
    pub state: ThreadState,
    pub priority: u8,
    pub base_priority: u8,
    pub is_idle_thread: bool,

    // --- 上下文 ---
    pub ctx: ThreadContext,      // EL0 寄存器（SVC 时保存）
    pub kctx: KernelContext,     // EL1 callee-saved（内核切换时保存）
    pub in_kernel: bool,         // 是否有有效 kctx

    // --- 栈 ---
    pub stack_base: u64,
    pub stack_size: u64,
    pub kstack_base: u64,
    pub kstack_size: u64,
    pub teb_va: u64,

    // --- 调度 ---
    pub affinity_mask: u32,
    pub last_vcpu_hint: u8,
    pub slice_remaining_100ns: u64,
    pub last_start_100ns: u64,

    // --- 等待 ---
    pub wait_state: WaitState,   // 收敛到单一结构体

    // --- 就绪队列链接 ---
    pub sched_next: u32,
}

pub struct WaitState {
    pub kind: WaitKind,
    pub result: u32,
    pub deadline: u64,
    pub timer_task_id: u32,
    pub handles: [u64; 64],
    pub handle_count: u8,
    pub signaled_mask: u64,
}
```

### 3.5 KernelContext（去冗余）

```rust
/// 内核上下文：仅保存 EL1 callee-saved 寄存器
/// 布局与汇编严格对应：
///   [0x00] x19–x28 (10 × u64)
///   [0x50] x29 (fp)
///   [0x58] x30 (lr) — 也是 continuation 函数指针
///   [0x60] sp_el1
#[repr(C)]
pub struct KernelContext {
    pub x19_x29: [u64; 11],  // x19–x29
    pub lr: u64,              // x30，continuation 入口
    pub sp_el1: u64,
}

impl KernelContext {
    pub fn has_continuation(&self) -> bool {
        self.sp_el1 != 0 && self.lr != 0
    }
    pub fn set_continuation(&mut self, sp_top: u64, entry: u64) {
        self.sp_el1 = sp_top;
        self.lr = entry;
        self.x19_x29 = [0; 11];
    }
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}
```

消除 `lr_el1` 冗余字段，`x19_x30[11]` 改为 `lr`，汇编偏移不变。

---

## 四、调度锁设计（RAII）

### 4.1 KSchedulerLockState

```rust
pub struct KSchedulerLockState {
    spinlock: AtomicU32,
    owner_vcpu: UnsafeCell<u32>,   // vcpu_id + 1，0 = 无主
    depth: UnsafeCell<u32>,        // 重入深度
}
```

### 4.2 KSchedulerLock（RAII guard）

```rust
pub struct KSchedulerLock<'a> {
    state: &'a KSchedulerLockState,
}

impl<'a> KSchedulerLock<'a> {
    pub fn acquire(state: &'a KSchedulerLockState) -> Self { ... }
}

impl Drop for KSchedulerLock<'_> {
    fn drop(&mut self) {
        // 最终释放时：
        // 1. commit_deferred_scheduling()
        // 2. prepare_unlock_edge_switch()
        // 3. 释放 spinlock
        // 4. 锁外：kick idle vCPUs, execute unlock-edge switch
    }
}
```

### 4.3 Lock/Unlock Edge 调度入口

```
Lock Edge（sched_lock_acquire）:
  - 原子获取 spinlock
  - 记录 owner + depth

Unlock Edge（sched_lock_release / Drop）:
  - depth > 1: 仅递减
  - depth == 1:
      1. commit_deferred_scheduling_locked()
      2. prepare_unlock_edge_kernel_switch_locked(vid)
         → 选出 to_tid（有 kctx 的就绪线程）
         → 设置 from_tid.in_kernel = true
         → 更新 vcpu.current_tid, TPIDR_EL1
      3. 释放 spinlock
      4. kick_idle_vcpus(wake_mask)
      5. if let Some(switch) = unlock_edge_switch:
             switch_kernel_continuation(from, to)
             // 返回时 = 被其他线程切换回来
```

---

## 五、同步对象设计

### 5.1 KSyncObject trait

```rust
pub trait KSyncObject: Send {
    fn is_signaled(&self) -> bool;
    fn consume_signal(&mut self) -> bool;  // auto-reset 消费
    fn notify_waiters(&mut self, lock: &KSchedulerLock<'_>);
}
```

### 5.2 KEvent

```rust
pub struct KEvent {
    pub tid: u32,           // 所属线程（handle 查找用）
    pub signaled: bool,
    pub auto_reset: bool,
    pub waiters: WaitQueue,
}

impl KEvent {
    pub fn signal(&mut self, lock: &KSchedulerLock<'_>) {
        self.signaled = true;
        if self.auto_reset {
            if let Some(tid) = self.waiters.dequeue_highest() {
                end_wait_locked(tid, STATUS_SUCCESS, lock);
                self.signaled = false;
                return;
            }
        } else {
            self.waiters.wake_all(lock);
        }
    }
    pub fn clear(&mut self) { self.signaled = false; }
    pub fn wait(&mut self, tid: u32, deadline: u64, lock: &KSchedulerLock<'_>) -> u32 { ... }
}
```

### 5.3 KMutex（含 priority inheritance）

```rust
pub struct KMutex {
    pub owner_tid: u32,
    pub recursion: u32,
    pub waiters: WaitQueue,  // 按优先级排序
}

impl KMutex {
    pub fn acquire(&mut self, tid: u32, lock: &KSchedulerLock<'_>) -> u32 {
        if self.owner_tid == 0 {
            self.owner_tid = tid;
            self.recursion = 1;
            return STATUS_SUCCESS;
        }
        if self.owner_tid == tid {
            self.recursion += 1;
            return STATUS_SUCCESS;
        }
        // priority inheritance: boost owner to max(owner_prio, waiter_prio)
        self.boost_owner_priority(tid, lock);
        self.waiters.enqueue(tid);
        begin_wait_locked(tid, u64::MAX, lock)
    }

    pub fn release(&mut self, tid: u32, lock: &KSchedulerLock<'_>) -> u32 {
        if self.owner_tid != tid { return STATUS_MUTANT_NOT_OWNED; }
        self.recursion -= 1;
        if self.recursion > 0 { return STATUS_SUCCESS; }
        self.restore_owner_priority(tid, lock);
        self.owner_tid = 0;
        if let Some(next) = self.waiters.dequeue_highest() {
            self.owner_tid = next;
            self.recursion = 1;
            end_wait_locked(next, STATUS_SUCCESS, lock);
        }
        STATUS_SUCCESS
    }
}
```

### 5.4 KSemaphore

```rust
pub struct KSemaphore {
    pub count: i32,
    pub max_count: i32,
    pub waiters: WaitQueue,
}

impl KSemaphore {
    pub fn release(&mut self, count: i32, lock: &KSchedulerLock<'_>) -> u32 {
        if self.count + count > self.max_count { return STATUS_SEMAPHORE_LIMIT_EXCEEDED; }
        self.count += count;
        while self.count > 0 {
            let Some(tid) = self.waiters.dequeue_highest() else { break };
            self.count -= 1;
            end_wait_locked(tid, STATUS_SUCCESS, lock);
        }
        STATUS_SUCCESS
    }
    pub fn wait(&mut self, tid: u32, deadline: u64, lock: &KSchedulerLock<'_>) -> u32 {
        if self.count > 0 { self.count -= 1; return STATUS_SUCCESS; }
        self.waiters.enqueue(tid);
        begin_wait_locked(tid, deadline, lock)
    }
}
```

### 5.5 WaitQueue

```rust
pub struct WaitQueue {
    // 按优先级排序的侵入式链表（slab 分配节点）
    head: Option<NonNull<WaitNode>>,
    len: usize,
}

impl WaitQueue {
    pub fn enqueue(&mut self, tid: u32) { ... }
    pub fn dequeue_highest(&mut self) -> Option<u32> { ... }
    pub fn remove(&mut self, tid: u32) -> bool { ... }
    pub fn wake_all(&mut self, lock: &KSchedulerLock<'_>) { ... }
    pub fn highest_priority(&self) -> Option<u8> { ... }
}
```

---

## 六、调度核心流程

### 6.1 set_thread_state（唯一状态机入口）

```rust
impl KGlobalScheduler {
    pub fn set_thread_state(&self, tid: u32, new_state: ThreadState, _lock: &KSchedulerLock<'_>) {
        // 1. idle 线程：仅更新 state，跳过队列操作
        // 2. old_state == Ready: ready_queue.remove(tid)
        // 3. 更新 state
        // 4. new_state == Ready: ready_queue.push(tid), mark_reschedule_targeted(tid)
    }
}
```

### 6.2 scheduler_round（核心决策）

```rust
pub enum ScheduleAction {
    ContinueCurrent,
    SwitchTo { to_tid: u32, now: u64, deadline: u64, slice: u64 },
    IdleWait { now: u64, deadline: u64 },
}

impl KGlobalScheduler {
    pub fn scheduler_round(&self, vid: usize, from_tid: u32, _lock: &KSchedulerLock<'_>) -> ScheduleAction {
        // 1. 检查 from_tid 是否仍 Running 且无更高优先级线程 → ContinueCurrent
        // 2. 从 ready_queue 选 to_tid（scheduled 优先，再 suggested）
        // 3. to_tid == 0 → 返回 idle_tid
        // 4. 更新 vcpu.current_tid, TPIDR_EL1, vcpu_kernel_sp
        // 5. 返回 SwitchTo
    }
}
```

### 6.3 schedule_from_trap（trap 出口）

```rust
pub fn schedule_from_trap(frame: &mut TrapFrame) {
    let vid = vcpu_id();
    let from_tid = current_tid();

    // 保存 EL0 context
    save_ctx_for(from_tid, frame);

    loop {
        let lock = KSchedulerLock::acquire(&SCHED.lock);
        check_timeouts(now_ticks(), &lock);
        let action = SCHED.scheduler_round(vid, from_tid, &lock);
        // lock 在此 drop → unlock-edge 可能触发 kctx switch

        match action {
            ContinueCurrent => {
                restore_ctx_to_frame(from_tid, frame);
                return;  // ERET 回 EL0
            }
            SwitchTo { to_tid, .. } => {
                if has_kernel_continuation(to_tid) {
                    // kctx 路径：switch_kernel_continuation 或 enter_kernel_continuation
                    ...
                } else {
                    // EL0 frame 路径：restore_ctx_to_frame(to_tid, frame) + ERET
                    restore_ctx_to_frame(to_tid, frame);
                    return;
                }
            }
            IdleWait { .. } => {
                timer::idle_wait_until_deadline(...);
                continue;
            }
        }
    }
}
```

---

## 七、重构步骤

### 前提
保留 `nt/dispatch.rs` 的 SVC 分发入口不动（`schedule_from_trap`、`el0_page_fault` 等）。
**删除 `src/sched/` 下除 `mod.rs` 声明骨架之外的所有实现代码**，然后按以下顺序从零重写。

### Phase 1 — 删除旧实现
1. 删除 `sched/` 下所有 `.rs` 文件内容（保留空文件或仅保留 `mod.rs` 的 `pub mod` 声明）
2. 删除 `sched/sync/` 子目录下所有 `include!` 文件
3. 确认 `dispatch.rs` 编译报错（符号缺失），记录所有缺失符号作为重写目标
4. 不改 `dispatch.rs`，不改 `nt/` 其他文件

### Phase 2 — 类型层
1. 新建 `types.rs`：`ThreadState`, `ThreadContext`, `KernelContext`（`x19_x29[11]` + `lr` + `sp_el1`，无冗余 `lr_el1`）, `KThread`
2. 新建 `thread_store.rs`：`ObjectStore<KThread>`，`with_thread` / `with_thread_mut`
3. 新建 `global.rs`：`KGlobalScheduler` 单例 `SCHED`，所有全局状态字段
4. 新建 `cpu.rs`：per-vCPU TLS，`current_tid()` / `vcpu_id()`
5. 编译通过（其余模块暂为空 stub）

### Phase 3 — 锁层
1. 新建 `lock.rs`：`KSchedulerLock` RAII，`sched_lock_acquire/release`，`sched_lock_held_by_current_vcpu`
2. unlock-edge 决策逻辑在 `lock.rs` 的 `Drop` 中触发（或由 `topology.rs` 提供，`Drop` 调用）
3. 编译通过

### Phase 4 — 就绪队列
1. 新建 `queue.rs`：`KReadyQueue`，scheduled/suggested 双队列，BitSet O(1) 优先级
2. 新建 `topology.rs`：`set_thread_state_locked`，`ready_push/pop/remove`，vCPU 掩码，unlock-edge 决策
3. 编译通过

### Phase 5 — 上下文切换
1. 新建 `context.rs`：`switch_kernel_continuation`，`enter_kernel_continuation_noreturn`，`enter_user_thread_noreturn`，`has_kernel_continuation`，kstack 辅助
2. 汇编偏移与 `KernelContext` 布局严格对应（`x19_x29[0..11]` @ 0x00，`lr` @ 0x58，`sp_el1` @ 0x60）
3. 编译通过

### Phase 6 — 等待/唤醒
1. 新建 `wait.rs`：`prepare_wait_locked`，`begin_wait_locked`，`end_wait_locked`，`cancel_wait_locked`，`check_timeouts`，`block_current_and_resched`
2. 编译通过

### Phase 7 — 线程生命周期
1. 新建 `thread_control.rs`：优先级设置，suspend/resume，时间片记账
2. 新建 `threads.rs`：`spawn`，`create_user_thread`，`terminate_thread_by_tid`，kstack 分配/释放
3. 编译通过

### Phase 8 — 调度核心
1. 新建 `schedule.rs`：`scheduler_round_locked`，`schedule`，`wake`，`yield_current_thread`，`terminate_current_thread`，idle 线程，`enter_core_scheduler_entry`
2. 编译通过，`dispatch.rs` 所有符号全部解析

### Phase 9 — 同步对象
1. 新建 `sync.rs` + `sync/` 子文件：`WaitQueue`，`KEvent`，`KMutex`，`KSemaphore`，handle table
2. 所有 sync 方法接受 `&KSchedulerLock` 参数，不依赖隐式全局锁
3. 编译通过

### Phase 10 — 验证
1. 运行 thread_test，行为与重构前一致
2. 统一 `unsafe` 边界，添加 Safety 注释
3. 无 unused import / dead_code warnings

---

## 八、关键设计决策

| 决策 | 选择 | 理由 |
|---|---|---|
| 调度锁粒度 | 单全局锁（同 HOS） | 简单，避免死锁；WinEmu 是单进程 VMM |
| 就绪队列 | scheduled/suggested 双队列 | 消除 O(n) 线性扫描，O(1) 调度决策 |
| 同步对象锁 | 复用调度锁（同 HOS） | 避免锁层级问题；sync 操作必须原子修改线程状态 |
| kctx 冗余字段 | 去掉 `lr_el1`，只保留 `lr`（即 x30） | 消除双写 bug 根源 |
| 模块边界 | 真正的 `mod`，不用 `include!` | 编译器可检查可见性，IDE 支持更好 |
| 同步对象方法 | 方法在结构体内，`&KSchedulerLock` 作参数 | 明确锁依赖，不依赖全局隐式锁 |
| idle 线程 | 每 vCPU 一个，永远不进就绪队列 | 同 HOS；简化 scheduler_round 逻辑 |

---

## 九、不在本次重构范围内

- 优先级继承（KMutex 的 priority inheritance 仅设计，不实现）
- 跨 vCPU 迁移优先级限制（priority ≥ 2 才允许迁移）
- 线程 suspend/resume 机制
- 调试/backtrace suspend flags
- 用户态 condvar / address arbiter（NtWaitForKeyedEvent）

这些可在重构完成后作为独立 feature 添加。
