# Guest Kernel <-> VMM 通用 HostCall IPC 设计

## 1. 背景

当前 `HOST_OPEN/HOST_READ/...` 是同步 hypercall，适合短操作，但对以下场景不够通用：

- Win32k/图形路径：调用可能需要跨线程或主线程调度，不能在 HVC 热路径阻塞。
- 后续异步资源：文件监控、窗口消息、音频、Vulkan、网络等。
- 线程语义：需要做到“发起后线程进入 Waiting，Host 完成后 signal，再恢复读取结果”。

另外，当前目录通知是特例实现（pending 列表 + 轮询），缺少统一框架。

## 2. 设计目标

1. 统一同步/异步调用模型，避免每个子系统重复造轮子。
2. 保持架构原则：NT 语义在 guest kernel，VMM 仅提供 host 资源能力。
3. 异步调用不阻塞 vCPU 主循环，caller 线程可被调度器正确挂起与唤醒。
4. 支持超时、取消、回收，避免悬挂请求与资源泄漏。
5. 支持 Host 主动 signal，且仅使用 IRQ 驱动通知路径。
6. 在同等语义下优先走低开销路径，控制 VM-exit 次数和锁竞争，保证高并发下吞吐稳定。

非目标（本设计阶段不强行覆盖）：

- 不重写已有全部 `HOST_*` 路径；先做兼容层，逐步迁移。
- 不要求第一版就实现零拷贝大 payload；先保证语义正确与可扩展。

## 3. 总体模型

引入统一抽象：`HostCall`。

- 统一提交入口：`submit(op, flags, arg0..arg3)`（对应 `HOSTCALL_SUBMIT`）。
- 调用方可通过 helper 暴露：
  - `hostcall_sync(...)`：要求同步语义；
  - `hostcall_may_async(...)`：允许 host 按任务特征选择同步立即返回或异步排队。

返回码分流语义（关键）：

1. Guest 发起 `HOSTCALL_SUBMIT`。
2. 若 hypercall 返回 `HOST_PENDING_RESULT`，表示该请求进入异步路径：
   - 读取 `request_id`；
   - 当前线程登记为 waiter 并进入 `Waiting`；
   - 等待 host completion 通知后唤醒取结果。
3. 若返回值不是 `HOST_PENDING_RESULT`，则该值即本次调用的最终同步结果（HostCall 结果码），当前线程不挂起。

说明：

- HostCall 返回码不承载 NT 语义；NTSTATUS 由 guest kernel 的 syscall 层自行映射。

这是一套“轻量 IPC”：

- 控制面：HVC（提交/取消/配置）。
- 数据面：共享描述符 + 结果缓冲（由 guest kernel 管理生命周期）。
- 事件面：Host signal guest（IRQ 驱动）。

### 3.1 性能目标（SLO）

首版给出可量化目标，后续以压测数据校准：

- `submit_sync`（短调用）：
  - 仅 1 次 HVC，不入线程池，不分配长期对象。
  - p50 < 10 us，p99 < 40 us（本地文件/轻量 host 操作）。
- `submit_async`：
  - 注：这里的 `submit_async` 指返回 `HOST_PENDING_RESULT` 的请求集合。
  - 提交路径不阻塞执行体，caller 线程进入 Waiting 的附加成本 p50 < 5 us。
  - broker 入队+出队额外开销（不含真实业务处理）p50 < 15 us。
- completion 路径：
  - completion 到达后，waiter 被标记 Ready 的内核路径 p50 < 10 us。
- 稳定性：
  - 饱和时通过背压快速失败，避免尾延迟无限放大与内存失控。

## 3.2 性能关键策略

- **双路径执行**：同步短操作走 fast path；仅长耗时/需要异步语义才进入 worker 池。
- **返回码分流**：统一 `HOSTCALL_SUBMIT`，仅当返回 `HOST_PENDING_RESULT` 才进入挂起等待路径，其余返回码直接同步完成。
- **批处理 completion**：`HOSTCALL_POLL` 支持一次拉取 N 条 completion，减少 HVC 次数。
- **事件合并**：同一时间窗内只做一次 `kick_guest_completion`（coalesce），避免中断风暴。
- **对象池化**：`PendingHostCall` / completion 节点使用 slab/object pool，减少频繁分配。
- **小包内联**：小输入参数内联到请求头，避免额外拷贝和分配。
- **锁分片**：`inflight` 与队列按 shard 或 lane 分段，降低全局锁竞争。
- **资源串行键**：需要顺序的资源走 keyed serial lane，避免额外同步开销与乱序重试。

### 3.3 性能实现约束（落地级）

为避免“设计正确但实现慢”，第一版实现应同时满足以下约束：

- **队列结构**：
  - `submit queue` 与 `completion queue` 使用有界 ring buffer（优先无锁 MPSC/MPMC 实现，至少要做到单锁短临界区）。
  - 明确 `capacity` 与 `high_watermark`，超过阈值时提前返回背压错误，禁止无限增长链表队列。
- **内存布局**：
  - `PendingHostCall` 热字段（`state/request_id/waiter_tid/host_result/value0/value1`）与冷字段（调试信息、统计）分离，减少 cache miss。
  - 高频原子字段按 cache line 对齐，避免伪共享（尤其是 head/tail/counter）。
- **批量策略**：
  - `POLL_BATCH` 默认批次大小建议 32，允许按负载自适应到 64/128。
  - pump 每次处理设置时间片上限（例如 50-100 us），防止 trap 路径长时间占用导致调度抖动。
- **拷贝与封送**：
  - 请求体 `<= 128B` 内联；更大 payload 走预分配缓冲区引用，避免多次堆分配。
  - 高频 opcode 的封送缓冲走对象池，降低 malloc/free 抖动。
- **锁与临界区**：
  - broker 全局结构不持锁执行 I/O；锁内只做索引操作与状态翻转。
  - `inflight` 至少按 opcode 或 request_id hash 分片，降低高并发冲突。
- **可观测性**：
  - 必须提供 per-op 统计：提交速率、排队时延、执行时延、completion 延迟、背压率、取消率。
  - 指标采样默认常开，debug 详情可按 opcode 开关，避免日志风暴拖慢热路径。

## 4. 组件设计

### 4.1 Guest 侧（`winemu-kernel`）

新增 `hostcall` 子系统（建议文件：`winemu-kernel/src/hostcall/`）：

- `pending.rs`：`PendingHostCall` 表（`ObjectStore`），记录：
  - `request_id`
  - `owner_pid / waiter_tid`
  - `state`（Submitted/Completed/Canceled/TimedOut）
  - `host_result/value0/value1`
  - `out_ptr/out_cap`（内核可访问缓冲）
  - `deadline`（可选）
- `api.rs`：内核内部 API：
  - `hostcall_submit(...) -> SubmitOutcome::{Completed, Pending}`
  - `hostcall_sync(...)`（基于 `hostcall_submit` 封装）
  - `hostcall_may_async(...)`（基于 `hostcall_submit` 封装）
  - `hostcall_wait(...)`
  - `hostcall_cancel(...)`
- `pump.rs`：completion pump
  - `drain_completions()`：消费完成队列，写回 pending 表并 `sched::wake(waiter_tid)`

调度集成：

- 新增等待类型 `WAIT_KIND_HOSTCALL`（内部使用）。
- `hostcall_wait` 复用现有调度器 `Waiting` 路径和超时机制。
- 完成后由 completion pump 调用 `wake()`，保证线程语义一致。

### 4.2 Host 侧（`winemu-vmm`）

新增 `HostCallBroker`（建议文件：`crates/winemu-vmm/src/hostcall/`）：

- `submit()`：接收提交请求后按请求类型与负载做二选一：
  - 短任务：直接同步执行并返回最终 HostCall 结果码；
  - 长任务/需异步：返回 `HOST_PENDING_RESULT` + `request_id`，入队后台 worker。
- `inflight`：`request_id -> metadata`（owner/waiter/op/状态）。
- `worker_pool`：执行通用异步 host 资源操作（文件、网络、部分图形资源、音频等）。
- `main_thread_executor`：处理必须在平台主线程执行的任务（例如 macOS UI/window）。
- `completion_queue`：worker 产出 completion，等待 guest 消费。
- `cancel()`：最佳努力取消（未执行可取消，执行中返回取消失败）。

#### 4.2.1 Worker 线程池模型

HostCall 异步执行采用“分发器 + 线程池 + 特殊执行器”模型：

- `submit queue`（MPSC）：所有 async request 先进入 broker 输入队列。
- `dispatcher`：按 `opcode` / `flags` 路由到目标执行域：
  - `PoolClass::Io`：文件/目录监控/阻塞 I/O。
  - `PoolClass::Cpu`：纯计算或编解码类任务（可选）。
  - `ExecClass::MainThread`：必须主线程执行的 UI/窗口调用（不进入普通线程池）。
- `worker pool`：固定大小线程池消费 `Io/Cpu` 队列，执行后写 `completion_queue`。
- `main_thread_executor`：由宿主主线程在 vCPU 主循环中按预算主动 pump `ExecClass::MainThread` 队列，执行后写 completion。
- `sync fast path`：`flags=SYNC_FAST` 时由 `dispatch` 线程直接执行，不经 submit queue/worker。

建议初始配置：

- `io_workers = clamp(host_cpu_count, 2, 8)`。
- `cpu_workers = clamp(host_cpu_count / 2, 1, 4)`（如暂不需要可先不开）。
- 每类队列配置 `max_inflight` 上限（例如 4096），超限立即返回 `HC_BUSY`（或 `HC_NO_MEMORY`）。

调度与亲和建议：

- I/O 池与 completion pump 线程分离，避免 completion 消费被阻塞 I/O 拖慢。
- 对短任务优先队列（small/latency lane）和长任务队列（bulk lane）分离，降低头阻塞。
- 主线程执行域限制单帧预算（例如每 tick 最多处理 N 个 main-thread hostcall），避免吞掉消息循环。

自适应建议：

- 按队列深度和平均等待时间动态调节 `io_workers`（仅在安全区间内伸缩）。
- 对 `MainThread` 执行域单独限流，防止 UI 任务被高频后台请求淹没。

#### 4.2.2 任务路由与顺序保证

为避免跨域乱序导致语义问题，路由采用以下规则：

- 同一 `request_id` 只进入一个执行域，不迁移。
- 对“需要顺序”的资源可使用 `keyed serial lane`：
  - 例如同一 `host_fd` 的目录通知请求，可按 `resource_key=host_fd` 绑定到同一 lane。
- 默认不保证全局完成顺序，只保证单请求完成一次和同 key 的串行语义。
- `keyed serial lane` 默认采用一致性哈希到固定 lane，避免每次动态建锁/建队列。

#### 4.2.3 取消与协作中断

- 队列中未开始任务：可直接标记 canceled 并产出 canceled completion。
- 执行中任务：采用协作取消（检查 `cancel_token`），无法抢占时允许“完成后丢弃结果”。
- 无论取消是否即时生效，broker 都必须最终产出一次 completion（Canceled / Success / Error 之一），避免 guest 永久等待。

### 4.3 事件通知（signal）

统一 `GuestKick` 抽象：

- `kick_guest_completion()`：Host 有 completion 时调用。

实现策略：

1. 注入虚拟 IRQ（HVF 可用 `pending interrupt`），立即打断 WFI/长时间运行路径。
2. 同时 unpark idle vCPU 线程，避免纯 park 状态下错过唤醒。
3. 不提供无 IRQ 降级路径；若 IRQ 注入不可用，视为当前后端不满足 HostCall 异步通知要求。

## 5. ABI 设计（草案）

在 `winemu_shared::nr` 新增 HostCall 控制编号（示例区间 `0x0820+`）：

- `HOSTCALL_SETUP`：初始化 IPC 通道能力与参数。
- `HOSTCALL_SUBMIT`：统一提交请求（由返回码区分同步完成或异步挂起）。
- `HOSTCALL_CANCEL`：取消请求。
- `HOSTCALL_POLL`：主动拉取 completion（调试/自检接口；非通知通道）。
- `HOSTCALL_POLL_BATCH`：批量拉取 completion（性能路径，减少 HVC 次数）。
- `HOSTCALL_QUERY_STATS`：导出 broker 统计快照（可选 read-and-reset）。

`HOSTCALL_SUBMIT` 调用约定（寄存器优先）：

- `a0 = opcode`
- `a1 = flags`（bit0=ALLOW_ASYNC, bit1=FORCE_ASYNC, bit2=EXT_BUF）
- `a2 = arg0`
- `a3 = arg1`
- `a4 = arg2`
- `a5 = arg3`

扩展参数（仅在必要时）：

- 当 `flags.EXT_BUF=1` 时，`a2 = arg_buf_ptr`（内核地址），`a3 = arg_buf_len`，其余参数按 opcode 定义复用。
- 常见短调用优先使用 `a2..a5`，避免构造大描述符对象。

返回值（寄存器）：

- `r0 = host_result`
- `r1 = aux`

返回码约定：

- `r0 == HOST_PENDING_RESULT`：异步已提交，`r1 = request_id`。
- `r0 != HOST_PENDING_RESULT`：同步已完成，`r0` 为该 opcode 的 host 结果码，`r1` 为可选附加值（按 opcode 定义）。

约束：

- `HOST_PENDING_RESULT` 必须是保留哨兵值，且不与其他 host 结果码冲突。
- guest 侧判断异步的唯一条件是“`r0 == HOST_PENDING_RESULT`”。
- HostCall 结果码属于 host 域，不等同 NTSTATUS；是否映射 NTSTATUS 由 guest syscall 层决定。
- 协议不做版本协商；guest kernel 与 vmm 按同一构建版本一一对应，ABI 变更通过同步升级两侧代码完成。

可选扩展参数块（仅复杂 opcode 使用）：

```c
struct HostCallArgBuf {
    u32 flags;
    u64 words[];
};
```

说明：

- `words` 长度由 `arg_buf_len` 推导，不单独携带 `word_count`。

completion 描述符建议：

```c
struct HostCallCpl {
    u64 request_id;
    i32 host_result;  // HostCall result code (host domain, non-NT)
    u32 flags;
    u64 value0;       // opcode-defined payload
    u64 value1;       // opcode-defined payload
    u64 user_tag;
};
```

批量 completion 拉取建议：

- guest 提供 completion ring（固定容量）；
- `HOSTCALL_POLL_BATCH` 返回本次写入条目数；
- 支持“部分写入 + 下次继续”，避免单次超长处理阻塞 trap 路径。

## 6. 典型时序

### 6.1 同步返回分支（ret != `HOST_PENDING_RESULT`）

1. Guest 调用 `HOSTCALL_SUBMIT`（可带 `ALLOW_ASYNC`，也可不带）。
2. Host 判定该请求可短路径完成，直接执行并返回 host 结果码。
3. Guest 直接返回给 syscall 调用方；caller 不进入 Waiting。

### 6.2 异步返回分支（ret == `HOST_PENDING_RESULT`）

1. Guest 构造 `PendingHostCall` + 输出缓冲，调用 `HOSTCALL_SUBMIT(flags=ALLOW_ASYNC/FORCE_ASYNC)`。
2. 返回 `HOST_PENDING_RESULT + request_id`。
3. Guest 将当前线程设为 `WAIT_KIND_HOSTCALL` 并调度出去。
4. Host worker 执行完成，写 completion 并 `kick_guest_completion()`。
5. Guest 在 IRQ/trap 路径 `drain_completions()`，匹配 `request_id`，更新 pending，`wake(waiter_tid)`。
6. waiter 恢复，读取 `host_result/value0/value1/out_buf`，结束调用。

## 7. 超时与取消语义

- Guest wait 超时：
  - 线程返回 `STATUS_TIMEOUT`。
  - 内核发 `HOSTCALL_CANCEL(request_id)`（best effort）。
  - 若 Host 已完成，completion 仍可到达，但会按“已超时/已取消”状态回收，不再二次唤醒。
- `HOSTCALL_SUBMIT` ABI 不携带 `timeout_ms`；超时策略由 guest wait 侧统一控制，避免调用方绕过内核调度策略。
- 主动取消（未来对接 `NtCancelIoFileEx`）：
  - guest 调 `hostcall_cancel(request_id)`。
  - Host 返回：已取消 / 已完成 / 不存在。

保证：

- completion 对同一 `request_id` 只生效一次（幂等消费）。
- `request_id` 必须带代际（generation）或足够大单调 ID，防止 ABA 误命中。

## 8. 内存与并发约束

- 通过 `a2..a5` 传递的指针参数（或 `EXT_BUF` 指针）必须指向 **内核可稳定访问** 的内存。
- 若来源是用户缓冲，先由 guest 内核拷贝/封送，再提交 HostCall。
- completion 写回后，guest pump 在唤醒前执行可见性屏障（Acquire/Release 语义）。
- Host 不持有裸 guest 用户态 VA 作为长期引用。
- worker 池队列必须有上限并可观测（长度、执行时长、超时率），避免无限堆积。
- 主线程执行域与通用线程池隔离，避免 UI 调用被 I/O 大量占满而饥饿。
- completion 入队失败必须有兜底策略（重试或错误 completion），不可静默丢失。
- 对高频 opcode 建议预分配请求对象和输出缓冲，避免热路径 malloc/free 抖动。
- 避免大锁包围慢系统调用；I/O 执行阶段仅持有局部状态，不持有 broker 全局锁。

## 9. 与现有代码的对齐与迁移

当前状态：

- 同步 `HOST_*` 已可用。
- 异步仅有目录通知特例（轮询式）。

迁移步骤（建议）：

1. 落地 `hostcall` 基础框架（`SUBMIT/CANCEL/POLL` + pending 表 + wake 路径）。
2. 落地 Host 侧 `HostCallBroker + worker_pool + main_thread_executor`。
3. 先把 `HOST_NOTIFY_DIR` 迁移到 HostCall async，替换特例轮询。
4. win32k 首批需要主线程/异步资源的调用接入 HostCall async。
5. 逐步把长耗时 `HOST_READ/WRITE` 增加 async 变体（保留 sync 快路径）。

兼容性策略：

- 保留现有 `HOST_OPEN/HOST_READ/...` 编号和行为。
- 新框架作为增量能力，不破坏已跑通路径。

## 10. 测试计划

### 10.1 单元级

- request_id 分配与回收
- completion 幂等消费
- timeout/cancel 竞争态（先完成后取消、先取消后完成）

### 10.2 内核集成

- 单线程 async 调用：提交->等待->唤醒->读取输出
- 多线程并发 async 调用：结果归属正确
- caller 超时后不被错误二次唤醒

### 10.3 端到端

- 目录通知改造后回归（替换现有 pending 轮询路径）
- win32k 异步调用场景（窗口创建/消息派发）
- 压测：高并发提交 + completion 风暴下无死锁/无请求泄漏
- 压测：线程池饱和 + 主线程队列压力下，无饥饿且返回合理背压错误

### 10.4 性能基准

- 微基准：
  - `submit_sync` 空操作延迟（p50/p95/p99）
  - `submit_async + immediate completion` 端到端延迟
  - `poll_batch` 不同 batch size 的 HVC 次数与 CPU 占用
- 宏基准：
  - 并发 1/4/16/64 caller 的吞吐（req/s）
  - 混合负载（80% Io, 20% MainThread）下尾延迟
  - 背压触发时的错误率与恢复时间

### 10.5 性能回归门槛（CI 建议）

- 若 `submit_sync` p99 相对基线退化 > 20%，标记回归失败。
- 若 `submit_async` 在 16 并发下吞吐下降 > 15%，标记回归失败。
- 若 `completion pending` 连续超过高水位 3 个采样窗口，标记潜在阻塞风险。
- 若背压后 5 秒内队列无法回落到 `high_watermark` 以下，标记恢复能力不足。

## 11. 先实现范围（建议）

为了快速验证模型，第一步建议仅实现：

1. `HOSTCALL_SUBMIT`（sync + async，包含 sync fast path）
2. `HOSTCALL_POLL` + `HOSTCALL_POLL_BATCH`（用于 IRQ 触发后的 completion 拉取与调试）
3. Host 侧最小 `worker_pool`（先 `Io` 类）和 `completion_queue`
4. guest `PendingHostCall + wait/wake` 基础路径
5. 用目录通知或一个 win32k 调用做首个异步接入

等这条链路稳定后，再加：

- cancel 语义完善
- 大 payload 优化与零拷贝路径
