# WinEmu 架构职责划分

## 核心原则

**Guest Kernel（EL1）** 负责一切可以在 guest 内部完成的事情，不需要访问 host 资源。
**Host VMM** 只负责 guest 无法自己完成的事情：访问 host 文件系统、host 内存、host 内核对象。
**Hypercall** 是两者之间唯一的通信通道，应当尽量减少调用次数和传递的数据量。

---

## 当前架构的问题

目前几乎所有逻辑都在 VMM 里，guest kernel 只做了 PE 加载和 SVC 转发。每次 NT syscall 都触发一次 VM exit（HVC），开销约 1–5 μs，比原生 syscall 慢 20–100x。

具体问题：

- **调度器在 host**：线程切换、等待、超时全部在 VMM 里，每次 yield/block 都需要 HVC
- **同步原语在 host**：Event/Mutex/Semaphore 的状态机在 VMM，guest 无法直接操作
- **虚拟内存管理在 host**：VaSpace 在 VMM，NtAllocateVirtualMemory 每次都走 HVC
- **PE 加载混乱**：EXE 由 guest kernel 加载，DLL 由 VMM 加载，职责不统一
- **TEB/PEB 由 guest 构造**：但 VMM 也需要知道 TEB 地址，存在耦合

---

## 目标架构

### Guest Kernel 负责

| 功能 | 说明 |
|------|------|
| **PE 加载（EXE + DLL）** | 全部在 guest 内完成；DLL 文件内容由 VMM 通过 hypercall 提供，但解析/重定位/IAT 填充在 guest |
| **虚拟地址空间管理** | VaSpace 移入 guest kernel；NtAllocateVirtualMemory / NtFreeVirtualMemory 不再走 HVC，直接在 guest 内分配 VA，然后用一次 hypercall 通知 VMM 建立物理映射 |
| **TEB / PEB 构造** | 完全在 guest 内，VMM 只需知道 TEB 基址（通过 KERNEL_READY 传递） |
| **同步原语状态机** | Event/Mutex/Semaphore 的 signal/wait 逻辑在 guest；只有真正需要阻塞（无法在 guest 内自旋解决）时才走 HVC |
| **线程调度（用户态）** | 简单的 round-robin 或优先级队列在 guest 内维护；VMM 只提供 vCPU 时间片 |
| **异常向量 / SVC 分发** | 现有设计保留 |
| **堆分配器（用户堆）** | RtlAllocateHeap / RtlFreeHeap 在 guest ntdll 内实现，不走 HVC |

### Host VMM 负责

| 功能 | 说明 |
|------|------|
| **物理内存映射** | 响应 guest 的 MAP_PAGES / UNMAP_PAGES hypercall，建立 GPA→HPA 映射 |
| **文件 I/O** | NtCreateFile / NtReadFile / NtWriteFile / NtClose 等，访问 host 文件系统 |
| **DLL 文件内容提供** | 响应 LOAD_DLL_IMAGE hypercall，把 DLL 文件内容写入 guest 内存；解析/重定位由 guest 完成 |
| **真正的阻塞等待** | 当 guest 需要等待一个 host 事件（如文件 I/O 完成、定时器）时，VMM 负责阻塞 vCPU 线程 |
| **进程/线程生命周期** | NtCreateProcess / NtTerminateProcess 等需要 host 资源的操作 |
| **时钟 / 定时器** | NtQuerySystemTime、NtDelayExecution 等需要 host 时钟的操作 |
| **注册表** | 维护 in-process 注册表数据库（现有设计保留） |
| **调试输出** | DEBUG_PRINT hypercall（现有设计保留） |

### 不需要 Hypercall 的操作（全部在 guest 完成）

- NtAllocateVirtualMemory / NtFreeVirtualMemory（VA 分配在 guest，物理映射按需触发缺页）
- NtProtectVirtualMemory（guest 内部权限管理）
- NtQueryVirtualMemory（查询 guest 自己的 VaSpace）
- RtlAllocateHeap / RtlFreeHeap（用户堆，ntdll 内实现）
- RtlInitializeCriticalSection / RtlEnterCriticalSection（无竞争路径，guest 内自旋）
- NtYieldExecution（guest 内调度器处理）
- NtCreateEvent / NtSetEvent / NtResetEvent（无跨进程场景时，guest 内状态机）
- NtCreateMutex / NtReleaseMutex（同上）
- NtCreateSemaphore / NtReleaseSemaphore（同上）

---

## Hypercall 接口重新设计

### 保留的 Hypercall

```
KERNEL_READY        (0x0000)  — 内核启动完成，传递 entry/stack/teb/heap_end
DEBUG_PRINT         (0x0001)  — 调试输出
LOAD_DLL_IMAGE      (0x0300)  — 请求 VMM 把 DLL 文件内容写入 guest buffer
```

### 新增 / 替换

```
MAP_PAGES           (0x0100)  — guest 请求 VMM 建立 GPA 物理映射（替代 NT_ALLOC_VIRTUAL）
UNMAP_PAGES         (0x0101)  — 解除映射

NT_CREATE_FILE      (0x0400)  — 保留（需要 host 文件系统）
NT_OPEN_FILE        (0x0401)
NT_READ_FILE        (0x0402)
NT_WRITE_FILE       (0x0403)
NT_CLOSE            (0x0404)
NT_QUERY_INFO_FILE  (0x0405)

BLOCK_THREAD        (0x0600)  — guest 请求阻塞当前线程，等待 host 事件
WAKE_THREAD         (0x0601)  — VMM 唤醒指定线程（内部使用）

NT_DELAY_EXECUTION  (0x0700)  — sleep，需要 host 定时器
NT_QUERY_SYSTEM_TIME (0x0701) — 获取 host 时钟
NT_TERMINATE_PROCESS (0x0702) — 进程退出
```

### 删除的 Hypercall（移入 guest）

```
NT_ALLOC_VIRTUAL    → guest VaSpace + MAP_PAGES
NT_FREE_VIRTUAL     → guest VaSpace + UNMAP_PAGES
NT_PROTECT_VIRTUAL  → guest VaSpace
NT_QUERY_VIRTUAL    → guest VaSpace
NT_CREATE_SECTION   → guest（pagefile-backed）；file-backed 仍需 host
NT_MAP_VIEW_OF_SECTION → guest（pagefile-backed）
NT_UNMAP_VIEW_OF_SECTION → guest
NT_CREATE_EVENT     → guest
NT_SET_EVENT        → guest
NT_RESET_EVENT      → guest
NT_CREATE_MUTEX     → guest
NT_RELEASE_MUTEX    → guest
NT_CREATE_SEMAPHORE → guest
NT_RELEASE_SEMAPHORE → guest
NT_WAIT_SINGLE      → guest（无竞争）；有竞争时走 BLOCK_THREAD
NT_WAIT_MULTIPLE    → 同上
NT_YIELD_EXECUTION  → guest 调度器
THREAD_CREATE       → guest 调度器（VMM 只需知道新线程的入口）
THREAD_EXIT         → guest 调度器
```

---

## 迁移路径（建议顺序）

1. **VaSpace 移入 guest**：实现 guest 内 VA 分配器 + MAP_PAGES hypercall；删除 VMM 侧 VaSpace
2. **同步原语移入 guest**：在 guest kernel 实现 Event/Mutex/Semaphore 状态机；VMM 只保留 BLOCK_THREAD
3. **DLL 加载统一到 guest**：VMM 只提供文件内容，guest 负责全部解析/重定位/IAT
4. **调度器移入 guest**：guest 维护线程队列，VMM 只提供 vCPU 时间片和 BLOCK_THREAD/WAKE_THREAD
5. **Section 移入 guest**：pagefile-backed section 完全在 guest 内管理

---

## 性能预期

| 操作 | 当前（全走 HVC） | 目标（guest 内处理） |
|------|----------------|-------------------|
| NtAllocateVirtualMemory | ~2 μs | ~50 ns（guest bump alloc） |
| NtCreateEvent / NtSetEvent | ~2 μs each | ~10 ns（guest 原子操作） |
| NtWaitForSingleObject（已 signal） | ~2 μs | ~20 ns（guest 检查） |
| NtYieldExecution | ~2 μs | ~100 ns（guest 调度器） |
| NtWriteFile（stdout） | ~2 μs | ~2 μs（仍需 HVC，访问 host） |
| NtCreateFile | ~5 μs | ~5 μs（仍需 HVC，访问 host） |

文件 I/O 和真正的阻塞等待无法避免 HVC，其余操作可以降低 10–100x。
