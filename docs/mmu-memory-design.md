# WinEmu-Kernel 内存管理与 MMU 技术设计

## 1. 概述

WinEmu-kernel 是运行在 macOS HVF (Hypervisor Framework) 之上的 ARM64 EL1 微内核，
负责加载 Windows PE 二进制并在 EL0 执行。内存管理分为三层：

1. **物理内存管理** — 通过 hypercall 向宿主 VMM 请求/释放物理页框
2. **虚拟内存管理** — 维护虚拟地址空间布局，分配/回收虚拟地址区间
3. **页表管理** — ARM64 三级页表 (L1→L2→L3)，负责 VA→GPA 映射

### 参考实现

- hermit-os/kernel `src/arch/aarch64/mm/paging.rs` — 页表结构与 PTE 操作
- hermit-os/kernel `src/arch/aarch64/kernel/start.rs` — MMU 寄存器配置时序
- hermit-os/kernel `src/mm/physicalmem.rs` — 物理页框分配器 (FrameAlloc)
- hermit-os/kernel `src/mm/virtualmem.rs` — 虚拟地址分配器 (PageAlloc)

### 与传统 OS 的核心差异

| 方面 | 传统 OS 内核 | WinEmu-Kernel |
|------|-------------|---------------|
| 物理内存 | 内核管理 (buddy/slab) | 通过 hypercall 委托宿主 VMM |
| 虚拟地址空间 | 内核管理 VMA/VaSpace | 相同，内核管理 VaSpace |
| 页表 | 多级页表，按需分页 | 相同，L1→L2→L3 三级页表 |
| TLB 管理 | IPI 多核广播 | 相同，多 vCPU 使用 TLBI IS 广播 |
| 文件 I/O | 内核文件系统驱动 | 通过 hypercall 读写宿主文件 |
| PE 加载 | 内核加载器 | 相同，内核侧 PE 加载器 |
| 换页/交换 | 有 | 无（所有内存常驻） |

## 2. 硬件上下文

- **架构**: ARMv8-A, AArch64, EL1 (内核) + EL0 (用户)
- **虚拟化**: macOS HVF — stage-2 透明，GPA = IPA
- **vCPU**: 多 vCPU（每个宿主线程绑定一个 HVF vCPU）
- **客户物理内存**: 基址 GPA = `0x4000_0000`，大小由 VMM 启动时通过 x0 传入
- **页粒度**: 4 KB
- **VA 宽度**: 39-bit (T0SZ = 25)
- **页表级数**: L1 → L2 → L3（无需 L0）

## 3. 物理内存管理

### 3.1 设计思路

传统 OS 内核通过 FDT/ACPI 探测物理内存，建立空闲页框链表（如 hermit-os 的
`FrameAlloc`）。WinEmu-kernel 运行在 HVF 之上，物理内存由宿主管理，内核通过
hypercall 按需申请和释放。

### 3.2 Hypercall 接口

```rust
// winemu-shared/src/lib.rs nr 模块
/// 分配连续物理页框
/// args: [num_pages, 0, 0, 0, 0, 0]
/// 返回: 首页 GPA（失败返回 0）
pub const ALLOC_PHYS_PAGES: u64 = 0x0800;

/// 释放连续物理页框
/// args: [gpa, num_pages, 0, 0, 0, 0]
pub const FREE_PHYS_PAGES:  u64 = 0x0801;
```

### 3.3 VMM 侧 GPA 分配器 (`gpa_alloc.rs`)

VMM 使用 **伙伴系统 (Buddy Allocator)** 管理动态 GPA 分配，配合内存池自动伸缩：

**核心参数**:
- 最小块 = 宿主页大小（通过 `sysconf(_SC_PAGESIZE)` 运行时获取，Apple Silicon 为 16KB）
- 伙伴阶数: 0 = 1 宿主页, 1 = 2 宿主页, ... MAX_ORDER-1 = 1024 宿主页
- MAX_ORDER = 11

**内存池管理**:
- 低水位 (POOL_LOW_PAGES = 16): 空闲页低于此值时触发 `grow_pool()`
- 增长批次 (POOL_GROW_PAGES = 64): 每次 mmap 分配 64 宿主页
- 高水位 (POOL_HIGH_PAGES = 256): 空闲页超过此值时触发 `shrink_pool()`

**API**:
```rust
/// 分配 size 字节的 guest 物理内存
/// size 必须 4KB 对齐，内部向上对齐到宿主页大小
/// 返回 (gpa, hva)，调用者需执行 hv_vm_map
pub fn alloc(&mut self, size: usize) -> Option<(Gpa, *mut u8)>;

/// 释放已分配区域，size 为原始请求大小（4KB 对齐）
pub fn free(&mut self, gpa: u64, size: usize) -> Option<usize>;
```

**分配流程**:
```
alloc(size):
  1. 检查 size 非零且 4KB 对齐
  2. 向上对齐到宿主页大小 → alloc_size
  3. 计算所需伙伴阶数 order
  4. 若空闲页不足 → grow_pool() (mmap + 插入伙伴空闲链)
  5. 从 order 空闲链取块；若无则递归拆分高阶块
  6. 解析 GPA → HVA，清零内存
  7. 返回 (gpa, hva)
```

**释放流程**:
```
free(gpa, size):
  1. 计算 order
  2. 归还到伙伴空闲链，尝试与伙伴合并（递归向上合并）
  3. shrink_pool(): 若空闲页 > POOL_HIGH_PAGES，
     扫描完全空闲的 chunk，munmap 归还宿主内存
```

**Hypercall 处理**:
```
ALLOC_PHYS_PAGES handler:
  1. size = num_pages * 4096
  2. gpa_alloc.alloc(size) → (gpa, hva)
  3. hv_vm_map(gpa, hva, alloc_size, RWX)
  4. 返回 gpa

FREE_PHYS_PAGES handler:
  1. size = num_pages * 4096
  2. hv_vm_unmap(gpa, alloc_size)
  3. gpa_alloc.free(gpa, size)
```

### 3.4 内核侧封装

```rust
// winemu-kernel/src/hypercall/mod.rs
pub fn alloc_phys_pages(num_pages: u64) -> u64 {
    hypercall(nr::ALLOC_PHYS_PAGES, num_pages, 0, 0)
}

pub fn free_phys_pages(gpa: u64, num_pages: u64) {
    hypercall(nr::FREE_PHYS_PAGES, gpa, num_pages, 0);
}
```

### 3.5 启动阶段的物理内存

VMM 在启动时通过 `GuestMemory::new(512MB)` 预分配并映射整个区域。
Phase 1 不需要 `ALLOC_PHYS_PAGES`，内核直接对预映射区域建立页表。
Phase 2 引入动态分配，GPA 分配器的 `next_gpa` 从预映射区域之后开始，
用于运行时扩展（新线程栈、共享内存段等）。

### 3.6 16KB 宿主页 vs 4KB 客户页

macOS Apple Silicon 宿主页大小为 16KB，而 Windows guest 使用 4KB 页。
两层映射独立处理：

- **Stage-2 (hv_vm_map)**: GPA、HVA、size 均需 16KB 对齐。
  GPA 分配器内部以宿主页为最小单位，保证对齐。
- **Stage-1 (guest 页表)**: L3 PTE 以 4KB 为粒度。
  一个 16KB 宿主页内可容纳 4 个独立的 4KB L3 映射，
  每个可有不同的保护属性（RW/RX/无访问）。

这意味着 guest 请求 4KB 时，实际分配 16KB 宿主页（内部对齐），
但 guest 页表仍以 4KB 粒度管理权限。

### 3.7 文件映射 — mmap 宿主文件与 16KB 对齐策略

VMM 可以直接 `mmap()` 宿主文件到 HVA，再通过 `hv_vm_map()` 映射到 GPA，
实现零拷贝文件映射。这是 NtMapViewOfSection 和 PE/DLL 加载的最优路径。

**对齐约束**:
- `mmap(fd, offset)` 在 macOS 上要求 offset 16KB 对齐，否则 EINVAL
- `hv_vm_map(gpa, hva, size)` 三个参数都必须 16KB 对齐
- 但 PE section 的 file offset 可能只是 4KB 对齐（如 .text 在 0x1000）
- `NtMapViewOfSection` 也允许 4KB 对齐的 offset

**方案：16KB 对齐宿主映射 + 4KB 粒度客户页表**

```
请求: 映射文件 offset=0x1000, size=0x3000 (12KB)

1. 宿主侧 — offset 向下对齐、size 向上对齐到 16KB:
   aligned_offset = offset & ~0x3FFF           = 0x0000
   inner_offset   = offset - aligned_offset     = 0x1000
   aligned_size   = align_up_16k(inner_offset + size) = 0x4000

2. VMM 执行:
   hva = mmap(NULL, 0x4000, PROT_READ, MAP_PRIVATE, fd, 0x0000)
   gpa = buddy_alloc(0x4000)  // 16KB 对齐
   hv_vm_map(gpa, hva, 0x4000, RX)

3. 返回给内核: gpa, inner_offset, aligned_size

4. 客户侧 — L3 页表以 4KB 粒度选择性映射:
   VA+0x000  → gpa+0x1000  (文件数据第 1 页)
   VA+0x1000 → gpa+0x2000  (文件数据第 2 页)
   VA+0x2000 → gpa+0x3000  (文件数据第 3 页)

   gpa+0x0000 的 4KB 不建立 L3 映射（padding，不可访问）
```

**PE section 加载优化**:

多个 section 落在同一个 16KB 对齐区间内时，只需一次 mmap + hv_vm_map，
通过不同的 L3 PTE 属性区分权限：

```
PE file layout:
  .text  FileOffset=0x0400  Size=0x1A00
  .rdata FileOffset=0x2000  Size=0x0800
  .data  FileOffset=0x2800  Size=0x0400

对 .text (offset=0x400, size=0x1A00):
  aligned_offset=0x0000, aligned_size=0x4000, inner_offset=0x400
  → mmap 16KB from file offset 0
  → L3 映射 0x400..0x1E00 范围的 4KB 页 (RX)

对 .rdata+.data (offset=0x2000, size=0xC00):
  aligned_offset=0x0000 (同一个 16KB 区间)
  → 可复用同一个 hv_vm_map
  → L3: .rdata 页 RO, .data 页 RW
```

**Hypercall 接口**:

```
HOST_MMAP hypercall:
  args: [host_fd, offset, size, prot, 0, 0]
  VMM 内部:
    1. aligned_offset = offset & ~(host_page_size - 1)
    2. inner_offset = offset - aligned_offset
    3. aligned_size = align_up_host(inner_offset + size)
    4. hva = mmap(NULL, aligned_size, prot, MAP_PRIVATE, fd, aligned_offset)
    5. gpa = buddy_alloc(aligned_size)
    6. hv_vm_map(gpa, hva, aligned_size, prot)
  返回: gpa | (inner_offset << 48)
  （高 16 位编码 inner_offset，最大 0x3FFF，足够）

HOST_MUNMAP hypercall:
  args: [gpa, aligned_size, 0, 0, 0, 0]
  VMM 内部:
    1. hv_vm_unmap(gpa, aligned_size)
    2. munmap(hva, aligned_size)
    3. buddy_free(gpa, aligned_size)
```

**优势**:
- 零拷贝——文件内容直接出现在 guest 物理地址空间
- 利用宿主页缓存，无需 guest 侧缓冲
- MAP_PRIVATE 保证写时复制，不影响宿主文件
- 每次映射最多浪费 12KB（一个 16KB 页内的 padding），可忽略

### 3.8 内核侧物理页管理器 (`mm/phys.rs`)

guest kernel 不应每次需要物理页时都发起 hypercall（VM exit 开销大），
而是维护自己的物理页池，批量从 host 获取，内部以 4KB 粒度管理。

**设计动机**:
- 每次 ALLOC_PHYS_PAGES hypercall 都是 VM exit，开销约数百 ns
- 小分配（4KB）在 VMM 侧被向上对齐到 16KB，浪费 12KB
- 频繁小分配/释放导致 VMM 伙伴系统碎片化
- 内核侧缓存物理页可大幅减少 hypercall 次数

**核心参数**:
- 批量分配单位: CHUNK_PAGES = 64（64 个 4KB 页 = 256KB = 16 个 host 页）
- 低水位: LOW_PAGES = 16（空闲页低于此值触发 grow）
- 高水位: HIGH_PAGES = 128（空闲页超过此值触发 shrink）
- 最大 chunk 数: MAX_CHUNKS = 64（最大管理 64 × 256KB = 16MB）

**数据结构**:
```rust
// winemu-kernel/src/mm/phys.rs (no_std, 无堆分配)

struct PhysChunk {
    base_gpa: u64,           // chunk 起始 GPA（由 ALLOC_PHYS_PAGES 返回）
    bitmap: u64,             // 64 位 bitmap，1=free, 0=allocated
}

pub struct PhysAllocator {
    chunks: [PhysChunk; MAX_CHUNKS],
    chunk_count: usize,
    free_page_count: usize,  // 全局空闲 4KB 页计数
}
```

每个 chunk 用 1 个 u64 bitmap 管理 64 个 4KB 页，利用硬件 CLZ/CTZ 指令
快速查找空闲位。

**API**:
```rust
/// 分配 1 个 4KB 物理页，返回 GPA
pub fn alloc_page(&mut self) -> Option<u64>;

/// 分配 n 个连续 4KB 物理页（同一 chunk 内），返回首页 GPA
pub fn alloc_pages(&mut self, n: usize) -> Option<u64>;

/// 释放 1 个 4KB 物理页
pub fn free_page(&mut self, gpa: u64);

/// 释放 n 个连续 4KB 物理页
pub fn free_pages(&mut self, gpa: u64, n: usize);
```

**分配流程**:
```
alloc_page():
  1. 若 free_page_count < LOW_PAGES → grow()
  2. 遍历 chunks，找 bitmap != 0 的 chunk
  3. CTZ(bitmap) → bit_idx，清除该位
  4. 返回 chunk.base_gpa + bit_idx * 4096

alloc_pages(n):
  1. 若 free_page_count < n + LOW_PAGES → grow()
  2. 遍历 chunks，在 bitmap 中查找连续 n 个 set bits
     （滑动窗口: mask = (1<<n)-1, 逐位移动检查）
  3. 清除对应位，返回首页 GPA
```

**释放流程**:
```
free_page(gpa):
  1. 定位 chunk: (gpa - chunk.base_gpa) / 4096 → bit_idx
  2. 设置 bitmap 对应位
  3. free_page_count += 1
  4. 若 free_page_count > HIGH_PAGES → shrink()

free_pages(gpa, n):
  1. 定位 chunk + bit_idx
  2. 设置连续 n 位
  3. free_page_count += n
  4. 若 free_page_count > HIGH_PAGES → shrink()
```

**池伸缩**:
```
grow():
  gpa = HVC ALLOC_PHYS_PAGES(CHUNK_PAGES)  // 批量分配 64 页 = 256KB
  新建 PhysChunk { base_gpa: gpa, bitmap: u64::MAX }
  free_page_count += CHUNK_PAGES

shrink():
  遍历 chunks，找 bitmap == u64::MAX 的（全部空闲）
  HVC FREE_PHYS_PAGES(chunk.base_gpa, CHUNK_PAGES)
  移除该 chunk
  free_page_count -= CHUNK_PAGES
  重复直到 free_page_count <= HIGH_PAGES
```

**与现有模块的关系**:
```
缺页处理 / VaSpace 操作
  │
  ▼
PhysAllocator.alloc_page()    ← 内核侧 4KB 粒度
  │
  ├─ 池中有空闲页 → 直接返回（无 VM exit）
  │
  └─ 池不足 → grow():
       HVC ALLOC_PHYS_PAGES(64)  ← 批量 hypercall
         │
         ▼
       VMM GpaAllocator.alloc(256KB)  ← VMM 侧 16KB 粒度伙伴系统
         │
         ▼
       hv_vm_map() 建立 stage-2
```

**优势**:
- 绝大多数 alloc_page() 无需 VM exit，仅需 bitmap 操作 + CTZ 指令
- 批量分配 256KB 在 VMM 侧是 16 个 host 页，对齐友好无浪费
- bitmap 天然支持连续分配（栈、大页等场景）
- 全部 no_std 兼容，固定大小数组，零堆分配
- shrink 只归还完全空闲的 chunk，不会打断部分使用的批次

## 4. Host 文件操作 Hypercall

### 4.1 设计思路

内核需要读写宿主文件系统（加载 PE/DLL、读取配置等），但不具备文件系统驱动。
通过一组专用 hypercall 委托 VMM 执行宿主文件操作。这些是内核内部的底层接口，
与 NT 系统调用（NtCreateFile 等）无关——NT syscall 由内核翻译后调用这些底层接口。

### 4.2 Hypercall 编号

```rust
// winemu-shared/src/lib.rs nr 模块
// ── Host 文件操作: 0x0810 - 0x081F ────────────────────
/// 打开宿主文件
/// args: [path_gpa, path_len, flags(0=RD,1=WR,2=RW,3=CREATE), 0, 0, 0]
/// 返回: host_fd (失败返回 -1)
pub const HOST_OPEN:       u64 = 0x0810;

/// 读取文件内容到 guest 内存
/// args: [host_fd, dst_gpa, len, offset(-1=current), 0, 0]
/// 返回: 实际读取字节数
pub const HOST_READ:       u64 = 0x0811;

/// 写入 guest 内存到文件
/// args: [host_fd, src_gpa, len, offset(-1=current), 0, 0]
/// 返回: 实际写入字节数
pub const HOST_WRITE:      u64 = 0x0812;

/// 关闭文件
/// args: [host_fd, 0, 0, 0, 0, 0]
pub const HOST_CLOSE:      u64 = 0x0813;

/// 查询文件大小
/// args: [host_fd, 0, 0, 0, 0, 0]
/// 返回: 文件大小（字节）
pub const HOST_STAT:       u64 = 0x0814;

/// mmap 宿主文件到 guest 物理地址空间（零拷贝）
/// args: [host_fd, offset, size, prot, 0, 0]
/// offset 可以是 4KB 对齐（VMM 内部向下对齐到 16KB）
/// 返回: gpa | (inner_offset << 48)
///   gpa = 16KB 对齐的映射基址
///   inner_offset = offset 对齐产生的偏移 (0..0x3FFF)
///   失败返回 0
pub const HOST_MMAP:       u64 = 0x0815;

/// 解除文件映射
/// args: [gpa, aligned_size, 0, 0, 0, 0]
/// gpa 和 aligned_size 必须是 16KB 对齐的（即 HOST_MMAP 返回的值）
pub const HOST_MUNMAP:     u64 = 0x0816;
```

### 4.3 内核侧封装

```rust
// winemu-kernel/src/hypercall/mod.rs
pub fn host_open(path: &[u8], flags: u64) -> i64 {
    hypercall(nr::HOST_OPEN,
              path.as_ptr() as u64, path.len() as u64, flags) as i64
}

pub fn host_read(fd: i64, dst: *mut u8, len: usize, offset: i64) -> usize {
    hypercall(nr::HOST_READ,
              fd as u64, dst as u64, len as u64) as usize
}

pub fn host_mmap(fd: i64, offset: u64, size: u64, prot: u64) -> (u64, u64) {
    // 返回值高 16 位编码 inner_offset
    let ret = hypercall(nr::HOST_MMAP, fd as u64, offset, size);
    let gpa = ret & 0x0000_FFFF_FFFF_FFFF;
    let inner_offset = ret >> 48;
    (gpa, inner_offset)
}

pub fn host_munmap(gpa: u64, aligned_size: u64) {
    hypercall(nr::HOST_MUNMAP, gpa, aligned_size, 0);
}
```

### 4.4 与 NT 系统调用的关系

```
NT 层 (EL0 用户代码调用)          内核底层 (hypercall)
─────────────────────────         ──────────────────────
NtCreateFile / NtOpenFile    →    host_open()
NtReadFile                   →    host_read()
NtWriteFile                  →    host_write()
NtClose                      →    host_close()
NtMapViewOfSection           →    host_mmap() + mm::map_page()
NtUnmapViewOfSection         →    mm::unmap_page() + host_munmap()
```

内核 SVC handler 接收 NT syscall，翻译参数后调用底层 host hypercall。
NT 句柄表由内核维护，映射 NT HANDLE → host_fd。

## 5. 虚拟内存管理

### 5.1 设计思路

虚拟内存管理负责维护虚拟地址空间的布局，跟踪哪些 VA 区间已分配、用途、保护属性。
这是 NtAllocateVirtualMemory / NtFreeVirtualMemory 等 NT 系统调用的底层支撑。

WinEmu 采用 **恒等映射 (VA = GPA)**，因此虚拟地址分配等价于 GPA 区间分配。
这大幅简化了实现——不需要维护独立的 VA→PA 映射关系。

### 5.2 虚拟地址空间布局

```
0x4000_0000 ┌─────────────────────────────┐
            │ 内核保留区                   │  内核镜像 + 栈 + 堆 + SVC 栈
            │ (0x4000_0000 ~ kernel_end)  │  约 4.2 MB
            ├─────────────────────────────┤
            │ EXE 加载缓冲区 (64 MB)      │  0x4080_0000 起
            ├─────────────────────────────┤
            │ 用户可分配区域               │  NtAllocateVirtualMemory
            │ (VaSpace 管理)              │  DLL 映射、线程栈、Section
            ├─────────────────────────────┤
            │ 页表页池                     │  静态池 + 动态 hypercall 分配
0x4000_0000+N └─────────────────────────────┘
```

### 5.3 VMA (Virtual Memory Area) 管理

每个已分配的虚拟地址区间用 VMA 结构描述：

```rust
pub struct Vma {
    pub base: u64,       // 起始 VA (页对齐)
    pub size: u64,       // 大小 (页对齐)
    pub prot: VmProt,    // 保护属性
    pub vma_type: VmaType, // 用途类型
}

pub enum VmaType {
    Kernel,          // 内核保留（不可释放）
    ExeImage,        // PE 主映像
    DllImage,        // DLL 映像
    ThreadStack,     // 线程栈
    Section,         // NtMapViewOfSection
    FileMapped,      // host_mmap 文件映射（零拷贝）
    Private,         // NtAllocateVirtualMemory
    PageTable,       // 页表页
}

bitflags! {
    pub struct VmProt: u32 {
        const READ    = 0x01;
        const WRITE   = 0x02;
        const EXEC    = 0x04;
    }
}
```

### 5.4 VaSpace — 虚拟地址空间管理器

```rust
pub struct VaSpace {
    vmas: Vec<Vma>,       // 按 base 排序的 VMA 列表
    base: u64,            // 可分配区域起始
    limit: u64,           // 可分配区域结束
}

impl VaSpace {
    /// 分配指定大小的虚拟地址区间
    /// hint=0 时自动查找空闲区间（首次适配）
    pub fn allocate(&mut self, hint: u64, size: u64, prot: VmProt,
                    vma_type: VmaType) -> Option<u64>;

    /// 释放虚拟地址区间
    pub fn free(&mut self, base: u64) -> Option<Vma>;

    /// 修改保护属性
    pub fn protect(&mut self, base: u64, size: u64, new_prot: VmProt) -> bool;

    /// 查询地址所属 VMA
    pub fn query(&self, addr: u64) -> Option<&Vma>;

    /// 查找包含指定地址的 VMA
    pub fn find_vma(&self, addr: u64) -> Option<&Vma>;
}
```

### 5.5 VaSpace 的位置

VaSpace 在 guest kernel 侧（`winemu-kernel/src/mm/`）实现，与传统 OS 内核一致。
内核直接管理虚拟地址空间布局，处理 NT 系统调用时由内核 SVC handler 操作 VaSpace，
仅在需要物理内存时通过 hypercall 请求 VMM 分配/释放物理页框。

这样设计的原因：

- 与传统 OS 架构一致——内核拥有完整的地址空间视图
- 内核同时管理 VaSpace 和页表，保证两者一致性
- VMM 仅负责物理资源（`hv_vm_map`/`hv_vm_unmap`），职责清晰
- 减少 hypercall 开销——纯虚拟地址操作无需陷出到 VMM

**数据流**:
```
EL0 用户代码
  → SVC → 内核 SVC handler
  → 内核 VaSpace.allocate() 分配 VA 区间
  → HVC ALLOC_PHYS_PAGES → VMM 分配物理页 + hv_vm_map()
  → 内核 mm::map_page() 更新页表
  → ERET 回 EL0，x0 = 分配的 VA
```

## 6. 页表管理

### 6.1 三级页表结构

T0SZ = 25 → 39-bit VA → L1 → L2 → L3:

```
VA[38:30]  →  L1 表 (512 项，每项覆盖 1 GB)
VA[29:21]  →  L2 表 (512 项，每项覆盖 2 MB)
VA[20:12]  →  L3 表 (512 项，每项覆盖 4 KB)
VA[11:0]   →  页内偏移 (12 bits)
```

### 6.2 描述符格式 (ARM ARM D5.3)

**表描述符** (L1→L2, L2→L3):
```
[47:12] = 下级表物理地址 (4KB 对齐)
[1:0]   = 0b11 (表描述符)
```

**L2 块描述符** (2 MB 映射):
```
[47:21] = 输出地址 [47:21] (2MB 对齐)
[10]    = AF (访问标志，必须为 1)
[9:8]   = SH (0b11 = 内部共享)
[7:6]   = AP (0b01 = EL1+EL0 读写)
[4:2]   = AttrIdx (MAIR 索引)
[1:0]   = 0b01 (块描述符)
```

**L3 页描述符** (4 KB 映射):
```
[54]    = UXN (非特权执行禁止)
[53]    = PXN (特权执行禁止)
[47:12] = 输出地址 [47:12] (4KB 对齐)
[10]    = AF (必须为 1)
[9:8]   = SH (0b11 = 内部共享)
[7:6]   = AP (访问权限)
[4:2]   = AttrIdx
[1:0]   = 0b11 (L3 页描述符)
```

### 6.3 PTE 标志位 (参考 hermit-os PageTableEntryFlags)

```rust
/// 页表项属性标志
pub struct PteFlags(u64);

impl PteFlags {
    const VALID:       u64 = 1 << 0;       // 有效位
    const TABLE_PAGE:  u64 = 1 << 1;       // 表描述符或 L3 页描述符
    const ATTR_NORMAL: u64 = 4 << 2;       // AttrIdx=4 → MAIR Normal WB
    const ATTR_DEVICE: u64 = 0 << 2;       // AttrIdx=0 → MAIR Device-nGnRnE
    const ATTR_NC:     u64 = 3 << 2;       // AttrIdx=3 → MAIR Normal NC
    const AP_EL1_RW:   u64 = 0b00 << 6;    // 仅 EL1 读写
    const AP_EL0_RW:   u64 = 0b01 << 6;    // EL1+EL0 读写
    const AP_EL1_RO:   u64 = 0b10 << 6;    // 仅 EL1 只读
    const AP_EL0_RO:   u64 = 0b11 << 6;    // EL1+EL0 只读
    const INNER_SH:    u64 = 0b11 << 8;    // 内部共享
    const AF:          u64 = 1 << 10;       // 访问标志
    const PXN:         u64 = 1 << 53;       // 特权执行禁止
    const UXN:         u64 = 1 << 54;       // 非特权执行禁止

    // 常用组合
    const BLOCK_NORMAL_RW: u64 = Self::VALID | Self::ATTR_NORMAL
        | Self::AP_EL0_RW | Self::INNER_SH | Self::AF;
    const PAGE_NORMAL_RW: u64 = Self::VALID | Self::TABLE_PAGE
        | Self::ATTR_NORMAL | Self::AP_EL0_RW | Self::INNER_SH | Self::AF;
    const TABLE_DESC: u64 = Self::VALID | Self::TABLE_PAGE;
}
```

### 6.4 页表分配器

页表页需要 4KB 对齐、清零。两种来源：

**静态池（启动阶段）**:
```rust
const PT_POOL_PAGES: usize = 4;  // L1 + L2 + 2 备用

#[repr(C, align(4096))]
struct PageTablePage([u64; 512]);

static mut PT_POOL: [PageTablePage; PT_POOL_PAGES] = ...;
static mut PT_POOL_NEXT: usize = 0;
```

**Hypercall（运行时）**: 静态池耗尽后通过 `ALLOC_PHYS_PAGES` 分配。

### 6.5 映射策略

**启动阶段 (Phase 1)**:
- 对 VMM 预映射的整个区域建立 L2 块描述符 (2 MB)
- L2 项数 = `mem_size / 2MB`
- 所有块: AP=0b01 (EL0+EL1 RW), AttrIdx=4 (Normal WB), AF=1, SH=内部共享
- 仅需 2 个页表页: 1 个 L1 + 1 个 L2

**运行时 (Phase 2)**:
- 需要细粒度控制时，将 2MB 块"打碎"为 L3 页表 (512 × 4KB)
- 用途: 栈保护页、W^X 强制、按需映射

### 6.6 核心操作 API

```rust
/// 构建恒等映射并启用 MMU
pub fn init(mem_size: u64);

/// 映射单个 4KB 页（如目标在 2MB 块内则先打碎）
pub fn map_page(va: u64, pa: u64, flags: PteFlags);

/// 取消映射单个 4KB 页
pub fn unmap_page(va: u64);

/// 修改已有映射的保护属性
pub fn protect_page(va: u64, flags: PteFlags);

/// 刷新单页 TLB
fn flush_tlb_page(va: u64);

/// 刷新全部 TLB
fn flush_tlb_all();
```

### 6.7 块打碎流程 (Break-Before-Make)

当 `map_page` 的目标 VA 当前由 2MB L2 块覆盖时：

```
1. 读取 L2 块描述符，记录原始属性
2. 将 L2 项写为 0（无效化）         ← break
3. TLBI + DSB + ISB                  ← 确保旧映射失效
4. 分配新 L3 页表页（清零）
5. 填充 512 个 L3 页描述符，继承原块属性
6. 修改目标 L3 项为新属性
7. 将 L2 项写为表描述符指向 L3      ← make
8. DSB + ISB
```

## 7. 页面映射管理 — 端到端流程

### 7.1 NtAllocateVirtualMemory 流程

```
用户 EL0: NtAllocateVirtualMemory(hint, size, prot)
  │
  ▼ SVC → 内核 SVC handler
  │
  ├─ 内核 VaSpace.allocate(hint, size, prot, Private)
  │   → 找到空闲 VA 区间，创建 VMA
  │
  ├─ 如果 Phase 1（全区域已映射）:
  │   → 直接返回 VA（物理页已由启动时 hv_vm_map 覆盖）
  │
  ├─ 如果 Phase 2（按需映射）:
  │   → HVC ALLOC_PHYS_PAGES(num_pages) → VMM 分配物理页
  │   → 内核 mm::map_page() 逐页建立 L3 映射
  │   → 返回 VA
  │
  ▼ ERET 回 EL0，x0 = 分配的 VA
```

### 7.2 NtFreeVirtualMemory 流程

```
用户 EL0: NtFreeVirtualMemory(base)
  │
  ▼ SVC → 内核 SVC handler
  │
  ├─ 内核 VaSpace.free(base) → 移除 VMA
  │
  ├─ Phase 1: 不做物理释放（全区域常驻）
  │
  ├─ Phase 2:
  │   → 内核 mm::unmap_page() 清除 L3 映射
  │   → HVC FREE_PHYS_PAGES(gpa, num_pages) → VMM 释放物理页
  │
  ▼ 返回 STATUS_SUCCESS
```

### 7.3 NtProtectVirtualMemory 流程

```
用户 EL0: NtProtectVirtualMemory(base, size, new_prot)
  │
  ▼ SVC → 内核 SVC handler
  │
  ├─ 内核 VaSpace.protect(base, size, new_prot) → 更新 VMA
  │
  ├─ Phase 1: 仅更新 VMA 元数据（2MB 块无法细粒度保护）
  │
  ├─ Phase 2:
  │   → 内核 mm::protect_page() 修改 L3 PTE 属性
  │   → TLBI VALE1IS + DSB ISH + ISB（多 vCPU 广播）
  │
  ▼ 返回 STATUS_SUCCESS
```

### 7.4 线程栈分配

```
内核 SVC handler 处理 THREAD_CREATE:
  1. 内核 VaSpace.allocate(0, stack_size, RW, ThreadStack)
  2. Phase 2: 底部 1 页设为 guard page（unmap 或 AP=无访问）
  3. 返回 stack_top VA
```

### 7.5 DLL/PE 加载

内核侧 PE 加载器通过 host 文件 hypercall 读取 DLL 文件，自行完成映像映射：

```
内核 PE 加载器:
  1. HVC HOST_OPEN(dll_path, RD) → 获取 host_fd
  2. HVC HOST_READ(fd, buf, len, 0) → 读取 PE 头部
  3. 解析 PE 头: SizeOfImage, SectionAlignment, 各 Section
  4. 内核 VaSpace.allocate(0, image_size, RWX, DllImage)
  5. 方案 A（零拷贝）: HVC HOST_MMAP(fd, 0, image_size, RX) → 获取 (gpa, inner_offset)
     内核 mm::map_page() 以 4KB 粒度建立 VA→(gpa+inner_offset) 映射
     不同 section 通过 L3 PTE 设置不同权限（.text RX, .data RW）
  6. 方案 B（逐段读取）: HVC ALLOC_PHYS_PAGES + mm::map_page()
     HVC HOST_READ() → 逐 Section 读入对应 VA
  7. 处理重定位、导入表解析
  8. HVC HOST_CLOSE(fd)
  9. 返回 dll_base VA
```

## 8. 缺页异常处理

### 8.1 设计思路

缺页（Data Abort / Instruction Abort from EL0）是实现按需映射的核心机制。
VMM 通过 `hv_vm_map()` 建立 stage-2（GPA→HVA）映射，但 guest 内核的
stage-1 页表可以延迟建立。当 EL0 访问未映射的 VA 时，触发同步异常，
内核在异常处理中查询 VaSpace，按需建立 PTE。

### 8.2 异常类型

```
ESR_EL1.EC:
  0x20 — Instruction Abort from lower EL (EL0 取指缺页)
  0x24 — Data Abort from lower EL (EL0 数据缺页)

ESR_EL1.ISS.DFSC / IFSC:
  0x04 — Translation fault, level 0
  0x05 — Translation fault, level 1
  0x06 — Translation fault, level 2
  0x07 — Translation fault, level 3  ← 最常见，L3 PTE 缺失
  0x09 — Access flag fault, level 1
  0x0B — Access flag fault, level 3
  0x0D — Permission fault, level 1
  0x0F — Permission fault, level 3  ← 权限违规（如写只读页）
```

### 8.3 缺页处理流程

```
EL0 访问未映射 VA
  │
  ▼ Data Abort → vectors.rs sync_handler
  │
  ├─ 读取 ESR_EL1, FAR_EL1（故障地址）
  │
  ├─ 查询 VaSpace.find_vma(far)
  │   │
  │   ├─ 未找到 VMA → 非法访问，发送 SIGSEGV / 终止进程
  │   │
  │   └─ 找到 VMA → 检查访问权限
  │       │
  │       ├─ Permission fault + 权限不匹配 → SIGSEGV
  │       │
  │       └─ Translation fault → 按需映射:
  │           │
  │           ├─ VmaType::FileMapped:
  │           │   GPA 已由 HOST_MMAP 建立 stage-2
  │           │   → mm::map_page(va, gpa, flags) 建立 L3 PTE
  │           │
  │           ├─ VmaType::Private / ThreadStack:
  │           │   → HVC ALLOC_PHYS_PAGES(1) 分配物理页
  │           │   → mm::map_page(va, gpa, flags)
  │           │   → 清零页面内容
  │           │
  │           └─ VmaType::DllImage / ExeImage:
  │               → 从 VMA 元数据获取 GPA
  │               → mm::map_page(va, gpa, flags)
  │
  ▼ ERET 回 EL0，重新执行故障指令
```

### 8.4 按需映射 vs 预映射

| 策略 | 适用场景 | 优势 |
|------|---------|------|
| 预映射 | Phase 1 启动、小区域 | 简单，无缺页开销 |
| 按需映射 | 大内存分配、文件映射 | 节省物理内存，启动快 |

Phase 1 使用 2MB 块预映射整个区域，不会触发缺页。
Phase 2 引入按需映射后，NtAllocateVirtualMemory 可以只记录 VMA 而不立即
分配物理页，首次访问时通过缺页处理分配并映射。

### 8.5 文件映射的缺页路径

NtMapViewOfSection 的典型实现：

```
NtMapViewOfSection(section, base, size):
  1. 内核 VaSpace.allocate(base, size, prot, FileMapped)
  2. HVC HOST_MMAP(fd, offset, size, prot) → 获取 (gpa, inner_offset)
     VMM: offset 向下对齐 16KB → mmap() + hv_vm_map() 建立 stage-2
  3. 记录 VMA.gpa_base = gpa + inner_offset（不建立 stage-1 PTE）
  4. 返回 VA

首次访问 VA:
  → Data Abort (Translation fault)
  → 查 VMA → FileMapped → mm::map_page(va, vma.gpa_base + offset, flags)
  → ERET，零拷贝访问文件内容
```

## 9. MMU 寄存器配置

### 9.1 MAIR_EL1 (参考 hermit-os start.rs)

采用 hermit-os 的 5 个 MAIR 索引：

```
idx 0: 0x00 — Device-nGnRnE
idx 1: 0x04 — Device-nGnRE
idx 2: 0x0c — Device-GRE
idx 3: 0x44 — Normal Non-Cacheable
idx 4: 0xFF — Normal Write-Back RW-Allocate

MAIR_EL1 = 0x0000_00FF_440C_0400
```

内核和用户内存使用 AttrIdx=4（Normal 可缓存），这对以下功能至关重要：
- HVF 下页表遍历的正确性
- LDXR/STXR 原子操作（要求可缓存 Normal 内存）

### 9.2 TCR_EL1

```
T0SZ   = 25        [5:0]    39-bit VA
IRGN0  = 0b01      [9:8]    内部 WB-WA（可缓存页表遍历）
ORGN0  = 0b01      [11:10]  外部 WB-WA
SH0    = 0b11      [13:12]  内部共享
TG0    = 0b00      [15:14]  4 KB 粒度
EPD1   = 1         [23]     禁用 TTBR1 遍历
IPS    = 从 ID_AA64MMFR0_EL1.PARange 读取 [34:32]
```

**关键**: IPS 从硬件寄存器读取而非硬编码，确保在不同 Apple Silicon 芯片上正确。

### 9.3 SCTLR_EL1

参考 hermit-os `smp_start`（值 `0x0405D01D`）：

```
M   [0]  = 1   启用 MMU
A   [1]  = 0   禁用对齐检查
C   [2]  = 1   启用数据缓存 ← 关键
SA  [3]  = 1   栈对齐检查
SA0 [4]  = 1   EL0 栈对齐检查
I   [12] = 1   启用指令缓存 ← 关键
WXN [19] = 0   无写即不可执行
```

**之前失败的根因**: C=0, I=0。HVF 下页表遍历要求可缓存内存属性，
禁用缓存导致硬件遍历器产生同步外部中止 (DFSC=0x15)。

## 10. MMU 启用时序

参考 hermit-os `smp_start` (start.rs 156-248 行)：

```
 1. DSB SY                           — 排空所有待处理内存操作
 2. IC IALLU                         — 无效化指令缓存
 3. TLBI VMALLE1IS                   — 无效化所有 TLB 项
 4. DSB ISH                          — 确保无效化完成
 5. MSR MAIR_EL1, <mair>            — 设置内存属性
 6. MSR TCR_EL1, <tcr>              — 设置翻译控制
 7. MSR TTBR0_EL1, <l1_base>        — 设置页表基址
 8. DSB SY                           — 确保寄存器写入完成
 9. ISB                              — 上下文同步
10. MSR SCTLR_EL1, <sctlr>          — 启用 MMU + 缓存
11. ISB                              — MMU 启用后同步
```

## 11. 集成与启动流程

```
_start:
    清零 BSS，设置 SP
    x0 = mem_size（VMM 设置）
    bl kernel_main

kernel_main(mem_size):
    1. vectors::install()       — 设置 VBAR_EL1
    2. mm::init(mem_size)       — 构建页表 + 启用 MMU
    3. alloc::init()            — bump 分配器（MMU 已开启）
    4. vaspace::init()          — 初始化 VaSpace，注册内核保留区
    5. PE 加载器: 通过 host 文件 hypercall 读取 EXE，映射各 Section
    6. 初始化 TEB/PEB
    7. kernel_ready hypercall   — 通知 VMM 内核就绪，传入入口点和栈
```

## 12. 实现计划

### Phase 1（当前）
1. 重写 `mm/mod.rs`: 静态 L1+L2 在 BSS，2MB 块恒等映射
2. 按第 10 节时序启用 MMU（缓存开启）
3. MAIR 5 索引，TCR 从硬件读 IPS
4. 测试: 内核启动、原子操作正常、EL0 代码运行

### Phase 2（已完成）
1. ✅ `ALLOC_PHYS_PAGES` / `FREE_PHYS_PAGES` hypercall
2. ✅ VMM 侧伙伴系统 GPA 分配器（内存池 grow/shrink、运行时宿主页大小）
3. ✅ L3 页表支持 + 块打碎 (Break-Before-Make)
4. ✅ VaSpace 内核侧实现（VMA 管理、首次适配分配器）
5. 内核侧物理页管理器（PhysAllocator，bitmap 池，批量 hypercall）
6. 栈保护页（guard page）
7. W^X 强制（代码页 RX，数据页 RW）
8. VaSpace 与页表联动（NtProtectVirtualMemory 修改 PTE）

### Phase 3
1. Host 文件操作 hypercall（HOST_OPEN/READ/WRITE/CLOSE/STAT）
2. HOST_MMAP / HOST_MUNMAP — 零拷贝文件映射
3. 缺页异常处理（Data Abort from EL0 → 按需建立 PTE）
4. NtMapViewOfSection 基于缺页的延迟映射
5. PE/DLL 加载器迁移到内核侧，使用 host 文件 hypercall
