# vaspace 虚拟地址空间管理重构方案

## 一、现状分析

### 1.1 两套并存的死活代码

| 文件 | 状态 | 说明 |
|---|---|---|
| `src/mm/vaspace.rs` | **死代码** | 旧的 `VaSpace`，固定 256 槽位数组，NT 路径完全没有使用 |
| `src/nt/state.rs` | **实际工作** | `VmRegion` + 全局 `ObjectStore<VmRegion>`，所有进程混放 |

### 1.2 核心问题

| 问题 | 具体表现 | 影响 |
|---|---|---|
| 全局 flat store | `regions_store_mut()` 混放所有进程的 VmRegion，依赖 `owner_pid` 字段区分 | 进程隔离差，难以审计 |
| O(n²) 查找 | `vm_find_free_base` 每次循环都全表扫描；`vm_find_region` 线性扫描全部 region | 进程 region 多时性能退化 |
| 无 split/merge | Region 边界创建后固定，`VirtualProtect` 跨 region 边界会失败 | NT 语义不完整 |
| 双命名系统 | `VmaType` (mm/vaspace.rs) 与 `VM_KIND_*` 常量 (nt/state.rs) 并存 | 命名混乱 |
| 裸指针数组 | `phys_pages: *mut u64`，`prot_pages: *mut u32`，`commit_bits: *mut u64` | 无生命周期约束，容易泄漏 |
| `vm_find_region` 语义模糊 | 既按 base 查，又按 addr-in-range 查，调用方需要自行区分 | 容易误用 |

### 1.3 现有 VmRegion 的关键字段（需要完整保留语义）

```
VmRegion {
    owner_pid, base, size, default_prot, kind,
    page_count,
    phys_pages: *mut u64,   // per-page GPA; 0 => not yet mapped
    prot_pages: *mut u32,   // per-page NT protection
    commit_bits: *mut u64,  // 1 bit per page, packed
    commit_words: usize,
    section_file_fd, section_file_offset, section_view_size,
    section_file_backed, section_is_image,
    owns_phys_pages,
}
```

---

## 二、参考实现分析（Quark AreaSet）

参考文件：
- `qkernel/src/qlib/mem/areaset.rs` — 通用区间集合数据结构
- `qkernel/src/qlib/kernel/memmgr/mm.rs` — MemoryManager 使用示例

### 2.1 AreaSet 核心设计

`AreaSet<T: AreaValue>` 的内部结构：
- `BTreeMap<u64, AreaEntry<T>>` — 按 start 地址索引，O(log n) 查找
- 双向链表（`head` dummy → seg1 → seg2 → ... → `tail` dummy）— 支持相邻 seg/gap 的 O(1) 遍历
- `AreaSeg` / `AreaGap` — 两种迭代器，分别代表「已占用区间」和「空洞」

```
                head
                 │
        ┌────────▼──────────────────────────────────────────┐
        │  dummy(start=va_base, len=0)                       │
        └────────┬──────────────────────────────────────────┘
                 │ next
        ┌────────▼──────────────────────────────────────────┐
gap0    │  [va_base .. seg1.start)                           │
        └───────────────────────────────────────────────────┘
        ┌────────▼──────────────────────────────────────────┐
seg1    │  AreaEntry { range, value: VmArea }                │
        └────────┬──────────────────────────────────────────┘
                 │ next
        ┌────────▼──────────────────────────────────────────┐
gap1    │  [seg1.end .. seg2.start)                          │
        └───────────────────────────────────────────────────┘
        ...
        ┌────────▼──────────────────────────────────────────┐
        │  dummy(start=va_limit, len=0)                      │
        └───────────────────────────────────────────────────┘
                tail
```

### 2.2 AreaValue trait

```rust
pub trait AreaValue: Clone {
    // 判断相邻的两个 seg 是否可以合并；能合并则返回 Some(merged_val)
    fn merge(&self, r1: &Range, r2: &Range, other: &Self) -> Option<Self>;
    // 在 at 地址处把当前 seg 拆成两个
    fn split(&self, r: &Range, at: u64) -> (Self, Self);
}
```

### 2.3 关键操作接口

| 操作 | 方法 | 说明 |
|---|---|---|
| 查找地址所在 seg | `find(key)` → `(AreaSeg, AreaGap)` | 返回 seg（命中）或 gap（未命中） |
| 找 seg 下界 | `lower_bound_seg(key)` | 最低的包含 ≥ key 的 seg |
| 找 gap | `find_gap(key)` | 包含 key 的空洞 |
| 插入 | `insert(gap, range, val)` | 插入并尝试与邻居合并 |
| 删除 | `remove(seg)` | 删除 seg，返回空出的 gap |
| 范围删除 | `remove_range(range)` | 自动 isolate 边界 seg |
| 分裂 | `split(seg, at)` | 在 at 处把 seg 一分为二 |
| 隔离 | `isolate(seg, range)` | 确保 seg 不超出 range 边界（自动 split） |
| 合并相邻 | `merge_adjacent(range)` | 尝试合并 range 首尾的邻居 |

### 2.4 需要适配 winemu-kernel 的部分

| Quark 依赖 | winemu-kernel 替换 |
|---|---|
| `QMutex<AreaEntryInternal<T>>` | `SpinLock<AreaEntryInternal<T>>`（已有） |
| `Arc<QMutex<...>>` | `alloc::sync::Arc<SpinLock<...>>` |
| `Weak<QMutex<...>>` | `alloc::sync::Weak<SpinLock<...>>` |
| `BTreeMap` | `alloc::collections::BTreeMap`（已有 extern crate alloc） |
| `QUpgradableLock` | 移除，`AreaSet` 本身不加锁，外层负责 |
| `String` / `Vec` | `alloc::string::String` / `alloc::vec::Vec` |
| Quark 特有的 `Range` 类型 | 自定义轻量 `Range` 结构体 |

---

## 三、目标架构

### 3.1 整体关系

```
KProcess
 ├── address_space: ProcessAddressSpace   ← 保留（ARM64 页表硬件管理）
 └── vm: ProcessVmManager                 ← 新增（替换全局 regions store）
      └── vmas: AreaSet<VmArea>           ← BTreeMap + 双向链表，O(log n)
           └── VmArea                     ← 含 Box<[u64]> 等安全数组

nt/state.rs（VM 相关函数）
  vm_find_region(pid, addr)   →  with_process(pid, |p| p.vm.find_vma(addr))
  vm_find_free_base(pid, ..)  →  p.vm.find_free_va(hint, size)
  vm_create_region(..)        →  p.vm.reserve(..)
  vm_commit_region_pages(..)  →  p.vm.commit(..)
  vm_protect_range(..)        →  p.vm.protect(..)   // 自动 split/merge
  vm_handle_page_fault(..)    →  p.vm.handle_page_fault(..)
  vm_query_region(..)         →  p.vm.query(..)
  cleanup_process(..)         →  p.vm.cleanup_all()
```

`ProcessAddressSpace` 管理 ARM64 页表硬件（TTBR0/L0/L1/L2/L3），
`ProcessVmManager` 管理 VMA 语义（reserved/committed/prot/guard），两者职责分明。

---

## 四、新增文件

### 4.1 `src/mm/range.rs`

轻量 Range 工具类型，移植自 Quark 但精简为 winemu-kernel 所需的最小集合：

```rust
/// [start, start+len) 半开区间
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Range {
    pub start: u64,
    pub len: u64,
}

impl Range {
    pub fn new(start: u64, len: u64) -> Self;
    pub fn end(&self) -> u64;                          // start + len
    pub fn contains(&self, addr: u64) -> bool;        // start <= addr < end
    pub fn overlaps(&self, other: &Range) -> bool;
    pub fn is_superset_of(&self, other: &Range) -> bool;
    pub fn can_split_at(&self, addr: u64) -> bool;    // start < addr < end
    pub fn intersect(&self, other: &Range) -> Range;  // 交集（可能 len=0）
}
```

### 4.2 `src/mm/areaset.rs`

从 Quark 移植，适配后的完整接口：

```rust
pub trait AreaValue: Clone {
    fn merge(&self, r1: &Range, r2: &Range, other: &Self) -> Option<Self>;
    fn split(&self, r: &Range, at: u64) -> (Self, Self);
}

// 链表节点（Arc 包装，通过 SpinLock 内部可变）
pub struct AreaEntry<T: AreaValue>(Arc<SpinLock<AreaEntryInternal<T>>>);
pub struct AreaSeg<T: AreaValue>(AreaEntry<T>);          // 代表一个已占用区间
pub struct AreaGap<T: AreaValue>(AreaEntry<T>);          // 代表 entry 后面的空洞

pub struct AreaSet<T: AreaValue> {
    range: Range,       // 整个可管理范围
    head: AreaEntry<T>, // dummy head（range=[va_base, 0)）
    tail: AreaEntry<T>, // dummy tail（range=[va_limit, 0)）
    map: BTreeMap<u64, AreaEntry<T>>,  // start -> entry
}

impl<T: AreaValue> AreaSet<T> {
    pub fn new(start: u64, len: u64) -> Self;

    // 查询
    pub fn find(&self, key: u64) -> (AreaSeg<T>, AreaGap<T>);
    pub fn find_seg(&self, key: u64) -> AreaSeg<T>;
    pub fn lower_bound_seg(&self, key: u64) -> AreaSeg<T>;
    pub fn upper_bound_seg(&self, key: u64) -> AreaSeg<T>;
    pub fn find_gap(&self, key: u64) -> AreaGap<T>;
    pub fn lower_bound_gap(&self, key: u64) -> AreaGap<T>;
    pub fn first_seg(&self) -> AreaSeg<T>;
    pub fn last_seg(&self) -> AreaSeg<T>;
    pub fn first_gap(&self) -> AreaGap<T>;
    pub fn last_gap(&self) -> AreaGap<T>;
    pub fn is_empty(&self) -> bool;
    pub fn is_empty_range(&self, r: &Range) -> bool;

    // 修改
    pub fn insert(&mut self, gap: &AreaGap<T>, r: &Range, val: T) -> AreaSeg<T>;
    pub fn insert_without_merging(&mut self, gap: &AreaGap<T>, r: &Range, val: T) -> AreaSeg<T>;
    pub fn remove(&mut self, seg: &AreaSeg<T>) -> AreaGap<T>;
    pub fn remove_range(&mut self, r: &Range) -> AreaGap<T>;
    pub fn split(&mut self, seg: &AreaSeg<T>, at: u64) -> (AreaSeg<T>, AreaSeg<T>);
    pub fn split_at(&mut self, at: u64) -> bool;
    pub fn isolate(&mut self, seg: &AreaSeg<T>, r: &Range) -> AreaSeg<T>;
    pub fn merge(&mut self, first: &AreaSeg<T>, second: &AreaSeg<T>) -> AreaSeg<T>;
    pub fn merge_adjacent(&mut self, r: &Range);
    pub fn merge_all(&mut self);
    pub fn apply_contiguous(&mut self, r: &Range, f: impl FnMut(&AreaEntry<T>)) -> AreaGap<T>;
}
```

### 4.3 `src/mm/vm_area.rs`

NT-semantics VMA，替换掉 `VmRegion`：

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmKind {
    Private,      // MEM_PRIVATE — VirtualAlloc 私有内存
    Section,      // MEM_MAPPED/MEM_IMAGE — NtMapViewOfSection
    ThreadStack,  // 线程栈（与 Private 类似但有 guard page 生长语义）
    FileMapping,  // 已存在的文件映射（boot 阶段 track，owns_phys_pages=false）
}

/// NT-semantics Virtual Memory Area
/// 注意：per-page 数组通过 Box<[T]> 持有，无裸指针
#[derive(Clone)]
pub struct VmArea {
    pub kind: VmKind,
    /// 整个 region 的默认保护（VirtualQuery 返回的 AllocationProtect）
    pub default_prot: u32,
    /// 是否持有物理页的所有权（false = 外部已映射，我们只 track）
    pub owns_phys_pages: bool,
    /// 页数（= range.len / PAGE_SIZE）
    pub page_count: usize,

    /// per-page GPA：0 = 尚未分配物理页
    pub phys_pages: Box<[u64]>,
    /// per-page NT protection flags
    pub prot_pages: Box<[u32]>,
    /// per-page commit bitmap（1 bit per page，packed u64）
    pub commit_bits: Box<[u64]>,

    // Section/FileMapping 附加信息
    pub section_file_backed: bool,
    pub section_file_fd: u64,
    pub section_file_offset: u64,
    pub section_view_size: u64,
    pub section_is_image: bool,
}

impl AreaValue for VmArea {
    /// 合并条件：
    ///   - 两段都是 Private 且 owns_phys_pages 一致
    ///   - default_prot 相同
    ///   - 不是 section-backed
    ///   - （实现时可以选择保守策略：Section/FileMapping 永不合并）
    fn merge(&self, r1: &Range, r2: &Range, other: &Self) -> Option<Self> { ... }

    /// 在 at 地址处分裂，拆分 phys_pages/prot_pages/commit_bits 数组
    fn split(&self, r: &Range, at: u64) -> (Self, Self) { ... }
}

impl VmArea {
    /// 分配一个 reserved（未 committed）的 Private VmArea
    pub fn new_reserved(page_count: usize, prot: u32) -> Option<Self>;
    /// 分配一个 Section VmArea
    pub fn new_section(page_count: usize, prot: u32) -> Option<Self>;
    /// 分配一个 FileMapping VmArea（owns_phys_pages=false）
    pub fn new_file_mapping(page_count: usize, prot: u32) -> Option<Self>;

    pub fn is_page_committed(&self, idx: usize) -> bool;
    pub fn set_page_committed(&mut self, idx: usize, committed: bool);
    pub fn commit_word_count(&self) -> usize;  // commit_bits.len()
}
```

**关键：`split` 实现**

```rust
fn split(&self, r: &Range, at: u64) -> (Self, Self) {
    let left_pages = ((at - r.start) / PAGE_SIZE) as usize;
    let right_pages = self.page_count - left_pages;

    let mut left = VmArea::new_reserved(left_pages, self.default_prot).unwrap();
    let mut right = VmArea::new_reserved(right_pages, self.default_prot).unwrap();

    // 拷贝 phys_pages
    left.phys_pages.copy_from_slice(&self.phys_pages[..left_pages]);
    right.phys_pages.copy_from_slice(&self.phys_pages[left_pages..]);

    // 拷贝 prot_pages
    left.prot_pages.copy_from_slice(&self.prot_pages[..left_pages]);
    right.prot_pages.copy_from_slice(&self.prot_pages[left_pages..]);

    // 拆分 commit_bits（按位拆分 packed u64）
    split_commit_bits(&self.commit_bits, left_pages, &mut left.commit_bits, &mut right.commit_bits);

    // 其他字段复制
    left.kind = self.kind;
    left.owns_phys_pages = self.owns_phys_pages;
    right.kind = self.kind;
    right.owns_phys_pages = self.owns_phys_pages;
    // section 字段：left 保留原始，right 调整 offset
    if self.section_file_backed {
        let left_size = (left_pages as u64) * PAGE_SIZE;
        right.section_file_offset = self.section_file_offset + left_size;
        right.section_file_backed = true;
        right.section_file_fd = self.section_file_fd;
        right.section_is_image = self.section_is_image;
        right.section_view_size = self.section_view_size.saturating_sub(left_size);
    }

    (left, right)
}
```

---

## 五、重写 `src/mm/vaspace.rs` — ProcessVmManager

```rust
pub struct ProcessVmManager {
    /// 核心 VMA 集合：O(log n) 查找，支持 split/merge
    vmas: AreaSet<VmArea>,
    /// 自底向上分配游标（hint=0 时使用）
    alloc_cursor: u64,
    va_base: u64,
    va_limit: u64,
}

impl ProcessVmManager {
    pub fn new(va_base: u64, va_limit: u64) -> Self;

    // ─── 查找 ──────────────────────────────────────────────────────
    /// 返回包含 addr 的 VmArea（不存在返回 None）
    pub fn find_vma(&self, addr: u64) -> Option<AreaSeg<VmArea>>;

    /// 返回以 base 为起始地址的 VmArea（精确匹配）
    pub fn find_vma_by_base(&self, base: u64) -> Option<AreaSeg<VmArea>>;

    /// 找一块大小 >= size 的空洞，hint=0 则 first-fit
    pub fn find_free_va(&self, hint: u64, size: u64) -> Option<u64>;

    // ─── NT MEM_RESERVE ────────────────────────────────────────────
    /// VirtualAlloc(MEM_RESERVE) / NtAllocateVirtualMemory(MEM_RESERVE)
    /// 仅记录 VMA，不分配物理页
    pub fn reserve(&mut self, hint: u64, size: u64, prot: u32, kind: VmKind)
        -> Option<u64>;

    // ─── NT MEM_COMMIT ─────────────────────────────────────────────
    /// VirtualAlloc(MEM_COMMIT)
    /// 标记页为 committed，物理页仍懒分配（缺页时才分配）
    pub fn commit(&mut self, base: u64, size: u64, prot: u32) -> bool;

    // ─── NT MEM_DECOMMIT ───────────────────────────────────────────
    /// VirtualFree(MEM_DECOMMIT)
    /// 清除 commit 标记，释放已分配的物理页，解除页表映射
    /// 不改变 VMA 边界
    pub fn decommit(
        &mut self,
        pid: u32,
        base: u64,
        size: u64,
        address_space: &mut ProcessAddressSpace,
    ) -> bool;

    // ─── NT MEM_RELEASE ────────────────────────────────────────────
    /// VirtualFree(MEM_RELEASE)
    /// 释放整个 allocation（Windows 要求必须传 allocation base，size=0）
    pub fn release(
        &mut self,
        pid: u32,
        base: u64,
        address_space: &mut ProcessAddressSpace,
    ) -> bool;

    // ─── VirtualProtect ────────────────────────────────────────────
    /// 修改 [base, base+size) 内所有已 committed 页的保护属性
    /// 自动在 base 和 base+size 处 split，修改后尝试 merge_adjacent
    /// 返回 Ok(old_prot) 或 Err(ntstatus)
    pub fn protect(
        &mut self,
        pid: u32,
        base: u64,
        size: u64,
        new_prot: u32,
        address_space: &mut ProcessAddressSpace,
    ) -> Result<u32, u32>;

    // ─── 缺页处理 ──────────────────────────────────────────────────
    /// 从 el0_page_fault 调用，处理 demand-paging / guard / COW
    pub fn handle_page_fault(
        &mut self,
        pid: u32,
        fault_addr: u64,
        access: u8,
        address_space: &mut ProcessAddressSpace,
    ) -> bool;

    // ─── VirtualQuery ──────────────────────────────────────────────
    pub fn query(&self, addr: u64) -> Option<VmQueryInfo>;

    // ─── Section / FileMapping ─────────────────────────────────────
    /// NtMapViewOfSection / boot 时 track 已存在的文件映射
    pub fn track_file_mapping(
        &mut self,
        base: u64,
        size: u64,
        prot: u32,
        pid: u32,
        address_space: &mut ProcessAddressSpace,
    ) -> bool;

    /// 设置 section 后端信息（NtMapViewOfSection 后调用）
    pub fn set_section_backing(
        &mut self,
        base: u64,
        file_fd: Option<u64>,
        file_offset: u64,
        view_size: u64,
        is_image: bool,
    ) -> bool;

    // ─── 进程清理 ──────────────────────────────────────────────────
    /// 进程退出时释放所有 VMA 及物理页
    pub fn cleanup_all(&mut self, pid: u32, address_space: &mut ProcessAddressSpace);
}
```

### 5.1 `find_free_va` 实现（替换 O(n²) 旧实现）

```
// 旧实现：外层循环 + 内层全表扫描 = O(n²)
// 新实现：gap 迭代器，O(n) 最坏，O(log n) hint 命中时

fn find_free_va(&self, hint: u64, size: u64) -> Option<u64> {
    if hint != 0 {
        let base = align_down_4k(hint);
        // 检查该地址处是否有足够空间
        let gap = self.vmas.find_gap(base);
        if gap.ok() && gap.range().start <= base && gap.range().end() >= base + size {
            return Some(base);
        }
        return None;
    }
    // first-fit: 从 va_base 开始找第一个足够大的 gap
    let mut gap = self.vmas.first_gap();
    while gap.ok() {
        let gr = gap.range();
        if gr.len >= size {
            let start = gr.start.max(self.va_base);
            if start + size <= gr.end() && start + size <= self.va_limit {
                return Some(start);
            }
        }
        gap = gap.next_gap();
    }
    None
}
```

### 5.2 `protect` 的 split/merge 流程

```
VirtualProtect(base, size, new_prot):

1. 找到 [base, base+size) 范围内的所有 seg
2. split_at(base)         — 在 base 处切开（如果 base 落在某 seg 中间）
3. split_at(base+size)    — 在 end 处切开
4. 对范围内每个 seg：
     a. 检查所有页是否 committed（有未 committed 的页返回 NOT_COMMITTED）
     b. 更新 prot_pages[i] = new_prot
     c. 如果该页有 GPA，调用 address_space.protect_user_page(va, new_prot)
5. merge_adjacent(Range{base, size})  — 尝试与左邻和右邻合并
6. 返回 Ok(old_prot)

注意：步骤 2/3 的 split 是「廉价」的：VmArea::split 只是分割 Box<[T]> 数组，
无需与物理层交互。
```

---

## 六、修改 `KProcess`

```rust
// src/process/mod.rs

pub struct KProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub state: ProcessState,
    pub exit_status: u32,
    pub image_base: u64,
    pub peb_va: u64,
    pub main_thread_tid: u32,
    pub thread_count: u32,
    pub create_time_100ns: u64,
    pub waiters: crate::sched::sync::WaitQueue,
    pub address_space: ProcessAddressSpace,   // 保留：ARM64 页表硬件
    pub vm: ProcessVmManager,                 // 新增：NT VM 语义管理
}
```

`ProcessAddressSpace` 职责：ARM64 L0/L1/L2/L3 页表操作（map/unmap/protect/tlb）
`ProcessVmManager` 职责：VMA 区间管理，NT reserve/commit/decommit/protect/release 语义

两者交互：`ProcessVmManager` 在需要映射/解映射时调用 `address_space.map_user_range()` /
`address_space.unmap_user_range()` / `address_space.protect_user_range()`。

---

## 七、改写 `nt/state.rs` 的 VM 函数

去掉全局 `regions: ObjectStore<VmRegion>` 和整个 `VmRegion` 结构体。

### 7.1 函数映射表

| 旧函数（nt/state.rs） | 新实现 |
|---|---|
| `vm_find_region(pid, addr)` | `with_process(pid, \|p\| p.vm.find_vma(addr))` |
| `vm_find_region_by_base(pid, base)` | `with_process(pid, \|p\| p.vm.find_vma_by_base(base))` |
| `vm_find_free_base(pid, hint, size)` | `with_process(pid, \|p\| p.vm.find_free_va(hint, size))` |
| `vm_region_overlaps(pid, base, size)` | `with_process(pid, \|p\| !p.vm.vmas.is_empty_range(&Range::new(base, size)))` |
| `vm_create_region(pid, base, size, prot, kind)` | `with_process_mut(pid, \|p\| p.vm.reserve(base, size, prot, kind))` |
| `vm_commit_region_pages(pid, id, base, size, prot, eager)` | `with_process_mut(pid, \|p\| p.vm.commit(base, size, prot))` |
| `vm_decommit_region_pages(id, base, size)` | `with_process_mut(pid, \|p\| p.vm.decommit(pid, base, size, &mut p.address_space))` |
| `vm_release_region_by_id(id)` | `with_process_mut(pid, \|p\| p.vm.release(pid, base, &mut p.address_space))` |
| `vm_set_region_prot(id, prot)` | `with_process_mut(pid, \|p\| p.vm.protect(pid, base, size, prot, ..))` |
| `vm_protect_range(pid, base, size, prot)` | `with_process_mut(pid, \|p\| p.vm.protect(pid, base, size, prot, &mut p.address_space))` |
| `vm_handle_page_fault(pid, addr, access)` | `with_process_mut(pid, \|p\| p.vm.handle_page_fault(pid, addr, access, &mut p.address_space))` |
| `vm_query_region(pid, addr)` | `with_process(pid, \|p\| p.vm.query(addr))` |
| `vm_track_existing_file_mapping(pid, base, size, prot)` | `with_process_mut(pid, \|p\| p.vm.track_file_mapping(base, size, prot, pid, &mut p.address_space))` |
| `vm_set_section_backing(pid, base, ..)` | `with_process_mut(pid, \|p\| p.vm.set_section_backing(base, ..))` |
| `vm_make_guard_page(pid, va)` | 内联到 `vm.protect` 或 `vm_area` 方法 |
| `vm_alloc_region_typed(pid, hint, size, prot, type)` | `with_process_mut(pid, \|p\| p.vm.reserve(hint, size, prot, kind))` |
| `vm_clone_external_mappings(src, dst)` | 遍历 src 的 vm.vmas，对每个 FileMapping 调用 dst 的 track |
| `cleanup_process_owned_resources(pid)` | `with_process_mut(pid, \|p\| p.vm.cleanup_all(pid, &mut p.address_space))` |
| `vm_translate_user_va(pid, va, access)` | 不变，仍调用 `p.address_space.translate_user_va_for_access(va, access)` |
| `vm_apply_page_prot(pid, va, prot)` | 不变，仍调用 `p.address_space.protect_user_range(va, PAGE_SIZE, prot)` |

### 7.2 `vm_query_region` 简化

旧实现需要两次扫描（一次找 region，一次找 gap 边界），新实现通过 AreaSet 的 seg/gap 迭代直接得到：

```
query(addr):
  let (seg, gap) = self.vmas.find(addr)
  if seg.ok():
      // addr 在某个 VMA 内
      返回该 seg 的区间信息（committed/reserved/prot 来自 per-page 数组）
  else if gap.ok():
      // addr 在空洞内
      返回 MEM_FREE 区间 [gap.range().start, gap.range().end)
```

---

## 八、NT 语义保留要点

### 8.1 Reserve vs Commit 的完整流程

```
NtAllocateVirtualMemory(MEM_RESERVE):
    → vm.reserve(hint, size, prot, VmKind::Private)
    → vmas.insert(gap, range, VmArea::new_reserved(page_count, prot))
    注：phys_pages 全为 0，commit_bits 全为 0

NtAllocateVirtualMemory(MEM_COMMIT) 对已 reserve 区域:
    → vm.commit(base, size, prot)
    → 找到对应 VmArea，设置 commit_bits，更新 prot_pages
    注：物理页仍懒分配（缺页时 handle_page_fault 分配）

NtAllocateVirtualMemory(MEM_RESERVE | MEM_COMMIT):
    → vm.reserve() + vm.commit() 合并操作

缺页（demand paging）:
    → handle_page_fault(pid, fault_addr, access)
    → 找到 VmArea，检查 commit_bits[idx]
    → 分配物理页，调用 address_space.map_user_range()
    → 记录到 phys_pages[idx]
```

### 8.2 VirtualFree 两种模式

```
VirtualFree(base, 0, MEM_RELEASE):
    Windows 语义：释放整个 allocation（base 必须是 allocation base）
    → vm.release(pid, base, address_space)
    → 遍历 VmArea 的所有页，若有 phys_pages[i] != 0，释放物理页
    → 解除页表映射
    → vmas.remove(seg)

VirtualFree(base, size, MEM_DECOMMIT):
    Windows 语义：仅取消提交指定范围（保留 VMA 结构）
    → vm.decommit(pid, base, size, address_space)
    → 对范围内每个 committed 页：
        - address_space.unmap_user_page(va)
        - 若 owns_phys_pages：释放物理页，phys_pages[i] = 0
        - clear commit_bits[i]
    注：VmArea 本身不 split，边界保持不变
```

### 8.3 VirtualProtect 的 split/merge

```
VirtualProtect(base, size, new_prot, old_prot):
    → vm.protect(pid, base, size, new_prot, address_space)
    1. vmas.split_at(base)         // base 可能落在某 seg 中间
    2. vmas.split_at(base+size)    // end 同理
    3. 对 [base, base+size) 内每个 seg：
       a. isolate(seg, range)
       b. 对每个 committed 页更新 prot_pages[i] = new_prot
       c. 有 GPA 的页调用 address_space.protect_user_page(va, new_prot)
    4. vmas.merge_adjacent(Range{base, size})  // 能合并的就合并
    5. 返回第一个页的旧 prot（Windows 语义）
```

### 8.4 PAGE_GUARD 处理

保持 per-page `prot_pages` 中的 `PAGE_GUARD` bit，逻辑不变：
```
handle_page_fault(...):
    prot = vma.prot_pages[idx]
    had_guard = prot & PAGE_GUARD != 0
    if had_guard:
        prot &= !PAGE_GUARD
        vma.prot_pages[idx] = prot   // 清除 guard（one-shot）
    if had_guard && kind == ThreadStack:
        vm_on_thread_stack_guard_hit(...)  // 下移 guard，更新 TEB.StackLimit
```

### 8.5 Section mapping / FileMapping

`VmArea::section_*` 字段完整保留：
- `section_file_backed`、`section_file_fd`、`section_file_offset`
- `section_view_size`、`section_is_image`

文件内容填充逻辑（`vm_fill_section_page`）迁移到 `ProcessVmManager::handle_page_fault` 内部，
通过 `VmKind::Section` 分支触发。

---

## 九、文件改动清单

| 文件 | 操作 | 说明 |
|---|---|---|
| `src/mm/range.rs` | **新建** | Range 基础类型 |
| `src/mm/areaset.rs` | **新建** | 从 Quark 移植，去 QMutex 换 SpinLock/Arc |
| `src/mm/vm_area.rs` | **新建** | VmArea + AreaValue 实现 |
| `src/mm/vaspace.rs` | **完全重写** | ProcessVmManager（替换旧 VaSpace） |
| `src/mm/mod.rs` | **修改** | 添加 range / areaset / vm_area 模块，删除对旧 vaspace 的 VmaType 导出 |
| `src/process/mod.rs` | **修改** | KProcess 添加 `vm: ProcessVmManager` 字段 |
| `src/process/lifecycle.rs` | **修改** | 进程创建时 `vm: ProcessVmManager::new(USER_VA_BASE, USER_VA_LIMIT)`；进程销毁时 `p.vm.cleanup_all()` |
| `src/nt/state.rs` | **大幅改写** | 删除 `VmRegion` / `regions: ObjectStore` / `NT_STATE.regions`；所有 `vm_*` 函数改为调用 `with_process_mut(pid, \|p\| p.vm.*)` |
| `src/nt/memory.rs` | **少量修改** | 调整调用 `vm_protect_range` / `vm_query_region` 等函数的签名（如有变化） |
| `src/main.rs` | **基本不变** | 调用 `vm_alloc_region_typed` 等公开函数，签名不变 |

---

## 十、实施顺序

按以下顺序实施，每步可独立编译验证：

1. **建** `src/mm/range.rs` — 纯数据结构，零依赖
2. **建** `src/mm/areaset.rs` — 依赖 range，移植 Quark 代码
3. **建** `src/mm/vm_area.rs` — 依赖 range + areaset，定义 VmArea
4. **更新** `src/mm/mod.rs` — 注册新模块
5. **重写** `src/mm/vaspace.rs` — ProcessVmManager，依赖 areaset + vm_area
6. **修改** `src/process/mod.rs` — KProcess 加 `vm` 字段，更新构造
7. **修改** `src/process/lifecycle.rs` — 初始化和清理 vm
8. **大改** `src/nt/state.rs` — 删 regions_store，改调 p.vm.*（最大改动量）
9. **修正编译错误** — 调整 API 边界，修复类型不匹配

---

## 十一、性能对比

| 操作 | 旧实现 | 新实现 |
|---|---|---|
| `vm_find_region(pid, addr)` | O(N_all_regions)，全表线性扫描 | O(log n_pid_regions)，BTreeMap 二分 |
| `vm_find_free_base(pid, hint, size)` | O(n²)，外循环 × 内层全表 | O(n)，gap 迭代器 |
| `vm_region_overlaps(pid, base, size)` | O(N_all_regions) | O(log n + k)，找到 gap 后 O(1) 判断 |
| `cleanup_process(pid)` | O(N_all_regions)，全表过滤 | O(n_pid_regions)，per-process 遍历 |
| `vm_protect_range` with split | 不支持跨 region | O(log n + k)，自动 split/merge |

其中 `N_all_regions` = 所有进程的 region 总数，`n_pid_regions` = 单进程 region 数，k = 被影响的 region 数。
