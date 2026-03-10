# Kernel Physmap 实现方案

## 一、问题定义

当前 `mm/phys.rs` 管理的页由 VMM 以 GPA 形式返回，但内核在 EL1 并没有一段稳定的 `GPA -> KVA` 映射窗口。结果是：

1. `translate_user_va_for_access()` 返回 GPA 后，内核不能可靠地直接解引用。
2. 跨进程内存访问、COW、page fill 等路径只能退回 `HOST_MEMCPY` / `HOST_MEMSET`。
3. 一旦 GPA 落在当前进程 TTBR0 下未映射的区域，就会触发 EL1 translation fault。

核心问题不是“MMU 开了以后物理页不能访问”，而是“当前没有独立、稳定、进程无关的 kernel physmap”。

## 二、现状与约束

### 2.1 当前内核 MMU 模型

`winemu-kernel/src/arch/aarch64/mmu.rs` 当前是单 `TTBR0` 模型：

1. `setup_kernel_mapping()` 只建立 `0x4000_0000..0x7fff_ffff` 的 1GB 低地址窗口。
2. `TCR_EL1` 中设置了 `EPD1=1`，当前不使用 `TTBR1`。
3. 低地址窗口里同时承载 kernel image、DLL、heap、用户可访问区等现有布局。

### 2.2 当前进程页表行为

`ProcessAddressSpace::clone_l2_child_tables()` 会把 user window 对应的 L2 项清掉并按需重建，因此：

1. `0x7000_0000..0x7fff_ffff` 不能被视为稳定的 kernel 直映。
2. 任何依赖“GPA 落在这个区间就能直接读写”的做法都不成立。

### 2.3 当前 guest physical 范围

VMM 默认配置下：

1. Guest physical memory 范围为 `0x4000_0000..0x8000_0000`（1GB）。
2. `phys.rs` 的物理页池默认位于高端，即 `0x7c00_0000..0x8000_0000`。

因此，physmap 方案至少要覆盖这整个 1GB GPA aperture，而不是只覆盖 `phys.rs` 当前缓存的 chunk。

## 三、结论：旧方案哪些不可取

旧版 `docs/kernel-phy-map.md` 的两个关键前提不可取：

1. `PHYSMAP_BASE = 0x5000_0000` 不可取。
   - `0x5000_0000` 不是空洞地址。
   - VMM 的 `EARLY_HOST_MMAP_BASE` 就在 `0x5000_0000`，会与现有 host mmap / image 布局冲突。
2. 只为 `phys.rs` 的 chunk slot 建 16MB physmap 不可取。
   - 这只能覆盖 chunk cache。
   - 不能覆盖任意 `translate_user_va_for_access()` 返回的 GPA。
   - 不能真正解决跨进程读写、COW、section/file-backed page 这些路径。

可保留的思路只有两点：

1. physmap 必须是共享的 kernel 映射。
2. physmap 相关 L3 表不能跟普通 per-process user L3 一样被深拷贝和释放。

## 四、正确方案

### 4.1 方案选择

本次采用：

1. 保持当前单 `TTBR0` 架构不变。
2. 新增一段独立的 EL1-only kernel physmap 窗口。
3. 该窗口直接覆盖当前整个 1GB GPA aperture。

本次不引入 `TTBR1`，原因很简单：

1. 当前代码基线明确不是 higher-half 内核。
2. 引入 `TTBR1` 会把问题升级成完整内核 VA 架构重构。
3. 这次要解决的是“补稳定 physmap”，不是“重写整个 MMU 设计”。

### 4.2 新 VA 布局

建议布局：

| VA 范围 | 用途 | 备注 |
|--------|------|------|
| `0x4000_0000..0x6fff_ffff` | 现有 kernel / image / dll / heap / host mapping | 保持现状 |
| `0x7000_0000..0x7fff_ffff` | 用户私有窗口 | 保持现状 |
| `0x8000_0000..0xbfff_ffff` | 新增 kernel physmap | EL1 only |

映射关系：

```text
gpa in [0x4000_0000, 0x8000_0000)
  ->
kva = 0x8000_0000 + (gpa - 0x4000_0000)
```

这段 physmap：

1. 与当前用户窗口不重叠。
2. 不与 `0x5000_0000` 现有 early host mmap 布局冲突。
3. 覆盖整个当前 guest kernel 实际依赖的 GPA 范围。

## 五、页表设计

### 5.1 Bootstrap 页表

在 `winemu-kernel/src/arch/aarch64/mmu.rs` 中：

1. 保留现有 `L1[1] -> L2_TABLE` 的低地址 1GB 窗口。
2. 新增一张独立的 `PHYSMAP_L2_TABLE`。
3. 新增 `L1[2] -> PHYSMAP_L2_TABLE`。
4. `PHYSMAP_L2_TABLE` 以 2MB block 方式映射：
   - `VA = 0x8000_0000 + i * 2MB`
   - `PA = 0x4000_0000 + i * 2MB`

权限要求：

1. EL1 RW
2. EL0 no access
3. UXN/PXN
4. Normal memory / inner-shareable / AF=1

### 5.2 进程页表 clone

`clone_l2_child_tables()` 仍保持当前语义：

1. user window 对应的 L2 项清空并按需重建。
2. physmap 所在的 L1/L2 项保持 bootstrap 继承，不参与 user window 清理。
3. physmap 不进入 `self.l3_tables[]` 的生命周期管理。

由于本方案用的是专用 `PHYSMAP_L2_TABLE`，而不是动态 patch 普通 user L2 entry，因此：

1. 不需要 phys chunk slot 级别的共享 L3 patch 逻辑。
2. 不需要在 `grow()/shrink()` 中频繁改动 physmap 页表。
3. physmap 是真正静态稳定的全局映射。

## 六、访问模型

所有 translated GPA 访问统一改成：

```text
user_va
  -> translate_user_va_for_access()
  -> gpa
  -> gpa_to_kva()
  -> deref / memcpy / memset
```

不再允许两类错误用法：

1. `translate_user_va_for_access()` 后直接 `(gpa as *const T)`。
2. 假设 `gpa` 本身就是当前地址空间里稳定可访问的 VA。

## 七、实现模块

### 7.1 新增 `mm/physmap.rs`

建议新增：

```rust
pub const GUEST_PHYS_BASE: u64 = 0x4000_0000;
pub const GUEST_PHYS_LIMIT: u64 = 0x8000_0000;
pub const KERNEL_PHYSMAP_BASE: u64 = 0x8000_0000;
pub const KERNEL_PHYSMAP_LIMIT: u64 = 0xc000_0000;

pub fn gpa_to_kva(gpa: u64) -> Option<*mut u8>;
pub fn gpa_range_valid(gpa: u64, len: usize) -> bool;
pub fn copy_from_gpa(dst: *mut u8, src_gpa: u64, len: usize) -> bool;
pub fn copy_to_gpa(dst_gpa: u64, src: *const u8, len: usize) -> bool;
pub fn copy_gpa(dst_gpa: u64, src_gpa: u64, len: usize) -> bool;
pub fn memset_gpa(dst_gpa: u64, value: u8, len: usize) -> bool;
```

这个模块的职责只有一个：

1. 把“GPA 是否可在 EL1 访问、如何访问”抽象成统一 helper。

### 7.2 `arch/aarch64/mmu.rs`

需要新增：

1. `PHYSMAP_L2_TABLE`
2. physmap 常量
3. 建表逻辑
4. 如有需要，导出 `physmap_base/limit` 常量给 `mm/physmap.rs`

### 7.3 `mm/mod.rs`

需要：

1. `pub mod physmap;`
2. 导出 physmap helper

## 八、第一批必须修改的路径

这些路径当前已经错误地把 translated GPA 当指针，需要第一批一起收敛：

1. `winemu-kernel/src/nt/memory.rs`
   - `copy_from_process_user`
   - `copy_to_process_user`
   - `copy_between_process_users`
2. `winemu-kernel/src/nt/process.rs`
   - `read_user_u8` 的 translated GPA 读路径
3. `winemu-kernel/src/nt/win32k.rs`
   - `read_user_u64`
4. `winemu-kernel/src/mm/vaspace.rs`
   - `phys_memset`
   - `phys_memcpy`

## 九、第二批建议审计的路径

这些路径主要还是“当前进程用户 VA 直接解引用”，短期可不动，但后续应该收敛成统一 user copy helper：

1. `nt/file.rs`
2. `nt/sync.rs`
3. `nt/registry.rs`
4. `nt/path.rs`
5. `nt/thread.rs`
6. `process/set.rs`
7. `nt/section.rs`

## 十、为什么不采用 chunk-slot 动态映射

这类方案的问题在于：

1. 它只覆盖 `phys.rs` 缓存到的 chunk。
2. 它天然无法表达“任意 translated GPA 都可访问”。
3. 它会把 physmap 生命周期和 `grow()/shrink()` 绑定，增加锁顺序和 TLB 刷新复杂度。
4. 它更像一层 allocator cache 优化，而不是 kernel 物理映射基础设施。

因此，本次不采用：

1. `PHYSMAP_BASE=0x5000_0000`
2. `slot -> chunk`
3. `grow()/shrink()` 时动态 patch L3 PTE

## 十一、实施顺序

按以下顺序落地：

1. 在 `arch/aarch64/mmu.rs` 中加入静态 1GB physmap 窗口。
2. 新增 `mm/physmap.rs`。
3. 改 `nt/memory.rs`，用 physmap 替代当前错误的 GPA 直接解引用。
4. 改 `nt/process.rs`、`nt/win32k.rs`。
5. 改 `mm/vaspace.rs`，让 `phys_memset/phys_memcpy` 优先走内核 fast path。
6. 最后跑 `thread_test`、`full_test` 回归。

## 十二、验证目标

改造完成后需要满足：

1. `NtReadVirtualMemory` / `NtWriteVirtualMemory` 不再因 `0x7cxx_xxxx` GPA 触发 EL1 fault。
2. `full_test` 中不再出现 `PROCESS_EXIT: code=225`。
3. `thread_test` 保持通过。
4. COW、page fill、section page copy 不再依赖 `HOST_MEMCPY` / `HOST_MEMSET` 作为主路径。

---

最终结论：

`kernel physmap` 的目标应该是“为当前整个 guest physical aperture 提供稳定的 EL1 映射”，而不是“给 `phys.rs` 的 chunk cache 单独做一层 16MB slot patch”。前者能解决现在的架构问题，后者只能做局部优化，而且会和当前地址布局冲突。
