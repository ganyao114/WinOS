# 内核物理页映射实现方案

## 一、背景与问题

当前 `winemu-kernel` 在 AArch64 上启用 MMU 后，实际运行的是“单 TTBR0 + 低地址 1GB 窗口”模型：

1. `winemu-kernel/src/arch/aarch64/mmu.rs`
   - `setup_kernel_mapping()` 只建立了 `0x4000_0000..0x7fff_ffff` 的 1GB 低地址窗口。
   - 这段窗口本质上是早期 bootstrap 用的 `VA = GPA` 恒等映射。
2. `winemu-kernel/src/mm/address_space.rs`
   - `ProcessAddressSpace::clone_l2_child_tables()` 在 clone 进程页表时，会清空 `USER_VA_BASE..USER_VA_LIMIT` 对应的 L2 项。
   - 当前 `USER_VA_BASE = 0x7000_0000`，`USER_VA_LIMIT = 0x8000_0000`。
3. `crates/winemu-vmm/src/lib.rs`
   - 默认 guest memory 为 1GB，即 GPA 范围是 `0x4000_0000..0x8000_0000`。
   - 物理页池默认放在高端，即 `phys_pool = [0x7c00_0000, 0x8000_0000)`。

因此，当前的“恒等映射”并不是一个稳定的内核 physmap：

1. 它和用户地址空间共用同一段低地址窗口。
2. 进程页表 clone 之后，`0x7000_0000..0x8000_0000` 这段会被当作用户窗口按需重建，而不是永远保留内核物理直映。
3. `phys.rs` 返回的很多 GPA 正好落在 `0x7cxx_xxxx` 高端物理池中；这些地址在当前进程 TTBR0 下并不保证始终有内核可用映射。

这就是最近 `full_test` 中 `NtReadVirtualMemory` 路径触发 EL1 fault 的根因：

1. `translate_user_va_for_access()` 返回的是 GPA。
2. 内核代码把这个 GPA 直接当作当前地址空间下可解引用的 VA。
3. 当 GPA 落在 `0x7cxx_xxxx` 时，CPU 按 VA 重新走页表翻译，最终在 EL1 上报 translation fault。

## 二、现状归纳

当前代码里实际存在三类内存访问语义：

1. 当前进程用户 VA 直接解引用
   - 例如 `nt/win32k.rs`、`nt/file.rs`、`nt/sync.rs` 等大量 `va as *const _`。
   - 这依赖当前实现里 EL1 与 EL0 共用 TTBR0，且 `SPAN=1`，因此“当前进程的用户 VA”在 syscall 上下文里可以直接访问。
2. 翻译后 GPA 直接解引用
   - 例如 `nt/process.rs`、`nt/memory.rs` 中把 `translate_user_va_for_access()` 的返回值直接转成指针。
   - 这是当前明确错误的路径。
3. 通过 host side 读写 GPA
   - 例如 `HOST_MEMCPY`、`HOST_MEMSET`、`host_read(fd, gpa_as_ptr, ...)`。
   - 这些路径功能上可工作，但语义混乱，且把纯 guest 内核内存操作退化成 host 参与。

本次改造要解决的是第 2 类问题，并为第 3 类路径提供内核内快速路径。

## 三、目标

本次实现的目标是：

1. 为内核提供一段稳定、进程无关、所有 CPU 一致的 `GPA -> KVA` 映射窗口。
2. 允许内核在 MMU 开启后直接读写物理页，包括非当前进程页表翻译得到的 GPA。
3. 让 `NtReadVirtualMemory` / `NtWriteVirtualMemory` / 进程间拷贝 / COW / page fill 等路径不再依赖 `HOST_MEMCPY` / `HOST_MEMSET`。
4. 保持当前调度、进程、页表 clone 逻辑基本不动，不引入 TTBR 切换式 copy。
5. 尽量不改变现有用户 VA 布局，避免牵一发动全身。

## 四、设计选择

### 4.1 选择：在现有 TTBR0 模型下新增独立 kernel physmap 窗口

本次不引入 TTBR1 / higher-half 内核重构，而是在现有单 TTBR0 架构内新增一段只给 EL1 使用的物理直映窗口。

原因：

1. 当前实现明确使用 `EPD1=1`，即 TTBR1 walk 被关闭。
2. 大量现有代码、常量、日志窗口都假设内核仍在低地址区运行。
3. 直接切 TTBR1 会把本次问题从“补一段稳定 physmap”升级成“整体内核虚拟地址架构重做”，超出当前目标。

因此，本次采用最小可行方案：

1. 保留现有 `0x4000_0000..0x7fff_ffff` 低地址窗口行为不变。
2. 新增一段独立的 kernel physmap 窗口，例如：
   - `KERNEL_PHYSMAP_BASE = 0x8000_0000`
   - `KERNEL_PHYSMAP_SIZE = 0x4000_0000`（1GB）
   - 对应映射 GPA `0x4000_0000..0x7fff_ffff`
3. 该窗口只允许 EL1 访问，不给 EL0 用户态权限。

### 4.2 为什么选 1GB physmap

这不是新的限制，而是与当前 kernel stage-1 可见 GPA aperture 对齐：

1. 当前 bootstrap 页表只覆盖 `0x4000_0000..0x7fff_ffff`。
2. 当前 `USER_ACCESS_BASE/USER_VA_LIMIT` 设计也都建立在这 1GB 低地址窗口之上。
3. 默认 guest memory 正好也是 1GB。

所以本次 physmap 的直接覆盖范围就是当前 kernel 已经实际依赖的 GPA 范围。

补充说明：

1. VMM 侧 `WINEMU_GUEST_MEM_MB` 可以配置得更大。
2. 但当前 guest kernel 的 stage-1 布局并没有真正完成“>1GB GPA 全覆盖”的设计。
3. 因此“支持更大 guest memory”是后续独立课题，不作为这次 physmap 改造的范围。

## 五、地址空间布局

本次建议把 AArch64 当前布局明确为：

| VA 范围 | 用途 | 权限 | 备注 |
|--------|------|------|------|
| `0x4000_0000..0x6fff_ffff` | 现有 kernel / image / dll / heap / host file mapping | 现状保持 | 不改语义 |
| `0x7000_0000..0x7fff_ffff` | 用户私有窗口 | EL0/EL1 按 PTE 权限 | clone 时可被清空重建 |
| `0x8000_0000..0xbfff_ffff` | 新增 kernel physmap | EL1 RW only | 稳定 `GPA -> KVA` 直映 |

映射关系：

```text
gpa in [0x4000_0000, 0x8000_0000)
  ->
kva = 0x8000_0000 + (gpa - 0x4000_0000)
```

约束：

1. `USER_VA_LIMIT = 0x8000_0000`，因此 physmap 窗口与用户地址空间不重叠。
2. 这段 physmap 不应被 `ProcessAddressSpace` 在 clone 或 user mapping 更新中修改。
3. 这段映射必须在所有进程 TTBR0 中保持一致。

## 六、核心实现

### 6.1 新增 physmap 抽象层

建议新增 `winemu-kernel/src/mm/physmap.rs`，统一承载 GPA 直映辅助接口：

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
```

这个模块只做一件事：把“translated GPA 是否可在内核态访问、如何访问”统一起来。

### 6.2 在 bootstrap 页表中加入 physmap

`winemu-kernel/src/arch/aarch64/mmu.rs` 需要增加一组专用 page table：

1. 新增 `PHYSMAP_L2_TABLE`。
2. 在 `setup_kernel_mapping()` 中：
   - 保留现有 `L1[1] -> L2_TABLE` 的低地址 1GB 窗口。
   - 新增 `L1[2] -> PHYSMAP_L2_TABLE`。
3. `PHYSMAP_L2_TABLE` 的每个 2MB block 映射到对应 GPA：
   - `VA 0x8000_0000 + i*2MB`
   - `PA 0x4000_0000 + i*2MB`
4. 权限设置为 EL1 RW、EL0 不可访问、UXN/PXN。

这样可以保证：

1. 所有进程页表 clone 时都会继承 physmap。
2. `USER_VA_BASE..USER_VA_LIMIT` 的清理不会影响 physmap。
3. 内核访问 translated GPA 时不再依赖“它恰好还在低地址窗口里”。

### 6.3 访问路径统一

所有“先翻译用户 VA，再访问物理页”的路径都必须改成：

```text
user_va -> translate_user_va_for_access() -> gpa -> gpa_to_kva() -> deref/copy
```

不能再出现：

1. `translate_user_va_for_access(...)` 后直接 `(pa as *const T)`。
2. 把 GPA 直接当成“当前地址空间一定存在的 VA”。

## 七、必须一起修改的代码

### 7.1 第一批必须收敛到 physmap 的路径

这些路径本身已经依赖“翻译后 GPA”，因此必须第一批一起改：

1. `winemu-kernel/src/nt/memory.rs`
   - `copy_from_process_user`
   - `copy_to_process_user`
   - `copy_between_process_users`
2. `winemu-kernel/src/nt/process.rs`
   - `read_user_u8` 中的 translated GPA 读路径
3. `winemu-kernel/src/nt/win32k.rs`
   - `read_user_u64` 中基于 translated user pointer 的读路径
4. `winemu-kernel/src/mm/vaspace.rs`
   - `phys_memset`
   - `phys_memcpy`

### 7.2 第二批建议一并审计的路径

这些路径大多还是“当前进程用户 VA 直接解引用”，短期可以继续工作，但和 physmap 无关，后续应单独收敛成统一 user copy helper：

1. `nt/file.rs`
2. `nt/sync.rs`
3. `nt/registry.rs`
4. `nt/path.rs`
5. `nt/thread.rs`
6. `process/set.rs`
7. `nt/section.rs`

它们不一定要在本次全部重写，但应在文档和代码注释中明确：这类代码依赖“当前进程 user VA 可直接解引用”的现状，不应再被误用到跨进程 / translated GPA 场景。

## 八、文件级改造计划

### 8.1 `winemu-kernel/src/arch/aarch64/mmu.rs`

目标：

1. 新增 physmap L2 表。
2. 在 bootstrap 映射中挂上 physmap 窗口。
3. 使 physmap 成为所有进程共有的稳定内核映射。

### 8.2 `winemu-kernel/src/mm/mod.rs`

目标：

1. 新增 `pub mod physmap;`
2. 导出 physmap helper。

### 8.3 `winemu-kernel/src/mm/address_space.rs`

目标：

1. 保持当前“只清 user window”的行为。
2. 增加注释，明确 physmap 位于 user window 之外，clone 时必须保留。
3. 不允许后续改动误把 physmap 也纳入“按进程可变区”。

### 8.4 `winemu-kernel/src/nt/memory.rs`

目标：

1. 删除当前错误的 `gpa as *mut u8` 假设。
2. 删除对 `HOST_MEMCPY` 的依赖。
3. 改成 `translate -> gpa_to_kva -> copy`。

### 8.5 `winemu-kernel/src/mm/vaspace.rs`

目标：

1. `phys_memset` / `phys_memcpy` 使用 physmap 快速路径。
2. 减少纯 guest 内核内存操作绕回 host 的开销。

补充说明：

1. `host_read()` 当前 ABI 实际上传的是 GPA，只是内核侧签名伪装成 `*mut u8`。
2. 这本身是接口语义混乱，但不必在本次一起重构。
3. 本次先解决“内核自己访问 GPA”问题；host 文件 I/O ABI 清理可以后续单独做。

## 九、为何不直接上 TTBR1 / higher-half

不选这个方案的原因很明确：

1. 当前系统明确是单 TTBR0 模型，`EPD1=1`。
2. kernel image / dll / heap / bootstrap 常量都大量使用低地址假设。
3. 现阶段问题是“缺失稳定 physmap”，不是“整个 kernel VA 架构错误”。

因此，本次采用最小修改路线：

1. 先补出稳定 physmap。
2. 先把 translated GPA 访问语义收敛正确。
3. 未来如果要做 higher-half / TTBR1，再单独做大版本 MMU 架构重整。

## 十、风险与边界

### 10.1 已知边界

1. 本次 physmap 只覆盖当前 kernel 实际可见的 1GB GPA aperture。
2. 这与当前 stage-1 设计一致，不新增新的支持范围。
3. 若未来 guest memory 扩到 >1GB 且 guest kernel 真正开始访问更高 GPA，需要额外设计更大的 physmap 或 TTBR1。

### 10.2 风险点

1. 现有低地址窗口与新 physmap 会同时映射同一段物理内存。
2. 这属于 alias mapping，但在当前统一 normal WB memory 属性下是可接受的。
3. 需要确保属性一致，不能一边 normal、一边 device 或 cacheability 不一致。

### 10.3 调试风险

1. EL1 fault 日志中的 `far` 未来可能落到 physmap VA，而不是原 GPA。
2. 调试工具和日志要明确区分：
   - 原始 GPA
   - physmap KVA
   - user VA

## 十一、验证计划

实现完成后建议按以下顺序验证：

1. 编译
   - `cd winemu-kernel && cargo build --release --target aarch64-unknown-none`
   - `./scripts/build-kernel-bin.sh`
   - `cargo build --bin winemu`
2. 回归
   - `thread_test`
   - `full_test`
3. 重点观测
   - 不再出现 `KERNEL_FAULT far=0x7cxx_xxxx` 这类 translated GPA 直接解引用 fault
   - `PROCESS_EXIT: code=225` 消失
   - `NtReadVirtualMemory` / `NtWriteVirtualMemory` / COW / section page fill 路径正常
4. 补充验证
   - `window_test`
   - 涉及 `NtQueryInformationProcess`、C++ EH 元数据读取的路径

## 十二、实施顺序

建议按以下顺序落地：

1. 先在 `arch/aarch64/mmu.rs` 建立 physmap 窗口。
2. 新增 `mm/physmap.rs`，提供 `gpa_to_kva/copy_*` helper。
3. 改 `nt/memory.rs`，恢复跨进程读写虚拟内存路径。
4. 改 `nt/process.rs`、`nt/win32k.rs`，收敛 translated GPA 访问。
5. 改 `mm/vaspace.rs`，把纯 guest 物理页 copy/set 切到内核 fast path。
6. 最后统一 build + `thread_test` + `full_test` 验证。

---

这个方案的核心结论只有一句：

当前问题不是“MMU 开了之后物理页不能用了”，而是“缺少独立、稳定、进程无关的 kernel physmap”。本次改造的目标，就是把这层基础设施补出来，并让所有 translated GPA 访问都统一走它。
