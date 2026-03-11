# Kernel KVA 演进方案

## 一、定位

这份文档讨论的是 `kernel physmap` 之后的下一阶段：把当前“可用的物理页直映”演进成更接近真实内核的 `KVA` 体系。

它不是替代 [kernel-physmap-implementation-plan.md](/Users/swift/WinEmu/docs/kernel-physmap-implementation-plan.md)，而是在其基础上的上层设计：

1. `kernel physmap` 解决的是“内核能稳定访问 guest physical page”。
2. `kernel KVA` 解决的是“内核如何系统性地管理和使用自己的虚拟地址空间”。

当前代码已经具备最小版 physmap：

1. [mmu.rs](/Users/swift/WinEmu/winemu-kernel/src/arch/aarch64/mmu.rs) 中存在静态 `PHYSMAP_L2_TABLE`。
2. [physmap.rs](/Users/swift/WinEmu/winemu-kernel/src/mm/physmap.rs) 已提供 `phys_to_kva/copy_*` 等 `kernel linear map` helper，并通过 `crate::mm::linear_map` 作为语义入口暴露。
3. [usercopy.rs](/Users/swift/WinEmu/winemu-kernel/src/mm/usercopy.rs) 与 [vaspace.rs](/Users/swift/WinEmu/winemu-kernel/src/mm/vaspace.rs) 已开始收敛到 `linear map` 路径。

但这还不是完整的 KVA 体系。

## 二、当前实现的边界

当前实现本质上仍然是“固定 GPA aperture 的线性别名”：

1. `KVA` 基本等价于 `gpa + 常量偏移`。
2. 这段映射只覆盖当前 guest RAM aperture。
3. 内核还没有区分：
   - 永久线性映射
   - 临时映射
   - 动态内核映射
   - MMIO 映射
4. 仍有一些路径依赖“当前进程用户 VA 在 EL1 可直接解引用”。
5. 页表 walker 和上层调用者之间还缺少明确的地址类型边界。

因此，当前 physmap 更像“内核物理访问能力”，而不是“完整 kernel virtual memory model”。

## 三、目标

目标不是立刻切到 `TTBR1`，而是先把 KVA 的语义做对。

完成后的 KVA 体系应满足：

1. 内核只通过“自己拥有的 KVA”访问物理页。
2. `User VA` 不是通用内核指针，只能通过 `usercopy` 或受控 fastpath 访问。
3. RAM、页表页、跨进程页、内核动态对象、MMIO 在 KVA 层有明确分层。
4. 所有进程共享一致的 kernel mapping，只有用户部分随进程变化。
5. 上层代码不再依赖“当前恰好共用 TTBR0”这一偶然实现细节。
6. 后续即使迁移到 `TTBR1` / higher-half，也不需要大面积改业务逻辑。

## 四、设计原则

### 4.1 先抽象，后迁移

先建立统一的 KVA 抽象，再讨论是否切 `TTBR1`。

原因：

1. 当前真正的问题不是“没有 TTBR1”，而是“地址访问语义还不分层”。
2. 如果在抽象尚未稳定时直接切 `TTBR1`，改动会同时落在：
   - 页表布局
   - 地址常量
   - 用户访问路径
   - 内核访问路径
   - 调试与 fault 分析
3. 这样会把一个可渐进推进的工程问题，扩大成全栈重构。

### 4.2 KVA 不是只有 physmap

`physmap` 只是 KVA 的一种实现形式，后续还需要：

1. `linear map`
2. `kmap/fixmap`
3. `vmalloc` 风格动态内核映射
4. `ioremap`

### 4.3 地址类型必须显式化

后续应逐步减少“裸 `u64` 表示所有地址”的做法，至少在内核 MM 关键路径中区分：

1. `PhysAddr`
2. `KernelVa`
3. `UserVa`

哪怕第一版只是轻量 wrapper，也比继续混用更安全。

## 五、推荐的 KVA 分层

建议把未来的 KVA 体系拆成四层。

### 5.1 Kernel Linear Map

职责：

1. 为当前 guest RAM 提供永久稳定的内核线性映射。
2. 支撑：
   - 页分配器
   - 页表页访问
   - 跨进程 copy
   - COW
   - zero-fill
   - section page fill

特点：

1. 全局共享。
2. 建立后长期存在。
3. 所有 CPU、所有进程看到的映射一致。

这层就是当前 physmap 的正式化版本。

### 5.2 Kernel Kmap / Fixmap

职责：

1. 为“不能或不适合长期线性直映”的页提供短生命周期映射。
2. 为未来更大 guest memory 或非连续物理页访问提供补充手段。

适用场景：

1. 页表编辑时映射目标页。
2. 跨地址空间调试页。
3. 未来不在线性窗口内的物理页。
4. 每核短时 mapping。

建议：

1. 先做 `per-cpu kmap_local_page()`。
2. 再视需要增加固定槽位 `fixmap`。

### 5.3 Kernel Dynamic Map

职责：

1. 为非 page-granular 的内核对象提供独立 KVA 管理。
2. 承载未来类似 `vmalloc` 的能力。

适用场景：

1. 大块内核缓冲区
2. 稀疏内核对象
3. 长生命周期特殊映射

这一层不要求立刻实现，但地址空间上要预留位置，API 上要预留角色。

### 5.4 IoRemap

职责：

1. 为 MMIO / device memory 提供单独映射。
2. 使用与普通 RAM 不同的页属性。

原则：

1. 不把 MMIO 混进 RAM linear map。
2. 不让上层把 `ioremap` 返回值当普通物理页 KVA 使用。

## 六、推荐的地址空间模型

在当前单 `TTBR0` 架构下，建议先按“功能分区”定义 KVA，而不是立即调整成 higher-half 布局。

建议保留三类区域概念：

1. `User Region`
   - 每进程可变
   - 用户页表按需修改
2. `Kernel Global Region`
   - 所有进程共享
   - 包含 kernel image、linear map、fixmap、future vmalloc
3. `Kernel Peripheral Region`
   - MMIO / host-shared special mappings

当前实现里最重要的原则不是“基址一定放哪”，而是：

1. `kernel global mappings` 的生命周期不能再跟用户页表混在一起。
2. `linear map` 必须被定义为稳定的 kernel region，而不是临时偏移技巧。
3. 将来若切 `TTBR1`，只改变 `Kernel Global Region` 的挂载方式，不改变上层使用语义。

## 七、API 收敛方案

下一步应把 KVA 体系落到 API 上，而不是继续扩散 ad-hoc helper。

### 7.1 地址类型

建议新增轻量类型：

```rust
pub struct PhysAddr(pub u64);
pub struct KernelVa(pub u64);
pub struct UserVa(pub u64);
```

第一阶段不必追求极强类型系统，只要做到：

1. 页表 walker 返回 `PhysAddr`
2. `phys_to_kva()` 返回 `KernelVa`
3. `copy_from_user/copy_to_user` 明确接收 `UserVa`

### 7.2 线性映射接口

建议把当前 `mm/physmap.rs` 逐步提升为正式 `linear map` API：

1. `phys_to_kva(pa) -> Option<KernelVa>`
2. `kva_to_phys(kva) -> Option<PhysAddr>`
3. `memcpy_from_phys`
4. `memcpy_to_phys`
5. `memcpy_phys`
6. `memset_phys`

要求：

1. 页表 walker 不直接暴露“可解引用裸地址”。
2. 所有真正解引用都发生在 KVA 层。

### 7.3 用户访问接口

`usercopy` 需要继续收敛为唯一入口：

1. `copy_from_user`
2. `copy_to_user`
3. `copy_between_users`
4. `read_user_value`
5. `write_user_value`

允许保留一个受控 fastpath：

1. 若目标就是当前 CPU 正在运行的进程，且范围合法，可直接访问当前 user VA。
2. 但这个 fastpath 只能藏在 `usercopy` 内部。
3. 上层调用者不得再直接解引用 user VA。

### 7.4 临时映射接口

后续新增：

1. `kmap_local_page(pa) -> KmapGuard`
2. `KmapGuard::as_ptr()`
3. guard drop 时自动解除映射或释放槽位

这样可以避免未来出现：

1. 到处手写 temporary VA
2. 手动管理 flush / unmap
3. 锁顺序和生命周期混乱

## 八、页表与 MMU 演进方式

### 8.1 当前阶段：继续保持单 TTBR0

当前阶段建议保持现状：

1. `TTBR0` 同时承载 user + kernel global mappings
2. `EPD1=1`
3. 先把访问语义和 API 分层做对

这是过渡期最稳的方案。

### 8.2 中期阶段：抽出 Kernel Global Mapping 模板

建议把 bootstrap kernel mappings 明确分成两类：

1. 永久共享模板
2. 每进程用户私有部分

目标：

1. 让“哪些页表项属于所有进程共享内核空间”在实现上清晰可见。
2. 为未来迁移到 `TTBR1` 做准备。

### 8.3 后期阶段：再评估 TTBR1 / higher-half

只有下面几件事做完后，才建议评估 `TTBR1`：

1. 上层代码已经不直接解引用 user VA
2. 大部分物理页访问已统一走 `phys_to_kva` / `kmap`
3. kernel global mapping 的边界已经稳定
4. 调试工具和 fault 日志已适配 KVA 语义

否则，`TTBR1` 只会放大复杂度。

## 九、分阶段实施计划

### Phase 1：正式化当前 linear map

目标：

1. 把现有 physmap 明确提升为 `kernel linear map`
2. 让上层不再把它当临时 helper

工作项：

1. 统一命名，减少 `gpa_to_kva` 这种过于局部的心智模型
2. 引入 `PhysAddr/KernelVa/UserVa` 轻量类型
3. 清理残余“translate 后直接把 GPA 当指针”的路径
4. 继续把“当前进程 user VA 直接解引用”收缩到 `usercopy`

验收标准：

1. 页表 walker 的返回值不再被上层直接解引用
2. 物理页读写统一经过 linear-map helper

### Phase 2：引入 per-cpu kmap_local

目标：

1. 为未来超出 linear map 覆盖范围的页访问打基础
2. 为页表编辑和特殊页访问提供正式机制

工作项：

1. 预留 `kmap` VA 区域
2. 为每个 CPU 建立少量固定槽位
3. 实现 `kmap_local_page()` 和 guard
4. 先让少数页表操作路径试用

验收标准：

1. 临时物理页访问不再依赖手写地址偏移
2. `kmap` 生命周期由 guard 管理

### Phase 3：建立 KernelVmSpace

目标：

1. 统一管理 kernel dynamic mappings
2. 让内核虚拟地址空间成为正式子系统

工作项：

1. 定义 kernel VA 区域布局
2. 为 `vmalloc/fixmap/ioremap` 留出范围
3. 引入 `KernelVmSpace` 或等价管理器
4. 把非 RAM 特殊映射逐步迁移到这一层

验收标准：

1. KVA 不再只有 linear map 一种来源
2. 特殊映射拥有独立生命周期管理

### Phase 4：评估 TTBR1 迁移

目标：

1. 在不改变上层调用习惯的前提下，切换为更真实的 kernel VA 架构

前提：

1. Phase 1 - 3 已完成
2. 用户访问与内核访问语义已彻底分离

收益：

1. 更接近真实 OS 的地址空间分层
2. 用户 / 内核页表责任更清晰
3. 后续安全性与调试模型更自然

## 十、与现有代码的直接关系

接下来若按本方案推进，最先会影响这些模块：

1. [physmap.rs](/Users/swift/WinEmu/winemu-kernel/src/mm/physmap.rs)
   - 从“GPA 访问 helper”提升为 `kernel linear map` 抽象
2. [usercopy.rs](/Users/swift/WinEmu/winemu-kernel/src/mm/usercopy.rs)
   - 收敛所有 user VA fastpath
3. [mmu.rs](/Users/swift/WinEmu/winemu-kernel/src/arch/aarch64/mmu.rs)
   - 明确 kernel global mapping 的组织方式
4. [vaspace.rs](/Users/swift/WinEmu/winemu-kernel/src/mm/vaspace.rs)
   - 页填充、COW、跨进程页拷贝统一走 KVA 语义
5. `nt/*`
   - 逐步消灭直接 user pointer deref

## 十一、风险与边界

### 11.1 不要把“更真实”理解成“立刻更复杂”

如果现在直接做：

1. `TTBR1`
2. higher-half
3. 大规模地址常量改写
4. 所有 callsite 一次性迁移

大概率会把问题从“体系演进”做成“全盘不稳定”。

### 11.2 Linear map 不是最终形态，但必须先稳定

即便未来上 `TTBR1`，linear map 仍然是需要的。

所以先把它正式化，不是浪费工作，而是后续所有方案的基础。

### 11.3 User fastpath 可以保留，但必须被封装

真实内核也会针对“当前地址空间可直接访问”的场景做优化。

问题不在于 fastpath 本身，而在于：

1. 不能把它暴露成默认访问方式
2. 不能让跨进程、跨地址空间路径误用

## 十二、建议的下一步

如果按顺序推进，建议下一步只做 `Phase 1`，不要同时启动 `Phase 2+`。

具体顺序：

1. 把 `physmap` 语义升级为 `kernel linear map`
2. 引入轻量地址类型
3. 继续清理 `user VA` 直接解引用路径
4. 只在 `Phase 1` 稳定后，再设计 `kmap_local`

## 十三、结论

“真正的 KVA 映射”在当前项目里，不应理解为“立刻切 TTBR1”，而应理解为：

1. 先把 kernel virtual memory 变成正式分层体系
2. 让 `linear map / usercopy / kmap / dynamic map / ioremap` 各自归位
3. 再决定是否切换到底层页表架构

这样推进，改动面可控，也最接近真实内核会采用的演进路径。
