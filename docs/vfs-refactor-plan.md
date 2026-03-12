# WinEmu 文件系统/VFS 重构方案

## 1. 背景与目标

当前 WinEmu 的文件系统操作本质上是“guest kernel 直接调用 host file hostcall”：

- NT 文件 syscall 路径直接依赖 `hypercall::host_*`
- `section/image/pager` 直接依赖原始 `host fd`
- EXE/DLL 加载路径绕过 NT 文件层，直接读 host 文件

这套实现能工作，但边界是反的：现在不是“内核通过文件系统访问后端”，而是“业务逻辑直接知道 host 文件后端怎么工作”。这样会带来两个直接问题：

1. 代码分散且职责混乱，后续继续实现更多 syscall 会越来越难维护。
2. 将来要迁移到真正的 kernel 文件系统时，改动面会波及 `nt/mm/ldr/dll/main` 多个子系统，而不只是替换一个后端。

本方案的目标是：

1. 在 `winemu-kernel/src/fs` 建立内核内部的 VFS 边界。
2. 先实现 `hostfs` 后端，把现有 hostcall 文件能力收敛到 `fs` 内部。
3. 将 `nt/file.rs`、`nt/section.rs`、`mm/vaspace.rs`、`ldr.rs`、`dll.rs`、`main.rs` 统一迁移到 `fs` 接口。
4. 为后续真正的 kernel 文件系统保留替换空间，避免公共接口暴露 `host fd` / `host mmap` / 原始 hostcall opcode。

非目标：

1. 本阶段不重做完整 Windows 对象命名空间。
2. 本阶段不引入复杂 dentry cache / page cache / journaling。
3. 本阶段不要求一次性改造 VMM host backend，只要求把它降级为 `hostfs` 的实现细节。

## 2. 当前代码现状与主要问题

### 2.1 `nt/file.rs` 职责过载

`winemu-kernel/src/nt/file.rs` 当前同时承担了多类职责：

- NT syscall 参数解析与返回写回
- 文件对象创建/关闭
- 同步读写与异步 hostcall 跟踪
- 目录枚举与目录变更通知
- `\\Device\\WinEmuHost` 伪设备分发
- `DeviceIoControl` / `FsControl` / volume info 适配

这意味着“NT 语义层”和“文件系统后端层”完全耦合在一个文件里。

### 2.2 文件对象和 section 对象直接保存 `host fd`

当前 `winemu-kernel/src/nt/state.rs` 中：

- `GuestFile` 保存 `host_fd`
- `GuestSection` 保存 `file_fd`

并且：

- `file_free()` 直接 `hypercall::host_close`
- `nt/common.rs` 提供 `file_handle_to_host_fd()`
- `nt/section.rs` 用文件句柄解析出 `host fd`

这使得“文件对象 = host fd 包装”，而不是“文件对象 = VFS open file”。

### 2.3 `section` / `pager` 直接依赖原始文件后端

当前 file-backed section 的关键耦合点：

- `winemu-kernel/src/nt/section.rs`
- `winemu-kernel/src/mm/vm_area.rs`
- `winemu-kernel/src/mm/vaspace.rs`

其中 `mm/vaspace.rs` 的缺页填充直接：

- 读取 `area.section_file_fd`
- 调用 `hypercall::host_read_phys(...)`

这意味着 VM 子系统知道“背后是 host fd”，这是未来迁移真实内核文件系统时最不应该出现的耦合。

### 2.4 Loader / DLL / boot 路径绕过文件子系统

当前以下路径直接绕过 NT 文件层：

- `winemu-kernel/src/main.rs`
  - `query_exe_info()`
  - `host_read()`
  - `host_close()`
- `winemu-kernel/src/ldr.rs`
  - `host_read()`
  - `host_read_phys()`
- `winemu-kernel/src/dll.rs`
  - `host_open()`
  - `host_stat()`
  - `host_mmap_untracked()`
  - `host_munmap()`

这会导致以后即使重构了 `NtCreateFile/NtReadFile`，内核镜像加载路径依然继续打穿抽象层。

### 2.5 路径规范化存在，但还不是 VFS namespace

`winemu-kernel/src/nt/path.rs` 已经有：

- `ObjectAttributesView`
- `UnicodeStringView`
- `normalize_nt_path()`

但这仍然只是“从用户态读路径并做字符串规整”，不是 namespace / mount / device 分发。

### 2.6 VMM 侧已经具备可复用的 host 文件后端能力

当前 VMM 侧相关实现：

- `crates/winemu-vmm/src/host_file.rs`
- `crates/winemu-vmm/src/hostcall/handlers.rs`
- `crates/winemu-vmm/src/hostcall/modules/file_io/mod.rs`

它们已经提供：

- open/read/write/close/stat
- readdir/notify_dir_change
- mmap/munmap

这些能力足够作为第一版 `hostfs` 后端，但不应该继续直接暴露给 kernel 业务层。

## 3. 目标分层

目标分层如下：

```text
NT syscall / loader / MM
        |
        v
kernel fs facade (`winemu-kernel/src/fs`)
        |
        +-- namespace / mount / device dispatch
        +-- open file / node / backing / pager
        +-- async request token / completion abstraction
        |
        +-- hostfs backend
        +-- devfs backend
        +-- future real kernel fs backend
```

边界原则：

1. `nt/*` 只负责 NT ABI、句柄、`IO_STATUS_BLOCK`、event/APC/wait 语义。
2. `fs/*` 负责文件系统对象、路径解析、后端分发、文件/目录/设备操作、file-backed backing、pager 接口。
3. `mm/*` 不再知道 `host fd`，只依赖 `fs::pager` 或 `fs::backing`。
4. `ldr.rs` / `dll.rs` / `main.rs` 不再直接调用 `hypercall::host_*`，统一走 `fs`。

## 4. 核心设计原则

### 4.1 公共接口不能暴露 host 后端细节

以下内容只能存在于 `fs::hostfs` 内部，不能成为对上层公开的长期 API：

- `host fd`
- `host mmap`
- `hypercall::host_*`
- VMM hostcall opcode

否则未来真实 kernel 文件系统接入时，上层仍然要整体返工。

### 4.2 先做“简化 VFS”，不要一开始过度设计

本阶段建议采用简化模型：

- `Mount`
- `VNode` 或等价 `FsNode`
- `OpenFile`
- `SectionBacking`

先不做完整 dentry cache，也不做完整权限模型。目标是先把边界收口正确。

### 4.3 保持当前内核对象存储风格

结合当前代码现状，不建议第一步就上 `Arc<dyn Trait>` 风格的重抽象。

更贴合现状的做法是：

- `fs` 内部继续使用 `ObjectStore` / index 风格对象存储
- 通过 `backend kind + backend obj idx + 静态 ops 表` 做后端分发

这样更容易和现在的 `KObjectKind`、`handle_table`、`ObjectStore` 风格对齐。

### 4.4 `Section` 不能继续绑定“文件句柄生命周期”

未来 `Section` 的 file-backed backing 必须独立于用户态文件句柄生存。

也就是说：

- 关闭文件 handle 不应自动使已经创建的 file-backed section 失效
- `Section` 必须持有一个独立的 `FsBackingRef`

这比“简单把 `host fd` 换成 `FsFileHandle`”更重要。

## 5. 建议的 `fs` 模块结构

建议新增：

```text
winemu-kernel/src/fs/
  mod.rs
  types.rs
  path.rs
  namespace.rs
  object.rs
  file.rs
  dir.rs
  notify.rs
  device.rs
  volume.rs
  backing.rs
  pager.rs
  bootstrap.rs
  hostfs/
    mod.rs
    state.rs
    hostcall.rs
  devfs/
    mod.rs
    winemu_host.rs
```

各文件职责建议：

- `types.rs`
  - `FsNodeKind`
  - `FsOpenOptions`
  - `FsFileInfo`
  - `FsDirEntry`
  - `FsNotifyRecord`
  - `FsVolumeInfo`
  - `FsRequestId`
- `path.rs`
  - NT 风格路径规整
  - 路径切分
  - 设备前缀/根路径辅助
- `namespace.rs`
  - mount 表
  - path -> backend/node 分发
  - `\\Device\\...` / 普通文件路径路由
- `object.rs`
  - `FsNode`
  - `FsOpenFile`
  - `FsSectionBacking`
  - 统一 store / ref 管理
- `file.rs`
  - open/create/read/write/query/set/info
- `dir.rs`
  - readdir / query directory
- `notify.rs`
  - 目录变更通知
- `device.rs`
  - `DeviceIoControl` / `FsControl` 风格入口
- `volume.rs`
  - volume/device/fs attribute 查询
- `backing.rs`
  - 从 open file 派生 section/image backing
- `pager.rs`
  - read-at / page-in 到物理页
- `bootstrap.rs`
  - 初始 EXE 的过渡入口封装
- `hostfs/*`
  - hostcall 文件后端实现
- `devfs/*`
  - `\\Device\\WinEmuHost` 等设备节点

## 6. 核心对象模型

建议把“文件系统对象”和“NT handle 对象”分开看：

### 6.1 `FsOpenFile`

表示一次打开实例，包含：

- 后端类型
- 后端对象索引
- 访问权限/打开选项
- 可查询路径
- 可能的当前位置状态

对应 NT 的 `File` handle。

### 6.2 `FsNode`

表示文件系统节点，抽象底层“文件/目录/设备”。

短期内可以不做完整 inode/dentry 分离，但至少要有：

- kind: file / dir / device
- backend kind
- backend node idx
- 元信息查询入口

### 6.3 `FsSectionBacking`

表示可供 section / image / pager 使用的长期 backing 引用，包含：

- 后端类型
- 后端 backing idx
- 逻辑文件偏移
- 视图大小
- 是否 image
- 是否可执行/只读等能力位

`Section` 应保存这个 backing，而不是保存 `host fd`。

### 6.4 后端对象

以 `hostfs` 为例，内部可以有：

- `HostFsNode`
- `HostFsOpenFile`
- `HostFsBacking`

其中真正的 `host fd` 只放在这些 backend 对象里，并通过 refcount 控制何时调用 `host_close`。

## 7. 建议的公共接口形态

结合当前代码风格，建议先做“静态分发 + store id”的接口，而不是直接上 trait object。

示意接口如下：

```rust
pub struct FsOpenRequest<'a> {
    pub path: &'a str,
    pub desired_access: u32,
    pub share_access: u32,
    pub disposition: u32,
    pub options: u32,
}

pub struct FsReadRequest {
    pub file: u32,
    pub owner_pid: u32,
    pub user_buffer: UserVa,
    pub len: usize,
    pub offset: u64,
}

pub enum FsSubmitOutcome<T> {
    Completed(T),
    Pending(FsRequestId),
}

pub fn open(req: &FsOpenRequest<'_>) -> Result<u32, u32>;
pub fn close(file: u32);
pub fn read(req: &FsReadRequest) -> Result<FsSubmitOutcome<usize>, u32>;
pub fn write(req: &FsWriteRequest) -> Result<FsSubmitOutcome<usize>, u32>;
pub fn query_info(file: u32, class: u32) -> Result<FsFileInfo, u32>;
pub fn query_dir(file: u32, pattern: Option<&[u8]>, restart: bool) -> Result<FsDirEntry, u32>;
pub fn notify_dir(file: u32, watch_tree: bool, filter: u32)
    -> Result<FsSubmitOutcome<FsNotifyRecord>, u32>;
pub fn query_volume(file: u32, class: u32) -> Result<FsVolumeInfo, u32>;
pub fn device_io_control(file: u32, code: u32, input: &[u8])
    -> Result<FsSubmitOutcome<FsIoctlResult>, u32>;
pub fn create_backing_from_file(file: u32, offset: u64, size: u64, is_image: bool)
    -> Result<u32, u32>;
pub fn pager_read_into_phys(backing: u32, file_off: u64, dst: PhysAddr, len: usize)
    -> Result<usize, u32>;
```

这里的关键点不是返回值细节，而是边界：

1. 上层拿到的是 `fs object id`，不是 `host fd`。
2. `pager` 操作也是 `fs` 公共接口的一部分。
3. 异步结果通过 `FsSubmitOutcome` 暴露，不把 NT event/IOSB 放进 `fs`。

## 8. NT 层与 `fs` 层的边界调整

### 8.1 `nt/file.rs` 应保留什么

`nt/file.rs` 重构后建议只保留：

- syscall ABI 参数解析
- 用户缓冲区读写/结构布局适配
- `IO_STATUS_BLOCK` 写回
- `STATUS_PENDING`、event、wait/APC 语义
- NT specific information class 到 `fs` 查询结构的转换

### 8.2 `nt/file.rs` 应移出的内容

以下逻辑应迁移到 `fs`：

- 文件对象分配/关闭
- path -> backend 的实际分发
- hostcall open/read/write/stat/readdir/notify
- `\\Device\\WinEmuHost` 特判
- 目录通知后端请求管理
- file-backed backing 构造

### 8.3 异步请求边界

当前 `nt/file.rs` 里存在：

- `PendingFileIo`
- `PendingDirNotify`
- `PendingHostIoctl`

建议目标边界是：

1. `fs` 负责提交后端请求、取消请求、接收完成结果。
2. `nt/file.rs` 负责把 `Completed/Pending` 结果映射成 NT 的 `IOSB/event/wait` 行为。

这样既能让 `fs` 拥有“真实文件后端请求”的控制权，又不会把 NT wait/event 语义污染进 `fs`。

## 9. `hostfs` 后端设计

### 9.1 目标

`hostfs` 是第一版 VFS backend，实现方式仍然基于现有 hostcall 能力，但要求：

- 上层完全不知道 hostcall 细节
- `host fd` 生命周期由 `fs::hostfs` 内部维护
- 支持普通文件、目录、目录通知、volume 查询、pager read-at

### 9.2 能力映射

当前 hostcall 能力可映射为：

- `host_open` -> `hostfs::open`
- `host_read/host_read_phys` -> `hostfs::read` / `hostfs::pager_read_into_phys`
- `host_write/host_write_phys` -> `hostfs::write`
- `host_stat` -> `hostfs::query_info`
- `host_readdir` -> `hostfs::query_dir`
- `host_notify_dir` -> `hostfs::notify_dir`
- `host_close` -> `hostfs` 最终 ref release

### 9.3 关于 `host_mmap`

`host_mmap_untracked` / `host_munmap` 不应成为 VFS 公共接口。

处理建议：

1. 对 loader 来说，公共路径统一改成 `fs` 的 read/read-at。
2. `hostfs` 内部如果仍要保留 `mmap` 作为性能优化，可以作为 backend 私有 fastpath。
3. 上层 `dll.rs` / `ldr.rs` 不能再直接调用 `host_mmap_*`。

### 9.4 初始 EXE 的 bootstrap

当前 `main.rs` 通过 `query_exe_info()` 拿到 `(fd, size)`。

短期可接受的过渡方案：

1. 保留 `query_exe_info()` 作为 boot strap 来源。
2. 但立刻在 `fs::bootstrap` 中封装成 `open_initial_exe()` 或等价接口。
3. 从 `main.rs` 起，boot loader 也只和 `fs` 对话。

长期目标：

- 初始 EXE 也作为 `fs` namespace 中的一个正常文件来源。

## 10. `devfs` 与 `\\Device\\WinEmuHost`

当前 `\\Device\\WinEmuHost` 是 `nt/file.rs` 里的 special case。

这不利于后续扩展更多设备对象。建议改成：

- `fs::devfs` 挂载在 `\\Device`
- `WinEmuHost` 实现为一个 device node/backend
- `DeviceIoControlFile` 路由到 `fs::device`

这样后续如果要增加：

- console
- named pipe
- socket
- 图形/输入设备

就不需要继续在 `nt/file.rs` 里追加特殊分支。

## 11. 与 section / image / pager 的对接

这是本次方案最关键的一部分，必须从第一天就纳入设计。

### 11.1 `Section` 对象改造

当前 `GuestSection.file_fd` 需要改成：

- `section.backing_id: u32`
- 或等价 `FsSectionBackingRef`

`nt/section.rs` 的 `handle_create_section()` 应做的事情变成：

1. 从 file handle 拿到 `FsOpenFile`
2. 调用 `fs::create_backing_from_file(...)`
3. 把返回的 backing id 存入 section

### 11.2 `VmArea` 改造

当前 `VmArea.section_file_fd` / `section_file_backed` / `section_is_image` 这组字段，建议改成更明确的 backing 语义：

- `section_backing_id`
- `section_has_backing`
- `section_is_image`
- `section_file_offset`
- `section_view_size`

核心点是：`VmArea` 不再保存任何 host backend 细节。

### 11.3 `vaspace` 缺页填充改造

当前 `vm_fill_section_page()` 直接 `host_read_phys()`。

目标应改成：

```text
vm_fill_section_page()
  -> fs::pager_read_into_phys(backing_id, file_off, dst_pa, len)
      -> backend pager op
```

这样以后无论 backing 来自：

- hostfs
- 真实磁盘文件系统
- page cache
- 压缩镜像

VM 都不需要改。

### 11.4 Loader / image path

`ldr.rs` / `dll.rs` 应统一切换为：

- `fs::open`
- `fs::query_info`
- `fs::read`
- `fs::read_at`

而不是继续走独立的 host 文件加载逻辑。

如果后续 image section 进一步和 pager 对齐，还可以把 PE image load 与 section/image 映射路径继续合并。

## 12. 建议的迁移顺序

建议按以下顺序推进，风险最低。

### Phase 1：建立 `fs` 骨架与 `hostfs` 基础能力

目标：

- 新增 `winemu-kernel/src/fs`
- 建立最小对象模型
- 封装 `host_open/read/write/close/stat`

此阶段完成后要求：

- 新增 `fs::open/close/read/write/query_info`
- `host fd` 仅存在于 `fs::hostfs`

### Phase 2：先迁移 boot/loader/DLL 直连路径

优先迁移：

- `main.rs`
- `ldr.rs`
- `dll.rs`

原因：

1. 这些路径接口最简单，先验证 `fs` 基础 API 是否合理。
2. 不涉及 NT async/pending 语义，改造风险低。
3. 可以先把“直接使用 `hypercall::host_*` 的路径”快速清掉一大块。

此阶段完成后要求：

- `main.rs` / `ldr.rs` / `dll.rs` 不再直接调用 `hypercall::host_*`

### Phase 3：迁移 NT 文件对象创建与简单元信息查询

迁移范围：

- `NtCreateFile`
- `NtOpenFile`
- `NtQueryInformationFile`
- `NtQueryVolumeInformationFile`
- `NtClose(File)`

此阶段重点：

- 用 `FsOpenFile` 替换 `GuestFile.host_fd`
- 把 `file_handle_to_host_fd()` 收口为 `file_handle_to_fs_file()`

### Phase 4：迁移目录枚举与简单设备分发

迁移范围：

- `NtQueryDirectoryFile`
- `FsControl`
- `DeviceIoControlFile` 的路由骨架

此阶段要开始引入：

- `fs::dir`
- `fs::device`
- `fs::namespace`
- `fs::devfs::WinEmuHost`

完成后要求：

- `\\Device\\WinEmuHost` 不再在 `nt/file.rs` 中特判

### Phase 5：迁移读写与异步请求

迁移范围：

- `NtReadFile`
- `NtWriteFile`
- 目录通知
- host ioctl pending

此阶段目标：

- `PendingFileIo` / `PendingDirNotify` / `PendingHostIoctl` 的后端部分迁入 `fs`
- NT 层只保留 `IOSB/event/wait` 适配

### Phase 6：迁移 section/backing/pager

迁移范围：

- `nt/section.rs`
- `mm/vm_area.rs`
- `mm/vaspace.rs`

此阶段是整个方案的第二个关键点。完成后要求：

1. `GuestSection` 不再保存 `file_fd`
2. `VmArea` 不再保存 `section_file_fd`
3. `mm/vaspace.rs` 不再直接调用 `hypercall::host_read_phys`

### Phase 7：清理旧辅助接口与遗留状态

删除或收口：

- `nt/common.rs` 中的 `file_handle_to_host_fd*`
- `nt/state.rs` 中与 `host fd` 绑定的文件存储
- `dll.rs` / `ldr.rs` / `main.rs` 中遗留的 host 文件操作

最终验收标准：

1. `winemu-kernel` 中除 `fs::hostfs` 外，不再出现文件相关 `hypercall::host_*` 直接调用。
2. `nt/mm/ldr/main/dll` 不再保存或传播 `host fd`。
3. `\\Device\\WinEmuHost` 从 NT 特判收敛为 `devfs` 节点。

## 13. 风险点

### 13.1 生命周期风险

最大风险不是接口，而是生命周期：

- 文件 handle 关闭
- section 仍然存活
- pager 仍然需要继续读 backing

因此 `FsSectionBacking` 必须独立引用 backend 资源，不能偷懒复用用户态文件 handle 生命周期。

### 13.2 异步语义边界风险

如果把 event/IOSB/APC 也硬塞进 `fs`，后面 `fs` 会再次变成 NT 层的一部分。

因此要坚持：

- `fs` 负责真实后端请求
- `nt` 负责 NT 完成语义

### 13.3 path/namespace 过度设计风险

当前 `normalize_nt_path()` 仍然较简化，短期不应该顺手重做完整 Windows Object Manager namespace。

建议：

1. 先保留当前路径归一化语义。
2. 只把“设备/后端路由”收入口到 `fs::namespace`。
3. 完成边界收口后，再考虑更完整的命名空间。

## 14. 验收标准与回归建议

结构验收标准：

1. `winemu-kernel/src/fs` 成为唯一文件系统公共入口。
2. 文件相关 hostcall 只出现在 `fs::hostfs`。
3. `section/image/pager` 已经过 `fs` backing/pager 接口。
4. NT 文件 syscall 代码显著变薄。

建议回归顺序：

1. `cargo build`
2. `./scripts/build-kernel-bin.sh`
3. `tests/thread_test`
4. `guest/sysroot/process_test.exe`
5. `guest/sysroot/syscall_file_control_test.exe`
6. `guest/sysroot/syscall_directory_test.exe`
7. `guest/sysroot/syscall_directory_notify_test.exe`
8. `tests/full_test`
9. `tests/window_test`

## 15. 结论

这个重构的关键不是“新建一个 `fs` 目录”，而是把以下三个长期错误边界一起修正：

1. `File object != host fd`
2. `Section backing != raw file handle`
3. `Loader/MM/NT 不再各自直连 host file backend`

只要这三个边界收对了，后续无论是继续增强 `hostfs`，还是迁移到真正的 kernel 文件系统，改动面都会明显可控。
