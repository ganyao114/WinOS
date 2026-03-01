# WinEmu Kernel Object Ops 重构计划（参考 Wine object_ops）

## 1. 背景与目标

当前 guest kernel 的内核对象（`event/mutex/semaphore/file/process/section/key/token/thread`）在多个模块分散处理：

- `NtClose` 的销毁路径分散在 `nt/object.rs` + 各对象模块。
- `NtQueryObject` 的类型名/目标解析逻辑在 `nt/object.rs` 手工 `match`。
- `Wait` 相关逻辑在 `sched/sync.rs` 中按 `HANDLE_TYPE_*` 大量分支。

目标是引入一个类似 Wine `object_ops` 的统一接口层，把“按对象类型分发”的逻辑集中起来，降低后续扩展 syscall 时的改动面。

## 2. 设计原则

1. 保持架构原则：NT 语义继续在 guest kernel。
2. 先“统一接口层”，不一次性重写底层存储（仍保留各类型 `ObjectStore`）。
3. 采用渐进式改造，先覆盖低风险路径，再覆盖 wait/signal 等高风险路径。
4. 保持现有行为不变，先做重构再做能力增强。

## 3. 接口草案

新增 `winemu-kernel/src/nt/kobject.rs`：

- `KObjectOps`（按类型的静态函数表）
  - `type_name_utf16`
  - `close_last_ref(obj_idx) -> NTSTATUS`
  - （Phase B 起扩展）`is_waitable/add_waiter/remove_waiter/is_signaled/consume_signal/signal`
- 统一辅助方法
  - `ops_for_type(htype)`
  - `resolve_handle_target(handle) -> (htype, obj_idx)`（含 pseudo process 处理）
  - `close_last_ref(htype, obj_idx)`
  - `object_type_name(htype)`
  - `object_ref_count(htype, obj_idx)`

## 4. 分阶段计划

### Phase A（本次先推进）

范围：仅替换 `NtClose` / `NtQueryObject` 的对象分发入口。

- [x] 新增 `nt/kobject.rs` 静态 ops 表。
- [x] `NtClose` 从 `if/else + match` 改为 `kobject::close_last_ref()`。
- [x] `NtQueryObject` 的 `resolve target / type name` 改为 `kobject` 统一入口。
- [x] 回归测试：`open_process_test`、`syscall_file_control_test`、目录相关测试。

### Phase B

范围：将 `sched/sync.rs` 的 wait/signal 大分支改为对象 ops 调用。

- [x] 新增 `WaitableObjectOps` 统一分发层（`event/mutex/semaphore/thread/process`）。
- [x] `validate_waitable_handle_locked` 改为 ops 分发。
- [x] `is_handle_signaled_locked` 改为 ops 分发。
- [x] `consume_handle_signal_locked` 改为 ops 分发。
- [x] `register_waiter_on_handle_locked` 改为 ops 分发。
- [x] `remove_waiter_from_handle_locked` 改为 ops 分发。
- [x] 回归测试通过：`open_process_test`、`syscall_file_control_test`、`syscall_directory_test`、`syscall_directory_notify_test`。

### Phase C

范围：统一对象统计/可观测接口（类型计数、对象计数、句柄计数）。

- [x] 在 `sync` 层新增统一统计结构 `ObjectTypeStats` 与 `object_type_stats(htype)`。
- [x] 在 `nt/kobject.rs` 暴露统一统计入口，供上层 syscall 查询使用。
- [x] `NtQueryObject(ObjectTypeInformation)` 接入统一统计（对象总数/句柄总数/高水位字段）。
- [x] `ObjectTypeStats.object_count` 融合 backing store live 数（event/mutex/semaphore/thread/process）。

### Phase D（可选）

范围：逐步接入命名对象、安全描述符、访问映射等扩展接口。

- [x] `KObjectOps` 增加对象类型元数据（`valid_access_mask` / `security_required` / `maintain_handle_count`）。
- [x] `NtQueryObject(ObjectTypeInformation)` 改为读取 `kobject` 元数据填充访问与安全字段。
- [x] `KObjectOps` 增加命名查询入口（`query_name_utf16`），`NtQueryObject(ObjectNameInformation)` 改为按对象类型分发。
- [x] 首批命名对象接入：`Key` / `Section`。
- [x] `File` 对象命名接入（创建/打开时保留路径，支持 `ObjectNameInformation`）。
- [x] `NtDuplicateObject` 接入 `valid_access_mask` 校验（支持 `DUPLICATE_SAME_ACCESS`）。
- [x] `NtDuplicateObject` 接入 `DUPLICATE_CLOSE_SOURCE` 语义（复制后关闭源句柄）。
- [x] `NtOpenProcess` / `NtOpenProcessToken` 接入 `valid_access_mask` 校验。
- [x] `NtCreateProcessEx` / `NtCreateThreadEx` 接入 `valid_access_mask` 校验。

## 5. 风险与控制

- 风险：`Wait` 路径语义微妙，误改容易导致死锁/饥饿。
- 控制：Phase A 不碰 wait 语义，仅统一 close/query 路径；每阶段独立回归。

## 6. Phase A 验收标准

1. `NtClose` 与 `NtQueryObject` 行为与重构前一致。
2. 无新增死锁/资源泄露。
3. 构建与既有回归用例全部通过。
