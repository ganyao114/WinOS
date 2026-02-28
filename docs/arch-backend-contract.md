# WinEmu Kernel Arch Backend Contract

本文档定义 `winemu-kernel/src/arch/` 后端能力契约，目标是让新增架构时只改 `arch/mod.rs` 选择与对应 backend 目录，不改业务层代码。

## 后端选择

- `winemu-kernel/src/arch/mod.rs` 只负责选择 `backend`：
  - `aarch64 -> src/arch/aarch64/`
  - `x86_64 -> src/arch/x86_64/`
- 业务层只调用 `crate::arch::{cpu,mmu,timer,spin,hypercall,vectors}`。

## 必须实现的 backend 模块

每个 backend 目录都需要下列模块：

1. `cpu.rs`
   - `cpu_local_read() -> u64`
   - `cpu_local_write(u64)`
   - `fault_syndrome_read() -> u64`
   - `fault_address_read() -> u64`
   - `wait_for_interrupt()`

2. `mmu.rs`
   - `memory_features_raw() -> u64`
   - `physical_addr_range(u64) -> u8`
   - `supports_4k_granule(u64) -> bool`
   - `supports_64k_granule(u64) -> bool`
   - `current_user_table_root() -> u64`
   - `set_user_table_root(u64)`
   - `flush_tlb_global()`
   - `apply_translation_config(memory_attrs, translation_control, user_table_root)`
   - `read_system_control() -> u64`
   - `write_system_control(u64)`
   - `instruction_barrier()`

3. `timer.rs`
   - `DEFAULT_TIMESLICE_100NS`
   - `schedule_running_slice_100ns(now, next_deadline, quantum)`
   - `idle_wait_until_deadline_100ns(now, next_deadline)`

4. `spin.rs`
   - `lock_word(*mut u32)`
   - `unlock_word(*mut u32)`

5. `hypercall.rs`
   - `invoke6(nr, a0..a5) -> u64`
   - `forward_nt_syscall(frame, nr, table) -> u64`

6. `vectors.rs`
   - `install_exception_vectors()`

7. `boot.rs`
   - 提供平台入口（例如 `_start`），供 `#![no_main]` 内核镜像启动。

## 当前状态

- `aarch64`：完整实现。
- `x86_64`：已建立骨架（stub），接口齐全但未实现真实行为。

