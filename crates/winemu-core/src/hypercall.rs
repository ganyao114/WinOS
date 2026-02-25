// hypercall 编号和 ABI 常量统一定义在 winemu-shared
// 此处 re-export，保持现有 `winemu_core::hypercall::nr::*` 调用路径不变
pub use winemu_shared::nr;
pub use winemu_shared::status;
pub use winemu_shared::timeout;
