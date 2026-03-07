// sched/sync/legacy_handles.rs — Handle type constants (legacy NT handle API)
// All handle table operations have been migrated to process::KHandleTable.

pub const HANDLE_TYPE_NONE:      u64 = 0;
pub const HANDLE_TYPE_EVENT:     u64 = 1;
pub const HANDLE_TYPE_MUTEX:     u64 = 2;
pub const HANDLE_TYPE_SEMAPHORE: u64 = 3;
pub const HANDLE_TYPE_THREAD:    u64 = 4;
pub const HANDLE_TYPE_PROCESS:   u64 = 5;
pub const HANDLE_TYPE_FILE:      u64 = 6;
pub const HANDLE_TYPE_SECTION:   u64 = 7;
pub const HANDLE_TYPE_KEY:       u64 = 8;
pub const HANDLE_TYPE_TOKEN:     u64 = 9;
