// sched/sync/mod.rs

pub mod wait_queue;
pub mod primitives_api;
pub mod state;
pub mod handles;
pub mod legacy_handles;

pub use wait_queue::WaitQueue;
pub use primitives_api::{KEvent, KMutex, KSemaphore};
pub use state::{
    SyncObject, SyncHandleTable, SYNC_STATE, init_sync_state,
    sync_alloc, sync_get, sync_get_mut, sync_free,
    sync_get_by_idx, sync_get_mut_by_idx, sync_free_idx,
};
pub use handles::{
    create_event, set_event, reset_event, query_event,
    create_mutex, release_mutex,
    create_semaphore, release_semaphore,
    wait_for_single_object, wait_for_multiple_objects,
    close_handle,
    delay_current_thread_sync, event_set_by_handle_for_pid,
    STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH,
};
// HANDLE_TYPE_* constants still used by kobject::htype_to_kind
pub use legacy_handles::{
    HANDLE_TYPE_NONE, HANDLE_TYPE_EVENT, HANDLE_TYPE_MUTEX, HANDLE_TYPE_SEMAPHORE,
    HANDLE_TYPE_THREAD, HANDLE_TYPE_PROCESS, HANDLE_TYPE_FILE, HANDLE_TYPE_SECTION,
    HANDLE_TYPE_KEY, HANDLE_TYPE_TOKEN,
};
