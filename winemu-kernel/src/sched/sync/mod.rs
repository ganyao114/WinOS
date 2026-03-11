// sched/sync/mod.rs

pub mod handles;
pub mod legacy_handles;
pub mod primitives_api;
pub mod state;
pub mod wait_queue;

pub use handles::{
    create_event, create_mutex, create_semaphore, delay_current_thread_sync,
    detach_thread_sync_wait_links_locked, event_set_by_handle_for_pid, query_event, release_mutex,
    release_semaphore, reset_event, set_event, wait_for_multiple_objects, wait_for_single_object,
};
pub use state::{init_sync_state, sync_alloc, sync_free_idx, SyncObject};
pub use wait_queue::WaitQueue;
// HANDLE_TYPE_* constants still used by kobject::htype_to_kind
pub use legacy_handles::{
    HANDLE_TYPE_EVENT, HANDLE_TYPE_FILE, HANDLE_TYPE_KEY, HANDLE_TYPE_MUTEX, HANDLE_TYPE_PROCESS,
    HANDLE_TYPE_SECTION, HANDLE_TYPE_SEMAPHORE, HANDLE_TYPE_THREAD, HANDLE_TYPE_TOKEN,
};
