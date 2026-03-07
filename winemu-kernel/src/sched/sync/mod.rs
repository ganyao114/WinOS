// sched/sync/mod.rs

pub mod wait_queue;
pub mod primitives_api;
pub mod state;
pub mod handles;

pub use wait_queue::WaitQueue;
pub use primitives_api::{KEvent, KMutex, KSemaphore};
pub use state::{SyncObject, SyncHandleTable, SYNC_STATE, init_sync_state, sync_alloc, sync_get, sync_get_mut, sync_free};
pub use handles::{
    create_event, set_event, reset_event, query_event,
    create_mutex, release_mutex,
    create_semaphore, release_semaphore,
    wait_for_single_object, wait_for_multiple_objects,
    close_handle,
    STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH,
};
