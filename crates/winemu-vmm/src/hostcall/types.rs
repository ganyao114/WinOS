use std::vec::Vec;

#[derive(Debug)]
pub enum WorkerPayload {
    None,
    Path(Box<str>),
    Bytes(Box<[u8]>),
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct HostCallCompletion {
    pub request_id: u64,
    pub host_result: i32,
    pub flags: u32,
    pub value0: u64,
    pub value1: u64,
    pub user_tag: u64,
}

#[derive(Clone, Copy, Debug)]
pub enum SubmitResult {
    Completed { host_result: u64, aux: u64 },
    Pending { request_id: u64 },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HostCallOpStats {
    pub opcode: u64,
    pub submit_sync: u64,
    pub submit_async: u64,
    pub complete_sync: u64,
    pub complete_async: u64,
    pub cancel: u64,
    pub backpressure: u64,
}

#[derive(Clone, Debug, Default)]
pub struct HostCallStatsSnapshot {
    pub submit_sync_total: u64,
    pub submit_async_total: u64,
    pub complete_sync_total: u64,
    pub complete_async_total: u64,
    pub cancel_total: u64,
    pub backpressure_total: u64,
    pub completion_queue_high_watermark: usize,
    pub op_stats: Vec<HostCallOpStats>,
}
