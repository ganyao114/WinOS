type Backend = super::backend::ArchBackend;

pub const DEFAULT_TIMESLICE_100NS: u64 =
    <Backend as super::contract::TimerBackend>::DEFAULT_TIMESLICE_100NS;

#[inline(always)]
pub fn schedule_running_slice_100ns(now_100ns: u64, next_deadline_100ns: u64, quantum_100ns: u64) {
    <Backend as super::contract::TimerBackend>::schedule_running_slice_100ns(
        now_100ns,
        next_deadline_100ns,
        quantum_100ns,
    );
}

#[inline(always)]
pub fn idle_wait_until_deadline_100ns(now_100ns: u64, next_deadline_100ns: u64) {
    <Backend as super::contract::TimerBackend>::idle_wait_until_deadline_100ns(
        now_100ns,
        next_deadline_100ns,
    );
}
