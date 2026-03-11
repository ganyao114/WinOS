pub const DEFAULT_TIMESLICE_100NS: u64 = 150_000;

#[inline(always)]
fn unsupported() -> ! {
    panic!("x86_64 backend is a stub");
}

#[inline(always)]
pub fn schedule_running_slice_100ns(
    _now_100ns: u64,
    _next_deadline_100ns: u64,
    _quantum_100ns: u64,
) {
    unsupported()
}

#[inline(always)]
pub fn idle_wait_until_deadline_100ns(_now_100ns: u64, _next_deadline_100ns: u64) {
    unsupported()
}
