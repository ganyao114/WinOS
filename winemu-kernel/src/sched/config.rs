// sched/config.rs — Scheduler feature flags for staged refactor.
//
// Keep all flags disabled by default so baseline behavior stays on the
// legacy path until each stage is explicitly enabled.

/// Enable Mesosphere-style pick path in `update_highest_priority_threads`.
pub const SCHED_USE_MESO_PICK: bool = false;

/// Build/validate Mesosphere shadow queue during unlock-edge updates.
pub const SCHED_ENABLE_MESO_SHADOW: bool = false;

/// Legacy safety net: rebuild ready queue from thread states every scheduler
/// round. Keep disabled to avoid multi-core duplicate picks.
pub const SCHED_REBUILD_READY_EACH_ROUND: bool = false;
