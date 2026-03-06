// sched/global.rs — KGlobalScheduler 全局单例 + KScheduler per-vCPU

use core::cell::UnsafeCell;
use crate::kobj::ObjectStore;
use super::types::{KThread, MAX_VCPUS};
use super::queue::KReadyQueue;

pub(crate) const DEFERRED_KSTACK_CAP: usize = 1024;

// ── per-vCPU 调度器 ───────────────────────────────────────────

pub struct KScheduler {
    pub current_tid: u32,
    pub needs_scheduling: bool,
}

impl KScheduler {
    pub const fn new() -> Self {
        Self {
            current_tid: 0,
            needs_scheduling: false,
        }
    }
}

// ── 全局调度器 ────────────────────────────────────────────────

pub struct KGlobalScheduler {
    pub threads: UnsafeCell<Option<ObjectStore<KThread>>>,
    pub ready_queue: UnsafeCell<KReadyQueue>,
    pub vcpus: UnsafeCell<[KScheduler; MAX_VCPUS]>,
    pub idle_tid_by_vcpu: UnsafeCell<[u32; MAX_VCPUS]>,

    // 调度掩码
    pub pending_reschedule_mask: UnsafeCell<u32>,
    pub reschedule_mask: UnsafeCell<u32>,
    pub idle_vcpu_mask: UnsafeCell<u32>,
    pub online_vcpu_mask: UnsafeCell<u32>,

    // 轮询入队计数器
    pub enqueue_rr: UnsafeCell<u8>,

    // 统计
    pub schedule_unlock_edge_count: UnsafeCell<u64>,
    pub schedule_trap_count: UnsafeCell<u64>,

    // 延迟释放内核栈
    pub deferred_kstack_bases: UnsafeCell<[u64; DEFERRED_KSTACK_CAP]>,
    pub deferred_kstack_len: UnsafeCell<usize>,

    // 调度锁（可重入自旋锁）
    pub lock_count: UnsafeCell<u32>,
    pub lock_owner: UnsafeCell<u32>, // vcpu_id+1，0=未持有
    pub spinlock: UnsafeCell<u32>,   // 0=free, 1=locked
}

unsafe impl Sync for KGlobalScheduler {}

impl KGlobalScheduler {
    pub const fn new() -> Self {
        Self {
            threads: UnsafeCell::new(None),
            ready_queue: UnsafeCell::new(KReadyQueue::new()),
            vcpus: UnsafeCell::new([const { KScheduler::new() }; MAX_VCPUS]),
            idle_tid_by_vcpu: UnsafeCell::new([0; MAX_VCPUS]),
            pending_reschedule_mask: UnsafeCell::new(0),
            reschedule_mask: UnsafeCell::new(0),
            idle_vcpu_mask: UnsafeCell::new(0),
            online_vcpu_mask: UnsafeCell::new(0),
            enqueue_rr: UnsafeCell::new(0),
            schedule_unlock_edge_count: UnsafeCell::new(0),
            schedule_trap_count: UnsafeCell::new(0),
            deferred_kstack_bases: UnsafeCell::new([0; DEFERRED_KSTACK_CAP]),
            deferred_kstack_len: UnsafeCell::new(0),
            lock_count: UnsafeCell::new(0),
            lock_owner: UnsafeCell::new(0),
            spinlock: UnsafeCell::new(0),
        }
    }
}

pub static SCHED: KGlobalScheduler = KGlobalScheduler::new();

#[no_mangle]
pub static mut __winemu_vcpu_kernel_sp: [u64; MAX_VCPUS] = [0; MAX_VCPUS];
