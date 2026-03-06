// sched/thread_store.rs — ObjectStore<KThread> 封装
// 提供 with_thread / with_thread_mut / thread_exists 等安全 API

use crate::kobj::ObjectStore;
use super::types::KThread;
use super::global::SCHED;

pub(crate) fn thread_store_mut() -> &'static mut ObjectStore<KThread> {
    unsafe {
        let slot = &mut *SCHED.threads.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn thread_ptr(tid: u32) -> *mut KThread {
    if tid == 0 {
        return core::ptr::null_mut();
    }
    thread_store_mut().get_ptr(tid)
}

pub fn thread_exists(tid: u32) -> bool {
    if tid == 0 {
        return false;
    }
    unsafe {
        let Some(store) = (&*SCHED.threads.get()).as_ref() else {
            return false;
        };
        store.contains(tid)
    }
}

pub fn thread_count() -> u32 {
    unsafe {
        let Some(store) = (&*SCHED.threads.get()).as_ref() else {
            return 0;
        };
        let mut count = 0u32;
        store.for_each_live_id(|_| {
            count = count.saturating_add(1);
        });
        count
    }
}

#[inline(always)]
pub fn with_thread<R>(tid: u32, f: impl FnOnce(&KThread) -> R) -> R {
    let ptr = thread_ptr(tid);
    unsafe { f(&*ptr) }
}

#[inline(always)]
pub fn with_thread_mut<R>(tid: u32, f: impl FnOnce(&mut KThread) -> R) -> R {
    let ptr = thread_ptr(tid);
    unsafe { f(&mut *ptr) }
}
