fn thread_store_mut() -> &'static mut ObjectStore<KThread> {
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

#[inline(always)]
fn default_kernel_stack_top() -> u64 {
    crate::arch::vectors::default_kernel_stack_top()
}

#[inline(always)]
fn kstack_top_from_thread(t: &KThread) -> u64 {
    if t.kstack_base != 0 && t.kstack_size != 0 {
        t.kstack_base.saturating_add(t.kstack_size as u64)
    } else {
        default_kernel_stack_top()
    }
}

#[inline(always)]
fn set_vcpu_kernel_sp(vid: usize, sp: u64) {
    if vid < MAX_VCPUS {
        unsafe {
            __winemu_vcpu_kernel_sp[vid] = if sp != 0 { sp } else { default_kernel_stack_top() };
        }
    }
}

#[inline(always)]
fn set_vcpu_kernel_sp_for_tid(vid: usize, tid: u32) {
    if tid != 0 && thread_exists(tid) {
        let sp = with_thread(tid, kstack_top_from_thread);
        set_vcpu_kernel_sp(vid, sp);
    } else {
        set_vcpu_kernel_sp(vid, default_kernel_stack_top());
    }
}

pub fn current_thread_kernel_stack_top() -> u64 {
    let tid = current_tid();
    if tid == 0 || !thread_exists(tid) {
        return default_kernel_stack_top();
    }
    with_thread(tid, kstack_top_from_thread)
}

pub fn current_thread_kernel_stack_base() -> u64 {
    let tid = current_tid();
    if tid == 0 || !thread_exists(tid) {
        return 0;
    }
    with_thread(tid, |t| t.kstack_base)
}

pub fn migrate_svc_frame_to_current_kstack(frame_ptr: *mut u8, frame_size: usize) -> *mut u8 {
    if frame_ptr.is_null() || frame_size == 0 {
        return frame_ptr;
    }
    let tid = current_tid();
    if tid == 0 || !thread_exists(tid) {
        return frame_ptr;
    }
    let (base, top) = with_thread(tid, |t| (t.kstack_base, kstack_top_from_thread(t)));
    if base == 0 || top == 0 {
        return frame_ptr;
    }
    let base_usize = base as usize;
    let top_usize = top as usize;
    if top_usize <= base_usize || frame_size > top_usize.saturating_sub(base_usize) {
        return frame_ptr;
    }
    let new_frame_usize = top_usize.saturating_sub(frame_size);
    if new_frame_usize < base_usize {
        return frame_ptr;
    }
    let new_frame = new_frame_usize as *mut u8;
    if new_frame.is_null() || new_frame == frame_ptr {
        return frame_ptr;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(frame_ptr, new_frame, frame_size);
    }
    sched_lock_acquire();
    with_thread_mut(tid, |t| {
        t.kctx.sp_el1 = new_frame as u64;
        t.in_kernel = true;
    });
    sched_lock_release();
    new_frame
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

pub fn with_thread<R>(tid: u32, f: impl FnOnce(&KThread) -> R) -> R {
    let ptr = thread_ptr(tid);
    unsafe { f(&*ptr) }
}

pub fn with_thread_mut<R>(tid: u32, f: impl FnOnce(&mut KThread) -> R) -> R {
    let ptr = thread_ptr(tid);
    unsafe { f(&mut *ptr) }
}

pub fn current_tid() -> u32 {
    // Read TPIDR_EL1 low 32 bits — set by svc_dispatch on entry.
    crate::arch::cpu::current_cpu_local() as u32
}

pub fn vcpu_id() -> usize {
    // High 32 bits of TPIDR_EL1 hold vcpu_id once scheduler binds this CPU.
    let local = crate::arch::cpu::current_cpu_local();
    let vid = (local >> 32) as usize;
    if vid != 0 || (local as u32) != 0 {
        return vid;
    }
    bootstrap_vcpu_id()
}

#[inline(always)]
fn bootstrap_vcpu_id() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        // Early-boot fallback for CPUs that haven't populated TPIDR_EL1 yet.
        // Use MPIDR affinity level 0 as a stable vCPU index seed.
        let mpidr: u64;
        unsafe {
            core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack, nomem));
        }
        (mpidr as usize) & 0xff
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

pub fn set_current_cpu_thread(vcpu_id: usize, tid: u32) {
    let val = ((vcpu_id as u64) << 32) | (tid as u64);
    crate::arch::cpu::set_current_cpu_local(val);
}

pub fn running_vcpu_of_tid(tid: u32) -> Option<usize> {
    if tid == 0 || !thread_exists(tid) {
        return None;
    }
    unsafe {
        for vid in 0..MAX_VCPUS {
            if (*SCHED.vcpus.get())[vid].current_tid == tid {
                return Some(vid);
            }
        }
    }
    None
}

extern "C" fn thread_user_entry_continuation() -> ! {
    let tid = current_tid();
    if tid == 0 || !thread_exists(tid) {
        panic!("sched: invalid current tid in user-entry continuation");
    }
    // Enter EL0 from the scheduled kernel-thread continuation, not from scheduler loop.
    set_thread_in_kernel(tid, false);
    unsafe {
        enter_user_thread_noreturn(tid);
    }
}

pub(crate) fn ensure_user_entry_continuation_locked(tid: u32) -> bool {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "ensure_user_entry_continuation_locked requires sched lock"
    );
    if tid == 0 || !thread_exists(tid) {
        return false;
    }
    if has_kernel_continuation(tid) {
        return true;
    }
    if with_thread(tid, |t| t.in_kernel) {
        return false;
    }
    let sp_top = with_thread(tid, kstack_top_from_thread);
    if sp_top == 0 {
        return false;
    }
    with_thread_mut(tid, |t| {
        t.in_kernel = true;
        t.kctx = KernelContext::default();
        t.kctx.sp_el1 = sp_top;
        let cont = thread_user_entry_continuation as *const () as usize as u64;
        t.kctx.x19_x30[11] = cont; // x30
        t.kctx.lr_el1 = cont;
    });
    true
}

pub(crate) fn set_thread_in_kernel_locked(tid: u32, in_kernel: bool) {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "set_thread_in_kernel_locked requires sched lock"
    );
    if tid == 0 || !thread_exists(tid) {
        return;
    }
    with_thread_mut(tid, |t| {
        t.in_kernel = in_kernel;
        if !in_kernel {
            clear_thread_kernel_continuation_locked_inner(t);
        }
    });
}

#[inline(always)]
fn clear_thread_kernel_continuation_locked_inner(t: &mut KThread) {
    t.kctx.x19_x30[11] = 0;
    t.kctx.lr_el1 = 0;
    t.kctx.sp_el1 = 0;
}

pub fn has_kernel_continuation(tid: u32) -> bool {
    if tid == 0 || !thread_exists(tid) {
        return false;
    }
    with_thread(tid, |t| {
        t.in_kernel && t.kctx.sp_el1 != 0 && t.kctx.x19_x30[11] != 0
    })
}

pub unsafe fn switch_kernel_continuation(from_tid: u32, to_tid: u32) -> bool {
    if from_tid == 0 || to_tid == 0 || from_tid == to_tid {
        return false;
    }
    if !thread_exists(from_tid) || !thread_exists(to_tid) {
        return false;
    }
    if !has_kernel_continuation(to_tid) {
        return false;
    }
    let from_ptr = thread_ptr(from_tid);
    let to_ptr = thread_ptr(to_tid);
    if from_ptr.is_null() || to_ptr.is_null() {
        return false;
    }
    let from_kctx = unsafe { &mut (*from_ptr).kctx as *mut KernelContext };
    let to_kctx = unsafe { &(*to_ptr).kctx as *const KernelContext };
    unsafe {
        crate::arch::context::switch_kernel_context(from_kctx, to_kctx);
    }
    true
}

pub unsafe fn enter_kernel_continuation_noreturn(tid: u32) -> ! {
    if tid == 0 || !thread_exists(tid) {
        panic!("sched: invalid tid for kernel continuation enter tid={}", tid);
    }
    if !has_kernel_continuation(tid) {
        panic!(
            "sched: missing kernel continuation for direct enter tid={}",
            tid
        );
    }
    let ptr = thread_ptr(tid);
    if ptr.is_null() {
        panic!("sched: null thread pointer for direct kernel enter tid={}", tid);
    }
    let kctx_ptr = core::ptr::addr_of!((*ptr).kctx);
    crate::arch::context::enter_kernel_context(kctx_ptr)
}

pub fn set_thread_in_kernel(tid: u32, in_kernel: bool) {
    sched_lock_acquire();
    set_thread_in_kernel_locked(tid, in_kernel);
    sched_lock_release();
}

pub fn set_current_in_kernel(in_kernel: bool) {
    let tid = current_tid();
    if tid != 0 {
        set_thread_in_kernel(tid, in_kernel);
    }
}

pub unsafe fn enter_user_thread_noreturn(tid: u32) -> ! {
    if tid == 0 || !thread_exists(tid) {
        loop {
            crate::arch::cpu::wait_for_event();
        }
    }
    let ptr = thread_ptr(tid);
    if ptr.is_null() {
        loop {
            crate::arch::cpu::wait_for_event();
        }
    }
    let ctx_ptr = core::ptr::addr_of!((*ptr).ctx);
    crate::arch::context::enter_user_thread_context(ctx_ptr)
}
