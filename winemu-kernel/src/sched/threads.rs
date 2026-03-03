// ── 线程创建 ──────────────────────────────────────────────────

/// 分配新 TID，初始化 KThread，加入就绪队列
pub fn spawn(
    pid: u32,
    pc: u64,
    sp: u64,
    arg: u64,
    teb_va: u64,
    stack_base: u64,
    stack_size: u64,
    kstack_base: u64,
    kstack_size: u64,
    priority: u8,
) -> u32 {
    sched_lock_acquire();
    let tid = thread_store_mut()
        .alloc_with(|id| {
            let mut t = KThread::zeroed();
            t.init_spawned(
                id,
                pid,
                pc,
                sp,
                arg,
                teb_va,
                stack_base,
                stack_size,
                kstack_base,
                kstack_size,
                priority,
            );
            t
        })
        .unwrap_or(0);
    if tid != 0 {
        set_thread_state_locked(tid, ThreadState::Ready);
    }
    sched_lock_release();
    tid
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateThreadError {
    InvalidParameter,
    NoMemory,
}

#[inline(always)]
fn normalize_stack_size(max_stack_size_arg: u64) -> u64 {
    if max_stack_size_arg == 0 {
        DEFAULT_THREAD_STACK_RESERVE
    } else {
        (max_stack_size_arg + (THREAD_STACK_ALIGN - 1)) & !(THREAD_STACK_ALIGN - 1)
    }
}

#[inline(always)]
fn alloc_kernel_stack() -> Option<(u64, u64)> {
    let ptr = crate::alloc::alloc_zeroed(KERNEL_STACK_SIZE, 16)?;
    Some((ptr as u64, KERNEL_STACK_SIZE as u64))
}

#[inline(always)]
fn free_kernel_stack(base: u64) {
    if base != 0 {
        crate::alloc::dealloc(base as *mut u8);
    }
}

fn defer_kernel_stack_free_locked(base: u64) {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "defer_kernel_stack_free_locked requires sched lock"
    );
    if base == 0 {
        return;
    }
    unsafe {
        let len_ptr = SCHED.deferred_kstack_len.get();
        let slots = &mut *SCHED.deferred_kstack_bases.get();
        let len = *len_ptr;
        if len < DEFERRED_KSTACK_CAP {
            slots[len] = base;
            *len_ptr = len + 1;
        } else {
            crate::kwarn!("sched: deferred kernel stack queue full; leaking {:#x}", base);
        }
    }
}

fn pop_deferred_kernel_stack_locked(current_base: u64) -> u64 {
    debug_assert!(
        sched_lock_held_by_current_vcpu(),
        "pop_deferred_kernel_stack_locked requires sched lock"
    );
    unsafe {
        let len_ptr = SCHED.deferred_kstack_len.get();
        let slots = &mut *SCHED.deferred_kstack_bases.get();
        let mut len = *len_ptr;
        let mut i = 0usize;
        while i < len {
            let base = slots[i];
            if base != 0 && base != current_base {
                len -= 1;
                slots[i] = slots[len];
                slots[len] = 0;
                *len_ptr = len;
                return base;
            }
            i += 1;
        }
        0
    }
}

pub fn reclaim_deferred_kernel_stacks() {
    let current_base = current_thread_kernel_stack_base();
    loop {
        sched_lock_acquire();
        let base = pop_deferred_kernel_stack_locked(current_base);
        sched_lock_release();
        if base == 0 {
            break;
        }
        free_kernel_stack(base);
    }
}

#[inline(always)]
fn normalize_stack_commit_size(stack_size_arg: u64, stack_reserve: u64) -> u64 {
    let requested = if stack_size_arg == 0 {
        DEFAULT_THREAD_STACK_COMMIT
    } else {
        (stack_size_arg + (PAGE_SIZE_4K - 1)) & !(PAGE_SIZE_4K - 1)
    };
    let max_commit = stack_reserve.saturating_sub(PAGE_SIZE_4K);
    if max_commit == 0 {
        return PAGE_SIZE_4K;
    }
    requested.max(PAGE_SIZE_4K).min(max_commit)
}

#[inline(always)]
fn write_process_user_bytes(pid: u32, user_va: u64, src: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let mut done = 0usize;
    while done < len {
        let cur_va = user_va.saturating_add(done as u64);
        let page = cur_va & !(PAGE_SIZE_4K - 1);
        if !vm_handle_page_fault(pid, page, VM_ACCESS_WRITE) {
            return false;
        }
        let Some(dst_pa) = crate::process::with_process(pid, |p| {
            p.address_space
                .translate_user_va_for_access(cur_va, VM_ACCESS_WRITE)
        })
        .flatten()
        else {
            return false;
        };
        let page_off = (cur_va as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let chunk = core::cmp::min(len - done, (PAGE_SIZE_4K as usize) - page_off);
        unsafe {
            core::ptr::copy_nonoverlapping(src.add(done), dst_pa as *mut u8, chunk);
        }
        done += chunk;
    }
    true
}

#[inline(always)]
fn zero_process_user_bytes(pid: u32, user_va: u64, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let mut done = 0usize;
    while done < len {
        let cur_va = user_va.saturating_add(done as u64);
        let page = cur_va & !(PAGE_SIZE_4K - 1);
        if !vm_handle_page_fault(pid, page, VM_ACCESS_WRITE) {
            return false;
        }
        let Some(dst_pa) = crate::process::with_process(pid, |p| {
            p.address_space
                .translate_user_va_for_access(cur_va, VM_ACCESS_WRITE)
        })
        .flatten()
        else {
            return false;
        };
        let page_off = (cur_va as usize) & ((PAGE_SIZE_4K as usize) - 1);
        let chunk = core::cmp::min(len - done, (PAGE_SIZE_4K as usize) - page_off);
        unsafe {
            core::ptr::write_bytes(dst_pa as *mut u8, 0, chunk);
        }
        done += chunk;
    }
    true
}

#[inline(always)]
fn write_teb_u64(pid: u32, teb_va: u64, offset: usize, value: u64) -> bool {
    let bytes = value.to_le_bytes();
    write_process_user_bytes(pid, teb_va + offset as u64, bytes.as_ptr(), bytes.len())
}

#[inline(never)]
pub fn create_user_thread(
    pid: u32,
    entry_va: u64,
    arg: u64,
    stack_size_arg: u64,
    max_stack_size_arg: u64,
    priority: u8,
) -> Result<u32, CreateThreadError> {
    if entry_va == 0 {
        return Err(CreateThreadError::InvalidParameter);
    }

    let stack_size = normalize_stack_size(max_stack_size_arg);
    let stack_commit = normalize_stack_commit_size(stack_size_arg, stack_size);
    let stack_base = vm_alloc_region_typed(pid, 0, stack_size, 0x04, VmaType::ThreadStack)
        .ok_or(CreateThreadError::NoMemory)?;
    let teb_va =
        vm_alloc_region_typed(pid, 0, PAGE_SIZE_4K, 0x04, VmaType::Private).map_or(0, |v| v);
    if teb_va == 0 {
        let _ = vm_free_region(pid, stack_base);
        return Err(CreateThreadError::NoMemory);
    }
    let (kstack_base, kstack_size) = match alloc_kernel_stack() {
        Some(v) => v,
        None => {
            let _ = vm_free_region(pid, stack_base);
            let _ = vm_free_region(pid, teb_va);
            return Err(CreateThreadError::NoMemory);
        }
    };
    let stack_top = stack_base + stack_size;
    let mut stack_limit = stack_top.saturating_sub(stack_commit);
    if stack_limit <= stack_base {
        stack_limit = stack_base.saturating_add(PAGE_SIZE_4K);
    }
    let guard_page = stack_limit.saturating_sub(PAGE_SIZE_4K);
    if guard_page < stack_base || !vm_make_guard_page(pid, guard_page) {
        let _ = vm_free_region(pid, stack_base);
        let _ = vm_free_region(pid, teb_va);
        free_kernel_stack(kstack_base);
        return Err(CreateThreadError::NoMemory);
    }

    let peb_va = crate::process::with_process(pid, |p| p.peb_va).unwrap_or(0);
    if !zero_process_user_bytes(pid, teb_va, PAGE_SIZE_4K as usize)
        || !write_teb_u64(pid, teb_va, teb_layout::EXCEPTION_LIST, u64::MAX)
        || !write_teb_u64(pid, teb_va, teb_layout::STACK_BASE, stack_top)
        || !write_teb_u64(pid, teb_va, teb_layout::STACK_LIMIT, stack_limit)
        || !write_teb_u64(pid, teb_va, teb_layout::SELF, teb_va)
        || !write_teb_u64(pid, teb_va, teb_layout::PEB, peb_va)
        || !write_teb_u64(pid, teb_va, teb_layout::CLIENT_ID, pid as u64)
    {
        let _ = vm_free_region(pid, stack_base);
        let _ = vm_free_region(pid, teb_va);
        free_kernel_stack(kstack_base);
        return Err(CreateThreadError::NoMemory);
    }

    let tid = spawn(
        pid,
        entry_va,
        stack_top,
        arg,
        teb_va,
        stack_base,
        stack_size,
        kstack_base,
        kstack_size,
        priority,
    );
    if tid == 0 {
        let _ = vm_free_region(pid, stack_base);
        let _ = vm_free_region(pid, teb_va);
        free_kernel_stack(kstack_base);
        return Err(CreateThreadError::NoMemory);
    }
    if !write_teb_u64(pid, teb_va, teb_layout::CLIENT_ID + 8, tid as u64) {
        let _ = terminate_thread_by_tid(tid);
        return Err(CreateThreadError::NoMemory);
    }
    crate::process::on_thread_created(pid, tid);
    Ok(tid)
}

pub fn terminate_thread_by_tid(tid: u32) -> bool {
    if tid == 0 || !thread_exists(tid) {
        return false;
    }
    sched_lock_acquire();
    let cur_tid = current_tid();
    let (state, pid, stack_base, teb_va, kstack_base) =
        with_thread(tid, |t| (t.state, t.pid, t.stack_base, t.teb_va, t.kstack_base));
    if state == ThreadState::Free || state == ThreadState::Terminated {
        sched_lock_release();
        return false;
    }
    if state == ThreadState::Waiting {
        debug_assert!(
            with_thread(tid, |t| t.wait_kind != WAIT_KIND_NONE),
            "waiting thread must carry wait metadata"
        );
        let _ = crate::sched::sync::cancel_wait_on_sync_objects_locked(
            tid,
            status::THREAD_IS_TERMINATING,
        );
    }
    with_thread_mut(tid, |t| {
        t.stack_base = 0;
        t.stack_size = 0;
        t.kstack_base = 0;
        t.kstack_size = 0;
        t.teb_va = 0;
        t.ctx.tpidr = 0;
        t.in_kernel = false;
        t.kctx = KernelContext::default();
    });
    set_thread_state_locked(tid, ThreadState::Terminated);
    let defer_kstack = tid == cur_tid;
    if defer_kstack {
        defer_kernel_stack_free_locked(kstack_base);
    }
    sched_lock_release();

    // Targeted hostcall cleanup replaces IRQ-time stale waiter scanning.
    let _ = crate::hostcall::cancel_requests_for_waiter_tid(tid);

    let _ = vm_free_region(pid, stack_base);
    let _ = vm_free_region(pid, teb_va);
    if !defer_kstack {
        free_kernel_stack(kstack_base);
    }
    crate::process::on_thread_terminated(pid, tid);
    true
}

pub fn thread_basic_info(tid: u32) -> Option<[u8; THREAD_BASIC_INFORMATION_SIZE]> {
    if tid == 0 || !thread_exists(tid) {
        return None;
    }
    Some(with_thread(tid, |t| t.basic_info_record()))
}

pub fn thread_pid(tid: u32) -> Option<u32> {
    if tid == 0 || !thread_exists(tid) {
        return None;
    }
    Some(with_thread(tid, |t| t.pid))
}

pub fn thread_ids_by_pid(pid: u32) -> Vec<u32> {
    if pid == 0 {
        return Vec::new();
    }
    unsafe {
        let Some(store) = (&*SCHED.threads.get()).as_ref() else {
            return Vec::new();
        };
        let mut tids = Vec::new();
        store.for_each_live_ptr(|tid, ptr| {
            let t = &*ptr;
            if t.pid == pid && t.state != ThreadState::Free && t.state != ThreadState::Terminated {
                let _ = tids.try_reserve(1);
                tids.push(tid);
            }
        });
        tids
    }
}
