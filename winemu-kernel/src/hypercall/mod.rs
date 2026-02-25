use winemu_shared::nr;

/// 6 引数 hypercall（HVC #0）
/// x0 = nr, x1-x6 = args, 返回值在 x0
#[inline(always)]
pub fn hypercall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") nr => ret,
            in("x1") a0,
            in("x2") a1,
            in("x3") a2,
            in("x4") a3,
            in("x5") a4,
            in("x6") a5,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub fn hypercall(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    hypercall6(nr, a0, a1, a2, 0, 0, 0)
}

/// KERNEL_READY — 通知 VMM 内核已就绪，传入 PE 入口点和栈
/// 返回 Thread 0 的 tid
pub fn kernel_ready(entry_va: u64, stack_va: u64, teb_gva: u64) -> u64 {
    hypercall(nr::KERNEL_READY, entry_va, stack_va, teb_gva)
}

pub fn debug_print(msg: &str) {
    hypercall(nr::DEBUG_PRINT, msg.as_ptr() as u64, msg.len() as u64, 0);
}

pub fn process_exit(code: u32) -> ! {
    hypercall(nr::PROCESS_EXIT, code as u64, 0, 0);
    loop { unsafe { core::arch::asm!("wfi"); } }
}

pub fn thread_create(entry_va: u64, stack_va: u64, arg: u64, teb_gva: u64) -> u64 {
    hypercall6(nr::THREAD_CREATE, entry_va, stack_va, arg, teb_gva, 0, 0)
}

pub fn thread_exit(code: u32) -> ! {
    hypercall(nr::THREAD_EXIT, code as u64, 0, 0);
    loop { unsafe { core::arch::asm!("wfi"); } }
}

pub fn alloc_virtual(hint: u64, size: u64, prot: u32) -> u64 {
    hypercall(nr::NT_ALLOC_VIRTUAL, hint, size, prot as u64)
}

pub fn free_virtual(base: u64) -> u64 {
    hypercall(nr::NT_FREE_VIRTUAL, base, 0, 0)
}

pub fn yield_execution() {
    hypercall(nr::NT_YIELD_EXECUTION, 0, 0, 0);
}

/// 请求 VMM 加载 DLL，返回 guest_base（失败返回 u64::MAX）
pub fn load_dll(name: &str) -> u64 {
    hypercall(nr::LOAD_DLL_IMAGE, name.as_ptr() as u64, name.len() as u64, 0)
}

/// 从已加载 DLL 的 export 表查找函数 VA（失败返回 0）
pub fn get_proc_address(dll_base: u64, name: &str) -> u64 {
    hypercall6(
        nr::GET_PROC_ADDRESS,
        dll_base,
        name.as_ptr() as u64,
        name.len() as u64,
        0, 0, 0,
    )
}
