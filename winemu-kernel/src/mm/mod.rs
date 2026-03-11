pub mod addr;
pub mod address_space;
pub mod areaset;
pub mod clone_plan;
pub mod kernel_vm;
pub mod kmap;
pub mod kmalloc;
pub mod phys;
pub mod physmap;
pub mod process_vm;
pub mod range;
pub mod usercopy;
pub mod vaspace;
pub mod vm_defs;
pub mod vm_area;

pub use addr::{KernelVa, PhysAddr, UserVa};
pub use physmap as linear_map;
pub use vm_defs::VmaType;
pub(crate) use clone_plan::clone_process_vm_for_fork;
pub(crate) use process_vm::{
    vm_alloc_region_typed, vm_alloc_stack, vm_commit_private, vm_decommit_private, vm_free_region,
    vm_make_guard_page, vm_protect_range, vm_query_region, vm_release_private,
    vm_reserve_private, vm_set_section_backing, vm_track_existing_file_mapping,
};
pub(crate) use vm_defs::{
    vm_access_allowed, vm_clone_shared_nt_prot, vm_is_copy_on_write_prot, vm_kind_from_vma_type,
    vm_promote_cow_prot, vm_sanitize_nt_prot, VmQueryInfo,
};

pub const VM_ACCESS_READ: u8 = 1;
pub const VM_ACCESS_WRITE: u8 = 2;
pub const VM_ACCESS_EXEC: u8 = 3;

pub fn bootstrap_user_tables() -> (*const u64, *const u64, *const u64) {
    crate::arch::mmu::bootstrap_user_tables()
}

pub fn switch_process_ttbr0(new_ttbr0: u64) {
    if new_ttbr0 == 0 {
        return;
    }
    let cur = crate::arch::mmu::current_user_table_root();
    if (cur & !0xfff) == (new_ttbr0 & !0xfff) {
        return;
    }

    crate::arch::mmu::switch_user_table_root(new_ttbr0);
}

pub fn init_global_bootstrap() {
    crate::arch::mmu::init_global_bootstrap();
    kernel_vm::init();
    kmap::init();
}

pub fn init_per_cpu() {
    crate::arch::mmu::init_per_cpu();
}

pub fn init() {
    init_global_bootstrap();
    init_per_cpu();
}

pub(crate) fn handle_process_page_fault(owner_pid: u32, fault_addr: UserVa, access: u8) -> bool {
    crate::process::with_process_mut(owner_pid, |p| {
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.handle_page_fault(aspace, owner_pid, fault_addr, access)
    })
    .unwrap_or(false)
}
