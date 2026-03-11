use crate::mm::range::Range;
use crate::mm::vm_area::{VmArea, PAGE_SIZE};
use crate::mm::{vm_clone_shared_nt_prot, UserVa};
use crate::mm::vaspace::ProcessVmManager;
use crate::process::{with_process, with_process_mut, ProcessAddressSpace};
use crate::rust_alloc::vec::Vec;

#[derive(Clone)]
pub(crate) struct TrackedAreaSnapshot {
    pub(crate) range: Range,
    pub(crate) area: VmArea,
}

pub(crate) struct ProcessVmClonePlan {
    tracked_areas: Vec<TrackedAreaSnapshot>,
    shared_writable_pages: Vec<(UserVa, u32)>,
}

impl ProcessVmManager {
    pub(crate) fn build_clone_plan(&self) -> ProcessVmClonePlan {
        let tracked_areas = self.collect_tracked_areas();
        let mut shared_writable_pages = Vec::new();
        for snapshot in &tracked_areas {
            let area = &snapshot.area;
            if !area.owns_phys_pages {
                continue;
            }
            for (idx, pa) in area.phys_pages.iter().copied().enumerate() {
                if pa.is_null() || !area.is_page_committed(idx) {
                    continue;
                }
                let prot = area
                    .prot_pages
                    .get(idx)
                    .copied()
                    .unwrap_or(area.default_prot);
                let cow_prot = vm_clone_shared_nt_prot(prot);
                if cow_prot == prot {
                    continue;
                }
                let _ = shared_writable_pages.try_reserve(1);
                shared_writable_pages.push((
                    UserVa::new(snapshot.range.start + (idx as u64) * PAGE_SIZE),
                    cow_prot,
                ));
            }
        }
        ProcessVmClonePlan {
            tracked_areas,
            shared_writable_pages,
        }
    }

    pub(crate) fn install_clone_plan(&mut self, plan: &ProcessVmClonePlan) -> bool {
        self.install_tracked_areas(&plan.tracked_areas)
    }

    pub(crate) fn apply_clone_cow_plan(
        &mut self,
        aspace: &mut ProcessAddressSpace,
        pid: u32,
        plan: &ProcessVmClonePlan,
    ) -> bool {
        for (va, cow_prot) in &plan.shared_writable_pages {
            if self
                .protect_range(aspace, pid, va.get(), PAGE_SIZE, *cow_prot)
                .is_err()
            {
                return false;
            }
        }
        true
    }
}

pub(crate) fn clone_process_vm_for_fork(parent_pid: u32, child_pid: u32) -> bool {
    let Some(plan) = with_process(parent_pid, |p| p.vm.build_clone_plan()) else {
        return false;
    };

    let child_installed = with_process_mut(child_pid, |p| p.vm.install_clone_plan(&plan))
        .unwrap_or(false);
    if !child_installed {
        return false;
    }

    let child_cow_ready = with_process_mut(child_pid, |p| {
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.apply_clone_cow_plan(aspace, child_pid, &plan)
    })
    .unwrap_or(false);
    if !child_cow_ready {
        return false;
    }

    with_process_mut(parent_pid, |p| {
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.apply_clone_cow_plan(aspace, parent_pid, &plan)
    })
    .unwrap_or(false)
}
