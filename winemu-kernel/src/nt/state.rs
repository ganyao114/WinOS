use crate::kobj::ObjectStore;
use crate::mm::vm_sanitize_nt_prot;
use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;

use crate::fs::FsBackingHandle;

pub(crate) const VM_FILE_MAPPING_DEFAULT_PROT: u32 = 0x20; // PAGE_EXECUTE_READ

pub(crate) struct GuestSection {
    pub(crate) size: u64,
    pub(crate) prot: u32,
    pub(crate) backing: Option<FsBackingHandle>,
    pub(crate) alloc_attrs: u32,
    pub(crate) is_image: bool,
    refs: u32,
}

impl Clone for GuestSection {
    fn clone(&self) -> Self {
        let backing = self.backing.and_then(|handle| {
            if crate::fs::retain_backing(handle) {
                Some(handle)
            } else {
                debug_assert!(false, "section backing retain failed");
                None
            }
        });
        Self {
            size: self.size,
            prot: self.prot,
            backing,
            alloc_attrs: self.alloc_attrs,
            is_image: self.is_image,
            refs: self.refs,
        }
    }
}

impl Drop for GuestSection {
    fn drop(&mut self) {
        if let Some(backing) = self.backing.take() {
            crate::fs::release_backing(backing);
        }
    }
}

#[derive(Clone, Copy)]
struct GuestView {
    owner_pid: u32,
    base: u64,
    size: u64,
}

struct NtState {
    sections: UnsafeCell<Option<ObjectStore<GuestSection>>>,
    views: UnsafeCell<Option<ObjectStore<GuestView>>>,
}

unsafe impl Sync for NtState {}

static NT_STATE: NtState = NtState {
    sections: UnsafeCell::new(None),
    views: UnsafeCell::new(None),
};

fn sections_store_mut() -> &'static mut ObjectStore<GuestSection> {
    unsafe {
        let slot = &mut *NT_STATE.sections.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn views_store_mut() -> &'static mut ObjectStore<GuestView> {
    unsafe {
        let slot = &mut *NT_STATE.views.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

// ─── Section 管理 ────────────────────────────────────────────────────────────

pub(crate) fn section_alloc(
    size: u64,
    prot: u32,
    backing: Option<FsBackingHandle>,
    alloc_attrs: u32,
) -> Option<u32> {
    let is_image = (alloc_attrs & 0x0100_0000) != 0;
    let id = sections_store_mut().alloc_with(|_| GuestSection {
        size,
        prot: vm_sanitize_nt_prot(prot),
        backing,
        alloc_attrs,
        is_image,
        refs: 1,
    });
    if id.is_none() {
        if let Some(backing) = backing {
            crate::fs::release_backing(backing);
        }
    }
    id
}

pub(crate) fn section_get(idx: u32) -> Option<GuestSection> {
    let ptr = sections_store_mut().get_ptr(idx);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: object store returns a stable live pointer for this id.
        Some(unsafe { (&*ptr).clone() })
    }
}

pub(crate) fn section_exists(idx: u32) -> bool {
    !sections_store_mut().get_ptr(idx).is_null()
}

pub(crate) fn section_retain(idx: u32) -> bool {
    let ptr = sections_store_mut().get_ptr(idx);
    if ptr.is_null() {
        return false;
    }
    // SAFETY: pointer comes from the live section store entry.
    unsafe {
        (*ptr).refs = (*ptr).refs.saturating_add(1);
    }
    true
}

pub(crate) fn section_ref_count(idx: u32) -> u32 {
    let ptr = sections_store_mut().get_ptr(idx);
    if ptr.is_null() {
        0
    } else {
        // SAFETY: pointer comes from the live section store entry.
        unsafe { (*ptr).refs }
    }
}

pub(crate) fn section_free(idx: u32) -> bool {
    let store = sections_store_mut();
    let ptr = store.get_ptr(idx);
    if ptr.is_null() {
        return false;
    }
    // SAFETY: pointer comes from the live section store entry.
    let entry = unsafe { &mut *ptr };
    if entry.refs > 1 {
        entry.refs -= 1;
        return false;
    }
    store.free(idx)
}

// ─── View 管理 ───────────────────────────────────────────────────────────────

pub(crate) fn view_alloc(owner_pid: u32, base: u64, size: u64) -> bool {
    views_store_mut()
        .alloc_with(|_| GuestView {
            owner_pid,
            base,
            size,
        })
        .is_some()
}

pub(crate) fn view_free(owner_pid: u32, base: u64) -> bool {
    let store = views_store_mut();
    let mut id = 0u32;
    store.for_each_live_ptr(|cur_id, ptr| unsafe {
        if (*ptr).owner_pid == owner_pid && (*ptr).base == base {
            id = cur_id;
        }
    });
    if id == 0 {
        return false;
    }
    store.free(id)
}

// ─── 进程资源清理 ─────────────────────────────────────────────────────────────

pub(crate) fn cleanup_process_owned_resources(owner_pid: u32) {
    if owner_pid == 0 {
        return;
    }

    let mut view_ids = Vec::new();
    views_store_mut().for_each_live_ptr(|id, ptr| unsafe {
        if (*ptr).owner_pid == owner_pid {
            let _ = view_ids.try_reserve(1);
            view_ids.push(id);
        }
    });
    for id in view_ids {
        let _ = views_store_mut().free(id);
    }

    // Cleanup VM regions owned by KProcess.vm
    let _ = crate::process::with_process_mut(owner_pid, |p| {
        let (vm, aspace) = (&mut p.vm, &mut p.address_space);
        vm.cleanup_all(aspace);
    });
}
