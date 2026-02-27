use crate::hypercall;

use super::common::align_up_4k;

const MAX_GUEST_FILES: usize = 256;
const MAX_GUEST_SECTIONS: usize = 128;
const MAX_GUEST_VIEWS: usize = 256;
const MAX_VM_REGIONS: usize = 512;

#[derive(Clone, Copy)]
pub(crate) struct GuestSection {
    pub(crate) in_use: bool,
    pub(crate) size: u64,
    pub(crate) prot: u32,
    pub(crate) file_handle: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct VmRegion {
    pub(crate) in_use: bool,
    pub(crate) base: u64,
    pub(crate) size: u64,
    pub(crate) prot: u32,
}

#[derive(Clone, Copy)]
struct GuestFile {
    in_use: bool,
    host_fd: u64,
}

impl GuestFile {
    const fn empty() -> Self {
        Self {
            in_use: false,
            host_fd: 0,
        }
    }
}

impl GuestSection {
    const fn empty() -> Self {
        Self {
            in_use: false,
            size: 0,
            prot: 0,
            file_handle: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct GuestView {
    in_use: bool,
    base: u64,
    size: u64,
}

impl GuestView {
    const fn empty() -> Self {
        Self {
            in_use: false,
            base: 0,
            size: 0,
        }
    }
}

impl VmRegion {
    const fn empty() -> Self {
        Self {
            in_use: false,
            base: 0,
            size: 0,
            prot: 0,
        }
    }
}

static mut GUEST_FILES: [GuestFile; MAX_GUEST_FILES] = [const { GuestFile::empty() }; MAX_GUEST_FILES];
static mut GUEST_SECTIONS: [GuestSection; MAX_GUEST_SECTIONS] =
    [const { GuestSection::empty() }; MAX_GUEST_SECTIONS];
static mut GUEST_VIEWS: [GuestView; MAX_GUEST_VIEWS] = [const { GuestView::empty() }; MAX_GUEST_VIEWS];
static mut VM_REGIONS: [VmRegion; MAX_VM_REGIONS] = [const { VmRegion::empty() }; MAX_VM_REGIONS];
static mut DUP_TAG: u64 = 1;

pub(crate) fn vm_alloc_region(size: u64, prot: u32) -> Option<u64> {
    let size = align_up_4k(size.max(0x1000));
    let base = crate::alloc::alloc_zeroed(size as usize, 0x1000).map(|p| p as u64)?;
    unsafe {
        for i in 1..MAX_VM_REGIONS {
            if !VM_REGIONS[i].in_use {
                VM_REGIONS[i].in_use = true;
                VM_REGIONS[i].base = base;
                VM_REGIONS[i].size = size;
                VM_REGIONS[i].prot = prot;
                return Some(base);
            }
        }
    }
    None
}

pub(crate) fn vm_find_region(base_or_addr: u64) -> Option<(usize, VmRegion)> {
    unsafe {
        for i in 1..MAX_VM_REGIONS {
            let r = VM_REGIONS[i];
            if r.in_use && base_or_addr >= r.base && base_or_addr < r.base + r.size {
                return Some((i, r));
            }
        }
    }
    None
}

pub(crate) fn vm_set_region_prot(idx: usize, prot: u32) {
    unsafe {
        if idx < MAX_VM_REGIONS && VM_REGIONS[idx].in_use {
            VM_REGIONS[idx].prot = prot;
        }
    }
}

pub(crate) fn vm_free_region(base: u64) -> bool {
    unsafe {
        for i in 1..MAX_VM_REGIONS {
            if VM_REGIONS[i].in_use && VM_REGIONS[i].base == base {
                VM_REGIONS[i].in_use = false;
                return true;
            }
        }
    }
    false
}

pub(crate) fn file_alloc(host_fd: u64) -> Option<u16> {
    unsafe {
        for i in 1..MAX_GUEST_FILES {
            if !GUEST_FILES[i].in_use {
                GUEST_FILES[i].in_use = true;
                GUEST_FILES[i].host_fd = host_fd;
                return Some(i as u16);
            }
        }
    }
    None
}

pub(crate) fn file_host_fd(idx: u16) -> Option<u64> {
    unsafe {
        let i = idx as usize;
        if i < MAX_GUEST_FILES && GUEST_FILES[i].in_use {
            return Some(GUEST_FILES[i].host_fd);
        }
    }
    None
}

pub(crate) fn file_free(idx: u16) {
    unsafe {
        let i = idx as usize;
        if i < MAX_GUEST_FILES && GUEST_FILES[i].in_use {
            hypercall::host_close(GUEST_FILES[i].host_fd);
            GUEST_FILES[i].in_use = false;
            GUEST_FILES[i].host_fd = 0;
        }
    }
}

pub(crate) fn section_alloc(size: u64, prot: u32, file_handle: u64) -> Option<u16> {
    unsafe {
        for i in 1..MAX_GUEST_SECTIONS {
            if !GUEST_SECTIONS[i].in_use {
                GUEST_SECTIONS[i].in_use = true;
                GUEST_SECTIONS[i].size = size;
                GUEST_SECTIONS[i].prot = prot;
                GUEST_SECTIONS[i].file_handle = file_handle;
                return Some(i as u16);
            }
        }
    }
    None
}

pub(crate) fn section_get(idx: u16) -> Option<GuestSection> {
    unsafe {
        let i = idx as usize;
        if i < MAX_GUEST_SECTIONS && GUEST_SECTIONS[i].in_use {
            return Some(GUEST_SECTIONS[i]);
        }
    }
    None
}

pub(crate) fn section_free(idx: u16) {
    unsafe {
        let i = idx as usize;
        if i < MAX_GUEST_SECTIONS {
            GUEST_SECTIONS[i].in_use = false;
        }
    }
}

pub(crate) fn view_alloc(base: u64, size: u64) -> bool {
    unsafe {
        for i in 1..MAX_GUEST_VIEWS {
            if !GUEST_VIEWS[i].in_use {
                GUEST_VIEWS[i].in_use = true;
                GUEST_VIEWS[i].base = base;
                GUEST_VIEWS[i].size = size;
                return true;
            }
        }
    }
    false
}

pub(crate) fn view_free(base: u64) -> bool {
    unsafe {
        for i in 1..MAX_GUEST_VIEWS {
            if GUEST_VIEWS[i].in_use && GUEST_VIEWS[i].base == base {
                GUEST_VIEWS[i].in_use = false;
                GUEST_VIEWS[i].base = 0;
                GUEST_VIEWS[i].size = 0;
                return true;
            }
        }
    }
    false
}

pub(crate) fn duplicate_handle(src: u64) -> u64 {
    unsafe {
        let dup = src | ((DUP_TAG & 0xFFFF_FFFF) << 16);
        DUP_TAG = DUP_TAG.wrapping_add(1);
        dup
    }
}
