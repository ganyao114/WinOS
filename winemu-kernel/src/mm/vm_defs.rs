use crate::mm::vm_area::VmKind;
use crate::mm::UserVa;

const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmaType {
    Kernel,
    ExeImage,
    DllImage,
    ThreadStack,
    Section,
    FileMapped,
    Private,
    PageTable,
}

#[derive(Clone, Copy)]
pub(crate) struct VmQueryInfo {
    pub(crate) base: UserVa,
    pub(crate) size: u64,
    pub(crate) allocation_base: UserVa,
    pub(crate) allocation_prot: u32,
    pub(crate) prot: u32,
    pub(crate) state: u32,
    pub(crate) mem_type: u32,
}

pub(crate) fn vm_kind_from_vma_type(t: VmaType) -> VmKind {
    match t {
        VmaType::Private | VmaType::Kernel | VmaType::PageTable => VmKind::Private,
        VmaType::ExeImage | VmaType::DllImage => VmKind::Image,
        VmaType::Section | VmaType::FileMapped => VmKind::Section,
        VmaType::ThreadStack => VmKind::ThreadStack,
    }
}

pub(crate) fn vm_sanitize_nt_prot(prot: u32) -> u32 {
    let base = prot & 0xFF;
    let sanitized = match base {
        PAGE_EXECUTE_READWRITE => 0x20,
        0 => 0x04,
        _ => base,
    };
    (prot & !0xFF) | sanitized
}

pub(crate) fn vm_decode_nt_prot(prot: u32) -> (bool, bool, bool) {
    match prot & 0xFF {
        0x01 => (false, false, false),
        0x02 => (true, false, false),
        0x04 => (true, true, false),
        0x08 => (true, false, false),
        0x10 => (false, false, true),
        0x20 => (true, false, true),
        0x40 | 0x80 => (true, false, true),
        _ => (true, true, false),
    }
}

pub(crate) fn vm_access_allowed(prot: u32, access: u8) -> bool {
    use crate::mm::{VM_ACCESS_EXEC, VM_ACCESS_READ, VM_ACCESS_WRITE};
    if access == VM_ACCESS_WRITE && vm_is_copy_on_write_prot(prot) {
        return true;
    }
    let (read, write, exec) = vm_decode_nt_prot(prot);
    match access {
        VM_ACCESS_READ => read,
        VM_ACCESS_WRITE => write,
        VM_ACCESS_EXEC => exec,
        _ => false,
    }
}

pub(crate) fn vm_is_copy_on_write_prot(prot: u32) -> bool {
    matches!(prot & 0xFF, PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)
}

pub(crate) fn vm_promote_cow_prot(prot: u32) -> u32 {
    match prot & 0xFF {
        PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY => (prot & !0xFF) | 0x04,
        _ => prot,
    }
}

pub(crate) fn vm_clone_shared_nt_prot(prot: u32) -> u32 {
    match vm_sanitize_nt_prot(prot) & 0xFF {
        0x04 => (prot & !0xFF) | PAGE_WRITECOPY,
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => (prot & !0xFF) | PAGE_EXECUTE_WRITECOPY,
        _ => prot,
    }
}
