// VaSpace — 虚拟地址空间管理器
// 管理 VMA (Virtual Memory Area) 列表，支持分配/释放/查询/保护属性修改
// no_std 环境，使用固定大小数组

/// 最大 VMA 数量
const MAX_VMAS: usize = 256;

/// 保护属性
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VmProt(pub u32);

impl VmProt {
    pub const READ: VmProt = VmProt(0x01);
    pub const WRITE: VmProt = VmProt(0x02);
    pub const EXEC: VmProt = VmProt(0x04);
    pub const RW: VmProt = VmProt(0x03);
    pub const RX: VmProt = VmProt(0x05);
    pub const RWX: VmProt = VmProt(0x07);

    pub fn contains(self, other: VmProt) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// VMA 用途类型
#[derive(Clone, Copy, PartialEq, Eq)]
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

/// Virtual Memory Area
#[derive(Clone, Copy)]
pub struct Vma {
    pub base: u64,
    pub size: u64,
    pub prot: VmProt,
    pub vma_type: VmaType,
}

pub struct VaSpace {
    vmas: [Vma; MAX_VMAS],
    count: usize,
    /// Allocatable region start
    alloc_base: u64,
    /// Allocatable region end
    alloc_limit: u64,
}

impl VaSpace {
    pub const fn new() -> Self {
        Self {
            vmas: [Vma {
                base: 0,
                size: 0,
                prot: VmProt(0),
                vma_type: VmaType::Private,
            }; MAX_VMAS],
            count: 0,
            alloc_base: 0,
            alloc_limit: 0,
        }
    }

    /// Initialize with the allocatable VA range
    pub fn init(&mut self, base: u64, limit: u64) {
        self.alloc_base = base;
        self.alloc_limit = limit;
    }

    /// Insert a VMA at the correct sorted position (by base).
    /// Returns true on success, false if full.
    fn insert_sorted(&mut self, vma: Vma) -> bool {
        if self.count >= MAX_VMAS {
            return false;
        }
        // Find insertion point
        let mut pos = self.count;
        for i in 0..self.count {
            if self.vmas[i].base > vma.base {
                pos = i;
                break;
            }
        }
        // Shift right
        let mut i = self.count;
        while i > pos {
            self.vmas[i] = self.vmas[i - 1];
            i -= 1;
        }
        self.vmas[pos] = vma;
        self.count += 1;
        true
    }

    /// Remove VMA at index, shift left
    fn remove_at(&mut self, idx: usize) -> Vma {
        let vma = self.vmas[idx];
        for i in idx..self.count - 1 {
            self.vmas[i] = self.vmas[i + 1];
        }
        self.count -= 1;
        vma
    }

    /// Allocate a VA region. hint=0 → first-fit search.
    /// Returns the base VA on success.
    pub fn allocate(
        &mut self,
        hint: u64,
        size: u64,
        prot: VmProt,
        vma_type: VmaType,
    ) -> Option<u64> {
        let size = page_align_up(size);
        if size == 0 {
            return None;
        }

        let base = if hint != 0 {
            let hint = page_align_down(hint);
            if hint < self.alloc_base || hint + size > self.alloc_limit {
                return None;
            }
            if self.overlaps(hint, size) {
                return None;
            }
            hint
        } else {
            self.find_gap(size)?
        };

        let vma = Vma {
            base,
            size,
            prot,
            vma_type,
        };
        if !self.insert_sorted(vma) {
            return None;
        }
        Some(base)
    }

    /// Free a VMA by its base address.
    pub fn free(&mut self, base: u64) -> Option<Vma> {
        for i in 0..self.count {
            if self.vmas[i].base == base {
                return Some(self.remove_at(i));
            }
        }
        None
    }

    /// Change protection on a region matching base.
    pub fn protect(&mut self, base: u64, new_prot: VmProt) -> bool {
        for i in 0..self.count {
            if self.vmas[i].base == base {
                self.vmas[i].prot = new_prot;
                return true;
            }
        }
        false
    }

    /// Find the VMA containing `addr`.
    pub fn find_vma(&self, addr: u64) -> Option<&Vma> {
        for i in 0..self.count {
            let v = &self.vmas[i];
            if addr >= v.base && addr < v.base + v.size {
                return Some(v);
            }
        }
        None
    }

    fn overlaps(&self, base: u64, size: u64) -> bool {
        let end = base + size;
        for i in 0..self.count {
            let v = &self.vmas[i];
            if base < v.base + v.size && end > v.base {
                return true;
            }
        }
        false
    }

    fn find_gap(&self, size: u64) -> Option<u64> {
        let mut cursor = self.alloc_base;
        for i in 0..self.count {
            let v = &self.vmas[i];
            if v.base + v.size <= cursor {
                continue;
            }
            if v.base >= cursor + size {
                return Some(cursor);
            }
            cursor = v.base + v.size;
        }
        if cursor + size <= self.alloc_limit {
            Some(cursor)
        } else {
            None
        }
    }
}

#[inline(always)]
fn page_align_up(v: u64) -> u64 {
    (v + 0xFFF) & !0xFFF
}

#[inline(always)]
fn page_align_down(v: u64) -> u64 {
    v & !0xFFF
}
