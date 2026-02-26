// Guest 进程虚拟地址空间分配器
// 管理 [USER_BASE, USER_END) 范围内的 VA 区间

use std::collections::BTreeMap;

/// 用户空间范围 (Windows ARM64 convention)
const USER_BASE: u64 = 0x0000_0001_0000;       // 64 KB
const USER_END:  u64 = 0x0000_7FFF_FFFF_0000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegionState {
    Free,
    Reserved,
    Committed,
}

#[derive(Clone, Debug)]
pub struct Region {
    pub base:  u64,
    pub size:  u64,
    pub state: RegionState,
    pub prot:  u32,  // Windows PAGE_* flags
}

pub struct VaSpace {
    // key = region base VA
    regions: BTreeMap<u64, Region>,
}

impl VaSpace {
    /// 在 KERNEL_READY 时用实际 heap_start 重置 VaSpace
    pub fn set_base(&mut self, heap_start: u64) {
        // Align up to 64KB
        let base = (heap_start + 0xFFFF) & !0xFFFF;
        // GuestMemory is 512MB: [0x40000000, 0x60000000)
        let end = 0x6000_0000u64;
        self.regions.clear();
        self.regions.insert(base, Region {
            base,
            size: end - base,
            state: RegionState::Free,
            prot: 0,
        });
    }
    pub fn new() -> Self {
        let mut regions = BTreeMap::new();
        regions.insert(USER_BASE, Region {
            base:  USER_BASE,
            size:  USER_END - USER_BASE,
            state: RegionState::Free,
            prot:  0,
        });
        Self { regions }
    }

    /// 分配 `size` 字节（向上对齐到 64KB），返回 base VA。
    /// `hint` 为 0 时系统自动选择地址。
    pub fn alloc(&mut self, hint: u64, size: u64, prot: u32) -> Option<u64> {
        let size = align_up(size, 0x10000);
        if hint != 0 {
            self.alloc_at(hint, size, prot)
        } else {
            self.alloc_anywhere(size, prot)
        }
    }

    fn alloc_anywhere(&mut self, size: u64, prot: u32) -> Option<u64> {
        let base = self.regions.values()
            .find(|r| r.state == RegionState::Free && r.size >= size)
            .map(|r| r.base)?;
        self.alloc_at(base, size, prot)
    }

    fn alloc_at(&mut self, base: u64, size: u64, prot: u32) -> Option<u64> {
        let base = align_up(base, 0x10000);
        // Find the free region that contains [base, base+size)
        let (&rbase, _) = self.regions.range(..=base).next_back()
            .filter(|(_, r)| r.state == RegionState::Free && r.base + r.size >= base + size)?;
        let old = self.regions.remove(&rbase).unwrap();

        // Split: [rbase, base) stays free (if non-empty)
        if base > rbase {
            self.regions.insert(rbase, Region {
                base: rbase, size: base - rbase,
                state: RegionState::Free, prot: 0,
            });
        }
        // Allocated region
        self.regions.insert(base, Region {
            base, size, state: RegionState::Committed, prot,
        });
        // Tail: [base+size, old_end) stays free (if non-empty)
        let old_end = old.base + old.size;
        if base + size < old_end {
            self.regions.insert(base + size, Region {
                base: base + size, size: old_end - (base + size),
                state: RegionState::Free, prot: 0,
            });
        }
        Some(base)
    }

    /// 释放从 `base` 开始的区域（合并相邻 Free 区间）。
    pub fn free(&mut self, base: u64) -> bool {
        let base = align_down(base, 0x10000);
        if let Some(r) = self.regions.get_mut(&base) {
            r.state = RegionState::Free;
            r.prot  = 0;
        } else {
            return false;
        }
        self.coalesce(base);
        true
    }

    /// 查询包含 `addr` 的区域。
    pub fn query(&self, addr: u64) -> Option<&Region> {
        self.regions.range(..=addr).next_back()
            .map(|(_, r)| r)
            .filter(|r| addr < r.base + r.size)
    }

    fn coalesce(&mut self, base: u64) {
        // Merge with next
        if let Some(next_base) = self.regions.range((base + 1)..).next().map(|(&k, _)| k) {
            let next_free = self.regions.get(&next_base)
                .map(|r| r.state == RegionState::Free)
                .unwrap_or(false);
            if next_free {
                let next = self.regions.remove(&next_base).unwrap();
                self.regions.get_mut(&base).unwrap().size += next.size;
            }
        }
        // Merge with prev
        if let Some(prev_base) = self.regions.range(..base).next_back().map(|(&k, _)| k) {
            let prev_free = self.regions.get(&prev_base)
                .map(|r| r.state == RegionState::Free)
                .unwrap_or(false);
            if prev_free {
                let cur_size = self.regions.get(&base).unwrap().size;
                self.regions.get_mut(&prev_base).unwrap().size += cur_size;
                self.regions.remove(&base);
            }
        }
    }
}

fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

fn align_down(v: u64, align: u64) -> u64 {
    v & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_and_free() {
        let mut va = VaSpace::new();
        let a = va.alloc(0, 0x1000, 0x04).unwrap();
        assert_eq!(a % 0x10000, 0);
        let b = va.alloc(0, 0x10000, 0x04).unwrap();
        assert_ne!(a, b);
        assert!(va.free(a));
        assert!(va.free(b));
    }

    #[test]
    fn alloc_at_hint() {
        let mut va = VaSpace::new();
        let hint = 0x0000_0010_0000u64;
        let addr = va.alloc(hint, 0x1000, 0x04).unwrap();
        assert_eq!(addr, hint);
    }

    #[test]
    fn query_region() {
        let mut va = VaSpace::new();
        let base = va.alloc(0, 0x20000, 0x04).unwrap();
        let r = va.query(base + 0x100).unwrap();
        assert_eq!(r.base, base);
        assert_eq!(r.size, 0x20000);
        assert_eq!(r.state, RegionState::Committed);
    }

    #[test]
    fn coalesce_after_free() {
        let mut va = VaSpace::new();
        let a = va.alloc(0, 0x10000, 0x04).unwrap();
        let b = va.alloc(0, 0x10000, 0x04).unwrap();
        va.free(a);
        va.free(b);
        // After coalescing, a single free region should cover both
        let r = va.query(a).unwrap();
        assert_eq!(r.state, RegionState::Free);
        assert!(r.size >= 0x20000);
    }
}
