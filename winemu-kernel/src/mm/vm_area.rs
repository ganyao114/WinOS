/// VmArea — 虚拟内存区域，作为 AreaSet 的值类型
///
/// 每个 VmArea 对应一段连续的虚拟地址区间，包含：
///   - 区域类型和保护属性
///   - 每页的物理地址（phys_pages）
///   - 每页的 NT 保护标志（prot_pages）
///   - 每页的提交位图（commit_bits）
///   - 可选的 section/文件映射元信息
use crate::mm::areaset::AreaValue;
use crate::mm::range::Range;
use crate::mm::PhysAddr;
use crate::rust_alloc::vec::Vec;

pub(crate) const PAGE_SIZE: u64 = crate::nt::constants::PAGE_SIZE_4K;

// ─── VmKind ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmKind {
    Private,
    Image,
    Section,
    ThreadStack,
    Other,
}

// ─── VmArea ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct VmArea {
    /// 本次 VirtualAlloc 的原始基地址（用于 MEM_RELEASE 整块释放）
    pub alloc_base: u64,
    pub kind: VmKind,
    /// 分配时的 NT 保护属性（VirtualQuery.AllocationProtect）
    pub default_prot: u32,
    /// false = 文件映射（不释放物理页引用）
    pub owns_phys_pages: bool,

    /// 每页物理页地址；`PhysAddr::default()` = 尚未映射
    pub phys_pages: Vec<PhysAddr>,
    /// 每页 NT 保护标志
    pub prot_pages: Vec<u32>,
    /// commit 位图：bit i = 1 → 第 i 页已提交
    pub commit_bits: Vec<u64>,

    // Section / 文件映射元信息（仅 kind == Section 时有意义）
    pub section_file_fd: u64,
    pub section_file_offset: u64,
    pub section_view_size: u64,
    pub section_file_backed: bool,
    pub section_is_image: bool,
}

impl VmArea {
    /// 创建纯保留（未提交）的私有区域
    pub fn new_reserved(
        alloc_base: u64,
        page_count: usize,
        default_prot: u32,
        kind: VmKind,
    ) -> Option<Self> {
        let cwords = commit_words_for(page_count);
        let mut phys_pages = Vec::new();
        let mut prot_pages = Vec::new();
        let mut commit_bits = Vec::new();
        phys_pages.try_reserve_exact(page_count).ok()?;
        prot_pages.try_reserve_exact(page_count).ok()?;
        commit_bits.try_reserve_exact(cwords).ok()?;
        phys_pages.resize(page_count, PhysAddr::default());
        prot_pages.resize(page_count, default_prot);
        commit_bits.resize(cwords, 0u64);
        Some(Self {
            alloc_base,
            kind,
            default_prot,
            owns_phys_pages: true,
            phys_pages,
            prot_pages,
            commit_bits,
            section_file_fd: 0,
            section_file_offset: 0,
            section_view_size: 0,
            section_file_backed: false,
            section_is_image: false,
        })
    }

    /// 创建外部文件映射区域（物理页不由内核管理）
    pub fn new_file_mapping(
        alloc_base: u64,
        page_count: usize,
        prot: u32,
        view_size: u64,
    ) -> Option<Self> {
        let cwords = commit_words_for(page_count);
        let mut phys_pages = Vec::new();
        let mut prot_pages = Vec::new();
        let mut commit_bits = Vec::new();
        phys_pages.try_reserve_exact(page_count).ok()?;
        prot_pages.try_reserve_exact(page_count).ok()?;
        commit_bits.try_reserve_exact(cwords).ok()?;
        phys_pages.resize(page_count, PhysAddr::default());
        prot_pages.resize(page_count, prot);
        commit_bits.resize(cwords, 0u64);
        Some(Self {
            alloc_base,
            kind: VmKind::Section,
            default_prot: prot,
            owns_phys_pages: false,
            phys_pages,
            prot_pages,
            commit_bits,
            section_file_fd: 0,
            section_file_offset: 0,
            section_view_size: view_size,
            section_file_backed: false,
            section_is_image: false,
        })
    }

    pub fn page_count(&self) -> usize {
        self.phys_pages.len()
    }

    pub fn phys_page(&self, idx: usize) -> PhysAddr {
        self.phys_pages.get(idx).copied().unwrap_or_default()
    }

    pub fn set_phys_page(&mut self, idx: usize, pa: PhysAddr) {
        if idx < self.phys_pages.len() {
            self.phys_pages[idx] = pa;
        }
    }

    pub fn is_page_committed(&self, idx: usize) -> bool {
        if idx >= self.phys_pages.len() {
            return false;
        }
        let word = idx / 64;
        let bit = idx % 64;
        word < self.commit_bits.len() && (self.commit_bits[word] & (1u64 << bit)) != 0
    }

    pub fn set_page_committed(&mut self, idx: usize, committed: bool) {
        if idx >= self.phys_pages.len() {
            return;
        }
        let word = idx / 64;
        let bit = idx % 64;
        if word < self.commit_bits.len() {
            if committed {
                self.commit_bits[word] |= 1u64 << bit;
            } else {
                self.commit_bits[word] &= !(1u64 << bit);
            }
        }
    }

    pub fn has_any_committed(&self) -> bool {
        self.commit_bits.iter().any(|&b| b != 0)
    }

    pub fn has_any_phys(&self) -> bool {
        self.phys_pages.iter().any(|&p| !p.is_null())
    }
}

// ─── 辅助函数 ────────────────────────────────────────────────────────────────

pub(crate) fn commit_words_for(page_count: usize) -> usize {
    ((page_count + 63) / 64).max(1)
}

/// 把 commit 位图在第 split_idx 页处切分成左右两份
pub(crate) fn split_commit_bits(
    bits: &[u64],
    split_idx: usize,
    total: usize,
) -> (Vec<u64>, Vec<u64>) {
    let right_count = total - split_idx;
    let left_words = commit_words_for(split_idx);
    let right_words = commit_words_for(right_count);

    let mut left = Vec::new();
    let mut right = Vec::new();
    let _ = left.try_reserve_exact(left_words);
    let _ = right.try_reserve_exact(right_words);
    left.resize(left_words, 0u64);
    right.resize(right_words, 0u64);

    for i in 0..split_idx {
        let sw = i / 64;
        let sb = i % 64;
        if sw < bits.len() && (bits[sw] & (1u64 << sb)) != 0 {
            left[i / 64] |= 1u64 << (i % 64);
        }
    }
    for i in 0..right_count {
        let si = i + split_idx;
        let sw = si / 64;
        let sb = si % 64;
        if sw < bits.len() && (bits[sw] & (1u64 << sb)) != 0 {
            right[i / 64] |= 1u64 << (i % 64);
        }
    }
    (left, right)
}

// ─── AreaValue 实现 ───────────────────────────────────────────────────────────

impl AreaValue for VmArea {
    /// 保守合并：仅限两端均未提交、无物理页、同类型的纯保留区域
    fn merge(&self, _r1: &Range, _r2: &Range, other: &Self) -> Option<Self> {
        if self.kind != other.kind
            || self.default_prot != other.default_prot
            || self.owns_phys_pages != other.owns_phys_pages
            || self.alloc_base != other.alloc_base
            || self.kind == VmKind::Section
            || self.has_any_committed()
            || other.has_any_committed()
            || self.has_any_phys()
            || other.has_any_phys()
        {
            return None;
        }
        let total_pages = self.page_count() + other.page_count();
        let cwords = commit_words_for(total_pages);
        let mut phys_pages = Vec::new();
        let mut prot_pages = Vec::new();
        let mut commit_bits = Vec::new();
        phys_pages.try_reserve_exact(total_pages).ok()?;
        prot_pages.try_reserve_exact(total_pages).ok()?;
        commit_bits.try_reserve_exact(cwords).ok()?;
        phys_pages.resize(total_pages, PhysAddr::default());
        prot_pages.resize(total_pages, self.default_prot);
        commit_bits.resize(cwords, 0u64);
        Some(Self {
            alloc_base: self.alloc_base,
            kind: self.kind,
            default_prot: self.default_prot,
            owns_phys_pages: self.owns_phys_pages,
            phys_pages,
            prot_pages,
            commit_bits,
            section_file_fd: 0,
            section_file_offset: 0,
            section_view_size: 0,
            section_file_backed: false,
            section_is_image: false,
        })
    }

    /// 在 at 字节处（页对齐）将当前区域分裂为左右两半
    fn split(&self, r: &Range, at: u64) -> (Self, Self) {
        let split_idx = ((at - r.start) / PAGE_SIZE) as usize;
        let total = (r.len / PAGE_SIZE) as usize;

        let left_phys = self.phys_pages[..split_idx].to_vec();
        let right_phys = self.phys_pages[split_idx..].to_vec();
        let left_prot = self.prot_pages[..split_idx].to_vec();
        let right_prot = self.prot_pages[split_idx..].to_vec();
        let (left_bits, right_bits) = split_commit_bits(&self.commit_bits, split_idx, total);

        let split_bytes = (split_idx as u64) * PAGE_SIZE;
        let left_view_size = self.section_view_size.min(split_bytes);
        let right_view_size = self.section_view_size.saturating_sub(split_bytes);
        let right_file_offset = self.section_file_offset + split_bytes;

        let left = Self {
            alloc_base: self.alloc_base,
            kind: self.kind,
            default_prot: self.default_prot,
            owns_phys_pages: self.owns_phys_pages,
            phys_pages: left_phys,
            prot_pages: left_prot,
            commit_bits: left_bits,
            section_file_fd: self.section_file_fd,
            section_file_offset: self.section_file_offset,
            section_view_size: left_view_size,
            section_file_backed: self.section_file_backed,
            section_is_image: self.section_is_image,
        };
        let right = Self {
            alloc_base: self.alloc_base,
            kind: self.kind,
            default_prot: self.default_prot,
            owns_phys_pages: self.owns_phys_pages,
            phys_pages: right_phys,
            prot_pages: right_prot,
            commit_bits: right_bits,
            section_file_fd: self.section_file_fd,
            section_file_offset: right_file_offset,
            section_view_size: right_view_size,
            section_file_backed: self.section_file_backed,
            section_is_image: self.section_is_image,
        };
        (left, right)
    }
}
