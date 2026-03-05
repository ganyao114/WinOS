/// [start, start+len) 半开区间，所有地址均为字节地址
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Range {
    pub start: u64,
    pub len: u64,
}

impl Range {
    #[inline]
    pub const fn new(start: u64, len: u64) -> Self {
        Self { start, len }
    }

    #[inline]
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    #[inline]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }

    #[inline]
    pub fn overlaps(&self, other: &Range) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    #[inline]
    pub fn is_superset_of(&self, other: &Range) -> bool {
        self.start <= other.start && self.end() >= other.end()
    }

    /// 是否可以在 addr 处分裂（即 start < addr < end）
    #[inline]
    pub fn can_split_at(&self, addr: u64) -> bool {
        addr > self.start && addr < self.end()
    }

    /// 与另一个 Range 的交集（长度为 0 表示无交集）
    #[inline]
    pub fn intersect(&self, other: &Range) -> Range {
        let s = self.start.max(other.start);
        let e = self.end().min(other.end());
        if e > s {
            Range::new(s, e - s)
        } else {
            Range::new(s, 0)
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}
