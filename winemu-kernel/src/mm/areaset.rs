use super::range::Range;
use crate::rust_alloc::collections::BTreeMap;
use crate::rust_alloc::sync::{Arc, Weak};
/// AreaSet — 有序区间集合，移植自 Quark (gVisor AreaSet)
///
/// 数据结构：
///   - BTreeMap<start, AreaEntry<T>>  — O(log n) 按起始地址查找
///   - 双向链表（head dummy → seg0 → seg1 → ... → tail dummy）— O(1) 邻居遍历
///
/// 并发说明：
///   AreaEntry 内部使用 UnsafeCell，不加互斥锁。
///   ProcessVmManager 的所有访问均在单线程（per-process with_process_mut）下进行，
///   因此 UnsafeCell 是安全的。
use core::cell::UnsafeCell;

// ─────────────────────────────────────────────────────────────────────────────
// AreaValue trait
// ─────────────────────────────────────────────────────────────────────────────

pub trait AreaValue: Clone {
    /// 尝试合并相邻的两个区间值，返回 Some(merged) 或 None（不可合并）
    fn merge(&self, r1: &Range, r2: &Range, other: &Self) -> Option<Self>;
    /// 在 at 地址处把当前区间值分裂成两个
    fn split(&self, r: &Range, at: u64) -> (Self, Self);
}

// ─────────────────────────────────────────────────────────────────────────────
// AreaEntry 链表节点
// ─────────────────────────────────────────────────────────────────────────────

struct AreaEntryInternal<T: AreaValue> {
    range: Range,
    value: Option<T>,
    prev: Option<AreaEntryWeak<T>>,
    next: Option<AreaEntry<T>>,
}

struct AreaEntryWeak<T: AreaValue>(Weak<UnsafeCell<AreaEntryInternal<T>>>);

impl<T: AreaValue> Clone for AreaEntryWeak<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: AreaValue> AreaEntryWeak<T> {
    fn upgrade(&self) -> Option<AreaEntry<T>> {
        self.0.upgrade().map(AreaEntry)
    }
}

pub struct AreaEntry<T: AreaValue>(Arc<UnsafeCell<AreaEntryInternal<T>>>);

impl<T: AreaValue> Clone for AreaEntry<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: AreaValue> PartialEq for AreaEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<T: AreaValue> AreaEntry<T> {
    pub(crate) fn new_dummy(start: u64) -> Self {
        Self(Arc::new(UnsafeCell::new(AreaEntryInternal {
            range: Range::new(start, 0),
            value: None,
            prev: None,
            next: None,
        })))
    }

    fn new_node(r: Range, val: T) -> Self {
        Self(Arc::new(UnsafeCell::new(AreaEntryInternal {
            range: r,
            value: Some(val),
            prev: None,
            next: None,
        })))
    }

    fn downgrade(&self) -> AreaEntryWeak<T> {
        AreaEntryWeak(Arc::downgrade(&self.0))
    }

    #[inline(always)]
    fn i(&self) -> &AreaEntryInternal<T> {
        // SAFETY: single-threaded per-process access
        unsafe { &*self.0.get() }
    }

    #[inline(always)]
    #[allow(clippy::mut_from_ref)]
    fn im(&self) -> &mut AreaEntryInternal<T> {
        // SAFETY: single-threaded per-process access
        unsafe { &mut *self.0.get() }
    }

    pub fn range(&self) -> Range {
        self.i().range
    }

    fn set_range(&self, r: Range) {
        self.im().range = r;
    }

    /// 仅在 value.is_some() 时调用（非 head/tail）
    pub fn value(&self) -> &T {
        self.i()
            .value
            .as_ref()
            .expect("AreaEntry::value on head/tail")
    }

    /// 获取可变引用（不 clone）
    pub fn value_mut(&self) -> &mut T {
        self.im()
            .value
            .as_mut()
            .expect("AreaEntry::value_mut on head/tail")
    }

    pub fn set_value(&self, v: T) {
        self.im().value = Some(v);
    }

    /// true = 真实 seg（有 prev、next 和 value）
    pub fn ok(&self) -> bool {
        let i = self.i();
        i.prev.is_some() && i.next.is_some() && i.value.is_some()
    }

    fn is_head(&self) -> bool {
        self.i().prev.is_none()
    }

    fn is_tail(&self) -> bool {
        self.i().next.is_none()
    }

    fn next_entry(&self) -> Option<AreaEntry<T>> {
        self.i().next.clone()
    }

    fn prev_entry(&self) -> Option<AreaEntry<T>> {
        self.i().prev.as_ref()?.upgrade()
    }

    /// 在 self 之后插入新节点，返回新节点
    fn insert_after(&self, r: Range, val: T) -> AreaEntry<T> {
        let new_e = AreaEntry::new_node(r, val);
        let next = self.im().next.take().expect("insert_after: null next");
        self.im().next = Some(new_e.clone());
        new_e.im().prev = Some(self.downgrade());
        new_e.im().next = Some(next.clone());
        next.im().prev = Some(new_e.downgrade());
        new_e
    }

    /// 从链表中移除 self（不修改 BTreeMap）
    fn unlink(&self) {
        let prev_weak = self.im().prev.take().expect("unlink: null prev");
        let next = self.im().next.take().expect("unlink: null next");
        let prev = prev_weak.upgrade().expect("unlink: prev expired");
        prev.im().next = Some(next.clone());
        next.im().prev = Some(prev.downgrade());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AreaSeg — 已占用区间迭代器
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AreaSeg<T: AreaValue>(pub AreaEntry<T>);

impl<T: AreaValue> PartialEq for AreaSeg<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: AreaValue> AreaSeg<T> {
    pub fn ok(&self) -> bool {
        self.0.ok()
    }

    pub fn range(&self) -> Range {
        self.0.range()
    }

    pub fn value(&self) -> &T {
        self.0.value()
    }

    pub fn value_mut(&self) -> &mut T {
        self.0.value_mut()
    }

    pub fn set_value(&self, v: T) {
        self.0.set_value(v);
    }

    /// 下一个 seg，若已是最后一个则 ok() == false
    pub fn next_seg(&self) -> AreaSeg<T> {
        match self.0.next_entry() {
            Some(e) if e.ok() => AreaSeg(e),
            Some(e) => AreaSeg(e), // tail，ok()==false
            None => self.clone(),
        }
    }

    /// 上一个 seg，若已是第一个则 ok() == false
    pub fn prev_seg(&self) -> AreaSeg<T> {
        match self.0.prev_entry() {
            Some(e) if e.ok() => AreaSeg(e),
            Some(e) => AreaSeg(e),
            None => self.clone(),
        }
    }

    /// self 之后的空洞（即 self.range.end 到 next_seg.range.start 之间）
    /// AreaGap 包裹 self（gap 在 self 之后）
    pub fn next_gap(&self) -> AreaGap<T> {
        AreaGap(Some(self.0.clone()))
    }

    /// self 之前的空洞（即 prev_seg.range.end 到 self.range.start 之间）
    pub fn prev_gap(&self) -> AreaGap<T> {
        match self.0.prev_entry() {
            Some(prev) => AreaGap(Some(prev)),
            None => AreaGap(None),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AreaGap — 空洞迭代器
//
// AreaGap(Some(entry)) = entry.range.end 到 entry.next.range.start 之间的空洞
// AreaGap(None)        = 无效
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AreaGap<T: AreaValue>(pub Option<AreaEntry<T>>);

impl<T: AreaValue> AreaGap<T> {
    /// 有效的 gap：inner entry 存在且不是 tail
    pub fn ok(&self) -> bool {
        self.0.as_ref().map_or(false, |e| !e.is_tail())
    }

    /// gap 所覆盖的地址范围
    pub fn range(&self) -> Range {
        let entry = match self.0.as_ref() {
            Some(e) if !e.is_tail() => e,
            _ => return Range::new(0, 0),
        };
        let start = entry.range().end();
        let end = entry.next_entry().map(|n| n.range().start).unwrap_or(start);
        if end >= start {
            Range::new(start, end - start)
        } else {
            Range::new(0, 0)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.range().len == 0
    }

    /// gap 之前的 seg（即包裹的 entry 本身，如果它是真实 seg）
    pub fn prev_seg(&self) -> AreaSeg<T> {
        match self.0.as_ref() {
            Some(e) => AreaSeg(e.clone()),
            None => {
                // 无效，返回自身（ok()==false）
                AreaSeg(AreaEntry::new_dummy(0))
            }
        }
    }

    /// gap 之后的 seg
    pub fn next_seg(&self) -> AreaSeg<T> {
        let entry = match self.0.as_ref() {
            Some(e) if !e.is_tail() => e,
            _ => return AreaSeg(AreaEntry::new_dummy(0)),
        };
        match entry.next_entry() {
            Some(n) => AreaSeg(n),
            None => AreaSeg(AreaEntry::new_dummy(0)),
        }
    }

    /// 下一个空洞（即 next_seg 之后的空洞）
    pub fn next_gap(&self) -> AreaGap<T> {
        let entry = match self.0.as_ref() {
            Some(e) if !e.is_tail() => e,
            _ => return AreaGap(None),
        };
        match entry.next_entry() {
            Some(next) if !next.is_tail() => AreaGap(Some(next)),
            _ => AreaGap(None),
        }
    }

    /// 上一个空洞（即 prev_seg 之前的空洞）
    pub fn prev_gap(&self) -> AreaGap<T> {
        let entry = match self.0.as_ref() {
            Some(e) => e,
            None => return AreaGap(None),
        };
        match entry.prev_entry() {
            Some(prev) => AreaGap(Some(prev)),
            None => AreaGap(None),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AreaSet
// ─────────────────────────────────────────────────────────────────────────────

pub struct AreaSet<T: AreaValue> {
    /// 整个可管理范围
    pub range: Range,
    /// 哨兵头（range=[va_base,0)）
    head: AreaEntry<T>,
    /// 哨兵尾（range=[va_limit,0)）
    tail: AreaEntry<T>,
    /// start → entry
    map: BTreeMap<u64, AreaEntry<T>>,
}

impl<T: AreaValue> AreaSet<T> {
    pub fn new(start: u64, len: u64) -> Self {
        let head = AreaEntry::new_dummy(start);
        let tail = AreaEntry::new_dummy(start.saturating_add(len));
        head.im().next = Some(tail.clone());
        tail.im().prev = Some(head.downgrade());
        Self {
            range: Range::new(start, len),
            head,
            tail,
            map: BTreeMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// 给定 key 对应的 range 是否完全位于 gap 中（无 seg 覆盖）
    pub fn is_empty_range(&self, r: &Range) -> bool {
        if r.len == 0 {
            return true;
        }
        let (seg, gap) = self.find(r.start);
        if seg.ok() {
            return false;
        }
        if !gap.ok() {
            return false;
        }
        r.end() <= gap.range().end()
    }

    // ─── 查找 ────────────────────────────────────────────────────────────

    /// 查找 key 所在的 seg 或 gap
    pub fn find(&self, key: u64) -> (AreaSeg<T>, AreaGap<T>) {
        use core::ops::Bound::{Included, Unbounded};

        let entry = self
            .map
            .range((Unbounded, Included(key)))
            .next_back()
            .map(|(_, e)| e.clone())
            .unwrap_or_else(|| self.head.clone());

        if entry.ok() && entry.range().contains(key) {
            (AreaSeg(entry), AreaGap(None))
        } else {
            // key 在 entry 之后的 gap 中
            (AreaSeg(AreaEntry::new_dummy(0)), AreaGap(Some(entry)))
        }
    }

    /// 返回包含 key 的 seg（若不在任何 seg 中则 ok()==false）
    pub fn find_seg(&self, key: u64) -> AreaSeg<T> {
        self.find(key).0
    }

    /// 返回包含 key 的 gap（若 key 在某 seg 中则 ok()==false）
    pub fn find_gap(&self, key: u64) -> AreaGap<T> {
        self.find(key).1
    }

    /// 最低 start >= key 的 seg
    pub fn lower_bound_seg(&self, key: u64) -> AreaSeg<T> {
        let (seg, gap) = self.find(key);
        if seg.ok() {
            return seg;
        }
        if gap.ok() {
            return gap.next_seg();
        }
        AreaSeg(self.tail.clone())
    }

    /// 最高 end <= key+1 的 seg（即最后一个 start <= key 的 seg）
    pub fn upper_bound_seg(&self, key: u64) -> AreaSeg<T> {
        let (seg, gap) = self.find(key);
        if seg.ok() {
            return seg;
        }
        if gap.ok() {
            return gap.prev_seg();
        }
        AreaSeg(self.head.clone())
    }

    /// start >= key 的最低 gap
    pub fn lower_bound_gap(&self, key: u64) -> AreaGap<T> {
        let (seg, gap) = self.find(key);
        if gap.ok() {
            return gap;
        }
        if seg.ok() {
            return seg.next_gap();
        }
        AreaGap(None)
    }

    /// 第一个（地址最低的）真实 seg
    pub fn first_seg(&self) -> AreaSeg<T> {
        match self.head.next_entry() {
            Some(e) => AreaSeg(e),
            None => AreaSeg(self.tail.clone()),
        }
    }

    /// 最后一个（地址最高的）真实 seg
    pub fn last_seg(&self) -> AreaSeg<T> {
        match self.tail.prev_entry() {
            Some(e) => AreaSeg(e),
            None => AreaSeg(self.head.clone()),
        }
    }

    /// 第一个空洞（从 va_base 到 first_seg.start）
    pub fn first_gap(&self) -> AreaGap<T> {
        AreaGap(Some(self.head.clone()))
    }

    /// 最后一个空洞（从 last_seg.end 到 va_limit）
    pub fn last_gap(&self) -> AreaGap<T> {
        match self.tail.prev_entry() {
            Some(prev) => AreaGap(Some(prev)),
            None => AreaGap(None),
        }
    }

    // ─── 插入 ────────────────────────────────────────────────────────────

    /// 在 gap 中插入 [r, val)，自动尝试与邻居合并
    pub fn insert(&mut self, gap: &AreaGap<T>, r: &Range, val: T) -> AreaSeg<T> {
        let prev = gap.prev_seg();
        let next = gap.next_seg();

        // 尝试与 prev 合并
        if prev.ok() && prev.range().end() == r.start {
            let r1 = prev.range();
            if let Some(mval) = prev.value().merge(&r1, r, &val) {
                // 扩展 prev
                let new_range = Range::new(r1.start, r1.len + r.len);
                prev.0.set_range(new_range);
                prev.0.set_value(mval.clone());

                // 再尝试与 next 合并
                if next.ok() && next.range().start == new_range.end() {
                    let r2 = next.range();
                    if let Some(mval2) = mval.merge(&new_range, &r2, next.value()) {
                        let merged_range = Range::new(new_range.start, new_range.len + r2.len);
                        prev.0.set_range(merged_range);
                        prev.0.set_value(mval2);
                        self.remove(&next);
                        return prev;
                    }
                }
                return prev;
            }
        }

        // 尝试与 next 合并
        if next.ok() && next.range().start == r.end() {
            let r2 = next.range();
            if let Some(mval) = val.merge(r, &r2, next.value()) {
                let new_range = Range::new(r.start, r.len + r2.len);
                // 把 next 的 map key 从 r2.start 改为 r.start
                self.map.remove(&r2.start);
                next.0.set_range(new_range);
                next.0.set_value(mval);
                self.map.insert(r.start, next.0.clone());
                return next;
            }
        }

        self.insert_without_merging_unchecked(gap, r, val)
    }

    /// 在 gap 中插入，不尝试合并
    pub fn insert_without_merging(&mut self, gap: &AreaGap<T>, r: &Range, val: T) -> AreaSeg<T> {
        self.insert_without_merging_unchecked(gap, r, val)
    }

    fn insert_without_merging_unchecked(
        &mut self,
        gap: &AreaGap<T>,
        r: &Range,
        val: T,
    ) -> AreaSeg<T> {
        let prev = gap.prev_seg();
        let new_e = prev.0.insert_after(*r, val);
        self.map.insert(r.start, new_e.clone());
        AreaSeg(new_e)
    }

    // ─── 删除 ────────────────────────────────────────────────────────────

    /// 删除 seg，返回空出的 gap（在 prev 和 next 之间）
    pub fn remove(&mut self, seg: &AreaSeg<T>) -> AreaGap<T> {
        assert!(seg.ok(), "remove: seg is not valid");
        let prev = seg.0.prev_entry().expect("remove: no prev");
        self.map.remove(&seg.range().start);
        seg.0.unlink();
        AreaGap(Some(prev))
    }

    /// 删除 [r] 范围内的所有 seg（自动 isolate 边界）
    pub fn remove_range(&mut self, r: &Range) -> AreaGap<T> {
        let (mut seg, mut gap) = self.find(r.start);

        if seg.ok() {
            seg = self.isolate(&seg, r);
            gap = self.remove(&seg);
        }

        let mut next = gap.next_seg();
        while next.ok() && next.range().start < r.end() {
            next = self.isolate(&next, r);
            gap = self.remove(&next);
            next = gap.next_seg();
        }

        gap
    }

    // ─── 分裂 ────────────────────────────────────────────────────────────

    /// 在 at 处把 seg 分裂为两个
    pub fn split(&mut self, seg: &AreaSeg<T>, at: u64) -> (AreaSeg<T>, AreaSeg<T>) {
        let r = seg.range();
        assert!(r.can_split_at(at), "split: cannot split at {:#x}", at);
        self.split_unchecked(seg, at)
    }

    /// 如果 at 地址有 seg 覆盖，在此处分裂；否则不做任何事
    pub fn split_at(&mut self, at: u64) -> bool {
        let seg = self.find_seg(at);
        if !seg.ok() {
            return false;
        }
        if seg.range().can_split_at(at) {
            self.split_unchecked(&seg, at);
            return true;
        }
        false
    }

    fn split_unchecked(&mut self, seg: &AreaSeg<T>, at: u64) -> (AreaSeg<T>, AreaSeg<T>) {
        let r = seg.range();
        let (val1, val2) = seg.value().split(&r, at);

        let end2 = r.end();
        // 修改 seg 为左半部分
        seg.0.set_range(Range::new(r.start, at - r.start));
        seg.0.set_value(val1);

        // 在 seg 之后插入右半部分
        let gap = seg.next_gap();
        let r2 = Range::new(at, end2 - at);
        let seg2 = self.insert_without_merging_unchecked(&gap, &r2, val2);

        (seg.clone(), seg2)
    }

    /// 确保 seg 不超出 r 的边界（在 r.start 和 r.end 处各 split 一次）
    pub fn isolate(&mut self, seg: &AreaSeg<T>, r: &Range) -> AreaSeg<T> {
        let mut cur = seg.clone();

        if cur.range().can_split_at(r.start) {
            let (_, right) = self.split_unchecked(&cur, r.start);
            cur = right;
        }

        if cur.range().can_split_at(r.end()) {
            let (left, _) = self.split_unchecked(&cur, r.end());
            cur = left;
        }

        cur
    }

    // ─── 合并 ────────────────────────────────────────────────────────────

    /// 尝试合并两个相邻 seg
    pub fn merge(&mut self, first: &AreaSeg<T>, second: &AreaSeg<T>) -> AreaSeg<T> {
        if !first.ok() || !second.ok() {
            return first.clone();
        }
        let r1 = first.range();
        let r2 = second.range();
        if r1.end() != r2.start {
            return first.clone();
        }
        if let Some(mval) = first.value().merge(&r1, &r2, second.value()) {
            let merged = Range::new(r1.start, r1.len + r2.len);
            first.0.set_range(merged);
            first.0.set_value(mval);
            self.remove(second);
            return first.clone();
        }
        first.clone()
    }

    /// 尝试合并 range 首尾两端与其邻居的 seg
    pub fn merge_adjacent(&mut self, r: &Range) {
        // 尝试合并 r.start 处 seg 与其前驱
        let first = self.find_seg(r.start);
        if first.ok() {
            let prev = first.prev_seg();
            if prev.ok() {
                let merged = self.merge(&prev, &first);
                let _ = merged;
            }
        }
        // 尝试合并 r.end-1 处 seg 与其后继
        let last = self.find_seg(r.end().saturating_sub(1));
        if last.ok() {
            let next = last.next_seg();
            if next.ok() {
                self.merge(&last, &next);
            }
        }
    }

    pub fn merge_all(&mut self) {
        let mut seg = self.first_seg();
        if !seg.ok() {
            return;
        }
        loop {
            let next = seg.next_seg();
            if !next.ok() {
                break;
            }
            let merged = self.merge(&seg, &next);
            if merged == seg {
                // 没有合并，前进
                seg = seg.next_seg();
            } else {
                seg = merged;
            }
        }
    }
}
