use crate::kobj::ObjectStore;
/// ProcessVmManager — 每进程虚拟地址空间管理器
///
/// 基于 AreaSet<VmArea> 提供：
///   - O(log n) 地址查找
///   - 自动 split/merge（支持 VirtualProtect 跨区边界）
///   - NT 完整语义：Reserve / Commit / Decommit / Release / Protect / Guard / COW
use crate::mm::areaset::{AreaEntry, AreaSeg, AreaSet};
use crate::mm::range::Range;
use crate::mm::vm_area::{VmArea, VmKind, PAGE_SIZE};
use crate::mm::{
    vm_access_allowed, vm_is_copy_on_write_prot, vm_promote_cow_prot, vm_sanitize_nt_prot,
    PhysAddr, UserVa, VmQueryInfo,
};
use crate::process::ProcessAddressSpace;
use crate::rust_alloc::vec::Vec;
use core::cell::UnsafeCell;
use winemu_shared::status;

// ─── NT 常量 ─────────────────────────────────────────────────────────────────

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_FREE: u32 = 0x1_0000;
const MEM_PRIVATE_TYPE: u32 = 0x0002_0000;
const MEM_MAPPED_TYPE: u32 = 0x0004_0000;
const MEM_IMAGE_TYPE: u32 = 0x0100_0000;

const PAGE_GUARD: u32 = 0x100;

#[derive(Clone, Copy)]
struct SharedPhysPageRef {
    pa: PhysAddr,
    refs: u32,
}

struct SharedPhysPageRefRuntime {
    page_refs: UnsafeCell<Option<ObjectStore<SharedPhysPageRef>>>,
}

unsafe impl Sync for SharedPhysPageRefRuntime {}

static SHARED_PHYS_PAGE_REFS: SharedPhysPageRefRuntime = SharedPhysPageRefRuntime {
    page_refs: UnsafeCell::new(None),
};

fn shared_phys_page_refs_mut() -> &'static mut ObjectStore<SharedPhysPageRef> {
    // SAFETY: kernel runs with a single global VM metadata domain here; this
    // matches the existing ObjectStore + UnsafeCell ownership model used by the
    // rest of the kernel runtime stores.
    unsafe {
        let slot = &mut *SHARED_PHYS_PAGE_REFS.page_refs.get();
        if slot.is_none() {
            *slot = Some(ObjectStore::new());
        }
        slot.as_mut().unwrap()
    }
}

fn shared_phys_page_add_ref(pa: PhysAddr) {
    if pa.is_null() {
        return;
    }
    let store = shared_phys_page_refs_mut();
    let mut found = 0u32;
    store.for_each_live_ptr(|id, ptr| {
        // SAFETY: ObjectStore guarantees live pointers during iteration.
        unsafe {
            if (*ptr).pa == pa {
                found = id;
            }
        }
    });
    if found != 0 {
        let ptr = store.get_ptr(found);
        if !ptr.is_null() {
            // SAFETY: `found` came from the same live ObjectStore iteration.
            unsafe {
                (*ptr).refs = (*ptr).refs.saturating_add(1);
            }
        }
        return;
    }
    let _ = store.alloc_with(|_| SharedPhysPageRef { pa, refs: 1 });
}

fn shared_phys_page_release(pa: PhysAddr) {
    if pa.is_null() {
        return;
    }
    let store = shared_phys_page_refs_mut();
    let mut found = 0u32;
    let mut refs = 0u32;
    store.for_each_live_ptr(|id, ptr| {
        // SAFETY: ObjectStore guarantees live pointers during iteration.
        unsafe {
            if (*ptr).pa == pa {
                found = id;
                refs = (*ptr).refs;
            }
        }
    });

    if found == 0 {
        crate::mm::phys::free_pages(pa, 1);
        return;
    }

    if refs > 1 {
        let ptr = store.get_ptr(found);
        if !ptr.is_null() {
            // SAFETY: `found` came from the same live ObjectStore iteration.
            unsafe {
                (*ptr).refs = refs - 1;
            }
        }
        return;
    }

    let _ = store.free(found);
    crate::mm::phys::free_pages(pa, 1);
}

fn vm_region_mem_type(area: &VmArea) -> u32 {
    match area.kind {
        VmKind::Image => MEM_IMAGE_TYPE,
        VmKind::Section => {
            if area.section_is_image {
                MEM_IMAGE_TYPE
            } else {
                MEM_MAPPED_TYPE
            }
        }
        _ => MEM_PRIVATE_TYPE,
    }
}

// ─── 按页填充 section 数据 ────────────────────────────────────────────────────

fn vm_fill_section_page(area: &VmArea, idx: usize, pa: PhysAddr) -> bool {
    if !area.section_file_backed {
        return true;
    }
    let page_off = (idx as u64) * PAGE_SIZE;
    if page_off >= area.section_view_size {
        return true;
    }
    let remain = area.section_view_size - page_off;
    let read_len = PAGE_SIZE.min(remain) as usize;
    let file_off = area.section_file_offset.saturating_add(page_off);
    let read = crate::hypercall::host_read_phys(area.section_file_fd, pa, read_len, file_off);
    if read < read_len {
        let Some(zero_pa) = pa.checked_add(read as u64) else {
            return false;
        };
        phys_memset(zero_pa, 0, read_len - read);
    }
    true
}

#[inline]
fn phys_memset(pa: PhysAddr, value: u8, len: usize) {
    if !crate::mm::linear_map::memset_phys(pa, value, len) {
        let _ = crate::hypercall::host_memset(pa.get(), len, value);
    }
}

#[inline]
fn phys_memcpy(dst_pa: PhysAddr, src_pa: PhysAddr, len: usize) {
    if !crate::mm::linear_map::copy_phys(dst_pa, src_pa, len) {
        let _ = crate::hypercall::host_memcpy(dst_pa.get(), src_pa.get(), len);
    }
}

// ─── ProcessVmManager ────────────────────────────────────────────────────────

pub struct ProcessVmManager {
    areas: AreaSet<VmArea>,
}

impl ProcessVmManager {
    pub fn new(base: UserVa, limit: UserVa) -> Self {
        Self {
            areas: AreaSet::new(base.get(), limit.get().saturating_sub(base.get())),
        }
    }

    // ── 地址查找 ─────────────────────────────────────────────────────────────

    pub fn find_free_va(&self, hint: u64, size: u64) -> Option<u64> {
        if hint != 0 {
            let base = hint & !(PAGE_SIZE - 1);
            let ar = self.areas.range;
            if base < ar.start || base.saturating_add(size) > ar.end() {
                return None;
            }
            let gap = self.areas.find_gap(base);
            if !gap.ok() {
                return None;
            }
            let gr = gap.range();
            if gr.start <= base && gr.end() >= base + size {
                return Some(base);
            }
            return None;
        }
        let mut gap = self.areas.first_gap();
        while gap.ok() {
            let gr = gap.range();
            if gr.len >= size {
                return Some(gr.start);
            }
            gap = gap.next_gap();
        }
        None
    }

    pub fn find_seg_at(&self, addr: u64) -> AreaSeg<VmArea> {
        self.areas.find_seg(addr)
    }

    pub fn find_seg_by_base(&self, base: u64) -> AreaSeg<VmArea> {
        let seg = self.areas.find_seg(base);
        if seg.ok() && seg.range().start == base {
            seg
        } else {
            AreaSeg(AreaEntry::new_dummy(0))
        }
    }

    // ── 保留 ─────────────────────────────────────────────────────────────────

    fn reserve_at(
        &mut self,
        base: u64,
        size: u64,
        prot: u32,
        kind: VmKind,
    ) -> Option<AreaSeg<VmArea>> {
        let gap = self.areas.find_gap(base);
        if !gap.ok() {
            return None;
        }
        let gr = gap.range();
        if gr.start > base || gr.end() < base + size {
            return None;
        }
        let page_count = (size / PAGE_SIZE) as usize;
        let area = VmArea::new_reserved(base, page_count, prot, kind)?;
        let r = Range::new(base, size);
        Some(self.areas.insert_without_merging(&gap, &r, area))
    }

    pub fn find_and_reserve(
        &mut self,
        hint: u64,
        size: u64,
        prot: u32,
        kind: VmKind,
    ) -> Option<u64> {
        let base = self.find_free_va(hint, size)?;
        self.reserve_at(base, size, prot, kind)?;
        Some(base)
    }

    // ── 提交 ─────────────────────────────────────────────────────────────────

    pub fn commit_pages(
        &mut self,
        aspace: &mut ProcessAddressSpace,
        pid: u32,
        base: u64,
        size: u64,
        prot: u32,
        eager: bool,
    ) -> bool {
        let _ = pid;
        let seg = self.areas.find_seg(base);
        if !seg.ok() {
            return false;
        }
        let r = seg.range();
        if base < r.start || base.saturating_add(size) > r.end() {
            return false;
        }
        let start_idx = ((base - r.start) / PAGE_SIZE) as usize;
        let page_count = (size / PAGE_SIZE) as usize;
        let total_pages = (r.len / PAGE_SIZE) as usize;

        for i in 0..page_count {
            let idx = start_idx + i;
            let va = UserVa::new(r.start + (idx as u64) * PAGE_SIZE);
            {
                let area = seg.value_mut();
                if idx < area.prot_pages.len() {
                    area.prot_pages[idx] = prot;
                }
                area.set_page_committed(idx, true);
            }
            if eager {
                let pa = seg.value().phys_page(idx);
                if pa.is_null() {
                    if !self.map_new_page_at(aspace, &seg, idx, va, prot) {
                        for rb in start_idx..idx {
                            let rb_va = UserVa::new(r.start + (rb as u64) * PAGE_SIZE);
                            self.unmap_free_page_at(aspace, &seg, rb, rb_va);
                            seg.value_mut().set_page_committed(rb, false);
                        }
                        return false;
                    }
                } else {
                    let _ = aspace.protect_user_range(va, PAGE_SIZE, prot);
                }
            }
        }
        if start_idx == 0 && page_count == total_pages {
            seg.value_mut().default_prot = prot;
        }
        true
    }

    // ── 去提交 ───────────────────────────────────────────────────────────────

    pub fn decommit_pages(
        &mut self,
        aspace: &mut ProcessAddressSpace,
        pid: u32,
        base: u64,
        size: u64,
    ) -> bool {
        let _ = pid;
        let seg = self.areas.find_seg(base);
        if !seg.ok() {
            return false;
        }
        let r = seg.range();
        if base < r.start || base.saturating_add(size) > r.end() {
            return false;
        }
        let start_idx = ((base - r.start) / PAGE_SIZE) as usize;
        let page_count = (size / PAGE_SIZE) as usize;
        for i in 0..page_count {
            let idx = start_idx + i;
            let va = UserVa::new(r.start + (idx as u64) * PAGE_SIZE);
            self.unmap_free_page_at(aspace, &seg, idx, va);
            seg.value_mut().set_page_committed(idx, false);
        }
        true
    }

    // ── 释放 ─────────────────────────────────────────────────────────────────

    pub fn release_at_base(
        &mut self,
        aspace: &mut ProcessAddressSpace,
        pid: u32,
        base: u64,
        kind_filter: Option<VmKind>,
    ) -> bool {
        let _ = pid;
        let first_seg = self.areas.find_seg(base);
        if !first_seg.ok() || first_seg.range().start != base {
            return false;
        }
        if let Some(kf) = kind_filter {
            if first_seg.value().kind != kf {
                return false;
            }
        }
        let alloc_base = first_seg.value().alloc_base;
        if alloc_base != base {
            return false;
        }
        // 计算整个 alloc 单元的 end
        let mut end = first_seg.range().end();
        let mut cur = first_seg.next_seg();
        while cur.ok() {
            if cur.value().alloc_base != alloc_base || cur.range().start != end {
                break;
            }
            end = cur.range().end();
            cur = cur.next_seg();
        }
        let r = Range::new(base, end - base);
        self.release_range_internal(aspace, &r);
        true
    }

    pub fn release_region(
        &mut self,
        aspace: &mut ProcessAddressSpace,
        pid: u32,
        base: u64,
    ) -> bool {
        let _ = pid;
        let seg = self.areas.find_seg(base);
        if !seg.ok() || seg.range().start != base {
            return false;
        }
        let r = seg.range();
        self.release_range_internal(aspace, &r);
        true
    }

    // ── VirtualProtect ────────────────────────────────────────────────────────

    pub fn protect_range(
        &mut self,
        aspace: &mut ProcessAddressSpace,
        pid: u32,
        base: u64,
        size: u64,
        new_prot: u32,
    ) -> Result<u32, u32> {
        let _ = pid;
        let seg = self.areas.find_seg(base);
        if !seg.ok() {
            return Err(status::INVALID_PARAMETER);
        }
        let r = seg.range();
        if base < r.start || base.saturating_add(size) > r.end() {
            return Err(status::INVALID_PARAMETER);
        }
        // 隔离出 [base, base+size) 这段
        let iso_r = Range::new(base, size);
        let iso = self.areas.isolate(&seg, &iso_r);
        let page_count = (iso.range().len / PAGE_SIZE) as usize;

        // 快照旧保护（用于回滚）
        let mut old_prots: Vec<u32> = Vec::new();
        if old_prots.try_reserve(page_count).is_err() {
            return Err(status::NO_MEMORY);
        }
        for i in 0..page_count {
            let pv = iso
                .value()
                .prot_pages
                .get(i)
                .copied()
                .unwrap_or(iso.value().default_prot);
            old_prots.push(pv);
        }
        let old_first = old_prots.first().copied().unwrap_or(0);

        for i in 0..page_count {
            let va = iso.range().start + (i as u64) * PAGE_SIZE;
            if !iso.value().is_page_committed(i) {
                self.rollback_prot(aspace, &iso, 0, i, &old_prots);
                return Err(status::NOT_COMMITTED);
            }
            if old_prots[i] != new_prot {
                {
                    let area = iso.value_mut();
                    if i < area.prot_pages.len() {
                        area.prot_pages[i] = new_prot;
                    }
                }
                let pa = iso.value().phys_page(i);
                if !pa.is_null() && !aspace.protect_user_range(UserVa::new(va), PAGE_SIZE, new_prot)
                {
                    self.rollback_prot(aspace, &iso, 0, i, &old_prots);
                    return Err(status::INVALID_PARAMETER);
                }
            }
        }
        iso.value_mut().default_prot = new_prot;
        self.areas.merge_adjacent(&iso_r);
        Ok(old_first)
    }

    // ── 缺页处理 ─────────────────────────────────────────────────────────────

    pub fn handle_page_fault(
        &mut self,
        aspace: &mut ProcessAddressSpace,
        pid: u32,
        fault_va: UserVa,
        access: u8,
    ) -> bool {
        let _ = pid;
        let page_va = UserVa::new(fault_va.get() & !(PAGE_SIZE - 1));
        let seg = self.areas.find_seg(page_va.get());
        if !seg.ok() {
            return false;
        }
        let r = seg.range();
        let idx = ((page_va.get() - r.start) / PAGE_SIZE) as usize;
        if !seg.value().is_page_committed(idx) {
            return false;
        }

        let raw_prot = {
            let a = seg.value();
            vm_sanitize_nt_prot(a.prot_pages.get(idx).copied().unwrap_or(a.default_prot))
        };
        let had_guard = (raw_prot & PAGE_GUARD) != 0;
        let prot = if had_guard {
            let a = seg.value_mut();
            if idx < a.prot_pages.len() {
                a.prot_pages[idx] &= !PAGE_GUARD;
            }
            raw_prot & !PAGE_GUARD
        } else {
            raw_prot
        };

        if access == crate::mm::VM_ACCESS_WRITE && vm_is_copy_on_write_prot(prot) {
            return self.handle_cow_fault(aspace, &seg, idx, page_va, prot);
        }
        if !vm_access_allowed(prot, access) {
            return false;
        }

        let pa = seg.value().phys_page(idx);
        if !pa.is_null() {
            let mapped = aspace.map_user_range(page_va, pa, PAGE_SIZE, prot);
            if mapped && had_guard && seg.value().kind == VmKind::ThreadStack {
                self.on_thread_stack_guard_hit(aspace, pid, &seg, idx, page_va);
            }
            return mapped;
        }

        let Some(new_pa) = crate::mm::phys::alloc_pages(1) else {
            return false;
        };
        phys_memset(new_pa, 0, PAGE_SIZE as usize);
        if seg.value().kind == VmKind::Section && !vm_fill_section_page(seg.value(), idx, new_pa) {
            crate::mm::phys::free_pages(new_pa, 1);
            return false;
        }
        if !aspace.map_user_range(page_va, new_pa, PAGE_SIZE, prot) {
            crate::mm::phys::free_pages(new_pa, 1);
            return false;
        }
        shared_phys_page_add_ref(new_pa);
        {
            let a = seg.value_mut();
            a.set_phys_page(idx, new_pa);
        }
        if had_guard && seg.value().kind == VmKind::ThreadStack {
            self.on_thread_stack_guard_hit(aspace, pid, &seg, idx, page_va);
        }
        true
    }

    // ── VirtualQuery ─────────────────────────────────────────────────────────

    pub fn query(&self, addr: UserVa) -> Option<VmQueryInfo> {
        let page_addr = addr.get() & !(PAGE_SIZE - 1);
        let user_access_base = crate::process::USER_ACCESS_BASE;
        let user_va_base = crate::process::USER_VA_BASE;
        let user_va_limit = crate::process::USER_VA_LIMIT;

        if page_addr < user_access_base || page_addr >= user_va_limit {
            return None;
        }

        let seg = self.areas.find_seg(page_addr);
        if seg.ok() {
            let r = seg.range();
            let area = seg.value();
            let idx = ((page_addr - r.start) / PAGE_SIZE) as usize;
            if idx >= area.page_count() {
                return None;
            }
            let committed = area.is_page_committed(idx);
            let prot = area
                .prot_pages
                .get(idx)
                .copied()
                .unwrap_or(area.default_prot);
            let state = if committed { MEM_COMMIT } else { MEM_RESERVE };

            let mut start = idx;
            while start > 0 {
                let prev = start - 1;
                let pc = area.is_page_committed(prev);
                if pc != committed {
                    break;
                }
                if committed {
                    let pp = area
                        .prot_pages
                        .get(prev)
                        .copied()
                        .unwrap_or(area.default_prot);
                    if pp != prot {
                        break;
                    }
                }
                start = prev;
            }
            let mut end = idx + 1;
            while end < area.page_count() {
                let nc = area.is_page_committed(end);
                if nc != committed {
                    break;
                }
                if committed {
                    let np = area
                        .prot_pages
                        .get(end)
                        .copied()
                        .unwrap_or(area.default_prot);
                    if np != prot {
                        break;
                    }
                }
                end += 1;
            }
            return Some(VmQueryInfo {
                base: UserVa::new(r.start + (start as u64) * PAGE_SIZE),
                size: ((end - start) as u64) * PAGE_SIZE,
                allocation_base: UserVa::new(area.alloc_base),
                allocation_prot: area.default_prot,
                prot: if committed { prot } else { 0 },
                state,
                mem_type: vm_region_mem_type(area),
            });
        }

        // addr 在空洞中
        if page_addr < user_va_base {
            return None;
        }
        let gap = self.areas.find_gap(page_addr);
        if !gap.ok() {
            return None;
        }
        let gr = gap.range();
        if page_addr < gr.start || page_addr >= gr.end() {
            return None;
        }
        Some(VmQueryInfo {
            base: UserVa::new(gr.start),
            size: gr.len,
            allocation_base: UserVa::new(0),
            allocation_prot: 0,
            prot: 0,
            state: MEM_FREE,
            mem_type: 0,
        })
    }

    // ── 文件映射 ─────────────────────────────────────────────────────────────

    pub fn track_file_mapping(&mut self, pid: u32, base: u64, size: u64, prot: u32) -> bool {
        let prot = vm_sanitize_nt_prot(prot);
        // 已有同 base 的区域
        let existing = self.areas.find_seg(base);
        if existing.ok() && existing.range().start == base {
            let area = existing.value_mut();
            if area.page_count() == (size / PAGE_SIZE) as usize {
                area.default_prot = prot;
                for p in area.prot_pages.iter_mut() {
                    *p = prot;
                }
                return true;
            }
            return false;
        }

        let page_count = (size / PAGE_SIZE) as usize;
        let area = match VmArea::new_file_mapping(base, page_count, prot, size) {
            Some(a) => a,
            None => return false,
        };
        let gap = self.areas.find_gap(base);
        if !gap.ok() {
            return false;
        }
        let gr = gap.range();
        if gr.start > base || gr.end() < base + size {
            return false;
        }
        let r = Range::new(base, size);
        let seg = self.areas.insert_without_merging(&gap, &r, area);

        // 从当前页表翻译物理页地址，并记录页基址。
        for i in 0..page_count {
            let va = base + (i as u64) * PAGE_SIZE;
            let pa = crate::process::with_process(pid, |p| {
                p.address_space
                    .translate_user_va_for_access(UserVa::new(va), crate::mm::VM_ACCESS_READ)
            })
            .flatten()
            .map(|pa| pa.page_base(PAGE_SIZE))
            .unwrap_or_default();
            if pa.is_null() {
                let _ = self.areas.remove(&seg);
                return false;
            }
            {
                let a = seg.value_mut();
                a.set_phys_page(i, pa);
                if i < a.prot_pages.len() {
                    a.prot_pages[i] = prot;
                }
                a.set_page_committed(i, true);
            }
        }
        true
    }

    pub fn collect_file_mappings(&self) -> Vec<(u64, u64, u32)> {
        let mut out = Vec::new();
        let mut seg = self.areas.first_seg();
        while seg.ok() {
            if !seg.value().owns_phys_pages {
                let r = seg.range();
                let prot = seg.value().default_prot;
                let _ = out.try_reserve(1);
                out.push((r.start, r.len, prot));
            }
            seg = seg.next_seg();
        }
        out
    }

    pub(crate) fn collect_tracked_areas(&self) -> Vec<crate::mm::clone_plan::TrackedAreaSnapshot> {
        let mut out = Vec::new();
        let mut seg = self.areas.first_seg();
        while seg.ok() {
            let _ = out.try_reserve(1);
            out.push(crate::mm::clone_plan::TrackedAreaSnapshot {
                range: seg.range(),
                area: seg.value().clone(),
            });
            seg = seg.next_seg();
        }
        out
    }

    pub(crate) fn install_tracked_areas(
        &mut self,
        areas: &[crate::mm::clone_plan::TrackedAreaSnapshot],
    ) -> bool {
        if !self.areas.is_empty() {
            return false;
        }
        for snapshot in areas {
            let gap = self.areas.find_gap(snapshot.range.start);
            if !gap.ok() {
                return false;
            }
            let gap_range = gap.range();
            if gap_range.start > snapshot.range.start || gap_range.end() < snapshot.range.end() {
                return false;
            }
            let area = snapshot.area.clone();
            if area.owns_phys_pages {
                for pa in area.phys_pages.iter().copied() {
                    if !pa.is_null() {
                        shared_phys_page_add_ref(pa);
                    }
                }
            }
            let _ = self
                .areas
                .insert_without_merging(&gap, &snapshot.range, area);
        }
        true
    }

    // ── Section 元信息 ────────────────────────────────────────────────────────

    pub fn set_section_backing(
        &mut self,
        base: u64,
        file_fd: Option<u64>,
        file_offset: u64,
        view_size: u64,
        is_image: bool,
    ) -> bool {
        let seg = self.areas.find_seg(base);
        if !seg.ok() || seg.range().start != base {
            return false;
        }
        if seg.value().kind != VmKind::Section {
            return false;
        }
        let area = seg.value_mut();
        area.section_file_backed = file_fd.is_some();
        area.section_file_fd = file_fd.unwrap_or(0);
        area.section_file_offset = file_offset;
        area.section_view_size = view_size.min(area.page_count() as u64 * PAGE_SIZE);
        area.section_is_image = is_image;
        true
    }

    // ── 整区保护 ─────────────────────────────────────────────────────────────

    pub fn set_region_prot_all(
        &mut self,
        aspace: &mut ProcessAddressSpace,
        pid: u32,
        base: u64,
        prot: u32,
    ) -> bool {
        let _ = pid;
        let seg = self.areas.find_seg(base);
        if !seg.ok() || seg.range().start != base {
            return false;
        }
        let r = seg.range();
        let prot = vm_sanitize_nt_prot(prot);
        {
            let area = seg.value_mut();
            area.default_prot = prot;
            for p in area.prot_pages.iter_mut() {
                *p = prot;
            }
        }
        let page_count = (r.len / PAGE_SIZE) as usize;
        for i in 0..page_count {
            let pa = seg.value().phys_page(i);
            if !pa.is_null() {
                let va = UserVa::new(r.start + (i as u64) * PAGE_SIZE);
                if !aspace.protect_user_range(va, PAGE_SIZE, prot) {
                    return false;
                }
            }
        }
        true
    }

    // ── Guard 页 ─────────────────────────────────────────────────────────────

    pub fn make_guard_page(
        &mut self,
        aspace: &mut ProcessAddressSpace,
        pid: u32,
        page_va: u64,
    ) -> bool {
        let _ = pid;
        let page_va = UserVa::new(page_va & !(PAGE_SIZE - 1));
        let seg = self.areas.find_seg(page_va.get());
        if !seg.ok() {
            return false;
        }
        let r = seg.range();
        let idx = ((page_va.get() - r.start) / PAGE_SIZE) as usize;
        if !seg.value().is_page_committed(idx) {
            return false;
        }
        let _ = aspace.unmap_user_range(page_va, PAGE_SIZE);
        let area = seg.value_mut();
        if idx < area.prot_pages.len() {
            let base_prot = vm_sanitize_nt_prot(area.prot_pages[idx]) & !PAGE_GUARD;
            area.prot_pages[idx] = base_prot | PAGE_GUARD;
        }
        true
    }

    // ── 清理 ─────────────────────────────────────────────────────────────────

    pub fn cleanup_all(&mut self, aspace: &mut ProcessAddressSpace) {
        let r = self.areas.range;
        self.release_range_internal(aspace, &r);
    }

    // ─── 内部辅助 ────────────────────────────────────────────────────────────

    fn release_range_internal(&mut self, aspace: &mut ProcessAddressSpace, r: &Range) {
        let (seg, mut gap) = self.areas.find(r.start);
        if seg.ok() {
            let iso = self.areas.isolate(&seg, r);
            self.free_seg_pages(aspace, &iso);
            gap = self.areas.remove(&iso);
        }
        let mut next = gap.next_seg();
        while next.ok() && next.range().start < r.end() {
            let iso = self.areas.isolate(&next, r);
            self.free_seg_pages(aspace, &iso);
            gap = self.areas.remove(&iso);
            next = gap.next_seg();
        }
    }

    fn free_seg_pages(&self, aspace: &mut ProcessAddressSpace, seg: &AreaSeg<VmArea>) {
        let r = seg.range();
        let owns = seg.value().owns_phys_pages;
        let page_count = seg.value().page_count();
        for i in 0..page_count {
            let va = UserVa::new(r.start + (i as u64) * PAGE_SIZE);
            let pa = seg.value().phys_page(i);
            if !pa.is_null() {
                let _ = aspace.unmap_user_range(va, PAGE_SIZE);
                if owns {
                    shared_phys_page_release(pa);
                }
            }
        }
    }

    fn map_new_page_at(
        &self,
        aspace: &mut ProcessAddressSpace,
        seg: &AreaSeg<VmArea>,
        idx: usize,
        va: UserVa,
        prot: u32,
    ) -> bool {
        let Some(pa) = crate::mm::phys::alloc_pages(1) else {
            return false;
        };
        phys_memset(pa, 0, PAGE_SIZE as usize);
        if seg.value().kind == VmKind::Section && !vm_fill_section_page(seg.value(), idx, pa) {
            crate::mm::phys::free_pages(pa, 1);
            return false;
        }
        if !aspace.map_user_range(va, pa, PAGE_SIZE, prot) {
            crate::mm::phys::free_pages(pa, 1);
            return false;
        }
        shared_phys_page_add_ref(pa);
        let area = seg.value_mut();
        area.set_phys_page(idx, pa);
        true
    }

    fn unmap_free_page_at(
        &self,
        aspace: &mut ProcessAddressSpace,
        seg: &AreaSeg<VmArea>,
        idx: usize,
        va: UserVa,
    ) {
        let pa = seg.value().phys_page(idx);
        if pa.is_null() {
            return;
        }
        let _ = aspace.unmap_user_range(va, PAGE_SIZE);
        if seg.value().owns_phys_pages {
            shared_phys_page_release(pa);
        }
        let area = seg.value_mut();
        area.set_phys_page(idx, PhysAddr::default());
    }

    fn rollback_prot(
        &self,
        aspace: &mut ProcessAddressSpace,
        seg: &AreaSeg<VmArea>,
        start: usize,
        end: usize,
        old_prots: &[u32],
    ) {
        let r = seg.range();
        for i in start..=end {
            if i >= old_prots.len() {
                break;
            }
            {
                let area = seg.value_mut();
                if i < area.prot_pages.len() {
                    area.prot_pages[i] = old_prots[i];
                }
            }
            let pa = seg.value().phys_page(i);
            if !pa.is_null() {
                let va = UserVa::new(r.start + (i as u64) * PAGE_SIZE);
                let _ = aspace.protect_user_range(va, PAGE_SIZE, old_prots[i]);
            }
        }
    }

    fn handle_cow_fault(
        &mut self,
        aspace: &mut ProcessAddressSpace,
        seg: &AreaSeg<VmArea>,
        idx: usize,
        page_va: UserVa,
        prot: u32,
    ) -> bool {
        let old_pa = seg.value().phys_page(idx);
        let Some(new_pa) = crate::mm::phys::alloc_pages(1) else {
            return false;
        };
        if !old_pa.is_null() {
            phys_memcpy(new_pa, old_pa, PAGE_SIZE as usize);
        } else {
            phys_memset(new_pa, 0, PAGE_SIZE as usize);
            if seg.value().kind == VmKind::Section
                && !vm_fill_section_page(seg.value(), idx, new_pa)
            {
                crate::mm::phys::free_pages(new_pa, 1);
                return false;
            }
        }
        let promoted = vm_promote_cow_prot(prot);
        if !aspace.map_user_range(page_va, new_pa, PAGE_SIZE, promoted) {
            crate::mm::phys::free_pages(new_pa, 1);
            return false;
        }
        shared_phys_page_add_ref(new_pa);
        if !old_pa.is_null() {
            shared_phys_page_release(old_pa);
        }
        {
            let a = seg.value_mut();
            a.set_phys_page(idx, new_pa);
            if idx < a.prot_pages.len() {
                a.prot_pages[idx] = promoted;
            }
        }
        true
    }

    fn on_thread_stack_guard_hit(
        &mut self,
        aspace: &mut ProcessAddressSpace,
        pid: u32,
        seg: &AreaSeg<VmArea>,
        idx: usize,
        page_va: UserVa,
    ) {
        crate::process::update_current_thread_stack_limit(pid, page_va.get());
        if idx == 0 {
            return;
        }
        let next_idx = idx - 1;
        if !seg.value().is_page_committed(next_idx) {
            return;
        }
        let next_va = UserVa::new(seg.range().start + (next_idx as u64) * PAGE_SIZE);
        let next_prot = {
            let a = seg.value();
            let p = a
                .prot_pages
                .get(next_idx)
                .copied()
                .unwrap_or(a.default_prot);
            vm_sanitize_nt_prot(p) & !PAGE_GUARD
        };
        {
            let a = seg.value_mut();
            if next_idx < a.prot_pages.len() {
                a.prot_pages[next_idx] = next_prot | PAGE_GUARD;
            }
        }
        let _ = aspace.unmap_user_range(next_va, PAGE_SIZE);
    }
}
