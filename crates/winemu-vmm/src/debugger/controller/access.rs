use super::formatting::{format_translation_space, hex_sample};
use super::DebugController;
use crate::debugger::translate;
use crate::debugger::translate::TranslationSpace;
use crate::debugger::types::VcpuSnapshot;
use winemu_core::{Result, WinemuError};

impl DebugController {
    pub fn read_guest_phys(&self, gpa: u64, len: usize) -> Result<Vec<u8>> {
        self.require_paused()?;
        self.memory.read_phys(gpa, len)
    }

    pub fn read_guest_virt(&self, vcpu_id: u32, va: u64, len: usize) -> Result<Vec<u8>> {
        self.require_paused()?;
        let snapshot = self.snapshot(vcpu_id).ok_or_else(|| {
            WinemuError::Memory(format!("no paused snapshot for vcpu {}", vcpu_id))
        })?;
        let space = translate::translation_space_for_va(&snapshot, va)?;
        self.read_guest_virt_in_space(space, va, len)
    }

    pub fn write_guest_virt(&self, vcpu_id: u32, va: u64, bytes: &[u8]) -> Result<()> {
        self.require_paused()?;
        let snapshot = self.snapshot(vcpu_id).ok_or_else(|| {
            WinemuError::Memory(format!("no paused snapshot for vcpu {}", vcpu_id))
        })?;
        let space = translate::translation_space_for_va(&snapshot, va)?;
        self.write_guest_virt_in_space(space, va, bytes)
    }

    pub fn read_guest_virt_resolved(
        &self,
        preferred_vcpu_id: Option<u32>,
        va: u64,
        len: usize,
    ) -> Result<Vec<u8>> {
        let (_, space) = self.resolve_virtual_access_space(preferred_vcpu_id, va)?;
        self.read_guest_virt_in_space(space, va, len)
    }

    pub fn write_guest_virt_resolved(
        &self,
        preferred_vcpu_id: Option<u32>,
        va: u64,
        bytes: &[u8],
    ) -> Result<()> {
        let (_, space) = self.resolve_virtual_access_space(preferred_vcpu_id, va)?;
        self.write_guest_virt_in_space(space, va, bytes)
    }

    pub(super) fn candidate_paused_vcpus(&self, preferred_vcpu_id: Option<u32>) -> Vec<u32> {
        let mut candidates = Vec::new();
        let mut push_unique = |vcpu_id: u32| {
            if !candidates.contains(&vcpu_id) {
                candidates.push(vcpu_id);
            }
        };
        if let Some(vcpu_id) = preferred_vcpu_id {
            push_unique(vcpu_id);
        }
        if let Some(vcpu_id) = self.stop_vcpu_id() {
            push_unique(vcpu_id);
        }
        if let Some(vcpu_id) = self.primary_paused_vcpu() {
            push_unique(vcpu_id);
        }
        let inner = self.inner.lock().unwrap();
        for (idx, snapshot) in inner.snapshots.iter().enumerate() {
            if snapshot.is_some() {
                push_unique(idx as u32);
            }
        }
        candidates
    }

    pub(super) fn resolve_virtual_access_space(
        &self,
        preferred_vcpu_id: Option<u32>,
        va: u64,
    ) -> Result<(u32, TranslationSpace)> {
        self.require_paused()?;

        let mut first_err = None;
        for vcpu_id in self.candidate_paused_vcpus(preferred_vcpu_id) {
            let snapshot = match self.snapshot(vcpu_id) {
                Some(snapshot) => snapshot,
                None => continue,
            };
            match translate::translation_space_for_va(&snapshot, va) {
                Ok(space) => match translate::translate_va_in_space(&self.memory, space, va) {
                    Ok(_) => return Ok((vcpu_id, space)),
                    Err(err) if first_err.is_none() => first_err = Some(err),
                    Err(_) => {}
                },
                Err(err) if first_err.is_none() => first_err = Some(err),
                Err(_) => {}
            }
        }

        Err(first_err.unwrap_or_else(|| {
            WinemuError::Memory(format!(
                "no paused vcpu can resolve virtual address {:#x}",
                va
            ))
        }))
    }

    pub(super) fn read_guest_virt_in_space(
        &self,
        space: TranslationSpace,
        va: u64,
        len: usize,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        let mut offset = 0usize;
        while offset < len {
            let cur_va = va.checked_add(offset as u64).ok_or_else(|| {
                WinemuError::Memory(format!("virtual address overflow at {:#x}", va))
            })?;
            let gpa = translate::translate_va_in_space(&self.memory, space, cur_va)?;
            let page_remaining = (0x1000 - ((cur_va as usize) & 0xfff)).min(len - offset);
            let chunk = self.memory.read_phys(gpa, page_remaining)?;
            out.extend_from_slice(&chunk);
            offset += page_remaining;
        }
        Ok(out)
    }

    pub(super) fn write_guest_virt_in_space(
        &self,
        space: TranslationSpace,
        va: u64,
        bytes: &[u8],
    ) -> Result<()> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let cur_va = va.checked_add(offset as u64).ok_or_else(|| {
                WinemuError::Memory(format!("virtual address overflow at {:#x}", va))
            })?;
            let trace = translate::translate_va_in_space_trace(&self.memory, space, cur_va)?;
            let page_remaining = (0x1000 - ((cur_va as usize) & 0xfff)).min(bytes.len() - offset);
            let chunk = &bytes[offset..offset + page_remaining];
            let before = self.memory.read_phys(trace.gpa, page_remaining)?;
            self.memory.write_phys(trace.gpa, chunk)?;
            let after = self.memory.read_phys(trace.gpa, page_remaining)?;
            log::debug!(
                "debugger: write_guest_virt space={} va={:#x} -> gpa={:#x} len={} before={} after={} requested={} l0e={:#x} l1e={:#x} l2e={:#x} l3e={:#x}",
                format_translation_space(space),
                cur_va,
                trace.gpa,
                page_remaining,
                hex_sample(&before),
                hex_sample(&after),
                hex_sample(chunk),
                trace.l0e,
                trace.l1e,
                trace.l2e,
                trace.l3e
            );
            offset += page_remaining;
        }
        Ok(())
    }

    pub(super) fn with_snapshot_mut<T>(
        &self,
        vcpu_id: u32,
        update: impl FnOnce(&mut VcpuSnapshot) -> Result<T>,
    ) -> Result<T> {
        self.require_paused()?;
        let mut inner = self.inner.lock().unwrap();
        let snapshot = inner
            .snapshots
            .get_mut(vcpu_id as usize)
            .and_then(Option::as_mut)
            .ok_or_else(|| {
                WinemuError::Memory(format!("no paused snapshot for vcpu {}", vcpu_id))
            })?;
        update(snapshot)
    }

    pub(super) fn require_paused(&self) -> Result<()> {
        if self.state() != crate::debugger::types::DebugState::Paused {
            return Err(WinemuError::Memory("debugger is not paused".to_string()));
        }
        Ok(())
    }
}
