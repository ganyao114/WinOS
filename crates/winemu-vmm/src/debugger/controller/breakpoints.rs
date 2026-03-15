use super::formatting::{format_breakpoint_key, hex_sample};
use super::DebugController;
use crate::debugger::breakpoint::{
    is_software_breakpoint_encoding, validate_software_breakpoint_kind, BreakpointKey,
    SoftwareBreakpoint, AARCH64_BRK_0, ESR_EC_BRK64, SOFTWARE_BREAKPOINT_KIND,
};
use crate::debugger::translate;
use crate::debugger::types::StopReason;
use winemu_core::{Result, WinemuError};

impl DebugController {
    pub fn insert_software_breakpoint(
        &self,
        preferred_vcpu_id: Option<u32>,
        addr: u64,
        kind: usize,
    ) -> Result<()> {
        self.require_paused()?;
        validate_software_breakpoint_kind(kind)?;
        let (vcpu_id, key) = self.resolve_breakpoint_anchor(preferred_vcpu_id, addr)?;
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(bp) = inner.breakpoints.get_mut(&key) {
                if bp.kind != kind {
                    return Err(WinemuError::Memory(format!(
                        "software breakpoint kind mismatch at {}: existing={} requested={}",
                        format_breakpoint_key(key),
                        bp.kind,
                        kind
                    )));
                }
                bp.refs += 1;
                return Ok(());
            }
        }

        let original = self.read_guest_virt_in_space(key.space, addr, SOFTWARE_BREAKPOINT_KIND)?;
        if is_software_breakpoint_encoding(&original) {
            return Err(WinemuError::Memory(format!(
                "refusing to install software breakpoint over existing BRK at {}",
                format_breakpoint_key(key)
            )));
        }
        self.write_guest_virt_in_space(key.space, addr, &AARCH64_BRK_0)?;

        let mut original_raw = [0u8; SOFTWARE_BREAKPOINT_KIND];
        original_raw.copy_from_slice(&original);
        self.inner.lock().unwrap().breakpoints.insert(
            key,
            SoftwareBreakpoint {
                key,
                kind,
                original: original_raw,
                refs: 1,
            },
        );
        log::debug!(
            "debugger: installed software breakpoint vcpu={} {} original={}",
            vcpu_id,
            format_breakpoint_key(key),
            hex_sample(&original_raw)
        );
        Ok(())
    }

    pub fn remove_software_breakpoint(
        &self,
        preferred_vcpu_id: Option<u32>,
        addr: u64,
        kind: usize,
    ) -> Result<()> {
        self.require_paused()?;
        validate_software_breakpoint_kind(kind)?;
        let (vcpu_id, key) = self.resolve_breakpoint_anchor(preferred_vcpu_id, addr)?;

        let original = {
            let mut inner = self.inner.lock().unwrap();
            let Some(bp) = inner.breakpoints.get_mut(&key) else {
                return Err(WinemuError::Memory(format!(
                    "software breakpoint not found at {}",
                    format_breakpoint_key(key)
                )));
            };
            if bp.kind != kind {
                return Err(WinemuError::Memory(format!(
                    "software breakpoint kind mismatch at {}: existing={} requested={}",
                    format_breakpoint_key(key),
                    bp.kind,
                    kind
                )));
            }
            if bp.refs > 1 {
                bp.refs -= 1;
                return Ok(());
            }
            let original = bp.original;
            inner.breakpoints.remove(&key);
            original
        };

        self.write_guest_virt_in_space(key.space, addr, &original)?;
        log::debug!(
            "debugger: removed software breakpoint vcpu={} {}",
            vcpu_id,
            format_breakpoint_key(key)
        );
        Ok(())
    }

    pub fn paused_software_breakpoint_key(&self, vcpu_id: u32) -> Option<BreakpointKey> {
        let snapshot = {
            let inner = self.inner.lock().unwrap();
            inner.snapshots.get(vcpu_id as usize)?.as_ref()?.clone()
        };
        let StopReason::DebugException { syndrome, .. } = snapshot.reason else {
            return None;
        };
        let ec = (syndrome >> 26) & 0x3f;
        if ec != ESR_EC_BRK64 {
            return None;
        }
        let pc = snapshot.regs.pc;
        let space = translate::translation_space_for_va(&snapshot, pc).ok()?;
        let key = BreakpointKey { space, addr: pc };
        if self.breakpoint_exists(key) {
            return Some(key);
        }
        let gpa = translate::translate_va_in_space(&self.memory, space, pc).ok()?;
        self.find_breakpoint_alias_key(pc, gpa, &[key])
    }

    pub fn temporarily_disable_software_breakpoint(
        &self,
        vcpu_id: u32,
        key: BreakpointKey,
    ) -> Result<()> {
        let original = {
            let inner = self.inner.lock().unwrap();
            let Some(bp) = inner.breakpoints.get(&key) else {
                return Err(WinemuError::Memory(format!(
                    "software breakpoint not found at {}",
                    format_breakpoint_key(key)
                )));
            };
            bp.original
        };
        self.write_guest_virt_in_space(key.space, key.addr, &original)?;
        log::debug!(
            "debugger: temporarily disabled software breakpoint vcpu={} {}",
            vcpu_id,
            format_breakpoint_key(key)
        );
        Ok(())
    }

    pub fn reenable_software_breakpoint(&self, vcpu_id: u32, key: BreakpointKey) -> Result<()> {
        {
            let inner = self.inner.lock().unwrap();
            if !inner.breakpoints.contains_key(&key) {
                return Err(WinemuError::Memory(format!(
                    "software breakpoint not found at {}",
                    format_breakpoint_key(key)
                )));
            }
        }
        self.write_guest_virt_in_space(key.space, key.addr, &AARCH64_BRK_0)?;
        log::debug!(
            "debugger: re-enabled software breakpoint vcpu={} {}",
            vcpu_id,
            format_breakpoint_key(key)
        );
        Ok(())
    }

    fn resolve_breakpoint_anchor(
        &self,
        preferred_vcpu_id: Option<u32>,
        addr: u64,
    ) -> Result<(u32, BreakpointKey)> {
        let (vcpu_id, space) = self.resolve_virtual_access_space(preferred_vcpu_id, addr)?;
        let key = BreakpointKey { space, addr };
        let gpa = translate::translate_va_in_space(&self.memory, space, addr)?;
        if self.breakpoint_exists(key) {
            return Ok((vcpu_id, key));
        }
        if let Some(alias_key) = self.find_breakpoint_alias_key(addr, gpa, &[key]) {
            return Ok((vcpu_id, alias_key));
        }
        Ok((vcpu_id, key))
    }

    fn breakpoint_exists(&self, key: BreakpointKey) -> bool {
        self.inner.lock().unwrap().breakpoints.contains_key(&key)
    }

    fn find_breakpoint_alias_key(
        &self,
        addr: u64,
        gpa: u64,
        skip_keys: &[BreakpointKey],
    ) -> Option<BreakpointKey> {
        let candidate_keys = {
            let inner = self.inner.lock().unwrap();
            inner
                .breakpoints
                .values()
                .map(|bp| bp.key)
                .filter(|key| key.addr == addr && !skip_keys.contains(key))
                .collect::<Vec<_>>()
        };
        for key in candidate_keys {
            let existing_gpa =
                match translate::translate_va_in_space(&self.memory, key.space, key.addr) {
                    Ok(gpa) => gpa,
                    Err(_) => continue,
                };
            if existing_gpa == gpa {
                return Some(key);
            }
        }
        None
    }
}
