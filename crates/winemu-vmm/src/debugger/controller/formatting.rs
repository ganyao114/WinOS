use super::DebugController;
use crate::debugger::translate::{TranslationRoot, TranslationSpace};
use crate::debugger::types::VcpuSnapshot;

impl DebugController {
    pub fn format_symbol(&self, addr: u64) -> String {
        let Some(symbolizer) = self.symbolizer.as_ref() else {
            return "error: kernel symbolizer not loaded\n".to_string();
        };
        let Some(symbol) = symbolizer.lookup(addr) else {
            return format!(
                "{:#018x}: <unknown> (symbols from {})\n",
                addr,
                symbolizer.path().display()
            );
        };
        format!(
            "{:#018x}: {} + {:#x} (base {:#018x}, symbols from {})\n",
            addr,
            symbol.symbol,
            symbol.offset,
            symbol.symbol_addr,
            symbolizer.path().display()
        )
    }

    pub fn format_backtrace(&self, vcpu_id: u32) -> String {
        if let Err(err) = self.require_paused() {
            return format!("error: {}\n", err);
        }
        let Some(snapshot) = self.snapshot(vcpu_id) else {
            return format!("error: no paused snapshot for vcpu {}\n", vcpu_id);
        };
        let Some(frames) = self.collect_backtrace_frames(vcpu_id, &snapshot) else {
            return "error: backtrace is only implemented for aarch64 snapshots\n".to_string();
        };

        let mut out = String::new();
        for (index, addr, label) in frames {
            out.push_str(&format!("#{} {:<4} {:#018x}", index, label, addr));
            if let Some(symbolizer) = self.symbolizer.as_ref() {
                if let Some(symbol) = symbolizer.lookup(addr) {
                    out.push_str(&format!(" {}+{:#x}", symbol.symbol, symbol.offset));
                }
            }
            out.push('\n');
        }
        out
    }

    pub fn format_status(&self) -> String {
        let inner = self.inner.lock().unwrap();
        let registered = inner.registered.iter().filter(|slot| **slot).count();
        let paused = if inner.state == crate::debugger::types::DebugState::Running {
            0
        } else {
            inner
                .registered
                .iter()
                .enumerate()
                .filter(|(idx, registered)| {
                    **registered && inner.acked_epoch[*idx] == inner.pause_epoch
                })
                .count()
        };
        format!(
            "state={:?} pause_epoch={} registered={} paused={} resume_mode={:?} reason={:?} stop_vcpu={:?}\n",
            inner.state,
            inner.pause_epoch,
            registered,
            paused,
            inner.resume_mode,
            inner.stop_reason,
            inner.stop_vcpu_id
        )
    }

    fn collect_backtrace_frames(
        &self,
        vcpu_id: u32,
        snapshot: &VcpuSnapshot,
    ) -> Option<Vec<(usize, u64, &'static str)>> {
        #[cfg(target_arch = "aarch64")]
        {
            let mut frames = Vec::new();
            frames.push((0, snapshot.regs.pc, "pc"));
            if snapshot.regs.x[30] != 0 {
                frames.push((1, snapshot.regs.x[30], "lr"));
            }

            let mut fp = snapshot.regs.x[29];
            let mut frame_index = frames.len();
            for _ in 0..16 {
                if fp == 0 {
                    break;
                }
                let raw = match self.read_guest_virt(vcpu_id, fp, 16) {
                    Ok(raw) if raw.len() == 16 => raw,
                    _ => break,
                };
                let mut prev_fp_raw = [0u8; 8];
                let mut ret_raw = [0u8; 8];
                prev_fp_raw.copy_from_slice(&raw[..8]);
                ret_raw.copy_from_slice(&raw[8..16]);
                let prev_fp = u64::from_le_bytes(prev_fp_raw);
                let ret = u64::from_le_bytes(ret_raw);
                if ret == 0 || prev_fp <= fp {
                    break;
                }
                frames.push((frame_index, ret, "fp"));
                frame_index += 1;
                fp = prev_fp;
            }
            Some(frames)
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = vcpu_id;
            let _ = snapshot;
            None
        }
    }
}

pub(super) fn format_breakpoint_key(key: crate::debugger::breakpoint::BreakpointKey) -> String {
    format!("{} va={:#x}", format_translation_space(key.space), key.addr)
}

pub(super) fn format_translation_space(space: TranslationSpace) -> String {
    format!(
        "{} root_base={:#x}",
        translation_root_name(space.root),
        space.root_base
    )
}

fn translation_root_name(root: TranslationRoot) -> &'static str {
    match root {
        TranslationRoot::Ttbr0 => "ttbr0",
        TranslationRoot::Ttbr1 => "ttbr1",
    }
}

pub(super) fn hex_sample(bytes: &[u8]) -> String {
    const LIMIT: usize = 16;
    let mut out = String::new();
    for (index, byte) in bytes.iter().take(LIMIT).enumerate() {
        if index != 0 {
            out.push(' ');
        }
        use std::fmt::Write as _;
        let _ = write!(out, "{:02x}", byte);
    }
    if bytes.len() > LIMIT {
        out.push_str(" ...");
    }
    out
}
