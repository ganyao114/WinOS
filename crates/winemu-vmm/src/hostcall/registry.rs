// registry.rs — HandlerModule trait + opcode registry
//
// Each subsystem (file I/O, win32k, …) implements HandlerModule and registers
// itself into HandlerRegistry.  broker.rs calls registry.dispatch() instead of
// a hardcoded match.

use super::handlers::HandlerCtx;
use super::types::WorkerPayload;

// ── Per-opcode descriptor ─────────────────────────────────────────────────────

/// A single opcode entry registered by a module.
pub struct OpcodeEntry {
    pub opcode: u64,

    /// Synchronous handler.  `payload` is Some only when the job was queued
    /// async and a payload was pre-captured (Path / Bytes).
    pub handler:
        fn(ctx: &HandlerCtx<'_>, args: [u64; 4], payload: Option<&WorkerPayload>) -> (u64, u64),

    /// Returns true when this opcode may be executed asynchronously.
    /// `args` are the raw submit args so the decision can be size-dependent.
    pub async_eligible: fn(args: [u64; 4]) -> bool,

    /// Optional: pre-capture a payload from guest memory before the job is
    /// handed to a worker thread.  None means WorkerPayload::None is used.
    pub prepare_payload: Option<
        fn(
            memory: &std::sync::Arc<std::sync::RwLock<crate::memory::GuestMemory>>,
            args: [u64; 4],
        ) -> Result<WorkerPayload, (u64, u64)>,
    >,

    /// True when this opcode must run on the main thread (FLAG_MAIN_THREAD
    /// semantics are still honoured by the caller, but some opcodes always
    /// require it regardless of flags).
    pub requires_main_thread: bool,
}

// ── HandlerModule trait ───────────────────────────────────────────────────────

pub trait HandlerModule: Send + Sync {
    fn opcodes(&self) -> &[OpcodeEntry];
}

// ── Registry ──────────────────────────────────────────────────────────────────

pub struct HandlerRegistry {
    /// Flat list of all registered entries, sorted by opcode for binary search.
    entries: Vec<OpcodeEntry>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register all opcodes from a module.  Panics on duplicate opcode.
    pub fn register(&mut self, module: &dyn HandlerModule) {
        for entry in module.opcodes() {
            assert!(
                !self.entries.iter().any(|e| e.opcode == entry.opcode),
                "duplicate opcode {:#x} registered",
                entry.opcode
            );
        }
        // We can't move out of a shared ref, so we copy the fn pointers.
        for e in module.opcodes() {
            self.entries.push(OpcodeEntry {
                opcode: e.opcode,
                handler: e.handler,
                async_eligible: e.async_eligible,
                prepare_payload: e.prepare_payload,
                requires_main_thread: e.requires_main_thread,
            });
        }
        self.entries.sort_unstable_by_key(|e| e.opcode);
    }

    pub fn is_supported(&self, opcode: u64) -> bool {
        self.find(opcode).is_some()
    }

    pub fn async_eligible(&self, opcode: u64, args: [u64; 4]) -> bool {
        self.find(opcode)
            .map(|e| (e.async_eligible)(args))
            .unwrap_or(false)
    }

    pub fn requires_main_thread(&self, opcode: u64) -> bool {
        self.find(opcode)
            .map(|e| e.requires_main_thread)
            .unwrap_or(false)
    }

    pub fn prepare_payload(
        &self,
        opcode: u64,
        memory: &std::sync::Arc<std::sync::RwLock<crate::memory::GuestMemory>>,
        args: [u64; 4],
    ) -> Result<WorkerPayload, (u64, u64)> {
        match self.find(opcode).and_then(|e| e.prepare_payload) {
            Some(f) => f(memory, args),
            None => Ok(WorkerPayload::None),
        }
    }

    pub fn dispatch(
        &self,
        ctx: &HandlerCtx<'_>,
        opcode: u64,
        args: [u64; 4],
        payload: Option<&WorkerPayload>,
    ) -> Option<(u64, u64)> {
        self.find(opcode).map(|e| (e.handler)(ctx, args, payload))
    }

    fn find(&self, opcode: u64) -> Option<&OpcodeEntry> {
        self.entries
            .binary_search_by_key(&opcode, |e| e.opcode)
            .ok()
            .map(|i| &self.entries[i])
    }
}
