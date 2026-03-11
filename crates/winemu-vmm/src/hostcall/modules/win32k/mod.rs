// win32k_module.rs — HandlerModule impl for OP_WIN32K_CALL

pub mod state;
pub use state::Win32kState;

use super::super::handlers::HandlerCtx;
use super::super::registry::{HandlerModule, OpcodeEntry};
use super::super::types::WorkerPayload;
use winemu_shared::hostcall as hc;

fn h_win32k_call(ctx: &HandlerCtx<'_>, args: [u64; 4], _: Option<&WorkerPayload>) -> (u64, u64) {
    super::super::handlers::execute_win32k_call(ctx, args)
}

fn no_async(_args: [u64; 4]) -> bool {
    false
}

static ENTRIES: &[OpcodeEntry] = &[OpcodeEntry {
    opcode: hc::OP_WIN32K_CALL,
    handler: h_win32k_call,
    async_eligible: no_async,
    prepare_payload: None,
    requires_main_thread: true,
}];

pub struct Win32kModule;

impl HandlerModule for Win32kModule {
    fn opcodes(&self) -> &[OpcodeEntry] {
        ENTRIES
    }
}
