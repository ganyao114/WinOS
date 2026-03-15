mod breakpoint;
mod controller;
mod gdb_remote;
mod memory;
mod server;
mod symbol;
mod translate;
mod types;

pub use controller::{DebugController, RunOutcome, WaitOutcome};
pub use server::server_addr_from_env;
pub use types::{DebugState, StopReason, VcpuSnapshot};

pub fn spawn_server(controller: std::sync::Arc<DebugController>, addr: String) {
    if std::env::var("WINEMU_GUEST_DEBUG_PROTOCOL").ok().as_deref() == Some("gdb") {
        gdb_remote::spawn_server(controller, addr);
    } else {
        server::spawn_server(controller, addr);
    }
}
