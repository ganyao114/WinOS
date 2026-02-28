#[cfg(target_arch = "aarch64")]
#[path = "aarch64/mod.rs"]
mod backend;

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
mod backend;

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("unsupported target_arch: add backend wiring in src/arch/mod.rs");

// Arch capability surface exposed to the rest of the kernel.
// Each backend must provide modules: cpu/hypercall/mmu/spin/timer/vectors.
pub mod cpu;
pub mod hypercall;
pub mod mmu;
pub mod spin;
pub mod timer;
pub mod vectors;
