pub mod debugger;
pub mod file_io;
pub mod gpa_alloc;
pub mod host_file;
pub mod hostcall;
pub mod hypercall;
pub mod memory;
pub mod sched;
pub mod section;
pub mod vaspace;
pub mod vcpu;

use hypercall::HypercallManager;
use memory::GuestMemory;
use sched::Scheduler;
use std::sync::{mpsc, Arc, RwLock};
use winemu_core::{addr::Gpa, mem::MemProt, Result, WinemuError};
use winemu_hypervisor::{Hypervisor, Regs, Vm, VmConfig};

#[cfg(target_arch = "aarch64")]
const KERNEL_ENTRY_PC: u64 = 0x4000_0000;
const GUEST_BASE_GPA: u64 = 0x4000_0000;
const DEFAULT_GUEST_MEMORY_MB: usize = 1024;
const MIN_GUEST_MEMORY_MB: usize = 256;
const MAX_GUEST_MEMORY_MB: usize = 16 * 1024;

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|v| *v > 0)
}

#[inline(always)]
fn set_kernel_boot_entry_pc(regs: &mut Regs) {
    #[cfg(target_arch = "aarch64")]
    {
        regs.pc = KERNEL_ENTRY_PC;
    }
}

pub struct Vmm {
    #[allow(dead_code)]
    hypervisor: Box<dyn Hypervisor>, // must outlive vm to prevent premature hv_vm_destroy
    vm: Arc<dyn Vm>,
    #[allow(dead_code)]
    memory: Arc<RwLock<GuestMemory>>,
    hypercall_mgr: Arc<HypercallManager>,
    sched: Arc<Scheduler>,
    debugger: Option<Arc<debugger::DebugController>>,
    vcpu_count: u32,
}

impl Vmm {
    pub fn new(
        hypervisor: Box<dyn Hypervisor>,
        kernel_image: &[u8],
        syscall_table_toml: String,
        fs_root: impl Into<std::path::PathBuf>,
        exe_path: impl Into<std::path::PathBuf>,
    ) -> Result<Self> {
        let host_cpus = num_cpus::get().max(1) as u32;
        let vcpu_count = std::env::var("WINEMU_VCPU_COUNT")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .map(|n| n.clamp(1, host_cpus))
            .unwrap_or(1);
        let guest_memory_mb = env_usize("WINEMU_GUEST_MEM_MB")
            .map(|mb| mb.clamp(MIN_GUEST_MEMORY_MB, MAX_GUEST_MEMORY_MB))
            .unwrap_or(DEFAULT_GUEST_MEMORY_MB);
        let guest_memory_size = guest_memory_mb * 1024 * 1024;
        let max_phys_pool_mb = (guest_memory_mb / 2).max(gpa_alloc::MIN_PHYS_POOL_MB);
        let phys_pool_mb = env_usize("WINEMU_PHYS_POOL_MB")
            .map(|mb| mb.clamp(gpa_alloc::MIN_PHYS_POOL_MB, max_phys_pool_mb))
            .unwrap_or(gpa_alloc::DEFAULT_PHYS_POOL_MB.min(max_phys_pool_mb));
        let phys_pool_size = phys_pool_mb * 1024 * 1024;
        let guest_gpa_end = GUEST_BASE_GPA + guest_memory_size as u64;
        let phys_pool_end = guest_gpa_end;
        let phys_pool_base = phys_pool_end - phys_pool_size as u64;
        let phys_alloc_budget_mb = env_usize("WINEMU_PHYS_ALLOC_BUDGET_MB")
            .map(|mb| mb.clamp(1, phys_pool_mb))
            .unwrap_or(phys_pool_mb);
        let phys_alloc_budget_bytes = phys_alloc_budget_mb * 1024 * 1024;
        log::info!(
            "vm config: guest_mem_mb={} phys_pool_mb={} phys_budget_mb={} vcpu_count={}",
            guest_memory_mb,
            phys_pool_mb,
            phys_alloc_budget_mb,
            vcpu_count
        );
        let config = VmConfig {
            memory_size: guest_memory_size,
            vcpu_count,
        };
        let vm: Arc<dyn Vm> = Arc::from(hypervisor.create_vm(config)?);
        let mut memory = GuestMemory::new(guest_memory_size)?;
        vm.map_memory(memory.base_gpa(), memory.hva(), memory.size(), MemProt::RWX)?;
        memory.write_bytes(Gpa(GUEST_BASE_GPA), kernel_image);

        let memory = Arc::new(RwLock::new(memory));
        let sched = Scheduler::new(vcpu_count);
        let hypercall_mgr = Arc::new(HypercallManager::new(
            syscall_table_toml,
            Arc::clone(&memory),
            fs_root,
            Arc::clone(&sched),
            exe_path,
            phys_pool_base,
            phys_pool_end,
            phys_alloc_budget_bytes,
        ));
        let debugger = debugger::server_addr_from_env().map(|_| {
            debugger::DebugController::new(vcpu_count, Arc::clone(&sched), Arc::clone(&memory))
        });

        Ok(Self {
            hypervisor,
            vm,
            memory,
            hypercall_mgr,
            sched,
            debugger,
            vcpu_count,
        })
    }

    pub fn hypercall_manager(&self) -> Arc<HypercallManager> {
        Arc::clone(&self.hypercall_mgr)
    }

    pub fn run(&mut self) -> Result<()> {
        let debugger = self.debugger.as_ref().map(Arc::clone);
        let vcpu0 = self.vm.create_vcpu(0)?;
        if let Some(debugger) = debugger.as_ref() {
            debugger.set_backend_caps(vcpu0.debug_caps());
            if let Some(addr) = debugger::server_addr_from_env() {
                debugger::spawn_server(Arc::clone(debugger), addr);
            }
        }
        if self.vcpu_count <= 1 {
            vcpu::vcpu_thread(
                0,
                vcpu0,
                Arc::clone(&self.hypercall_mgr),
                Arc::clone(&self.sched),
                debugger.as_ref().map(Arc::clone),
                true,
            );
            return Ok(());
        }

        let mut reset_regs = vcpu0.regs()?;
        set_kernel_boot_entry_pc(&mut reset_regs);
        let mut vcpu0 = vcpu0;
        vcpu0.set_regs(&reset_regs)?;
        let reset_special = vcpu0.special_regs()?;

        let mut joins = Vec::with_capacity((self.vcpu_count - 1) as usize);
        for id in 1..self.vcpu_count {
            let vm = Arc::clone(&self.vm);
            let hc_mgr = Arc::clone(&self.hypercall_mgr);
            let sched = Arc::clone(&self.sched);
            let debugger = debugger.as_ref().map(Arc::clone);
            let reset_regs = reset_regs.clone();
            let reset_special = reset_special.clone();
            let (ready_tx, ready_rx) = mpsc::channel::<std::result::Result<(), String>>();
            let name = format!("winemu-vcpu-{id}");
            let handle = std::thread::Builder::new()
                .name(name)
                .spawn(move || -> Result<()> {
                    let mut vcpu = match vm.create_vcpu(id) {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = ready_tx.send(Err(e.to_string()));
                            return Err(e);
                        }
                    };
                    if let Err(e) = vcpu.set_regs(&reset_regs) {
                        let _ = ready_tx.send(Err(e.to_string()));
                        return Err(e);
                    }
                    if let Err(e) = vcpu.set_special_regs(&reset_special) {
                        let _ = ready_tx.send(Err(e.to_string()));
                        return Err(e);
                    }
                    let _ = ready_tx.send(Ok(()));
                    vcpu::vcpu_thread(
                        id,
                        vcpu,
                        hc_mgr,
                        sched,
                        debugger.as_ref().map(Arc::clone),
                        false,
                    );
                    Ok(())
                })
                .map_err(|e| WinemuError::Hypervisor(format!("spawn vcpu thread failed: {e}")))?;

            match ready_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(msg)) => {
                    return Err(WinemuError::Hypervisor(format!(
                        "create vcpu{id} failed: {msg}"
                    )));
                }
                Err(e) => {
                    return Err(WinemuError::Hypervisor(format!(
                        "vcpu{id} ready handshake failed: {e}"
                    )));
                }
            }

            joins.push(handle);
        }

        vcpu::vcpu_thread(
            0,
            vcpu0,
            Arc::clone(&self.hypercall_mgr),
            Arc::clone(&self.sched),
            debugger.as_ref().map(Arc::clone),
            true,
        );

        for handle in joins {
            let thread_result = handle
                .join()
                .map_err(|_| WinemuError::Hypervisor("vcpu thread panicked".to_string()))?;
            thread_result?;
        }
        Ok(())
    }
}
