pub mod file_io;
pub mod host_file;
pub mod hypercall;
pub mod memory;
pub mod phys;
pub mod sched;
pub mod section;
pub mod syscall;
pub mod vaspace;
pub mod vcpu;

use hypercall::HypercallManager;
use memory::GuestMemory;
use sched::Scheduler;
use std::sync::{Arc, RwLock};
use winemu_core::{addr::Gpa, mem::MemProt, Result, WinemuError};
use winemu_hypervisor::{Hypervisor, Vm, VmConfig};

pub struct Vmm {
    #[allow(dead_code)]
    hypervisor: Box<dyn Hypervisor>, // must outlive vm to prevent premature hv_vm_destroy
    vm: Arc<dyn Vm>,
    #[allow(dead_code)]
    memory: Arc<RwLock<GuestMemory>>,
    hypercall_mgr: Arc<HypercallManager>,
    sched: Arc<Scheduler>,
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
        let config = VmConfig {
            memory_size: 512 * 1024 * 1024,
            vcpu_count,
        };
        let vm: Arc<dyn Vm> = Arc::from(hypervisor.create_vm(config)?);
        let mut memory = GuestMemory::new(512 * 1024 * 1024)?;
        vm.map_memory(memory.base_gpa(), memory.hva(), memory.size(), MemProt::RWX)?;
        memory.write_bytes(Gpa(0x40000000), kernel_image);

        let memory = Arc::new(RwLock::new(memory));
        let sched = Scheduler::new(vcpu_count);
        let hypercall_mgr = Arc::new(HypercallManager::new(
            syscall_table_toml,
            Arc::clone(&memory),
            fs_root,
            Arc::clone(&sched),
            exe_path,
        ));

        Ok(Self {
            hypervisor,
            vm,
            memory,
            hypercall_mgr,
            sched,
            vcpu_count,
        })
    }

    pub fn run(&mut self) -> Result<()> {
        let mut vcpus = Vec::with_capacity(self.vcpu_count as usize);
        for id in 0..self.vcpu_count {
            let vcpu = self.vm.create_vcpu(id)?;
            vcpus.push((id, vcpu));
        }

        if vcpus.len() == 1 {
            let (id, vcpu) = vcpus.pop().unwrap();
            vcpu::vcpu_thread(
                id,
                vcpu,
                Arc::clone(&self.hypercall_mgr),
                Arc::clone(&self.sched),
            );
            return Ok(());
        }

        let mut joins = Vec::with_capacity(vcpus.len());
        for (id, vcpu) in vcpus {
            let hc_mgr = Arc::clone(&self.hypercall_mgr);
            let sched = Arc::clone(&self.sched);
            let name = format!("winemu-vcpu-{id}");
            let handle = std::thread::Builder::new()
                .name(name)
                .spawn(move || {
                    vcpu::vcpu_thread(id, vcpu, hc_mgr, sched);
                })
                .map_err(|e| WinemuError::Hypervisor(format!("spawn vcpu thread failed: {e}")))?;
            joins.push(handle);
        }

        for handle in joins {
            handle
                .join()
                .map_err(|_| WinemuError::Hypervisor("vcpu thread panicked".to_string()))?;
        }
        Ok(())
    }
}
