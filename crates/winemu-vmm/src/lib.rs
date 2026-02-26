pub mod dll;
pub mod file_io;
pub mod hypercall;
pub mod memory;
pub mod sched;
pub mod section;
pub mod syscall;
pub mod vaspace;
pub mod vcpu;

use std::sync::{Arc, RwLock};
use winemu_core::{addr::Gpa, mem::MemProt, Result};
use winemu_hypervisor::{Hypervisor, Vm, VmConfig};
use memory::GuestMemory;
use hypercall::HypercallManager;
use sched::Scheduler;

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
        dll_search_paths: Vec<std::path::PathBuf>,
        exe_path: impl Into<std::path::PathBuf>,
    ) -> Result<Self> {
        let vcpu_count = num_cpus::get() as u32;
        let config = VmConfig { memory_size: 512 * 1024 * 1024, vcpu_count };
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
            dll_search_paths,
            exe_path,
        ));

        Ok(Self { hypervisor, vm, memory, hypercall_mgr, sched, vcpu_count })
    }

    pub fn run(&mut self) -> Result<()> {
        // HVF requires hv_vcpu_create on the same thread as hv_vm_create.
        // Run the single vCPU on the current (main) thread.
        let vcpu = self.vm.create_vcpu(0)?;
        vcpu::vcpu_thread(0, vcpu, Arc::clone(&self.hypercall_mgr), Arc::clone(&self.sched));
        Ok(())
    }
}
