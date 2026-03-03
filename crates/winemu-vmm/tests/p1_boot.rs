#[cfg(test)]
mod p1_boot {
    use memmap2::MmapMut;
    use winemu_core::{addr::Gpa, mem::MemProt};
    use winemu_hypervisor::{create_hypervisor, types::VmExit, VmConfig};
    use winemu_shared::nr;

    fn load_kernel_bin() -> Option<Vec<u8>> {
        let paths = [
            "../../winemu-kernel/target/aarch64-unknown-none/release/winemu-kernel.bin",
            "winemu-kernel/target/aarch64-unknown-none/release/winemu-kernel.bin",
        ];
        for p in &paths {
            if let Ok(data) = std::fs::read(p) {
                return Some(data);
            }
        }
        None
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn guest_kernel_sends_kernel_ready() {
        let kernel = match load_kernel_bin() {
            Some(k) => k,
            None => {
                eprintln!("SKIP: winemu-kernel.bin not found");
                return;
            }
        };

        let hv = match create_hypervisor() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("SKIP: hypervisor unavailable: {}", e);
                return;
            }
        };

        const MEM_SIZE: usize = 64 * 1024 * 1024;
        const KERNEL_GPA: u64 = 0x4000_0000;

        let config = VmConfig {
            memory_size: MEM_SIZE,
            vcpu_count: 1,
        };
        let vm = hv.create_vm(config).expect("create_vm");

        let mut mmap = MmapMut::map_anon(MEM_SIZE).expect("mmap");
        let hva = mmap.as_mut_ptr();
        mmap[..kernel.len()].copy_from_slice(&kernel);

        vm.map_memory(Gpa(KERNEL_GPA), hva, MEM_SIZE, MemProt::RWX)
            .expect("map_memory");

        let mut vcpu = vm.create_vcpu(0).expect("create_vcpu");
        let exit = vcpu.run().expect("vcpu run");

        match exit {
            VmExit::Hypercall {
                nr: hypercall_nr, ..
            } => {
                assert_eq!(
                    hypercall_nr,
                    nr::KERNEL_READY,
                    "expected KERNEL_READY ({:#x}), got {:#x}",
                    nr::KERNEL_READY,
                    hypercall_nr
                );
                println!("✓ Guest kernel ready hypercall received");
            }
            other => panic!("unexpected VmExit: {:?}", other),
        }
    }
}
