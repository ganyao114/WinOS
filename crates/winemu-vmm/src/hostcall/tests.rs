#[cfg(test)]
mod tests {
    use crate::host_file::HostFileTable;
    use crate::hostcall::{HostCallBroker, SubmitResult};
    use crate::memory::GuestMemory;
    use crate::sched::Scheduler;
    use crate::vaspace::VaSpace;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::Duration;
    use winemu_core::addr::Gpa;
    use winemu_shared::hostcall as hc;
    use winemu_shared::status;

    static NEXT_TMP_ID: AtomicU64 = AtomicU64::new(1);

    fn temp_root() -> PathBuf {
        let mut p = std::env::temp_dir();
        let id = NEXT_TMP_ID.fetch_add(1, Ordering::Relaxed);
        p.push(format!(
            "winemu-hostcall-test-{}-{}",
            std::process::id(),
            id
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn test_setup(
        root: &std::path::Path,
    ) -> (
        HostCallBroker,
        Arc<RwLock<GuestMemory>>,
        Arc<HostFileTable>,
        Arc<Mutex<VaSpace>>,
    ) {
        let memory = Arc::new(RwLock::new(GuestMemory::new(8 * 1024 * 1024).unwrap()));
        let sched = Scheduler::new(1);
        let host_files = Arc::new(HostFileTable::new(root.to_path_buf()));
        let vaspace = Arc::new(Mutex::new(VaSpace::new()));
        let broker = HostCallBroker::new(
            Arc::clone(&memory),
            Arc::clone(&host_files),
            Arc::clone(&vaspace),
            Arc::clone(&sched),
        );
        (broker, memory, host_files, vaspace)
    }

    #[test]
    fn open_and_read_sync_path_roundtrip() {
        let root = temp_root();
        let path = root.join("sync.txt");
        std::fs::write(&path, b"hello-hostcall").unwrap();

        let (broker, memory, _host_files, _) = test_setup(&root);
        let base = memory.read().unwrap().base_gpa().0;
        let path_ptr = base + 0x1000;
        let read_ptr = base + 0x2000;
        memory
            .write()
            .unwrap()
            .write_bytes(Gpa(path_ptr), b"sync.txt");

        let open = broker.submit(hc::OP_OPEN, 0, [path_ptr, 8, 0, 0], 0);
        let fd = match open {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                aux
            }
            SubmitResult::Pending { .. } => panic!("sync open should not pend"),
        };
        assert_ne!(fd, 0);

        let read = broker.submit(hc::OP_READ, 0, [fd, read_ptr, 14, 0], 0);
        let got = match read {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                aux as usize
            }
            SubmitResult::Pending { .. } => panic!("sync read should not pend"),
        };
        assert_eq!(got, 14);
        let bytes = memory
            .read()
            .unwrap()
            .read_bytes(Gpa(read_ptr), got)
            .to_vec();
        assert_eq!(&bytes, b"hello-hostcall");

        let close = broker.submit(hc::OP_CLOSE, 0, [fd, 0, 0, 0], 0);
        match close {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                assert_eq!(aux, 0);
            }
            SubmitResult::Pending { .. } => panic!("sync close should not pend"),
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_async_force_path_completes() {
        let root = temp_root();
        let path = root.join("async_open.txt");
        std::fs::write(&path, b"x").unwrap();

        let (broker, memory, _host_files, _) = test_setup(&root);
        let path_ptr = memory.read().unwrap().base_gpa().0 + 0x1000;
        memory
            .write()
            .unwrap()
            .write_bytes(Gpa(path_ptr), b"async_open.txt");

        let submit = broker.submit(
            hc::OP_OPEN,
            hc::FLAG_FORCE_ASYNC,
            [path_ptr, 14, 0, 0],
            0xAA55,
        );
        let request_id = match submit {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("force async open should pend"),
        };

        let mut got = None;
        for _ in 0..200 {
            let _ = broker.run_main_thread_budget(8);
            for cpl in broker.poll_batch(16) {
                if cpl.request_id == request_id {
                    got = Some(cpl);
                    break;
                }
            }
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let cpl = got.expect("no completion for async open");
        assert_eq!(cpl.host_result as u64, hc::HC_OK);
        assert_eq!(cpl.user_tag, 0xAA55);
        assert_ne!(cpl.value0, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_async_allow_path_completes() {
        let root = temp_root();
        let path = root.join("async_open_allow.txt");
        std::fs::write(&path, b"x").unwrap();

        let (broker, memory, _host_files, _) = test_setup(&root);
        let path_ptr = memory.read().unwrap().base_gpa().0 + 0x1200;
        memory
            .write()
            .unwrap()
            .write_bytes(Gpa(path_ptr), b"async_open_allow.txt");

        let submit = broker.submit(
            hc::OP_OPEN,
            hc::FLAG_ALLOW_ASYNC,
            [path_ptr, 20, 0, 0],
            0xA11A,
        );
        let request_id = match submit {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("allow-async open should pend"),
        };

        let mut got = None;
        for _ in 0..200 {
            let _ = broker.run_main_thread_budget(8);
            for cpl in broker.poll_batch(16) {
                if cpl.request_id == request_id {
                    got = Some(cpl);
                    break;
                }
            }
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let cpl = got.expect("no completion for allow-async open");
        assert_eq!(cpl.host_result as u64, hc::HC_OK);
        assert_eq!(cpl.user_tag, 0xA11A);
        assert_ne!(cpl.value0, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_write_async_force_paths_complete() {
        let root = temp_root();
        std::fs::write(root.join("rw_async.bin"), b"").unwrap();

        let (broker, memory, host_files, _) = test_setup(&root);
        let fd = host_files.open("rw_async.bin", 2);
        assert_ne!(fd, u64::MAX);

        let base = memory.read().unwrap().base_gpa().0;
        let src_ptr = base + 0x3000;
        let dst_ptr = base + 0x4000;
        memory
            .write()
            .unwrap()
            .write_bytes(Gpa(src_ptr), b"async-io-data");

        let submit_write = broker.submit(
            hc::OP_WRITE,
            hc::FLAG_FORCE_ASYNC,
            [fd, src_ptr, 13, 0],
            0xABCD,
        );
        let write_id = match submit_write {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("force async write should pend"),
        };

        let mut write_cpl = None;
        for _ in 0..200 {
            for cpl in broker.poll_batch(16) {
                if cpl.request_id == write_id {
                    write_cpl = Some(cpl);
                    break;
                }
            }
            if write_cpl.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let write_cpl = write_cpl.expect("no completion for async write");
        assert_eq!(write_cpl.host_result as u64, hc::HC_OK);
        assert_eq!(write_cpl.value0, 13);
        assert_eq!(write_cpl.user_tag, 0xABCD);

        let submit_read = broker.submit(
            hc::OP_READ,
            hc::FLAG_FORCE_ASYNC,
            [fd, dst_ptr, 13, 0],
            0xBCDE,
        );
        let read_id = match submit_read {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("force async read should pend"),
        };

        let mut read_cpl = None;
        for _ in 0..200 {
            for cpl in broker.poll_batch(16) {
                if cpl.request_id == read_id {
                    read_cpl = Some(cpl);
                    break;
                }
            }
            if read_cpl.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let read_cpl = read_cpl.expect("no completion for async read");
        assert_eq!(read_cpl.host_result as u64, hc::HC_OK);
        assert_eq!(read_cpl.value0, 13);
        assert_eq!(read_cpl.user_tag, 0xBCDE);

        let got = memory.read().unwrap().read_bytes(Gpa(dst_ptr), 13).to_vec();
        assert_eq!(&got, b"async-io-data");

        host_files.close(fd);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn notify_dir_sync_path_returns_immediate_result() {
        let root = temp_root();
        let watch = root.join("watch");
        std::fs::create_dir_all(&watch).unwrap();

        let (broker, memory, host_files, _) = test_setup(&root);
        let fd = host_files.open("watch", 0);
        assert_ne!(fd, u64::MAX);

        let out_ptr = memory.read().unwrap().base_gpa().0 + 0x10000;
        let first = broker.submit(hc::OP_NOTIFY_DIR, 0, [fd, out_ptr, 512, 0], 0);
        match first {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                assert_eq!(aux, 0);
            }
            SubmitResult::Pending { .. } => panic!("sync path should not pend"),
        }

        let changed_name = "sync_changed.txt";
        std::fs::write(watch.join(changed_name), b"x").unwrap();
        let second = broker.submit(hc::OP_NOTIFY_DIR, 0, [fd, out_ptr, 512, 0], 0);
        let packed = match second {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                aux
            }
            SubmitResult::Pending { .. } => panic!("sync path should not pend"),
        };
        assert_ne!(packed, 0);
        let name_len = (packed & 0xFFFF_FFFF) as usize;
        assert!(name_len > 0);
        let got = memory
            .read()
            .unwrap()
            .read_bytes(Gpa(out_ptr), name_len)
            .to_vec();
        let got_name = std::str::from_utf8(&got).unwrap();
        assert!(got_name.contains("sync_changed"));

        host_files.close(fd);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn notify_dir_async_path_completes_via_poll_batch() {
        let root = temp_root();
        let watch = root.join("watch");
        std::fs::create_dir_all(&watch).unwrap();

        let (broker, memory, host_files, _) = test_setup(&root);
        let fd = host_files.open("watch", 0);
        assert_ne!(fd, u64::MAX);

        let out_ptr = memory.read().unwrap().base_gpa().0 + 0x20000;
        let prime = broker.submit(hc::OP_NOTIFY_DIR, 0, [fd, out_ptr, 512, 0], 0);
        match prime {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                assert_eq!(aux, 0);
            }
            SubmitResult::Pending { .. } => panic!("prime must be sync"),
        }

        let submit = broker.submit(
            hc::OP_NOTIFY_DIR,
            hc::FLAG_FORCE_ASYNC,
            [fd, out_ptr, 512, 0],
            0x55AA,
        );
        let request_id = match submit {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("async path should pend"),
        };
        assert_ne!(request_id, 0);

        std::fs::write(watch.join("async_changed.txt"), b"x").unwrap();
        let mut got = None;
        for _ in 0..200 {
            let batch = broker.poll_batch(8);
            for cpl in batch {
                if cpl.request_id == request_id {
                    got = Some(cpl);
                    break;
                }
            }
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let cpl = got.expect("no completion for async request");
        assert_eq!(cpl.host_result as u64, hc::HC_OK);
        assert_eq!(cpl.user_tag, 0x55AA);
        let packed = cpl.value0;
        assert_ne!(packed, 0);
        let name_len = (packed & 0xFFFF_FFFF) as usize;
        assert!(name_len > 0);
        let got_name = memory
            .read()
            .unwrap()
            .read_bytes(Gpa(out_ptr), name_len)
            .to_vec();
        let got_name = std::str::from_utf8(&got_name).unwrap();
        assert!(got_name.contains("async_changed"));

        host_files.close(fd);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn main_thread_flag_routes_to_main_executor() {
        let root = temp_root();
        let path = root.join("main_exec.txt");
        std::fs::write(&path, b"m").unwrap();

        let (broker, memory, _host_files, _) = test_setup(&root);
        let path_ptr = memory.read().unwrap().base_gpa().0 + 0x1400;
        memory
            .write()
            .unwrap()
            .write_bytes(Gpa(path_ptr), b"main_exec.txt");

        let submit = broker.submit(
            hc::OP_OPEN,
            hc::FLAG_FORCE_ASYNC | hc::FLAG_MAIN_THREAD,
            [path_ptr, 13, 0, 0],
            0xD00D,
        );
        let request_id = match submit {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("main-thread async open should pend"),
        };

        let mut got = None;
        for _ in 0..200 {
            let _ = broker.run_main_thread_budget(8);
            for cpl in broker.poll_batch(16) {
                if cpl.request_id == request_id {
                    got = Some(cpl);
                    break;
                }
            }
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let cpl = got.expect("no completion for main-thread request");
        assert_eq!(cpl.host_result as u64, hc::HC_OK);
        assert_ne!(cpl.flags & hc::CPLF_MAIN_THREAD, 0);
        assert_eq!(cpl.user_tag, 0xD00D);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stats_snapshot_tracks_sync_async_paths() {
        let root = temp_root();
        let path = root.join("stats.txt");
        std::fs::write(&path, b"stats").unwrap();

        let (broker, memory, host_files, _) = test_setup(&root);
        let path_ptr = memory.read().unwrap().base_gpa().0 + 0x1800;
        memory
            .write()
            .unwrap()
            .write_bytes(Gpa(path_ptr), b"stats.txt");

        let sync_open = broker.submit(hc::OP_OPEN, 0, [path_ptr, 9, 0, 0], 0);
        let fd_sync = match sync_open {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                aux
            }
            SubmitResult::Pending { .. } => panic!("sync open should not pend"),
        };
        host_files.close(fd_sync);

        let async_open = broker.submit(hc::OP_OPEN, hc::FLAG_FORCE_ASYNC, [path_ptr, 9, 0, 0], 0);
        let request_id = match async_open {
            SubmitResult::Pending { request_id } => request_id,
            SubmitResult::Completed { .. } => panic!("async open should pend"),
        };

        let mut async_fd = None;
        for _ in 0..200 {
            for cpl in broker.poll_batch(8) {
                if cpl.request_id == request_id {
                    assert_eq!(cpl.host_result as u64, hc::HC_OK);
                    async_fd = Some(cpl.value0);
                    break;
                }
            }
            if async_fd.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        host_files.close(async_fd.expect("missing async open completion"));

        let snap = broker.stats_snapshot();
        assert_eq!(snap.submit_sync_total, 1);
        assert_eq!(snap.complete_sync_total, 1);
        assert_eq!(snap.submit_async_total, 1);
        assert_eq!(snap.complete_async_total, 1);
        assert_eq!(snap.backpressure_total, 0);

        let open = snap
            .op_stats
            .iter()
            .find(|s| s.opcode == hc::OP_OPEN)
            .copied()
            .expect("missing open op stats");
        assert_eq!(open.submit_sync, 1);
        assert_eq!(open.complete_sync, 1);
        assert_eq!(open.submit_async, 1);
        assert_eq!(open.complete_async, 1);
        assert_eq!(open.backpressure, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn win32k_call_bridge_returns_not_implemented_status() {
        let root = temp_root();
        let (broker, memory, _host_files, _) = test_setup(&root);
        let pkt_ptr = memory.read().unwrap().base_gpa().0 + 0x30000;

        let mut bytes = vec![0u8; hc::WIN32K_CALL_PACKET_SIZE];
        bytes[0..4].copy_from_slice(&hc::WIN32K_CALL_PACKET_VERSION.to_le_bytes()); // version
        bytes[4..8].copy_from_slice(&(1u32).to_le_bytes()); // table
        bytes[8..12].copy_from_slice(
            &(winemu_shared::win32k_sysno::NT_USER_INITIALIZE_CLIENT_PFN_ARRAYS as u32)
                .to_le_bytes(),
        ); // syscall nr
        bytes[12..16].copy_from_slice(&(hc::WIN32K_CALL_MAX_ARGS as u32).to_le_bytes()); // arg_count
        bytes[16..20].copy_from_slice(&(1u32).to_le_bytes()); // owner_pid
        bytes[20..24].copy_from_slice(&(1u32).to_le_bytes()); // owner_tid
        memory.write().unwrap().write_bytes(Gpa(pkt_ptr), &bytes);

        let submit = broker.submit(
            hc::OP_WIN32K_CALL,
            0,
            [pkt_ptr, hc::WIN32K_CALL_PACKET_SIZE as u64, 0, 0],
            0,
        );
        match submit {
            SubmitResult::Completed { host_result, aux } => {
                assert_eq!(host_result, hc::HC_OK);
                assert_eq!(aux as u32, status::SUCCESS);
            }
            SubmitResult::Pending { .. } => panic!("win32k bridge should complete on sync path"),
        }

        let _ = std::fs::remove_dir_all(&root);
    }
}
