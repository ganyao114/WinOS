use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::platform::pump_events::{EventLoopExtPumpEvents, PumpStatus};
use winit::window::WindowId;

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let (exe_path, syscall_table_path, fs_root, _extra_dll_paths) = parse_args(&args)?;

    let kernel_image =
        std::fs::read("winemu-kernel.bin").context("failed to read winemu-kernel.bin")?;

    let syscall_table_toml = std::fs::read_to_string(&syscall_table_path).with_context(|| {
        format!(
            "failed to read syscall table: {}",
            syscall_table_path.display()
        )
    })?;

    let hypervisor =
        winemu_hypervisor::create_hypervisor().context("failed to create hypervisor")?;

    let vmm = winemu_vmm::Vmm::new(
        hypervisor,
        &kernel_image,
        syscall_table_toml,
        &fs_root,
        &exe_path,
    )
    .context("failed to create VMM")?;

    log::info!("Starting WinEmu: {}", exe_path.display());
    run_vmm_with_host_ui(vmm)?;

    Ok(())
}

struct HostUiApp {
    hypercall_mgr: Arc<winemu_vmm::hypercall::HypercallManager>,
    started_at: Instant,
}

impl HostUiApp {
    fn new(hypercall_mgr: Arc<winemu_vmm::hypercall::HypercallManager>) -> Self {
        Self {
            hypercall_mgr,
            started_at: Instant::now(),
        }
    }

    fn pump_hostcalls_and_check_shutdown(&mut self, event_loop: &ActiveEventLoop) {
        let elapsed_ms = self.started_at.elapsed().as_millis().min(u32::MAX as u128) as u32;
        self.hypercall_mgr
            .pump_hostcall_main_thread_with_event_loop(event_loop, elapsed_ms);
        self.hypercall_mgr.force_exit_vcpus_if_shutdown();
        if self.hypercall_mgr.sched.shutdown.load(Ordering::Acquire) {
            let code = self.hypercall_mgr.guest_exit_code();
            std::process::exit(code as i32);
        }
    }
}

impl ApplicationHandler<()> for HostUiApp {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        event_loop.set_control_flow(ControlFlow::Poll);
    }

    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) {
        self.hypercall_mgr
            .handle_host_window_event(window_id, &event);
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, _event: ()) {
        self.pump_hostcalls_and_check_shutdown(event_loop);
        event_loop.set_control_flow(ControlFlow::Poll);
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        self.pump_hostcalls_and_check_shutdown(event_loop);
        event_loop.set_control_flow(ControlFlow::Poll);
    }
}

fn exit_after_host_ui_run(done: std::result::Result<(), String>) -> ! {
    match done {
        Ok(()) => std::process::exit(0),
        Err(msg) => {
            eprintln!("VMM run failed: {msg}");
            std::process::exit(1);
        }
    }
}

fn run_vmm_with_host_ui(mut vmm: winemu_vmm::Vmm) -> Result<()> {
    if std::env::var("WINEMU_DISABLE_HOST_UI").ok().as_deref() == Some("1") {
        std::env::remove_var("WINEMU_HOST_UI_MAIN_THREAD");
        vmm.run().context("VMM run failed")?;
        return Ok(());
    }
    std::env::set_var("WINEMU_HOST_UI_MAIN_THREAD", "1");

    let mut event_loop_builder = EventLoop::<()>::builder();
    #[cfg(target_os = "macos")]
    {
        use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
        event_loop_builder.with_activation_policy(ActivationPolicy::Regular);
        event_loop_builder.with_activate_ignoring_other_apps(true);
    }
    let mut event_loop = match event_loop_builder.build() {
        Ok(v) => v,
        Err(e) => {
            log::warn!("host UI event loop unavailable ({e}); fallback to headless mode");
            std::env::remove_var("WINEMU_HOST_UI_MAIN_THREAD");
            vmm.run().context("VMM run failed")?;
            return Ok(());
        }
    };

    let hypercall_mgr = vmm.hypercall_manager();
    install_host_ui_waker(&hypercall_mgr, event_loop.create_proxy());
    let (done_tx, done_rx) = mpsc::sync_channel::<std::result::Result<(), String>>(1);
    let _vmm_thread = thread::Builder::new()
        .name("winemu-vmm".to_string())
        .spawn(move || {
            let result = vmm.run().map_err(|e| format!("{e}"));
            let _ = done_tx.send(result);
        })
        .context("failed to spawn VMM thread")?;
    let _exit_thread = thread::Builder::new()
        .name("winemu-exit-watch".to_string())
        .spawn(move || match done_rx.recv() {
            Ok(done) => exit_after_host_ui_run(done),
            Err(_) => {
                exit_after_host_ui_run(Err("VMM completion channel disconnected".to_string()))
            }
        })
        .context("failed to spawn VMM exit watcher")?;

    let mut app = HostUiApp::new(Arc::clone(&hypercall_mgr));
    loop {
        match event_loop.pump_app_events(Some(Duration::from_millis(8)), &mut app) {
            PumpStatus::Continue => {}
            PumpStatus::Exit(code) => {
                if hypercall_mgr.sched.shutdown.load(Ordering::Acquire) {
                    exit_after_host_ui_run(Ok(()));
                }
                log::warn!("host-ui: event loop requested exit code={code}");
                hypercall_mgr.sched.request_shutdown();
                hypercall_mgr.force_exit_vcpus_if_shutdown();
                exit_after_host_ui_run(Err(format!("host UI event loop exited with code {code}")));
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn install_host_ui_waker(
    hypercall_mgr: &Arc<winemu_vmm::hypercall::HypercallManager>,
    proxy: EventLoopProxy<()>,
) {
    let pending = Arc::new(AtomicBool::new(false));
    let hypercall_mgr_for_wake = Arc::clone(hypercall_mgr);
    let wake = Arc::new(move || {
        if pending.swap(true, Ordering::AcqRel) {
            return;
        }
        let pending = Arc::clone(&pending);
        let hypercall_mgr = Arc::clone(&hypercall_mgr_for_wake);
        let proxy = proxy.clone();
        dispatch2::DispatchQueue::main().exec_async(move || {
            pending.store(false, Ordering::Release);
            hypercall_mgr.pump_hostcall_main_thread(usize::MAX);
            let _ = proxy.send_event(());
            stop_host_ui_pump_once();
        });
    });
    hypercall_mgr.set_host_ui_main_thread_waker(wake);
}

#[cfg(not(target_os = "macos"))]
fn install_host_ui_waker(
    hypercall_mgr: &Arc<winemu_vmm::hypercall::HypercallManager>,
    proxy: EventLoopProxy<()>,
) {
    let wake = Arc::new(move || {
        let _ = proxy.send_event(());
    });
    hypercall_mgr.set_host_ui_main_thread_waker(wake);
}

#[cfg(target_os = "macos")]
fn stop_host_ui_pump_once() {
    use objc2_app_kit::{
        NSApplication, NSEvent, NSEventModifierFlags, NSEventSubtype, NSEventType,
    };
    use objc2_foundation::{MainThreadMarker, NSPoint};

    let Some(mtm) = MainThreadMarker::new() else {
        log::debug!("host-ui: stop_host_ui_pump_once skipped (not on main thread)");
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    app.stop(None);
    let dummy = unsafe {
        NSEvent::otherEventWithType_location_modifierFlags_timestamp_windowNumber_context_subtype_data1_data2(
            NSEventType::ApplicationDefined,
            NSPoint::new(0.0, 0.0),
            NSEventModifierFlags(0),
            0.0,
            0,
            None,
            NSEventSubtype::WindowExposed.0,
            0,
            0,
        )
    };
    if let Some(dummy) = dummy {
        app.postEvent_atStart(&dummy, true);
    }
}

#[cfg(not(target_os = "macos"))]
fn stop_host_ui_pump_once() {}

fn parse_args(args: &[String]) -> Result<(PathBuf, PathBuf, PathBuf, Vec<PathBuf>)> {
    let default_table = PathBuf::from("config/syscall-tables/win11-arm64.toml");
    let default_root = PathBuf::from(".");

    let mut exe = None;
    let mut table = default_table;
    let mut root = default_root;
    let mut dll_paths = Vec::new();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "run" => {
                i += 1;
            }
            "--syscall-table" => {
                i += 1;
                table = PathBuf::from(args.get(i).context("--syscall-table requires a path")?);
                i += 1;
            }
            "--root" => {
                i += 1;
                root = PathBuf::from(args.get(i).context("--root requires a path")?);
                i += 1;
            }
            "--dll-path" => {
                i += 1;
                dll_paths.push(PathBuf::from(
                    args.get(i).context("--dll-path requires a path")?,
                ));
                i += 1;
            }
            arg => {
                exe = Some(PathBuf::from(arg));
                i += 1;
            }
        }
    }

    let exe = exe.context(
        "usage: winemu run [--syscall-table <path>] [--root <path>] [--dll-path <path>] <exe>",
    )?;
    Ok((exe, table, root, dll_paths))
}
