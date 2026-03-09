use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::sync::mpsc::{self, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
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
        self.hypercall_mgr.handle_host_window_event(window_id, &event);
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        let elapsed_ms = self.started_at.elapsed().as_millis().min(u32::MAX as u128) as u32;
        self.hypercall_mgr
            .pump_hostcall_main_thread_with_event_loop(event_loop, elapsed_ms);
        self.hypercall_mgr.force_exit_vcpus_if_shutdown();
        event_loop.set_control_flow(ControlFlow::Poll);
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
            log::warn!(
                "host UI event loop unavailable ({e}); fallback to headless mode"
            );
            std::env::remove_var("WINEMU_HOST_UI_MAIN_THREAD");
            vmm.run().context("VMM run failed")?;
            return Ok(());
        }
    };

    let hypercall_mgr = vmm.hypercall_manager();
    let (done_tx, done_rx) = mpsc::sync_channel::<std::result::Result<(), String>>(1);
    let join = thread::Builder::new()
        .name("winemu-vmm".to_string())
        .spawn(move || {
            let result = vmm.run().map_err(|e| format!("{e}"));
            let _ = done_tx.send(result);
        })
        .context("failed to spawn VMM thread")?;

    let mut app = HostUiApp::new(Arc::clone(&hypercall_mgr));
    let done_result = loop {
        match event_loop.pump_app_events(Some(Duration::from_millis(8)), &mut app) {
            PumpStatus::Continue => {}
            PumpStatus::Exit(code) => {
                log::warn!("host-ui: event loop requested exit code={code}");
                hypercall_mgr.sched.request_shutdown();
                hypercall_mgr.force_exit_vcpus_if_shutdown();
                break Err(format!("host UI event loop exited with code {code}"));
            }
        }

        match done_rx.try_recv() {
            Ok(done) => break done,
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                break Err("VMM completion channel disconnected".to_string());
            }
        }
    };

    if join.join().is_err() {
        return Err(anyhow!("VMM thread panicked"));
    }

    match done_result {
        Ok(()) => Ok(()),
        Err(msg) => Err(anyhow!("VMM run failed: {msg}")),
    }
}

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
