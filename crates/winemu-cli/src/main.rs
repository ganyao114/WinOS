use anyhow::{Context, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let (exe_path, syscall_table_path, fs_root, extra_dll_paths) = parse_args(&args)?;

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

    // DLL search order: fs_root, guest/sysroot, any --dll-path flags
    let mut dll_paths = vec![fs_root.clone(), PathBuf::from("guest/sysroot")];
    dll_paths.extend(extra_dll_paths);

    let mut vmm = winemu_vmm::Vmm::new(
        hypervisor,
        &kernel_image,
        syscall_table_toml,
        &fs_root,
        dll_paths,
        &exe_path,
    )
    .context("failed to create VMM")?;

    log::info!("Starting WinEmu: {}", exe_path.display());
    vmm.run().context("VMM run failed")?;

    Ok(())
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
