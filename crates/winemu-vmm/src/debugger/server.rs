use super::controller::DebugController;
use super::types::{DebugState, StopReason};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

const DEFAULT_ADDR: &str = "127.0.0.1:9001";
const MAX_MEMORY_DUMP_LEN: usize = 0x400;

pub fn server_addr_from_env() -> Option<String> {
    let enabled = std::env::var("WINEMU_GUEST_DEBUG")
        .ok()
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enabled {
        return None;
    }
    Some(
        std::env::var("WINEMU_GUEST_DEBUG_ADDR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_ADDR.to_string()),
    )
}

pub fn spawn_server(controller: Arc<DebugController>, addr: String) {
    let name = "winemu-guest-debug".to_string();
    let spawn_result = std::thread::Builder::new().name(name).spawn(move || {
        let listener = match TcpListener::bind(&addr) {
            Ok(listener) => listener,
            Err(err) => {
                log::error!("debugger: bind {} failed: {}", addr, err);
                return;
            }
        };
        log::info!("debugger: listening on {}", addr);
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                continue;
            };
            if let Err(err) = handle_client(stream, controller.as_ref()) {
                log::warn!("debugger: client session failed: {}", err);
            }
        }
    });
    if let Err(err) = spawn_result {
        log::error!("debugger: spawn server thread failed: {}", err);
    }
}

fn handle_client(stream: TcpStream, controller: &DebugController) -> std::io::Result<()> {
    let peer = stream.peer_addr().ok();
    let mut reader = BufReader::new(stream);
    write_reply(reader.get_mut(), "WinEmu guest debugger ready\n")?;
    loop {
        write_reply(reader.get_mut(), "debug> ")?;
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        let response = dispatch_command(controller, line.trim());
        write_reply(reader.get_mut(), &response)?;
        if line.trim() == "quit" {
            break;
        }
    }
    if let Some(peer) = peer {
        log::debug!("debugger: client disconnected {}", peer);
    }
    Ok(())
}

fn dispatch_command(controller: &DebugController, line: &str) -> String {
    let mut parts = line.split_whitespace();
    let Some(cmd) = parts.next() else {
        return "ok\n".to_string();
    };
    match cmd {
        "help" => help_text(),
        "status" => controller.format_status(),
        "pause" => match controller.request_pause_all(StopReason::ManualPause) {
            Ok(()) => controller.format_status(),
            Err(err) => format!("error: {}\n", err),
        },
        "continue" | "c" => {
            controller.resume_all();
            controller.format_status()
        }
        "regs" => format_snapshot(controller, parts.next(), false),
        "sregs" => format_snapshot(controller, parts.next(), true),
        "sym" => {
            let Some(addr) = parts.next().and_then(parse_u64) else {
                return "error: expected sym <addr>\n".to_string();
            };
            controller.format_symbol(addr)
        }
        "bt" => {
            let Some(vcpu_id) = parts.next().and_then(parse_u32) else {
                return "error: expected bt <vcpu>\n".to_string();
            };
            controller.format_backtrace(vcpu_id)
        }
        "xp" => {
            let (Some(gpa), Some(len)) = (parts.next(), parts.next()) else {
                return "error: expected xp <gpa> <len>\n".to_string();
            };
            let Some(gpa) = parse_u64(gpa) else {
                return "error: invalid physical address\n".to_string();
            };
            let Some(len) = parse_len(len) else {
                return "error: invalid length\n".to_string();
            };
            format_memory_result(controller.read_guest_phys(gpa, len), gpa)
        }
        "x" => {
            let (Some(vcpu), Some(va), Some(len)) = (parts.next(), parts.next(), parts.next())
            else {
                return "error: expected x <vcpu> <va> <len>\n".to_string();
            };
            let Some(vcpu_id) = parse_u32(vcpu) else {
                return "error: invalid vcpu id\n".to_string();
            };
            let Some(va) = parse_u64(va) else {
                return "error: invalid virtual address\n".to_string();
            };
            let Some(len) = parse_len(len) else {
                return "error: invalid length\n".to_string();
            };
            format_memory_result(controller.read_guest_virt(vcpu_id, va, len), va)
        }
        "quit" => "bye\n".to_string(),
        _ => format!("error: unknown command `{}`\n", cmd),
    }
}

fn help_text() -> String {
    [
        "commands:",
        "  help",
        "  status",
        "  pause",
        "  continue|c",
        "  regs <vcpu>",
        "  sregs <vcpu>",
        "  sym <addr>",
        "  bt <vcpu>",
        "  xp <gpa> <len>",
        "  x <vcpu> <va> <len>",
        "  quit",
        "",
    ]
    .join("\n")
}

fn format_snapshot(controller: &DebugController, arg: Option<&str>, special: bool) -> String {
    if controller.state() != DebugState::Paused {
        return "error: debugger is not paused\n".to_string();
    }
    let Some(vcpu_id) = arg.and_then(|value| value.parse::<u32>().ok()) else {
        return "error: expected vcpu id\n".to_string();
    };
    let Some(snapshot) = controller.snapshot(vcpu_id) else {
        return format!("error: no snapshot for vcpu {}\n", vcpu_id);
    };
    if special {
        format!(
            "vcpu={} reason={:?}\n{:#?}\n",
            snapshot.vcpu_id, snapshot.reason, snapshot.special_regs
        )
    } else {
        format!(
            "vcpu={} reason={:?}\n{:#?}\n",
            snapshot.vcpu_id, snapshot.reason, snapshot.regs
        )
    }
}

fn write_reply(stream: &mut TcpStream, text: &str) -> std::io::Result<()> {
    stream.write_all(text.as_bytes())?;
    stream.flush()
}

fn parse_u64(text: &str) -> Option<u64> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse::<u64>().ok()
    }
}

fn parse_u32(text: &str) -> Option<u32> {
    parse_u64(text).and_then(|value| u32::try_from(value).ok())
}

fn parse_len(text: &str) -> Option<usize> {
    let value = parse_u64(text)?;
    let value = usize::try_from(value).ok()?;
    if value == 0 || value > MAX_MEMORY_DUMP_LEN {
        return None;
    }
    Some(value)
}

fn format_memory_result(result: winemu_core::Result<Vec<u8>>, base_addr: u64) -> String {
    match result {
        Ok(bytes) => format!("{}\n", format_hexdump(base_addr, &bytes)),
        Err(err) => format!("error: {}\n", err),
    }
}

fn format_hexdump(base_addr: u64, bytes: &[u8]) -> String {
    let mut out = String::new();
    let line_count = bytes.len().div_ceil(16);
    for (line_idx, chunk) in bytes.chunks(16).enumerate() {
        let addr = base_addr + (line_idx as u64) * 16;
        out.push_str(&format!("{:#018x}: ", addr));
        for idx in 0..16 {
            if idx < chunk.len() {
                out.push_str(&format!("{:02x} ", chunk[idx]));
            } else {
                out.push_str("   ");
            }
        }
        out.push(' ');
        for byte in chunk {
            let ch = if (0x20..=0x7e).contains(byte) {
                *byte as char
            } else {
                '.'
            };
            out.push(ch);
        }
        if line_idx + 1 != line_count {
            out.push('\n');
        }
    }
    out
}
