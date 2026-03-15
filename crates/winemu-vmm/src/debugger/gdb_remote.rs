use super::controller::DebugController;
use super::types::{DebugState, StopReason, VcpuSnapshot};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use winemu_hypervisor::DebugCaps;

const SIGINT_SIGNAL: u8 = 2;
const SIGTRAP_SIGNAL: u8 = 5;
const STOPPED_SIGNAL: u8 = 0;
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_READ_LEN: usize = 0x4000;
const INTERRUPT_PACKET: &[u8] = b"\x03";
const ESR_EC_DEBUG_LOWER_EL: u64 = 0x30;
const ESR_EC_DEBUG_CURRENT_EL: u64 = 0x31;
const ESR_EC_SOFTWARE_STEP_LOWER_EL: u64 = 0x32;
const ESR_EC_SOFTWARE_STEP_CURRENT_EL: u64 = 0x33;
const ESR_EC_WATCHPOINT_LOWER_EL: u64 = 0x34;
const ESR_EC_WATCHPOINT_CURRENT_EL: u64 = 0x35;
const ESR_EC_BRK64: u64 = 0x3c;
const DEBUG_TRAP_AUTO_PAUSE_KERNEL_READY: u64 = 0xffff_0001;
const TARGET_XML: &str = r#"<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>aarch64</architecture>
  <feature name="org.gnu.gdb.aarch64.core">
    <reg name="x0" bitsize="64" type="int64"/>
    <reg name="x1" bitsize="64" type="int64"/>
    <reg name="x2" bitsize="64" type="int64"/>
    <reg name="x3" bitsize="64" type="int64"/>
    <reg name="x4" bitsize="64" type="int64"/>
    <reg name="x5" bitsize="64" type="int64"/>
    <reg name="x6" bitsize="64" type="int64"/>
    <reg name="x7" bitsize="64" type="int64"/>
    <reg name="x8" bitsize="64" type="int64"/>
    <reg name="x9" bitsize="64" type="int64"/>
    <reg name="x10" bitsize="64" type="int64"/>
    <reg name="x11" bitsize="64" type="int64"/>
    <reg name="x12" bitsize="64" type="int64"/>
    <reg name="x13" bitsize="64" type="int64"/>
    <reg name="x14" bitsize="64" type="int64"/>
    <reg name="x15" bitsize="64" type="int64"/>
    <reg name="x16" bitsize="64" type="int64"/>
    <reg name="x17" bitsize="64" type="int64"/>
    <reg name="x18" bitsize="64" type="int64"/>
    <reg name="x19" bitsize="64" type="int64"/>
    <reg name="x20" bitsize="64" type="int64"/>
    <reg name="x21" bitsize="64" type="int64"/>
    <reg name="x22" bitsize="64" type="int64"/>
    <reg name="x23" bitsize="64" type="int64"/>
    <reg name="x24" bitsize="64" type="int64"/>
    <reg name="x25" bitsize="64" type="int64"/>
    <reg name="x26" bitsize="64" type="int64"/>
    <reg name="x27" bitsize="64" type="int64"/>
    <reg name="x28" bitsize="64" type="int64"/>
    <reg name="fp" bitsize="64" type="data_ptr"/>
    <reg name="lr" bitsize="64" type="code_ptr"/>
    <reg name="sp" bitsize="64" type="data_ptr"/>
    <reg name="pc" bitsize="64" type="code_ptr"/>
    <reg name="cpsr" bitsize="32" type="int32"/>
  </feature>
</target>
"#;

pub fn spawn_server(controller: Arc<DebugController>, addr: String) {
    let name = "winemu-guest-gdb".to_string();
    let spawn_result = std::thread::Builder::new().name(name).spawn(move || {
        let listener = match TcpListener::bind(&addr) {
            Ok(listener) => listener,
            Err(err) => {
                log::error!("gdb-remote: bind {} failed: {}", addr, err);
                return;
            }
        };
        log::info!("gdb-remote: listening on {}", addr);
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                continue;
            };
            if let Err(err) = GdbSession::new(stream, controller.as_ref()).serve() {
                log::warn!("gdb-remote: client session failed: {}", err);
            }
        }
    });
    if let Err(err) = spawn_result {
        log::error!("gdb-remote: spawn server thread failed: {}", err);
    }
}

struct GdbSession<'a> {
    stream: TcpStream,
    controller: &'a DebugController,
    no_ack: bool,
    list_threads_in_stop_reply: bool,
    non_stop: bool,
    current_thread: u32,
    client_features: ClientFeatures,
}

enum StepOverOutcome {
    NotNeeded,
    Completed,
    Replied,
}

#[derive(Clone, Copy)]
struct StopMetadata {
    signal: u8,
    reason_name: &'static str,
    stop_kind: Option<StopKind>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopKind {
    SwBreak,
    HwBreak,
    Watch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BreakpointType {
    Software,
    Hardware,
    WriteWatch,
    ReadWatch,
    AccessWatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BreakpointOp {
    Insert,
    Remove,
}

#[derive(Clone, Copy, Default)]
struct ClientFeatures {
    swbreak: bool,
    hwbreak: bool,
}

impl<'a> GdbSession<'a> {
    fn new(stream: TcpStream, controller: &'a DebugController) -> Self {
        Self {
            stream,
            controller,
            no_ack: false,
            list_threads_in_stop_reply: false,
            non_stop: false,
            current_thread: 1,
            client_features: ClientFeatures::default(),
        }
    }

    fn serve(&mut self) -> std::io::Result<()> {
        self.stream.set_nodelay(true)?;
        loop {
            let Some(packet) = self.read_packet()? else {
                return Ok(());
            };
            if packet.as_slice() == INTERRUPT_PACKET {
                if self.controller.state() != DebugState::Paused && !self.supports_async_interrupt()
                {
                    continue;
                }
                if self
                    .controller
                    .request_pause_all(StopReason::ManualPause)
                    .is_err()
                {
                    self.write_packet("E04")?;
                } else {
                    self.sync_current_thread_to_stop_source();
                    self.write_packet(&self.stop_reply_for_current())?;
                }
                continue;
            }
            let keep_running = self.handle_packet(&packet)?;
            if !keep_running {
                return Ok(());
            }
        }
    }

    fn handle_packet(&mut self, packet: &[u8]) -> std::io::Result<bool> {
        if packet.starts_with(b"X") {
            self.handle_write_memory_binary(packet)?;
            return Ok(true);
        }

        let Ok(packet) = std::str::from_utf8(packet) else {
            self.write_packet("")?;
            return Ok(true);
        };

        match packet {
            "QStartNoAckMode" => {
                self.write_packet("OK")?;
                self.no_ack = true;
            }
            _ if packet.starts_with("qSupported") => {
                self.client_features = parse_qsupported_features(packet);
                self.write_packet(&self.qsupported_reply())?;
            }
            _ if packet.starts_with("qXfer:features:read:") => {
                self.handle_qxfer_features_read(packet)?;
            }
            "qAttached" => self.write_packet("1")?,
            "qHostInfo" => {
                self.write_packet(&self.host_info_reply())?;
            }
            "qProcessInfo" => {
                self.write_packet(
                    "pid:1;endian:little;ptrsize:8;ostype:windows;vendor:winemu;arch:aarch64;triple:aarch64-pc-windows-msvc;",
                )?;
            }
            "qOffsets" => self.write_packet("Text=0;Data=0;Bss=0")?,
            "qSymbol::" => self.write_packet("OK")?,
            "qTStatus" | "qTfV" | "qTsV" => self.write_packet("")?,
            "qfThreadInfo" => self.write_packet(&self.thread_list_packet())?,
            "qsThreadInfo" => self.write_packet("l")?,
            "qC" => self.write_packet(&format!("QC{:x}", self.reported_thread_id()))?,
            "QEnableErrorStrings" => self.write_packet("OK")?,
            _ if packet.starts_with("qMemoryRegionInfo:") => {
                self.handle_memory_region_info(packet)?;
            }
            "qThreadSuffixSupported"
            | "QThreadSuffixSupported"
            | "qVAttachOrWaitSupported"
            | "qStructuredDataPlugins"
            | "vMustReplyEmpty" => self.write_packet("")?,
            "QListThreadsInStopReply" => {
                self.list_threads_in_stop_reply = true;
                self.write_packet("OK")?;
            }
            "vStopped" => self.write_packet("OK")?,
            _ if packet.starts_with("QNonStop:") => self.handle_non_stop(packet)?,
            "vCont?" => self.write_packet(&self.vcont_reply())?,
            "?" => {
                self.ensure_paused();
                self.sync_current_thread_to_stop_source();
                self.write_packet(&self.stop_reply_for_current())?;
            }
            _ if packet.starts_with("Hc") || packet.starts_with("Hg") => {
                self.handle_thread_select(packet);
                self.write_packet("OK")?;
            }
            _ if packet.starts_with("qThreadExtraInfo,") => {
                self.handle_thread_extra_info(packet)?;
            }
            _ if packet.starts_with("qThreadStopInfo") => {
                self.handle_thread_stop_info(packet)?;
            }
            _ if packet.starts_with("qRegisterInfo") => {
                self.handle_register_info(packet)?;
            }
            "g" => self.handle_read_all_registers()?,
            _ if packet.starts_with('G') => self.handle_write_all_registers(packet)?,
            _ if packet.starts_with('p') => self.handle_read_register(packet)?,
            _ if packet.starts_with('P') => self.handle_write_register(packet)?,
            _ if packet.starts_with('m') => self.handle_read_memory_hex(packet)?,
            _ if packet.starts_with('M') => self.handle_write_memory_hex(packet)?,
            _ if packet.starts_with('x') => self.handle_read_memory_binary(packet)?,
            _ if packet.starts_with('Z') || packet.starts_with('z') => {
                self.handle_breakpoint_packet(packet)?
            }
            _ if is_legacy_resume_packet(packet) => self.handle_legacy_resume_packet(packet)?,
            _ if packet.starts_with("vCont;") => {
                self.handle_vcont(packet)?;
            }
            "D" | "k" => {
                self.write_packet("OK")?;
                return Ok(false);
            }
            _ if packet.starts_with("QThreadEvents")
                || packet.starts_with("QPassSignals")
                || packet.starts_with("QProgramSignals") =>
            {
                self.write_packet("OK")?;
            }
            "jThreadsInfo" => {
                self.write_packet(&self.thread_infos_json())?;
            }
            _ if packet.starts_with("jThreadExtendedInfo") => {
                self.handle_thread_extended_info(packet)?;
            }
            _ => self.write_packet("")?,
        }
        Ok(true)
    }

    fn ensure_paused(&mut self) {
        if self.controller.state() == DebugState::Paused {
            return;
        }
        let _ = self.controller.request_pause_all(StopReason::ManualPause);
    }

    fn handle_continue(&mut self) -> std::io::Result<()> {
        self.ensure_paused();
        if let Some(vcpu_id) = self.current_vcpu_id() {
            if let StepOverOutcome::Replied = self.step_over_current_software_breakpoint(vcpu_id)? {
                return Ok(());
            }
        }
        self.controller.resume_all();
        self.wait_for_continue_stop_reply()?;
        Ok(())
    }

    fn handle_step(&mut self, thread_id: Option<u32>) -> std::io::Result<()> {
        self.ensure_paused();
        if !self.supports_single_step() {
            return self.write_packet("E04");
        }
        let thread_id = thread_id.unwrap_or(self.current_thread);
        let Some(vcpu_id) = thread_id_to_vcpu_id(thread_id)
            .filter(|vcpu_id| self.controller.snapshot(*vcpu_id).is_some())
            .or_else(|| self.controller.primary_paused_vcpu())
        else {
            return self.write_packet("E03");
        };
        self.current_thread = vcpu_id + 1;
        match self.step_over_current_software_breakpoint(vcpu_id)? {
            StepOverOutcome::NotNeeded => {}
            StepOverOutcome::Completed => {
                self.sync_current_thread_to_stop_source();
                self.write_packet(&self.stop_reply_for_current())?;
                return Ok(());
            }
            StepOverOutcome::Replied => return Ok(()),
        }
        match self.controller.step_vcpu(vcpu_id) {
            Ok(()) => {}
            Err(_) => return self.write_packet("E04"),
        }
        match self
            .controller
            .wait_for_pause_or_shutdown(WAIT_POLL_INTERVAL)
        {
            super::controller::WaitOutcome::Paused => {
                self.sync_current_thread_to_stop_source();
                self.write_packet(&self.stop_reply_for_current())?;
            }
            super::controller::WaitOutcome::Shutdown => {
                self.write_packet("W00")?;
            }
        }
        Ok(())
    }

    fn handle_breakpoint_packet(&mut self, packet: &str) -> std::io::Result<()> {
        let Some((op, bp_type, addr, kind)) = parse_breakpoint_packet(packet) else {
            return self.write_packet("E01");
        };
        if !breakpoint_type_supported(self.debug_caps(), bp_type) {
            log::debug!(
                "gdb-remote: unsupported breakpoint packet op={:?} type={:?} addr={:#x} kind={}",
                op,
                bp_type,
                addr,
                kind
            );
            return self.write_packet("");
        }
        match (op, bp_type) {
            (BreakpointOp::Insert, BreakpointType::Software) => {
                self.handle_insert_software_breakpoint(addr, kind)
            }
            (BreakpointOp::Remove, BreakpointType::Software) => {
                self.handle_remove_software_breakpoint(addr, kind)
            }
            _ => self.write_packet(""),
        }
    }

    fn handle_insert_software_breakpoint(&mut self, addr: u64, kind: usize) -> std::io::Result<()> {
        self.ensure_paused();
        match self
            .controller
            .insert_software_breakpoint(self.current_vcpu_id(), addr, kind)
        {
            Ok(()) => self.write_packet("OK"),
            Err(err) => {
                log::debug!(
                    "gdb-remote: insert software breakpoint failed addr={:#x} kind={} err={}",
                    addr,
                    kind,
                    err
                );
                self.write_packet("E04")
            }
        }
    }

    fn handle_remove_software_breakpoint(&mut self, addr: u64, kind: usize) -> std::io::Result<()> {
        self.ensure_paused();
        match self
            .controller
            .remove_software_breakpoint(self.current_vcpu_id(), addr, kind)
        {
            Ok(()) => self.write_packet("OK"),
            Err(err) => {
                log::debug!(
                    "gdb-remote: remove software breakpoint failed addr={:#x} kind={} err={}",
                    addr,
                    kind,
                    err
                );
                self.write_packet("E04")
            }
        }
    }

    fn handle_vcont(&mut self, packet: &str) -> std::io::Result<()> {
        let Some(action) = parse_vcont(packet) else {
            return self.write_packet("");
        };
        match action {
            VContAction::Continue => self.handle_continue(),
            VContAction::Step(thread_id) => self.handle_step(thread_id),
        }
    }

    fn handle_legacy_resume_packet(&mut self, packet: &str) -> std::io::Result<()> {
        let Some(action) = parse_legacy_resume_packet(packet) else {
            return self.write_packet("");
        };
        match action {
            LegacyResumeAction::Continue { addr } => {
                self.ensure_paused();
                if let Some(addr) = addr {
                    self.set_resume_address(None, addr)?;
                }
                self.handle_continue()
            }
            LegacyResumeAction::Step { addr } => {
                self.ensure_paused();
                if let Some(addr) = addr {
                    self.set_resume_address(None, addr)?;
                }
                self.handle_step(None)
            }
        }
    }

    fn step_over_current_software_breakpoint(
        &mut self,
        vcpu_id: u32,
    ) -> std::io::Result<StepOverOutcome> {
        let Some(key) = self.controller.paused_software_breakpoint_key(vcpu_id) else {
            return Ok(StepOverOutcome::NotNeeded);
        };

        if self
            .controller
            .temporarily_disable_software_breakpoint(vcpu_id, key)
            .is_err()
        {
            self.write_packet("E04")?;
            return Ok(StepOverOutcome::Replied);
        }

        if self.controller.step_vcpu(vcpu_id).is_err() {
            let _ = self.controller.reenable_software_breakpoint(vcpu_id, key);
            self.write_packet("E04")?;
            return Ok(StepOverOutcome::Replied);
        }

        match self
            .controller
            .wait_for_pause_or_shutdown(WAIT_POLL_INTERVAL)
        {
            super::controller::WaitOutcome::Paused => {
                if self
                    .controller
                    .reenable_software_breakpoint(vcpu_id, key)
                    .is_err()
                {
                    self.write_packet("E04")?;
                    return Ok(StepOverOutcome::Replied);
                }
                Ok(StepOverOutcome::Completed)
            }
            super::controller::WaitOutcome::Shutdown => {
                self.write_packet("W00")?;
                Ok(StepOverOutcome::Replied)
            }
        }
    }

    fn wait_for_continue_stop_reply(&mut self) -> std::io::Result<()> {
        self.stream.set_nonblocking(true)?;
        let result = loop {
            if let Some(outcome) = self.controller.poll_pause_or_shutdown(WAIT_POLL_INTERVAL) {
                match outcome {
                    super::controller::WaitOutcome::Paused => {
                        self.sync_current_thread_to_stop_source();
                        break self.write_packet(&self.stop_reply_for_current());
                    }
                    super::controller::WaitOutcome::Shutdown => break self.write_packet("W00"),
                }
            }
            if self.supports_async_interrupt() && self.poll_running_interrupt()? {
                let _ = self.controller.request_pause_all(StopReason::ManualPause);
            }
        };
        let restore = self.stream.set_nonblocking(false);
        match (result, restore) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(err), _) => Err(err),
            (Ok(()), Err(err)) => Err(err),
        }
    }

    fn poll_running_interrupt(&mut self) -> std::io::Result<bool> {
        let mut peek = [0u8; 1];
        match self.stream.peek(&mut peek) {
            Ok(0) => Ok(false),
            Ok(_) if peek[0] == 0x03 => {
                let mut consume = [0u8; 1];
                let _ = self.stream.read(&mut consume)?;
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn handle_thread_select(&mut self, packet: &str) {
        let thread_text = &packet[2..];
        if thread_text == "-1" || thread_text == "0" || thread_text.is_empty() {
            return;
        }
        if let Ok(thread_id) = u32::from_str_radix(thread_text, 16) {
            if self.controller.thread_ids().contains(&thread_id) {
                self.current_thread = thread_id;
            }
        }
    }

    fn handle_thread_stop_info(&mut self, packet: &str) -> std::io::Result<()> {
        let thread_text = packet.trim_start_matches("qThreadStopInfo");
        if self.controller.state() != DebugState::Paused {
            return self.write_packet("OK");
        }
        let thread_id = if thread_text.is_empty() {
            self.reported_thread_id()
        } else if let Ok(thread_id) = u32::from_str_radix(thread_text, 16) {
            thread_id
        } else {
            return self.write_packet("OK");
        };
        if !self.controller.thread_ids().contains(&thread_id) {
            return self.write_packet("OK");
        }
        self.write_packet(&self.stop_reply_for_thread(thread_id))
    }

    fn handle_thread_extra_info(&mut self, packet: &str) -> std::io::Result<()> {
        let Some(thread_text) = packet.strip_prefix("qThreadExtraInfo,") else {
            return self.write_packet("E01");
        };
        let Ok(thread_id) = u32::from_str_radix(thread_text, 16) else {
            return self.write_packet("OK");
        };
        if !self.controller.thread_ids().contains(&thread_id) {
            return self.write_packet("OK");
        }
        let info = self.thread_extra_info(thread_id);
        self.write_packet(&encode_hex(info.as_bytes()))
    }

    fn handle_qxfer_features_read(&mut self, packet: &str) -> std::io::Result<()> {
        let Some((annex, offset, length)) = parse_qxfer_features_read(packet) else {
            return self.write_packet("E01");
        };
        if annex != "target.xml" {
            return self.write_packet("");
        }
        self.write_packet(&qfer_read_reply(TARGET_XML.as_bytes(), offset, length))
    }

    fn handle_non_stop(&mut self, packet: &str) -> std::io::Result<()> {
        match packet {
            "QNonStop:0" => {
                self.non_stop = false;
                self.write_packet("OK")
            }
            "QNonStop:1" => self.write_packet(""),
            _ => self.write_packet("E01"),
        }
    }

    fn handle_register_info(&mut self, packet: &str) -> std::io::Result<()> {
        let index_text = packet.trim_start_matches("qRegisterInfo");
        let Ok(index) = usize::from_str_radix(index_text, 16) else {
            return self.write_packet("E01");
        };
        let Some(info) = register_info(index) else {
            return self.write_packet("");
        };
        self.write_packet(&info)
    }

    fn handle_memory_region_info(&mut self, packet: &str) -> std::io::Result<()> {
        let addr_text = packet.trim_start_matches("qMemoryRegionInfo:");
        let Ok(addr) = u64::from_str_radix(addr_text, 16) else {
            return self.write_packet("E01");
        };
        let start = addr & !0xfff_u64;
        let size = 0x1000_u64;
        self.write_packet(&format!(
            "start:{:x};size:{:x};permissions:rwx;",
            start, size
        ))
    }

    fn handle_read_all_registers(&mut self) -> std::io::Result<()> {
        let Some(snapshot) = self.current_snapshot() else {
            return self.write_packet("E01");
        };
        self.write_packet(&encode_all_registers(snapshot))
    }

    fn handle_write_all_registers(&mut self, packet: &str) -> std::io::Result<()> {
        let Some(vcpu_id) = self.current_vcpu_id() else {
            return self.write_packet("E03");
        };
        let Some(raw) = decode_hex_bytes(&packet[1..]) else {
            return self.write_packet("E01");
        };
        match self.controller.replace_gdb_register_file(vcpu_id, &raw) {
            Ok(()) => self.write_packet("OK"),
            Err(_) => self.write_packet("E04"),
        }
    }

    fn handle_read_register(&mut self, packet: &str) -> std::io::Result<()> {
        let Some(snapshot) = self.current_snapshot() else {
            return self.write_packet("E01");
        };
        let Ok(index) = usize::from_str_radix(&packet[1..], 16) else {
            return self.write_packet("E01");
        };
        let Some(value) = encode_register(&snapshot, index) else {
            return self.write_packet("E01");
        };
        self.write_packet(&value)
    }

    fn handle_write_register(&mut self, packet: &str) -> std::io::Result<()> {
        let Some(vcpu_id) = self.current_vcpu_id() else {
            return self.write_packet("E03");
        };
        let Some((index_text, value_text)) = packet[1..].split_once('=') else {
            return self.write_packet("E01");
        };
        let Ok(index) = usize::from_str_radix(index_text, 16) else {
            return self.write_packet("E01");
        };
        let Some(raw) = decode_hex_bytes(value_text) else {
            return self.write_packet("E01");
        };
        match self.controller.set_gdb_register(vcpu_id, index, &raw) {
            Ok(()) => self.write_packet("OK"),
            Err(_) => self.write_packet("E04"),
        }
    }

    fn handle_read_memory_hex(&mut self, packet: &str) -> std::io::Result<()> {
        let Some((addr, len)) = parse_memory_request(&packet[1..]) else {
            return self.write_packet("E01");
        };
        if len > MAX_READ_LEN {
            return self.write_packet("E02");
        }
        match self
            .controller
            .read_guest_virt_resolved(self.current_vcpu_id(), addr, len)
        {
            Ok(bytes) => self.write_packet(&encode_hex(&bytes)),
            Err(_) => self.write_packet("E04"),
        }
    }

    fn handle_read_memory_binary(&mut self, packet: &str) -> std::io::Result<()> {
        let Some((addr, len)) = parse_memory_request(&packet[1..]) else {
            return self.write_packet("E01");
        };
        if len > MAX_READ_LEN {
            return self.write_packet("E02");
        }
        if len == 0 {
            return self.write_packet("");
        }
        match self
            .controller
            .read_guest_virt_resolved(self.current_vcpu_id(), addr, len)
        {
            Ok(bytes) => self.write_binary_packet(&bytes),
            Err(_) => self.write_packet("E04"),
        }
    }

    fn handle_write_memory_hex(&mut self, packet: &str) -> std::io::Result<()> {
        let Some((range_text, value_text)) = packet[1..].split_once(':') else {
            return self.write_packet("E01");
        };
        let Some((addr, len)) = parse_memory_request(range_text) else {
            return self.write_packet("E01");
        };
        let Some(raw) = decode_hex_bytes(value_text) else {
            return self.write_packet("E01");
        };
        if raw.len() != len || len > MAX_READ_LEN {
            return self.write_packet("E02");
        }
        match self
            .controller
            .write_guest_virt_resolved(self.current_vcpu_id(), addr, &raw)
        {
            Ok(()) => self.write_packet("OK"),
            Err(_) => self.write_packet("E04"),
        }
    }

    fn handle_write_memory_binary(&mut self, packet: &[u8]) -> std::io::Result<()> {
        let Some(colon) = packet.iter().position(|byte| *byte == b':') else {
            return self.write_packet("E01");
        };
        let Ok(header) = std::str::from_utf8(&packet[1..colon]) else {
            return self.write_packet("E01");
        };
        let Some((addr, len)) = parse_memory_request(header) else {
            return self.write_packet("E01");
        };
        if len > MAX_READ_LEN {
            return self.write_packet("E02");
        }
        let Some(raw) = unescape_binary(&packet[colon + 1..]) else {
            return self.write_packet("E01");
        };
        if raw.len() != len {
            return self.write_packet("E02");
        }
        match self
            .controller
            .write_guest_virt_resolved(self.current_vcpu_id(), addr, &raw)
        {
            Ok(()) => self.write_packet("OK"),
            Err(_) => self.write_packet("E04"),
        }
    }

    fn handle_thread_extended_info(&mut self, packet: &str) -> std::io::Result<()> {
        let thread_id = packet
            .strip_prefix("jThreadExtendedInfo:")
            .and_then(parse_thread_id_suffix)
            .unwrap_or(self.current_thread);
        self.write_packet(&self.thread_extended_info_json(thread_id))
    }

    fn current_snapshot(&self) -> Option<VcpuSnapshot> {
        self.current_vcpu_id()
            .and_then(|vcpu_id| self.controller.snapshot(vcpu_id))
    }

    fn debug_caps(&self) -> DebugCaps {
        self.controller.debug_caps()
    }

    fn supports_single_step(&self) -> bool {
        supports_single_step(self.debug_caps())
    }

    fn supports_async_interrupt(&self) -> bool {
        self.debug_caps().async_interrupt
    }

    fn current_vcpu_id(&self) -> Option<u32> {
        thread_id_to_vcpu_id(self.current_thread)
            .filter(|vcpu_id| self.controller.snapshot(*vcpu_id).is_some())
            .or_else(|| self.controller.primary_paused_vcpu())
    }

    fn stop_thread_id(&self) -> Option<u32> {
        self.controller.stop_vcpu_id().map(|vcpu_id| vcpu_id + 1)
    }

    fn reported_thread_id(&self) -> u32 {
        self.stop_thread_id().unwrap_or(self.current_thread)
    }

    fn sync_current_thread_to_stop_source(&mut self) {
        if let Some(thread_id) = self.stop_thread_id() {
            self.current_thread = thread_id;
        }
    }

    fn set_resume_address(&mut self, thread_id: Option<u32>, addr: u64) -> std::io::Result<()> {
        let thread_id = thread_id.unwrap_or_else(|| self.reported_thread_id());
        let Some(vcpu_id) = thread_id_to_vcpu_id(thread_id)
            .filter(|vcpu_id| self.controller.snapshot(*vcpu_id).is_some())
            .or_else(|| self.controller.primary_paused_vcpu())
        else {
            return self.write_packet("E03");
        };
        match self
            .controller
            .set_gdb_register(vcpu_id, 32, &addr.to_le_bytes())
        {
            Ok(()) => {
                self.current_thread = vcpu_id + 1;
                Ok(())
            }
            Err(_) => self.write_packet("E04"),
        }
    }

    fn stop_reply_for_current(&self) -> String {
        self.stop_reply_for_thread(self.reported_thread_id())
    }

    fn stop_reply_for_thread(&self, thread_id: u32) -> String {
        let thread_id = if self.controller.thread_ids().contains(&thread_id) {
            thread_id
        } else {
            self.controller.thread_ids().into_iter().next().unwrap_or(1)
        };
        let snapshot = thread_id_to_vcpu_id(thread_id)
            .and_then(|vcpu_id| self.controller.snapshot(vcpu_id));
        let metadata = self
            .thread_stop_metadata(thread_id)
            .unwrap_or(default_stop_metadata());
        let mut reply = format!("T{:02x}", metadata.signal);
        if let Some(field) = stop_kind_field(
            metadata.stop_kind,
            snapshot.as_ref(),
            self.client_features,
            self.debug_caps(),
        ) {
            reply.push_str(&field);
        }
        if let Some(field) = stop_reason_field(snapshot.as_ref(), metadata) {
            reply.push_str(&field);
        }
        if let Some(field) = stop_pc_field(snapshot.as_ref()) {
            reply.push_str(&field);
        }
        let _ = write!(reply, "thread:{:x};", thread_id);
        if self.list_threads_in_stop_reply {
            let thread_ids = self.controller.thread_ids();
            if let Some(field) = format_threads_stop_field(&thread_ids) {
                reply.push_str(&field);
            }
            if let Some(field) = format_thread_pcs_stop_field(self.controller, &thread_ids) {
                reply.push_str(&field);
            }
        }
        reply
    }

    fn thread_list_packet(&self) -> String {
        let ids = self.controller.thread_ids();
        if ids.is_empty() {
            return "l".to_string();
        }
        let mut out = String::from("m");
        for (index, thread_id) in ids.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            let _ = write!(out, "{:x}", thread_id);
        }
        out
    }

    fn thread_infos_json(&self) -> String {
        let mut out = String::from("[");
        for (index, thread_id) in self.controller.thread_ids().into_iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            out.push_str(&self.thread_info_json(thread_id));
        }
        out.push(']');
        out
    }

    fn thread_extended_info_json(&self, thread_id: u32) -> String {
        let name = thread_name(thread_id);
        let triggered = self.thread_matches_stop_source(thread_id);
        let reason = self
            .thread_stop_metadata(thread_id)
            .map_or("signal", |metadata| metadata.reason_name);
        format!(
            "{{\"tid\":{},\"name\":\"{}\",\"queue\":\"kernel\",\"state\":\"stopped\",\"reason\":\"{}\",\"triggered\":{}}}",
            thread_id, name, reason, triggered
        )
    }

    fn thread_extra_info(&self, thread_id: u32) -> String {
        let name = thread_name(thread_id);
        let triggered = self.thread_matches_stop_source(thread_id);
        let reason = self
            .thread_stop_metadata(thread_id)
            .map_or("signal", |metadata| metadata.reason_name);
        if triggered {
            format!("{name} ({reason}, triggered)")
        } else {
            format!("{name} ({reason})")
        }
    }

    fn thread_info_json(&self, thread_id: u32) -> String {
        let mut out = String::new();
        let name = thread_name(thread_id);
        let triggered = self.thread_matches_stop_source(thread_id);
        let metadata = self
            .thread_stop_metadata(thread_id)
            .unwrap_or(default_stop_metadata());
        let _ = write!(
            out,
            "{{\"tid\":{},\"name\":\"{}\",\"reason\":\"{}\",\"signal\":{},\"triggered\":{},\"registers\":{{",
            thread_id, name, metadata.reason_name, metadata.signal, triggered
        );
        if let Some(vcpu_id) = thread_id_to_vcpu_id(thread_id) {
            if let Some(snapshot) = self.controller.snapshot(vcpu_id) {
                for index in 0..34 {
                    if let Some(value) = encode_thread_register_value(&snapshot, index) {
                        if index != 0 {
                            out.push(',');
                        }
                        let _ = write!(out, "\"{}\":\"{}\"", index, value);
                    }
                }
            }
        }
        out.push_str("}}");
        out
    }

    fn thread_stop_metadata(&self, thread_id: u32) -> Option<StopMetadata> {
        let vcpu_id = thread_id_to_vcpu_id(thread_id)?;
        let snapshot = self.controller.snapshot(vcpu_id)?;
        Some(stop_metadata(
            &snapshot,
            self.thread_matches_stop_source(thread_id),
        ))
    }

    fn thread_matches_stop_source(&self, thread_id: u32) -> bool {
        self.stop_thread_id()
            .map(|stop_thread_id| stop_thread_id == thread_id)
            .unwrap_or(true)
    }

    fn read_packet(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let mut byte = [0u8; 1];
        loop {
            let read = self.stream.read(&mut byte)?;
            if read == 0 {
                return Ok(None);
            }
            match byte[0] {
                b'+' | b'-' => continue,
                0x03 => return Ok(Some(INTERRUPT_PACKET.to_vec())),
                b'$' => break,
                _ => continue,
            }
        }
        let mut payload = Vec::new();
        loop {
            let read = self.stream.read(&mut byte)?;
            if read == 0 {
                return Ok(None);
            }
            if byte[0] == b'#' {
                break;
            }
            payload.push(byte[0]);
        }
        let mut checksum = [0u8; 2];
        self.stream.read_exact(&mut checksum)?;
        if !self.no_ack {
            self.stream.write_all(b"+")?;
            self.stream.flush()?;
        }
        Ok(Some(payload))
    }

    fn write_packet(&mut self, payload: &str) -> std::io::Result<()> {
        self.write_escaped_packet(payload.as_bytes())
    }

    fn write_binary_packet(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let escaped = escape_binary(payload);
        self.write_packet_bytes(&escaped)
    }

    fn write_escaped_packet(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let escaped = escape_binary(payload);
        self.write_packet_bytes(&escaped)
    }

    fn write_packet_bytes(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(b"$")?;
        self.stream.write_all(payload)?;
        self.stream.write_all(b"#")?;
        self.stream
            .write_all(format!("{:02x}", checksum(payload)).as_bytes())?;
        self.stream.flush()
    }

    fn qsupported_reply(&self) -> String {
        qsupported_reply_for_caps(self.debug_caps())
    }

    fn host_info_reply(&self) -> String {
        host_info_reply_for_caps(self.debug_caps())
    }

    fn vcont_reply(&self) -> String {
        vcont_reply_for_caps(self.debug_caps())
    }
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, byte| acc.wrapping_add(*byte))
}

fn parse_memory_request(text: &str) -> Option<(u64, usize)> {
    let (addr, len) = text.split_once(',')?;
    let addr = u64::from_str_radix(addr, 16).ok()?;
    let len = usize::from_str_radix(len, 16).ok()?;
    Some((addr, len))
}

fn parse_qsupported_features(packet: &str) -> ClientFeatures {
    let mut features = ClientFeatures::default();
    let Some(rest) = packet.strip_prefix("qSupported") else {
        return features;
    };
    let rest = rest.strip_prefix(':').unwrap_or(rest);
    for feature in rest.split(';') {
        match feature {
            "swbreak+" => features.swbreak = true,
            "hwbreak+" => features.hwbreak = true,
            _ => {}
        }
    }
    features
}

fn parse_breakpoint_packet(text: &str) -> Option<(BreakpointOp, BreakpointType, u64, usize)> {
    let op = match text.as_bytes().first()? {
        b'Z' => BreakpointOp::Insert,
        b'z' => BreakpointOp::Remove,
        _ => return None,
    };
    let (type_text, rest) = text[1..].split_once(',')?;
    let bp_type = match type_text {
        "0" => BreakpointType::Software,
        "1" => BreakpointType::Hardware,
        "2" => BreakpointType::WriteWatch,
        "3" => BreakpointType::ReadWatch,
        "4" => BreakpointType::AccessWatch,
        _ => return None,
    };
    let (addr_text, kind_text) = rest.split_once(',')?;
    let addr = u64::from_str_radix(addr_text, 16).ok()?;
    let kind = usize::from_str_radix(kind_text, 16).ok()?;
    Some((op, bp_type, addr, kind))
}

fn decode_hex_bytes(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut chars = text.as_bytes().chunks_exact(2);
    for chunk in &mut chars {
        let hi = decode_hex_nibble(chunk[0])?;
        let lo = decode_hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

fn encode_u64(value: u64) -> String {
    encode_hex(&value.to_le_bytes())
}

fn encode_u32(value: u32) -> String {
    encode_hex(&value.to_le_bytes())
}

fn escape_binary(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for byte in bytes {
        match *byte {
            b'#' | b'$' | b'}' | b'*' => {
                out.push(b'}');
                out.push(*byte ^ 0x20);
            }
            _ => out.push(*byte),
        }
    }
    out
}

fn unescape_binary(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'}' {
            let next = *bytes.get(index + 1)?;
            out.push(next ^ 0x20);
            index += 2;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Some(out)
}

fn thread_id_to_vcpu_id(thread_id: u32) -> Option<u32> {
    thread_id.checked_sub(1)
}

fn parse_thread_id_suffix(text: &str) -> Option<u32> {
    if text.is_empty() {
        return None;
    }
    u32::from_str_radix(text, 16).ok()
}

fn thread_name(thread_id: u32) -> String {
    match thread_id_to_vcpu_id(thread_id) {
        Some(vcpu_id) => format!("vcpu{}", vcpu_id),
        None => format!("thread{}", thread_id),
    }
}

fn default_stop_metadata() -> StopMetadata {
    StopMetadata {
        signal: SIGTRAP_SIGNAL,
        reason_name: "signal",
        stop_kind: None,
    }
}

fn stop_metadata(snapshot: &VcpuSnapshot, triggered: bool) -> StopMetadata {
    if !triggered {
        return StopMetadata {
            signal: STOPPED_SIGNAL,
            reason_name: "stopped",
            stop_kind: None,
        };
    }
    match snapshot.reason {
        StopReason::ManualPause => StopMetadata {
            signal: SIGINT_SIGNAL,
            reason_name: "interrupt",
            stop_kind: None,
        },
        StopReason::GuestDebugTrap { code, .. } => {
            if code == DEBUG_TRAP_AUTO_PAUSE_KERNEL_READY {
                StopMetadata {
                    signal: SIGTRAP_SIGNAL,
                    reason_name: "kernel-ready",
                    stop_kind: None,
                }
            } else {
                StopMetadata {
                    signal: SIGTRAP_SIGNAL,
                    reason_name: "breakpoint",
                    stop_kind: Some(StopKind::SwBreak),
                }
            }
        }
        StopReason::DebugException { syndrome, .. } => {
            let ec = (syndrome >> 26) & 0x3f;
            match ec {
                ESR_EC_BRK64 => StopMetadata {
                    signal: SIGTRAP_SIGNAL,
                    reason_name: "breakpoint",
                    stop_kind: Some(StopKind::SwBreak),
                },
                ESR_EC_DEBUG_LOWER_EL | ESR_EC_DEBUG_CURRENT_EL => StopMetadata {
                    signal: SIGTRAP_SIGNAL,
                    reason_name: "breakpoint",
                    stop_kind: Some(StopKind::HwBreak),
                },
                ESR_EC_SOFTWARE_STEP_LOWER_EL | ESR_EC_SOFTWARE_STEP_CURRENT_EL => StopMetadata {
                    signal: SIGTRAP_SIGNAL,
                    reason_name: "trace",
                    stop_kind: None,
                },
                ESR_EC_WATCHPOINT_LOWER_EL | ESR_EC_WATCHPOINT_CURRENT_EL => StopMetadata {
                    signal: SIGTRAP_SIGNAL,
                    reason_name: "watchpoint",
                    stop_kind: Some(StopKind::Watch),
                },
                _ => default_stop_metadata(),
            }
        }
    }
}

fn stop_kind_field(
    kind: Option<StopKind>,
    snapshot: Option<&VcpuSnapshot>,
    client_features: ClientFeatures,
    caps: DebugCaps,
) -> Option<String> {
    match kind? {
        StopKind::SwBreak if supports_software_breakpoint(caps) && client_features.swbreak => {
            Some("swbreak:;".to_string())
        }
        StopKind::HwBreak if supports_hardware_breakpoint(caps) && client_features.hwbreak => {
            Some("hwbreak:;".to_string())
        }
        StopKind::Watch if supports_watchpoint(caps) => Some(
            stop_watch_address(snapshot)
                .map(|addr| format!("watch:{:x};", addr))
                .unwrap_or_else(|| "watch:;".to_string()),
        ),
        _ => None,
    }
}

fn stop_pc_field(snapshot: Option<&VcpuSnapshot>) -> Option<String> {
    let pc = encode_register(snapshot?, 32)?;
    Some(format!("20:{};", pc))
}

fn stop_watch_address(snapshot: Option<&VcpuSnapshot>) -> Option<u64> {
    let StopReason::DebugException {
        virtual_address, ..
    } = snapshot?.reason
    else {
        return None;
    };
    (virtual_address != 0).then_some(virtual_address)
}

fn stop_reason_field(snapshot: Option<&VcpuSnapshot>, metadata: StopMetadata) -> Option<String> {
    let snapshot = snapshot?;
    let reason = match snapshot.reason {
        StopReason::ManualPause => "trap",
        StopReason::DebugException { syndrome, .. } => match (syndrome >> 26) & 0x3f {
            ESR_EC_BRK64 | ESR_EC_DEBUG_LOWER_EL | ESR_EC_DEBUG_CURRENT_EL => "breakpoint",
            ESR_EC_SOFTWARE_STEP_LOWER_EL | ESR_EC_SOFTWARE_STEP_CURRENT_EL => "trace",
            ESR_EC_WATCHPOINT_LOWER_EL | ESR_EC_WATCHPOINT_CURRENT_EL => "watchpoint",
            _ => "signal",
        },
        StopReason::GuestDebugTrap { .. } => {
            if metadata.reason_name == "breakpoint" {
                "breakpoint"
            } else {
                return None;
            }
        }
    };
    Some(format!("reason:{};", reason))
}

fn supports_software_breakpoint(caps: DebugCaps) -> bool {
    caps.debug_exception_trap && caps.sw_breakpoint_candidate
}

fn supports_single_step(caps: DebugCaps) -> bool {
    caps.debug_exception_trap && caps.hw_single_step_candidate
}

fn supports_hardware_breakpoint(caps: DebugCaps) -> bool {
    caps.debug_exception_trap && caps.hw_breakpoint_candidate
}

fn supports_watchpoint(caps: DebugCaps) -> bool {
    caps.debug_exception_trap && caps.watchpoint_candidate
}

fn breakpoint_type_supported(caps: DebugCaps, bp_type: BreakpointType) -> bool {
    match bp_type {
        BreakpointType::Software => supports_software_breakpoint(caps),
        BreakpointType::Hardware => supports_hardware_breakpoint(caps),
        BreakpointType::WriteWatch | BreakpointType::ReadWatch | BreakpointType::AccessWatch => {
            supports_watchpoint(caps)
        }
    }
}

fn qsupported_reply_for_caps(caps: DebugCaps) -> String {
    let mut parts = vec![
        "PacketSize=4000".to_string(),
        "QStartNoAckMode+".to_string(),
        "qXfer:features:read+".to_string(),
        "vContSupported+".to_string(),
    ];
    parts.push(if supports_software_breakpoint(caps) {
        "swbreak+".to_string()
    } else {
        "swbreak-".to_string()
    });
    parts.push(if supports_hardware_breakpoint(caps) {
        "hwbreak+".to_string()
    } else {
        "hwbreak-".to_string()
    });
    parts.join(";")
}

fn host_info_reply_for_caps(caps: DebugCaps) -> String {
    let mut info = String::from(
        "triple:aarch64-pc-windows-msvc;endian:little;ptrsize:8;default_packet_timeout:10;",
    );
    if supports_watchpoint(caps) {
        info.push_str("watchpoint_exceptions_received:before;");
    }
    info
}

fn vcont_reply_for_caps(caps: DebugCaps) -> String {
    let mut reply = String::from("vCont;c;C");
    if supports_single_step(caps) {
        reply.push_str(";s;S");
    }
    reply
}

fn format_threads_stop_field(thread_ids: &[u32]) -> Option<String> {
    if thread_ids.is_empty() {
        return None;
    }
    let mut out = String::from("threads:");
    for (index, thread_id) in thread_ids.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        let _ = write!(out, "{:x}", thread_id);
    }
    out.push(';');
    Some(out)
}

fn format_thread_pcs_stop_field(
    controller: &DebugController,
    thread_ids: &[u32],
) -> Option<String> {
    if thread_ids.is_empty() {
        return None;
    }
    let mut out = String::from("thread-pcs:");
    for (index, thread_id) in thread_ids.iter().enumerate() {
        let vcpu_id = thread_id_to_vcpu_id(*thread_id)?;
        let snapshot = controller.snapshot(vcpu_id)?;
        if index != 0 {
            out.push(',');
        }
        let _ = write!(out, "{:x}", snapshot.regs.pc);
    }
    out.push(';');
    Some(out)
}

fn parse_qxfer_features_read(packet: &str) -> Option<(&str, usize, usize)> {
    let rest = packet.strip_prefix("qXfer:features:read:")?;
    let (annex, range) = rest.split_once(':')?;
    let (offset, length) = range.split_once(',')?;
    Some((
        annex,
        usize::from_str_radix(offset, 16).ok()?,
        usize::from_str_radix(length, 16).ok()?,
    ))
}

fn qfer_read_reply(bytes: &[u8], offset: usize, length: usize) -> String {
    if offset >= bytes.len() {
        return "l".to_string();
    }
    let end = offset.saturating_add(length).min(bytes.len());
    let mut out = String::new();
    out.push(if end < bytes.len() { 'm' } else { 'l' });
    out.push_str(std::str::from_utf8(&bytes[offset..end]).unwrap_or(""));
    out
}

fn is_legacy_resume_packet(packet: &str) -> bool {
    packet.starts_with('c')
        || packet.starts_with('s')
        || packet.starts_with('C')
        || packet.starts_with('S')
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VContAction {
    Continue,
    Step(Option<u32>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacyResumeAction {
    Continue { addr: Option<u64> },
    Step { addr: Option<u64> },
}

fn parse_legacy_resume_packet(packet: &str) -> Option<LegacyResumeAction> {
    if let Some(rest) = packet.strip_prefix('c') {
        let addr = if rest.is_empty() {
            None
        } else {
            Some(u64::from_str_radix(rest, 16).ok()?)
        };
        return Some(LegacyResumeAction::Continue { addr });
    }
    if let Some(rest) = packet.strip_prefix('s') {
        let addr = if rest.is_empty() {
            None
        } else {
            Some(u64::from_str_radix(rest, 16).ok()?)
        };
        return Some(LegacyResumeAction::Step { addr });
    }
    if let Some(rest) = packet.strip_prefix('C') {
        return Some(LegacyResumeAction::Continue {
            addr: parse_signaled_resume_address(rest)?,
        });
    }
    if let Some(rest) = packet.strip_prefix('S') {
        return Some(LegacyResumeAction::Step {
            addr: parse_signaled_resume_address(rest)?,
        });
    }
    None
}

fn parse_signaled_resume_address(rest: &str) -> Option<Option<u64>> {
    if rest.len() < 2 {
        return None;
    }
    u8::from_str_radix(&rest[..2], 16).ok()?;
    if rest.len() == 2 {
        return Some(None);
    }
    let addr_text = rest.strip_prefix(&format!("{};", &rest[..2]))?;
    if addr_text.is_empty() {
        return None;
    }
    Some(Some(u64::from_str_radix(addr_text, 16).ok()?))
}

fn parse_vcont(packet: &str) -> Option<VContAction> {
    let mut saw_continue = false;
    let mut step_thread = None;
    for segment in packet.strip_prefix("vCont;")?.split(';') {
        if segment.is_empty() {
            continue;
        }
        let (kind, thread_id) = if let Some((kind, thread_text)) = segment.split_once(':') {
            (kind, parse_thread_id_suffix(thread_text))
        } else {
            (segment, None)
        };
        match parse_vcont_action_kind(kind)? {
            VContAction::Continue => saw_continue = true,
            VContAction::Step(_) => {
                if step_thread.is_some() {
                    return None;
                }
                step_thread = Some(thread_id);
            }
        }
    }
    if let Some(thread_id) = step_thread {
        Some(VContAction::Step(thread_id))
    } else if saw_continue {
        Some(VContAction::Continue)
    } else {
        None
    }
}

fn parse_vcont_action_kind(kind: &str) -> Option<VContAction> {
    if kind == "c" {
        return Some(VContAction::Continue);
    }
    if kind == "s" {
        return Some(VContAction::Step(None));
    }
    if let Some(rest) = kind.strip_prefix('C') {
        parse_vcont_signal(rest)?;
        return Some(VContAction::Continue);
    }
    if let Some(rest) = kind.strip_prefix('S') {
        parse_vcont_signal(rest)?;
        return Some(VContAction::Step(None));
    }
    None
}

fn parse_vcont_signal(text: &str) -> Option<u8> {
    if text.len() != 2 {
        return None;
    }
    u8::from_str_radix(text, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use winemu_hypervisor::{Regs, SpecialRegs};

    fn hvf_like_caps() -> DebugCaps {
        DebugCaps {
            async_interrupt: true,
            debug_exception_trap: true,
            sw_breakpoint_candidate: true,
            hw_single_step_candidate: true,
            hw_breakpoint_candidate: false,
            watchpoint_candidate: false,
        }
    }

    fn snapshot_with_reason(reason: StopReason) -> VcpuSnapshot {
        let mut regs = Regs::default();
        regs.pc = 0x4003_cc28;
        VcpuSnapshot {
            vcpu_id: 0,
            regs,
            special_regs: SpecialRegs::default(),
            reason,
        }
    }

    #[test]
    fn parse_breakpoint_packet_supports_standard_gdb_types() {
        assert_eq!(
            parse_breakpoint_packet("Z0,4001371c,4"),
            Some((
                BreakpointOp::Insert,
                BreakpointType::Software,
                0x4001_371c,
                4,
            ))
        );
        assert_eq!(
            parse_breakpoint_packet("z1,1234,4"),
            Some((BreakpointOp::Remove, BreakpointType::Hardware, 0x1234, 4))
        );
        assert_eq!(
            parse_breakpoint_packet("Z2,1000,8"),
            Some((BreakpointOp::Insert, BreakpointType::WriteWatch, 0x1000, 8))
        );
        assert_eq!(
            parse_breakpoint_packet("Z3,1000,8"),
            Some((BreakpointOp::Insert, BreakpointType::ReadWatch, 0x1000, 8))
        );
        assert_eq!(
            parse_breakpoint_packet("Z4,1000,8"),
            Some((BreakpointOp::Insert, BreakpointType::AccessWatch, 0x1000, 8))
        );
        assert_eq!(parse_breakpoint_packet("Z9,1000,4"), None);
        assert_eq!(parse_breakpoint_packet("bad"), None);
    }

    #[test]
    fn parse_legacy_resume_packet_supports_signal_and_address_forms() {
        assert_eq!(
            parse_legacy_resume_packet("c"),
            Some(LegacyResumeAction::Continue { addr: None })
        );
        assert_eq!(
            parse_legacy_resume_packet("s4001371c"),
            Some(LegacyResumeAction::Step {
                addr: Some(0x4001_371c),
            })
        );
        assert_eq!(
            parse_legacy_resume_packet("C05"),
            Some(LegacyResumeAction::Continue { addr: None })
        );
        assert_eq!(
            parse_legacy_resume_packet("S05;4001371c"),
            Some(LegacyResumeAction::Step {
                addr: Some(0x4001_371c),
            })
        );
        assert_eq!(parse_legacy_resume_packet("C"), None);
        assert_eq!(parse_legacy_resume_packet("S05;"), None);
    }

    #[test]
    fn parse_vcont_all_stop_shapes() {
        assert_eq!(parse_vcont("vCont;c"), Some(VContAction::Continue));
        assert_eq!(parse_vcont("vCont;C05"), Some(VContAction::Continue));
        assert_eq!(parse_vcont("vCont;s:1"), Some(VContAction::Step(Some(1))));
        assert_eq!(parse_vcont("vCont;s:1;c"), Some(VContAction::Step(Some(1))));
        assert_eq!(
            parse_vcont("vCont;S05:2;c"),
            Some(VContAction::Step(Some(2)))
        );
        assert_eq!(parse_vcont("vCont;s:1;s:2"), None);
        assert_eq!(parse_vcont("vCont"), None);
    }

    #[test]
    fn capability_gates_unsupported_breakpoint_types() {
        let caps = hvf_like_caps();
        assert!(breakpoint_type_supported(caps, BreakpointType::Software));
        assert!(!breakpoint_type_supported(caps, BreakpointType::Hardware));
        assert!(!breakpoint_type_supported(caps, BreakpointType::WriteWatch));
        assert!(!breakpoint_type_supported(caps, BreakpointType::ReadWatch));
        assert!(!breakpoint_type_supported(
            caps,
            BreakpointType::AccessWatch
        ));
    }

    #[test]
    fn capability_driven_protocol_replies_match_expected_surface() {
        let caps = hvf_like_caps();
        assert_eq!(
            qsupported_reply_for_caps(caps),
            "PacketSize=4000;QStartNoAckMode+;qXfer:features:read+;vContSupported+;swbreak+;hwbreak-"
        );
        assert_eq!(
            host_info_reply_for_caps(caps),
            "triple:aarch64-pc-windows-msvc;endian:little;ptrsize:8;default_packet_timeout:10;"
        );
        assert_eq!(vcont_reply_for_caps(caps), "vCont;c;C;s;S");
    }

    #[test]
    fn parse_qxfer_features_read_packet() {
        assert_eq!(
            parse_qxfer_features_read("qXfer:features:read:target.xml:0,40"),
            Some(("target.xml", 0, 0x40))
        );
        assert_eq!(parse_qxfer_features_read("qXfer:features:read"), None);
        assert_eq!(
            parse_qxfer_features_read("qXfer:features:read:target.xml:zz,40"),
            None
        );
    }

    #[test]
    fn qfer_read_reply_chunks_target_description() {
        assert_eq!(qfer_read_reply(b"abcdef", 0, 3), "mabc");
        assert_eq!(qfer_read_reply(b"abcdef", 3, 3), "ldef");
        assert_eq!(qfer_read_reply(b"abcdef", 6, 4), "l");
    }

    #[test]
    fn binary_escape_roundtrips_textual_packets() {
        let payload = br#"{"tid":1,"note":"ends-with-} and has * # $"}"#;
        let escaped = escape_binary(payload);
        assert_ne!(escaped, payload);
        assert_eq!(unescape_binary(&escaped), Some(payload.to_vec()));
    }

    #[test]
    fn format_threads_stop_field_serializes_all_threads() {
        assert_eq!(format_threads_stop_field(&[]), None);
        assert_eq!(
            format_threads_stop_field(&[1, 2, 15]),
            Some("threads:1,2,f;".to_string())
        );
    }

    #[test]
    fn stop_kind_field_respects_caps_and_client_features() {
        let caps = hvf_like_caps();
        let features = ClientFeatures {
            swbreak: true,
            hwbreak: true,
        };
        let snapshot = snapshot_with_reason(StopReason::GuestDebugTrap {
            code: 0,
            arg0: 0,
            arg1: 0,
        });
        assert_eq!(
            stop_kind_field(Some(StopKind::SwBreak), Some(&snapshot), features, caps),
            Some("swbreak:;".to_string())
        );
        assert_eq!(
            stop_kind_field(Some(StopKind::HwBreak), Some(&snapshot), features, caps),
            None
        );
        assert_eq!(
            stop_kind_field(Some(StopKind::Watch), Some(&snapshot), features, caps),
            None
        );
    }

    #[test]
    fn stop_pc_field_serializes_pc_register_slot() {
        let snapshot = snapshot_with_reason(StopReason::ManualPause);
        assert_eq!(
            stop_pc_field(Some(&snapshot)),
            Some("20:28cc034000000000;".to_string())
        );
    }

    #[test]
    fn stop_kind_field_includes_watch_address_when_available() {
        let caps = DebugCaps {
            watchpoint_candidate: true,
            ..hvf_like_caps()
        };
        let snapshot = snapshot_with_reason(StopReason::DebugException {
            syndrome: 0,
            virtual_address: 0x7012_3456,
            physical_address: 0,
        });
        assert_eq!(
            stop_kind_field(
                Some(StopKind::Watch),
                Some(&snapshot),
                ClientFeatures::default(),
                caps,
            ),
            Some("watch:70123456;".to_string())
        );
    }

    #[test]
    fn stop_reason_field_maps_manual_pause_to_trap() {
        let snapshot = snapshot_with_reason(StopReason::ManualPause);
        assert_eq!(
            stop_reason_field(Some(&snapshot), default_stop_metadata()),
            Some("reason:trap;".to_string())
        );
    }

    #[test]
    fn stop_reason_field_maps_debug_break_to_breakpoint() {
        let snapshot = snapshot_with_reason(StopReason::DebugException {
            syndrome: ESR_EC_BRK64 << 26,
            virtual_address: 0,
            physical_address: 0,
        });
        assert_eq!(
            stop_reason_field(Some(&snapshot), default_stop_metadata()),
            Some("reason:breakpoint;".to_string())
        );
    }

    #[test]
    fn stop_reason_field_skips_kernel_ready_guest_trap() {
        let snapshot = snapshot_with_reason(StopReason::GuestDebugTrap {
            code: DEBUG_TRAP_AUTO_PAUSE_KERNEL_READY,
            arg0: 0,
            arg1: 0,
        });
        assert_eq!(stop_reason_field(Some(&snapshot), default_stop_metadata()), None);
    }
}

fn encode_register(snapshot: &VcpuSnapshot, index: usize) -> Option<String> {
    #[cfg(target_arch = "aarch64")]
    {
        match index {
            0..=28 => Some(encode_u64(snapshot.regs.x[index])),
            29 => Some(encode_u64(snapshot.regs.x[29])),
            30 => Some(encode_u64(snapshot.regs.x[30])),
            31 => Some(encode_u64(snapshot.regs.sp)),
            32 => Some(encode_u64(snapshot.regs.pc)),
            33 => Some(encode_u32(snapshot.regs.pstate as u32)),
            _ => None,
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = snapshot;
        let _ = index;
        None
    }
}

fn encode_thread_register_value(snapshot: &VcpuSnapshot, index: usize) -> Option<String> {
    encode_register(snapshot, index)
}

fn encode_all_registers(snapshot: VcpuSnapshot) -> String {
    let mut out = String::new();
    for index in 0..34 {
        if let Some(value) = encode_register(&snapshot, index) {
            out.push_str(&value);
        }
    }
    out
}

fn register_info(index: usize) -> Option<String> {
    let (name, alt_name, generic, bitsize, offset, dwarf, gcc) = match index {
        0..=7 => (
            format!("x{}", index),
            None,
            Some(format!("arg{}", index)),
            64,
            index * 8,
            index,
            index,
        ),
        8..=28 => (
            format!("x{}", index),
            None,
            None,
            64,
            index * 8,
            index,
            index,
        ),
        29 => (
            "fp".to_string(),
            Some("x29".to_string()),
            Some("fp".to_string()),
            64,
            29 * 8,
            29,
            29,
        ),
        30 => (
            "lr".to_string(),
            Some("x30".to_string()),
            Some("ra".to_string()),
            64,
            30 * 8,
            30,
            30,
        ),
        31 => (
            "sp".to_string(),
            None,
            Some("sp".to_string()),
            64,
            31 * 8,
            31,
            31,
        ),
        32 => (
            "pc".to_string(),
            None,
            Some("pc".to_string()),
            64,
            32 * 8,
            32,
            32,
        ),
        33 => (
            "cpsr".to_string(),
            Some("pstate".to_string()),
            Some("flags".to_string()),
            32,
            33 * 8,
            33,
            33,
        ),
        _ => return None,
    };

    let mut out = format!(
        "name:{};bitsize:{};offset:{};encoding:uint;format:hex;set:General Purpose Registers;gcc:{};dwarf:{};",
        name, bitsize, offset, gcc, dwarf
    );
    if let Some(alt_name) = alt_name {
        let _ = write!(out, "alt-name:{};", alt_name);
    }
    if let Some(generic) = generic {
        let _ = write!(out, "generic:{};", generic);
    }
    Some(out)
}
