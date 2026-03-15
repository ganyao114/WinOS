#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import pty
import re
import select
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterable


ROOT_DIR = Path(__file__).resolve().parent.parent
WINEMU_BIN = ROOT_DIR / "target/debug/winemu"
KERNEL_ELF = ROOT_DIR / "winemu-kernel/target/aarch64-unknown-none/release/winemu-kernel"
DEFAULT_GUEST = (
    ROOT_DIR
    / "tests/debugger_interrupt_test/target/aarch64-pc-windows-msvc/release/debugger_interrupt_test.exe"
)
BREAKPOINT_ADDR = 0x40028A98
BREAKPOINT_NEXT_PC = BREAKPOINT_ADDR + 4
BREAKPOINT_FAR_ADDR = BREAKPOINT_ADDR + 8
GDB_REGISTER_FILE_BYTES = (33 * 8) + 4
ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|[@-_])")


class SmokeFailure(RuntimeError):
    pass


class GuestVm:
    def __init__(
        self,
        guest_exe: Path,
        port: int,
        vcpu_count: int,
        rust_log: str,
        keep_log: bool,
    ) -> None:
        self.guest_exe = guest_exe
        self.port = port
        self.vcpu_count = vcpu_count
        self.rust_log = rust_log
        self.keep_log = keep_log
        self.proc: subprocess.Popen[str] | None = None
        self.log_path = Path(tempfile.mkstemp(prefix="winemu-debugger-smoke-", suffix=".log")[1])
        self._log_fp = None

    def __enter__(self) -> "GuestVm":
        env = os.environ.copy()
        env["WINEMU_DISABLE_HOST_UI"] = "1"
        env["WINEMU_GUEST_DEBUG"] = "1"
        env["WINEMU_GUEST_DEBUG_PROTOCOL"] = "gdb"
        env["WINEMU_GUEST_DEBUG_ADDR"] = f"127.0.0.1:{self.port}"
        env["WINEMU_GUEST_DEBUG_AUTO_PAUSE"] = "kernel_ready"
        env["WINEMU_VCPU_COUNT"] = str(self.vcpu_count)
        env["RUST_LOG"] = self.rust_log

        self._log_fp = self.log_path.open("w", encoding="utf-8")
        self.proc = subprocess.Popen(
            [str(WINEMU_BIN), "run", str(self.guest_exe)],
            cwd=ROOT_DIR,
            env=env,
            stdout=self._log_fp,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self._wait_for_gdb_server()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        if self._log_fp is not None:
            self._log_fp.close()
        if exc is None and not self.keep_log:
            self.log_path.unlink(missing_ok=True)

    def _wait_for_gdb_server(self) -> None:
        deadline = time.time() + 8.0
        while time.time() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                raise SmokeFailure(
                    f"guest exited before gdb server was ready; log={self.log_path}"
                )
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.1)
        raise SmokeFailure(f"timed out waiting for gdb server on 127.0.0.1:{self.port}")

    def tail_log(self, lines: int = 40) -> str:
        if not self.log_path.exists():
            return "<missing log>"
        content = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(content[-lines:])


class GdbRemoteClient:
    def __init__(self, port: int) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        self.sock.settimeout(5.0)

    def close(self) -> None:
        self.sock.close()

    def __enter__(self) -> "GdbRemoteClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def send_packet(self, payload: str) -> str:
        return self.send_packet_bytes(payload.encode()).decode()

    def send_packet_bytes(self, payload: bytes) -> bytes:
        self.sock.sendall(b"$" + payload + b"#" + _checksum(payload))
        ack = self.sock.recv(1)
        if ack != b"+":
            raise SmokeFailure(f"expected ack for {payload!r}, got {ack!r}")
        return self._recv_packet_bytes()

    def send_binary_read_packet(self, payload: str) -> bytes:
        return unescape_binary_payload(self.send_packet_bytes(payload.encode()))

    def continue_expect_timeout(self, payload: str = "c", timeout: float = 1.0) -> None:
        data = payload.encode()
        self.sock.sendall(b"$" + data + b"#" + _checksum(data))
        ack = self.sock.recv(1)
        if ack != b"+":
            raise SmokeFailure(f"expected ack for {payload!r}, got {ack!r}")
        old_timeout = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        try:
            unexpected = self._recv_packet_bytes().decode()
            raise SmokeFailure(f"unexpected immediate stop after {payload!r}: {unexpected}")
        except TimeoutError:
            return
        finally:
            self.sock.settimeout(old_timeout)

    def _recv_packet_bytes(self) -> bytes:
        while True:
            prefix = self.sock.recv(1)
            if not prefix:
                raise SmokeFailure("gdb-remote connection closed")
            if prefix == b"+":
                continue
            if prefix == b"$":
                break
        body = bytearray()
        while True:
            chunk = self.sock.recv(1)
            if not chunk:
                raise SmokeFailure("gdb-remote packet truncated")
            if chunk == b"#":
                break
            body.extend(chunk)
        got_checksum = self.sock.recv(2)
        expected = _checksum(bytes(body))
        if got_checksum.lower() != expected.lower():
            raise SmokeFailure(
                f"bad checksum got={got_checksum!r} expected={expected!r} payload={bytes(body)!r}"
            )
        self.sock.sendall(b"+")
        return bytes(body)


class LldbSession:
    def __init__(self, target_elf: Path) -> None:
        if shutil.which("lldb") is None:
            raise SmokeFailure("lldb is not installed or not on PATH")
        self.master_fd, slave_fd = pty.openpty()
        env = os.environ.copy()
        env["TERM"] = "dumb"
        self.proc = subprocess.Popen(
            ["lldb", str(target_elf)],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
        )
        os.close(slave_fd)
        self.buffer = ""

    def __enter__(self) -> "LldbSession":
        self.read_until(["(lldb) "])
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.proc.poll() is None:
            try:
                self.send("quit")
            except Exception:
                pass
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        os.close(self.master_fd)

    def send(self, command: str) -> None:
        os.write(self.master_fd, (command + "\n").encode())
        time.sleep(0.05)

    def run(self, command: str, needles: Iterable[str] | None = None, timeout: float = 20.0) -> str:
        start = len(self.buffer)
        self.send(command)
        return self.read_until(needles or ["(lldb) "], timeout=timeout, start=start)

    def run_until(self, command: str, needle: str, timeout: float = 20.0) -> str:
        start = len(self.buffer)
        self.send(command)
        self.read_until([needle], timeout=timeout, start=start)
        return self.read_until(["(lldb) "], timeout=timeout, start=start)

    def read_until(
        self, needles: Iterable[str], timeout: float = 20.0, start: int | None = None
    ) -> str:
        deadline = time.time() + timeout
        needles = list(needles)
        while time.time() < deadline:
            cleaned = self.cleaned_output(start=start)
            for needle in needles:
                if needle in cleaned:
                    return cleaned
            ready, _, _ = select.select([self.master_fd], [], [], 0.1)
            if self.master_fd not in ready:
                continue
            try:
                chunk = os.read(self.master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            self.buffer += chunk.decode("utf-8", "ignore")
        raise SmokeFailure(
            f"timeout waiting for {needles!r}\n--- lldb output ---\n{self.cleaned_output(start=start)}"
        )

    def cleaned_output(self, start: int | None = None) -> str:
        raw = self.buffer[start:] if start is not None else self.buffer
        return ANSI_ESCAPE_RE.sub("", raw).replace("\r", "")


def _checksum(payload: bytes) -> bytes:
    return f"{sum(payload) % 256:02x}".encode()


def escape_binary_payload(payload: bytes) -> bytes:
    out = bytearray()
    for byte in payload:
        if byte in (ord("#"), ord("$"), ord("}"), ord("*")):
            out.append(ord("}"))
            out.append(byte ^ 0x20)
        else:
            out.append(byte)
    return bytes(out)


def unescape_binary_payload(payload: bytes) -> bytes:
    out = bytearray()
    index = 0
    while index < len(payload):
        byte = payload[index]
        if byte == ord("}"):
            index += 1
            if index >= len(payload):
                raise SmokeFailure("truncated escaped binary payload")
            out.append(payload[index] ^ 0x20)
        else:
            out.append(byte)
        index += 1
    return bytes(out)


def parse_stop_thread_id(packet: str) -> int:
    match = re.search(r"thread:([0-9a-fA-F]+);", packet)
    if not match:
        raise SmokeFailure(f"stop reply missing thread id: {packet}")
    return int(match.group(1), 16)


def parse_stop_pc(packet: str) -> int:
    match = re.search(r"20:([0-9a-fA-F]+);", packet)
    if not match:
        raise SmokeFailure(f"stop reply missing pc field: {packet}")
    return int.from_bytes(bytes.fromhex(match.group(1)), "little")


def decode_le_u64_hex(text: str) -> int:
    raw = bytes.fromhex(text)
    if len(raw) != 8:
        raise SmokeFailure(f"expected 8-byte register payload, got {len(raw)} bytes from {text!r}")
    return int.from_bytes(raw, "little")


def encode_le_u64_hex(value: int) -> str:
    return value.to_bytes(8, "little").hex()


def ensure_contains(text: str, needle: str, context: str) -> None:
    if needle not in text:
        raise SmokeFailure(f"expected {needle!r} in {context}, got: {text}")


def parse_marker_hex(text: str, marker: str) -> int:
    matches = re.findall(rf"{re.escape(marker)}=0x([0-9a-fA-F]+)", text)
    if not matches:
        raise SmokeFailure(f"missing marker {marker!r} in output:\n{text}")
    return int(matches[-1], 16)


def parse_marker_bytes(text: str, marker: str, expected_len: int) -> bytes:
    matches = re.findall(rf"{re.escape(marker)}=([0-9a-fA-F]+)", text)
    if not matches:
        raise SmokeFailure(f"missing marker {marker!r} in output:\n{text}")
    raw = bytes.fromhex(matches[-1])
    if len(raw) != expected_len:
        raise SmokeFailure(
            f"marker {marker!r} length mismatch expected={expected_len} got={len(raw)}"
        )
    return raw


def run_raw_breakpoint_step(port: int, args: argparse.Namespace) -> None:
    with GuestVm(args.guest_exe, port, args.vcpu_count, args.rust_log, args.keep_logs) as vm:
        try:
            with GdbRemoteClient(port) as client:
                ensure_contains(
                    client.send_packet("qSupported:multiprocess+;swbreak+;hwbreak+;qXfer:features:read+"),
                    "swbreak+",
                    "qSupported reply",
                )
                ensure_contains(client.send_packet("vCont?"), "vCont;c;C;s;S", "vCont? reply")
                client.send_packet("?")
                ensure_contains(
                    client.send_packet(f"Z0,{BREAKPOINT_ADDR:x},4"), "OK", "software breakpoint insert"
                )
                first_hit = client.send_packet("c")
                ensure_contains(first_hit, "reason:breakpoint", "initial breakpoint hit")
                hit_thread = parse_stop_thread_id(first_hit)
                if parse_stop_pc(first_hit) != BREAKPOINT_ADDR:
                    raise SmokeFailure(f"unexpected first breakpoint pc: {first_hit}")
                ensure_contains(client.send_packet(f"Hg{hit_thread:x}"), "OK", "Hg thread select")
                step_hit = client.send_packet("s")
                ensure_contains(step_hit, "reason:trace", "single-step stop")
                if parse_stop_pc(step_hit) != BREAKPOINT_NEXT_PC:
                    raise SmokeFailure(f"unexpected pc after s: {step_hit}")
                second_hit = client.send_packet("c")
                ensure_contains(second_hit, "reason:breakpoint", "re-hit after s")
                if parse_stop_pc(second_hit) != BREAKPOINT_ADDR:
                    raise SmokeFailure(f"unexpected pc after re-hit: {second_hit}")
                vcont_step = client.send_packet(f"vCont;s:{hit_thread:x}")
                ensure_contains(vcont_step, "reason:trace", "vCont step stop")
                if parse_stop_pc(vcont_step) != BREAKPOINT_NEXT_PC:
                    raise SmokeFailure(f"unexpected pc after vCont step: {vcont_step}")
                third_hit = client.send_packet("vCont;c")
                ensure_contains(third_hit, "reason:breakpoint", "re-hit after vCont step")
                if parse_stop_pc(third_hit) != BREAKPOINT_ADDR:
                    raise SmokeFailure(f"unexpected pc after vCont re-hit: {third_hit}")
                ensure_contains(
                    client.send_packet(f"z0,{BREAKPOINT_ADDR:x},4"), "OK", "software breakpoint remove"
                )
                mem_after_remove = client.send_packet(f"m{BREAKPOINT_ADDR:x},4")
                if mem_after_remove != "5f2003d5":
                    raise SmokeFailure(
                        f"expected original instruction after z0, got {mem_after_remove}"
                    )
                client.continue_expect_timeout("c", timeout=1.0)
                print("raw-breakpoint-step: OK")
        except Exception as exc:
            raise SmokeFailure(f"{exc}\n--- guest log tail ---\n{vm.tail_log()}") from exc


def run_raw_memory_register_io(port: int, args: argparse.Namespace) -> None:
    with GuestVm(args.guest_exe, port, args.vcpu_count, args.rust_log, args.keep_logs) as vm:
        try:
            with GdbRemoteClient(port) as client:
                stop = client.send_packet("?")
                thread_id = parse_stop_thread_id(stop)
                ensure_contains(client.send_packet(f"Hg{thread_id:x}"), "OK", "Hg thread select")

                orig_x0 = decode_le_u64_hex(client.send_packet("p0"))
                sp = decode_le_u64_hex(client.send_packet("p1f"))
                orig_stack = bytes.fromhex(client.send_packet(f"m{sp:x},8"))
                if len(orig_stack) != 8:
                    raise SmokeFailure(f"expected 8 stack bytes, got {len(orig_stack)}")

                new_x0 = 0 if orig_x0 == 1 else 1
                ensure_contains(
                    client.send_packet(f"P0={encode_le_u64_hex(new_x0)}"),
                    "OK",
                    "write x0 with P packet",
                )
                if decode_le_u64_hex(client.send_packet("p0")) != new_x0:
                    raise SmokeFailure("x0 did not update after P packet")

                ensure_contains(
                    client.send_packet(f"P0={encode_le_u64_hex(orig_x0)}"),
                    "OK",
                    "restore x0 with P packet",
                )
                if decode_le_u64_hex(client.send_packet("p0")) != orig_x0:
                    raise SmokeFailure("x0 did not restore after P packet")

                hex_pattern = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
                ensure_contains(
                    client.send_packet(f"M{sp:x},8:{hex_pattern.hex()}"),
                    "OK",
                    "write stack bytes with M packet",
                )
                if bytes.fromhex(client.send_packet(f"m{sp:x},8")) != hex_pattern:
                    raise SmokeFailure("stack bytes did not update after M packet")
                if client.send_binary_read_packet(f"x{sp:x},8") != hex_pattern:
                    raise SmokeFailure("binary x packet did not match M-written bytes")

                binary_pattern = bytes([0x23, 0x24, 0x7D, 0x2A, 0x00, 0x7F, 0x55, 0xAA])
                payload = (
                    f"X{sp:x},8:".encode() + escape_binary_payload(binary_pattern)
                )
                ensure_contains(
                    client.send_packet_bytes(payload).decode(),
                    "OK",
                    "write stack bytes with X packet",
                )
                if bytes.fromhex(client.send_packet(f"m{sp:x},8")) != binary_pattern:
                    raise SmokeFailure("stack bytes did not update after X packet")

                ensure_contains(
                    client.send_packet(f"M{sp:x},8:{orig_stack.hex()}"),
                    "OK",
                    "restore stack bytes with M packet",
                )
                restored = bytes.fromhex(client.send_packet(f"m{sp:x},8"))
                if restored != orig_stack:
                    raise SmokeFailure(
                        f"stack bytes did not restore expected={orig_stack.hex()} got={restored.hex()}"
                    )
                print("raw-memory-register-io: OK")
        except Exception as exc:
            raise SmokeFailure(f"{exc}\n--- guest log tail ---\n{vm.tail_log()}") from exc


def run_raw_register_file_io(port: int, args: argparse.Namespace) -> None:
    with GuestVm(args.guest_exe, port, args.vcpu_count, args.rust_log, args.keep_logs) as vm:
        try:
            with GdbRemoteClient(port) as client:
                stop = client.send_packet("?")
                thread_id = parse_stop_thread_id(stop)
                ensure_contains(client.send_packet(f"Hg{thread_id:x}"), "OK", "Hg thread select")

                original_file = client.send_packet("g")
                expected_hex_len = GDB_REGISTER_FILE_BYTES * 2
                if len(original_file) != expected_hex_len:
                    raise SmokeFailure(
                        f"unexpected g register file length expected={expected_hex_len} got={len(original_file)}"
                    )

                original_x0 = decode_le_u64_hex(original_file[:16])
                new_x0 = 0 if original_x0 == 1 else 1
                modified_file = encode_le_u64_hex(new_x0) + original_file[16:]
                ensure_contains(
                    client.send_packet(f"G{modified_file}"),
                    "OK",
                    "write full register file with G packet",
                )
                read_back = client.send_packet("g")
                if read_back != modified_file:
                    raise SmokeFailure("g register file did not match modified payload after G")

                ensure_contains(
                    client.send_packet(f"G{original_file}"),
                    "OK",
                    "restore full register file with G packet",
                )
                restored = client.send_packet("g")
                if restored != original_file:
                    raise SmokeFailure("g register file did not restore to original payload")
                print("raw-register-file-io: OK")
        except Exception as exc:
            raise SmokeFailure(f"{exc}\n--- guest log tail ---\n{vm.tail_log()}") from exc


def run_raw_multi_breakpoint(port: int, args: argparse.Namespace) -> None:
    with GuestVm(args.guest_exe, port, 1, args.rust_log, args.keep_logs) as vm:
        try:
            with GdbRemoteClient(port) as client:
                ensure_contains(
                    client.send_packet("qSupported:multiprocess+;swbreak+;hwbreak+;qXfer:features:read+"),
                    "swbreak+",
                    "qSupported reply",
                )
                stop = client.send_packet("?")
                thread_id = parse_stop_thread_id(stop)
                ensure_contains(client.send_packet(f"Hg{thread_id:x}"), "OK", "Hg thread select")
                ensure_contains(
                    client.send_packet(f"Z0,{BREAKPOINT_ADDR:x},4"),
                    "OK",
                    "insert first software breakpoint",
                )
                ensure_contains(
                    client.send_packet(f"Z0,{BREAKPOINT_FAR_ADDR:x},4"),
                    "OK",
                    "insert second software breakpoint",
                )

                first_hit = client.send_packet("c")
                ensure_contains(first_hit, "reason:breakpoint", "first breakpoint hit")
                if parse_stop_pc(first_hit) != BREAKPOINT_ADDR:
                    raise SmokeFailure(f"unexpected first breakpoint pc: {first_hit}")

                second_hit = client.send_packet("c")
                ensure_contains(second_hit, "reason:breakpoint", "second breakpoint hit")
                if parse_stop_pc(second_hit) != BREAKPOINT_FAR_ADDR:
                    raise SmokeFailure(f"unexpected second breakpoint pc: {second_hit}")

                ensure_contains(
                    client.send_packet(f"z0,{BREAKPOINT_FAR_ADDR:x},4"),
                    "OK",
                    "remove second software breakpoint",
                )
                ensure_contains(
                    client.send_packet(f"z0,{BREAKPOINT_ADDR:x},4"),
                    "OK",
                    "remove first software breakpoint",
                )
                if client.send_packet(f"m{BREAKPOINT_ADDR:x},4") != "5f2003d5":
                    raise SmokeFailure("first breakpoint instruction did not restore")
                if client.send_packet(f"m{BREAKPOINT_FAR_ADDR:x},4") != "88d038d5":
                    raise SmokeFailure("second breakpoint instruction did not restore")
                print("raw-multi-breakpoint: OK")
        except Exception as exc:
            raise SmokeFailure(f"{exc}\n--- guest log tail ---\n{vm.tail_log()}") from exc


def run_lldb_memory_register_io(port: int, args: argparse.Namespace) -> None:
    with GuestVm(args.guest_exe, port, args.vcpu_count, args.rust_log, args.keep_logs) as vm:
        try:
            with LldbSession(KERNEL_ELF) as lldb:
                connect_output = lldb.run(f"gdb-remote 127.0.0.1:{port}")
                ensure_contains(connect_output, "Process 1 stopped", "gdb-remote attach")

                marker_output = lldb.run(
                    "script import lldb; "
                    "process=lldb.debugger.GetSelectedTarget().GetProcess(); "
                    "frame=process.GetSelectedThread().GetFrameAtIndex(0); "
                    "x0=frame.FindRegister('x0').GetValueAsUnsigned(); "
                    "sp=frame.FindRegister('sp').GetValueAsUnsigned(); "
                    "err=lldb.SBError(); "
                    "stack=process.ReadMemory(sp, 8, err); "
                    "print(f'SMOKE_X0_ORIG=0x{x0:x}'); "
                    "print(f'SMOKE_SP=0x{sp:x}'); "
                    "print(f'SMOKE_STACK_ORIG={stack.hex()}'); "
                    "print(f'SMOKE_STACK_ERR=0x{int(err.Success()):x}')"
                )
                orig_x0 = parse_marker_hex(marker_output, "SMOKE_X0_ORIG")
                sp = parse_marker_hex(marker_output, "SMOKE_SP")
                orig_stack = parse_marker_bytes(marker_output, "SMOKE_STACK_ORIG", 8)
                stack_ok = parse_marker_hex(marker_output, "SMOKE_STACK_ERR")
                if stack_ok != 1:
                    raise SmokeFailure(f"failed to read original stack bytes:\n{marker_output}")

                new_x0 = 0 if orig_x0 == 1 else 1
                lldb.run(f"register write x0 0x{new_x0:x}")
                reg_output = lldb.run("register read x0")
                expected_x0_text = f"0x{new_x0:016x}"
                ensure_contains(reg_output, expected_x0_text, "register read x0 after write")

                lldb.run(f"register write x0 0x{orig_x0:x}")
                reg_restore_output = lldb.run("register read x0")
                expected_restore_text = f"0x{orig_x0:016x}"
                ensure_contains(
                    reg_restore_output,
                    expected_restore_text,
                    "register read x0 after restore",
                )

                mem_read_output = lldb.run(f"memory read -f x -s 1 -c 8 0x{sp:x}")
                ensure_contains(mem_read_output, f"{sp:x}", "memory read output")

                pattern = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
                pattern_args = " ".join(f"0x{byte:02x}" for byte in pattern)
                lldb.run(f"memory write -s 1 0x{sp:x} {pattern_args}")
                after_output = lldb.run(
                    "script import lldb; "
                    "process=lldb.debugger.GetSelectedTarget().GetProcess(); "
                    "err=lldb.SBError(); "
                    f"data=process.ReadMemory(0x{sp:x}, 8, err); "
                    "print(f'SMOKE_STACK_AFTER={data.hex()}'); "
                    "print(f'SMOKE_STACK_AFTER_ERR=0x{int(err.Success()):x}')"
                )
                after_bytes = parse_marker_bytes(after_output, "SMOKE_STACK_AFTER", 8)
                after_ok = parse_marker_hex(after_output, "SMOKE_STACK_AFTER_ERR")
                if after_ok != 1 or after_bytes != pattern:
                    raise SmokeFailure(
                        f"unexpected stack bytes after memory write expected={pattern.hex()} "
                        f"got={after_bytes.hex()} ok={after_ok}\n{after_output}"
                    )

                restore_args = " ".join(f"0x{byte:02x}" for byte in orig_stack)
                lldb.run(f"memory write -s 1 0x{sp:x} {restore_args}")
                restore_output = lldb.run(
                    "script import lldb; "
                    "process=lldb.debugger.GetSelectedTarget().GetProcess(); "
                    "err=lldb.SBError(); "
                    f"data=process.ReadMemory(0x{sp:x}, 8, err); "
                    "print(f'SMOKE_STACK_RESTORED={data.hex()}'); "
                    "print(f'SMOKE_STACK_RESTORED_ERR=0x{int(err.Success()):x}')"
                )
                restored_bytes = parse_marker_bytes(restore_output, "SMOKE_STACK_RESTORED", 8)
                restored_ok = parse_marker_hex(restore_output, "SMOKE_STACK_RESTORED_ERR")
                if restored_ok != 1 or restored_bytes != orig_stack:
                    raise SmokeFailure(
                        f"unexpected stack bytes after restore expected={orig_stack.hex()} "
                        f"got={restored_bytes.hex()} ok={restored_ok}\n{restore_output}"
                    )
                print("lldb-memory-register-io: OK")
        except Exception as exc:
            raise SmokeFailure(f"{exc}\n--- guest log tail ---\n{vm.tail_log()}") from exc


def run_lldb_step_over(port: int, args: argparse.Namespace) -> None:
    with GuestVm(args.guest_exe, port, args.vcpu_count, args.rust_log, args.keep_logs) as vm:
        try:
            with LldbSession(KERNEL_ELF) as lldb:
                connect_output = lldb.run(f"gdb-remote 127.0.0.1:{port}")
                ensure_contains(connect_output, "Process 1 stopped", "gdb-remote attach")
                bp_output = lldb.run(f"breakpoint set --address 0x{BREAKPOINT_ADDR:x}")
                ensure_contains(bp_output, "Breakpoint 1:", "breakpoint set")
                continue_output = lldb.run("process continue")
                ensure_contains(continue_output, "breakpoint 1.1", "continue to breakpoint")
                step_output = lldb.run("thread step-inst")
                if (
                    "SIGTRAP" not in step_output
                    and "trace" not in step_output
                    and "instruction step into" not in step_output
                ):
                    raise SmokeFailure(f"unexpected step output:\n{step_output}")
                pc_output = lldb.run("register read pc")
                if f"0x{BREAKPOINT_NEXT_PC:016x}" not in pc_output:
                    raise SmokeFailure(
                        f"expected pc 0x{BREAKPOINT_NEXT_PC:016x} after step-over\n{pc_output}"
                    )
                final_output = lldb.run("process continue")
                ensure_contains(final_output, "breakpoint 1.1", "continue after step-over")
                print("lldb-step-over: OK")
        except Exception as exc:
            raise SmokeFailure(f"{exc}\n--- guest log tail ---\n{vm.tail_log()}") from exc


def run_lldb_breakpoint_delete_interrupt(port: int, args: argparse.Namespace) -> None:
    with GuestVm(args.guest_exe, port, args.vcpu_count, args.rust_log, args.keep_logs) as vm:
        try:
            with LldbSession(KERNEL_ELF) as lldb:
                connect_output = lldb.run(f"gdb-remote 127.0.0.1:{port}")
                ensure_contains(connect_output, "Process 1 stopped", "gdb-remote attach")
                bp_output = lldb.run(f"breakpoint set --address 0x{BREAKPOINT_ADDR:x}")
                ensure_contains(bp_output, "Breakpoint 1:", "breakpoint set")
                continue_output = lldb.run("process continue")
                ensure_contains(continue_output, "breakpoint 1.1", "continue to breakpoint")
                delete_output = lldb.run("breakpoint delete 1")
                ensure_contains(
                    delete_output,
                    "1 breakpoints deleted; 0 breakpoint locations disabled.",
                    "breakpoint delete",
                )
                lldb.run("process continue")
                running_output = lldb.run("thread list")
                ensure_contains(
                    running_output,
                    "Process is running.  Use 'process interrupt' to pause execution.",
                    "thread list while running",
                )
                interrupt_output = lldb.run_until("process interrupt", "signal SIGINT")
                ensure_contains(interrupt_output, "signal SIGINT", "first interrupt")
                stopped_output = lldb.run("thread list")
                ensure_contains(stopped_output, "Process 1 stopped", "thread list after interrupt")
                lldb.run("process continue")
                running_output_2 = lldb.run("thread list")
                ensure_contains(
                    running_output_2,
                    "Process is running.  Use 'process interrupt' to pause execution.",
                    "thread list while running after resume",
                )
                interrupt_output_2 = lldb.run_until("process interrupt", "signal SIGINT")
                ensure_contains(interrupt_output_2, "signal SIGINT", "second interrupt")
                print("lldb-breakpoint-delete-interrupt: OK")
        except Exception as exc:
            raise SmokeFailure(f"{exc}\n--- guest log tail ---\n{vm.tail_log()}") from exc


def run_lldb_multi_breakpoint(port: int, args: argparse.Namespace) -> None:
    with GuestVm(args.guest_exe, port, 1, args.rust_log, args.keep_logs) as vm:
        try:
            with LldbSession(KERNEL_ELF) as lldb:
                connect_output = lldb.run(f"gdb-remote 127.0.0.1:{port}")
                ensure_contains(connect_output, "Process 1 stopped", "gdb-remote attach")

                bp1_output = lldb.run(f"breakpoint set --address 0x{BREAKPOINT_ADDR:x}")
                ensure_contains(bp1_output, "Breakpoint 1:", "first breakpoint set")
                bp2_output = lldb.run(f"breakpoint set --address 0x{BREAKPOINT_FAR_ADDR:x}")
                ensure_contains(bp2_output, "Breakpoint 2:", "second breakpoint set")

                first_hit = lldb.run("process continue")
                ensure_contains(first_hit, "breakpoint 1.1", "first breakpoint hit")
                pc_first = lldb.run("register read pc")
                ensure_contains(
                    pc_first,
                    f"0x{BREAKPOINT_ADDR:016x}",
                    "pc after first breakpoint hit",
                )

                second_hit = lldb.run("process continue")
                ensure_contains(second_hit, "breakpoint 2.1", "second breakpoint hit")
                pc_second = lldb.run("register read pc")
                ensure_contains(
                    pc_second,
                    f"0x{BREAKPOINT_FAR_ADDR:016x}",
                    "pc after second breakpoint hit",
                )

                delete_output = lldb.run("breakpoint delete 1 2")
                ensure_contains(
                    delete_output,
                    "2 breakpoints deleted; 0 breakpoint locations disabled.",
                    "delete both breakpoints",
                )
                print("lldb-multi-breakpoint: OK")
        except Exception as exc:
            raise SmokeFailure(f"{exc}\n--- guest log tail ---\n{vm.tail_log()}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WinEmu guest debugger smoke tests")
    parser.add_argument(
        "case",
        choices=[
            "raw-breakpoint-step",
            "raw-register-file-io",
            "raw-memory-register-io",
            "raw-multi-breakpoint",
            "lldb-memory-register-io",
            "lldb-step-over",
            "lldb-multi-breakpoint",
            "lldb-breakpoint-delete-interrupt",
            "full",
        ],
        help="Smoke case to run",
    )
    parser.add_argument("--port-base", type=int, default=9035, help="Base TCP port for gdb server")
    parser.add_argument("--vcpu-count", type=int, default=2, help="WINEMU_VCPU_COUNT to use")
    parser.add_argument("--rust-log", default="info", help="RUST_LOG for the guest run")
    parser.add_argument("--keep-logs", action="store_true", help="Keep per-run guest logs on success")
    parser.add_argument(
        "--guest-exe",
        type=Path,
        default=DEFAULT_GUEST,
        help="Guest executable used for debugger smoke",
    )
    return parser.parse_args()


def ensure_prerequisites(args: argparse.Namespace) -> None:
    missing = []
    for path in [WINEMU_BIN, KERNEL_ELF, args.guest_exe]:
        if not path.exists():
            missing.append(str(path))
    if missing:
        raise SmokeFailure(
            "missing prerequisite binaries:\n" + "\n".join(f"  - {entry}" for entry in missing)
        )


def main() -> int:
    args = parse_args()
    ensure_prerequisites(args)

    cases = {
        "raw-breakpoint-step": run_raw_breakpoint_step,
        "raw-register-file-io": run_raw_register_file_io,
        "raw-memory-register-io": run_raw_memory_register_io,
        "raw-multi-breakpoint": run_raw_multi_breakpoint,
        "lldb-memory-register-io": run_lldb_memory_register_io,
        "lldb-step-over": run_lldb_step_over,
        "lldb-multi-breakpoint": run_lldb_multi_breakpoint,
        "lldb-breakpoint-delete-interrupt": run_lldb_breakpoint_delete_interrupt,
    }
    selected = (
        list(cases.items())
        if args.case == "full"
        else [(args.case, cases[args.case])]
    )

    try:
        for index, (name, fn) in enumerate(selected):
            port = args.port_base + index
            print(f"[run] {name} port={port}")
            fn(port, args)
        print("[ok] debugger smoke passed")
        return 0
    except SmokeFailure as exc:
        print(f"[error] {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
