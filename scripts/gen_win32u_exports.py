#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import re

from spec_codegen import (
    emit_c,
    emit_def,
    emit_win32syscalls_header,
    emit_win32k_sysno_header,
    emit_win32k_sysno_rust,
    parse_spec,
)


def load_passthrough_exports(path: Path | None) -> set[str]:
    if path is None:
        return set()
    if not path.exists():
        return set()
    names: set[str] = set()
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        names.add(line)
    return names


def load_syscall_reference(path: Path | None) -> dict[str, int]:
    if path is None or not path.exists():
        return {}
    out: dict[str, int] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(\S+)\s+([0-9]+)$", line)
        if not m:
            continue
        name = m.group(1).strip()
        nr = int(m.group(2))
        out[name] = nr
    return out


def apply_reference_syscalls(entries, ref: dict[str, int]) -> dict[str, tuple[str, int]]:
    # source map: syscall name -> (source_kind, ref_nr_or_0)
    source: dict[str, tuple[str, int]] = {}
    syscalls = [e for e in entries if e.is_syscall]
    if not syscalls:
        return source

    ref_low12_by_name: dict[str, int] = {}
    low12_count: dict[int, int] = {}
    for e in syscalls:
        ref_nr = ref.get(e.name)
        if ref_nr is None:
            continue
        low12 = ref_nr & 0x0FFF
        ref_low12_by_name[e.name] = low12
        low12_count[low12] = low12_count.get(low12, 0) + 1

    unique_ref_low12: set[int] = {k for (k, c) in low12_count.items() if c == 1}
    future_reserved = set(unique_ref_low12)
    used: set[int] = set()
    next_seq = 0

    for e in syscalls:
        ref_nr = ref.get(e.name, 0)
        ref_low12 = ref_low12_by_name.get(e.name)
        if ref_low12 is not None and ref_low12 in unique_ref_low12 and ref_low12 not in used:
            low12 = ref_low12
            used.add(low12)
            if low12 in future_reserved:
                future_reserved.remove(low12)
            source[e.name] = ("ref", ref_nr)
            e.syscall_nr = 0x1000 | low12
            continue

        while next_seq in used or next_seq in future_reserved:
            next_seq += 1
        low12 = next_seq
        used.add(low12)
        next_seq += 1
        source[e.name] = ("seq", ref_nr)
        e.syscall_nr = 0x1000 | low12

    return source


def emit_syscall_map(path: Path, entries, source: dict[str, tuple[str, int]]) -> None:
    lines = [
        "name,guest_x8_tag_hex,guest_nr_low12_hex,ref_nr_dec,source",
    ]
    for e in entries:
        if not e.is_syscall or e.syscall_nr is None:
            continue
        src_kind, ref_nr = source.get(e.name, ("seq", 0))
        lines.append(
            f"{e.name},0x{e.syscall_nr:04x},0x{(e.syscall_nr & 0x0FFF):03x},{ref_nr},{src_kind}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate win32u exports/syscall stubs from win32u.spec")
    ap.add_argument("--spec", required=True, help="Path to win32u.spec")
    ap.add_argument("--out-c", required=True, help="Generated C source output")
    ap.add_argument("--out-def", required=True, help="Generated DEF output")
    ap.add_argument("--out-sysno", required=True, help="Generated syscall number header output")
    ap.add_argument(
        "--out-win32syscalls",
        help="Optional generated win32syscalls.h output for building real win32u source objects",
    )
    ap.add_argument(
        "--out-rust",
        help="Optional generated Rust constants output (for shared kernel/vmm use)",
    )
    ap.add_argument(
        "--syscall-ref",
        help="Optional ARM64 win32k syscall reference table text file from SyscallTables-master",
    )
    ap.add_argument(
        "--out-map",
        help="Optional CSV output mapping syscall name -> guest/ref numbers",
    )
    ap.add_argument(
        "--no-dllmain",
        action="store_true",
        help="Do not emit DllMain stub in generated C (DllMain provided by real object)",
    )
    ap.add_argument("--passthrough", help="Optional file listing exports that map to real object symbols")
    args = ap.parse_args()

    spec_path = Path(args.spec)
    if not spec_path.exists():
        raise SystemExit(f"spec not found: {spec_path}")

    entries = parse_spec(spec_path)
    ref = load_syscall_reference(Path(args.syscall_ref) if args.syscall_ref else None)
    source = apply_reference_syscalls(entries, ref)
    out_c = Path(args.out_c)
    out_def = Path(args.out_def)
    out_sysno = Path(args.out_sysno)
    out_win32syscalls = Path(args.out_win32syscalls) if args.out_win32syscalls else None
    out_rust = Path(args.out_rust) if args.out_rust else None
    out_map = Path(args.out_map) if args.out_map else None
    out_c.parent.mkdir(parents=True, exist_ok=True)
    out_def.parent.mkdir(parents=True, exist_ok=True)
    out_sysno.parent.mkdir(parents=True, exist_ok=True)
    if out_win32syscalls is not None:
        out_win32syscalls.parent.mkdir(parents=True, exist_ok=True)
    if out_rust is not None:
        out_rust.parent.mkdir(parents=True, exist_ok=True)
    if out_map is not None:
        out_map.parent.mkdir(parents=True, exist_ok=True)
    passthrough = load_passthrough_exports(Path(args.passthrough) if args.passthrough else None)

    emit_c(
        out_c,
        "win32u",
        entries,
        stub_return=0xC0000002,
        emit_dllmain=not args.no_dllmain,
    )
    emit_def(out_def, "win32u", entries, passthrough_exports=passthrough)
    emit_win32k_sysno_header(out_sysno, entries)
    if out_win32syscalls is not None:
        emit_win32syscalls_header(out_win32syscalls, entries)
    if out_rust is not None:
        emit_win32k_sysno_rust(out_rust, entries)
    if out_map is not None:
        emit_syscall_map(out_map, entries, source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
