#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Iterable

TARGET_TAGS = {"arm64", "win64"}


@dataclass
class SpecExport:
    ordinal: int
    name: str
    public_name: str | None
    is_data: bool
    is_syscall: bool
    forward: str | None
    impl_name: str | None = None
    arg_count: int = 0
    syscall_nr: int | None = None
    noname: bool = False


def _target_tag_matches(tag: str) -> bool:
    tag = tag.strip().lower()
    if not tag:
        return False
    if tag in TARGET_TAGS:
        return True
    # Wine uses "win64" for 64-bit generic exports; arm64 builds should include it.
    if tag == "win64":
        return True
    return False


def _arch_option_allows(value: str) -> bool:
    parts = [p.strip() for p in value.split(",") if p.strip()]
    has_positive = False
    positive_match = False
    for part in parts:
        if part.startswith("!"):
            if _target_tag_matches(part[1:]):
                return False
            continue
        has_positive = True
        if _target_tag_matches(part):
            positive_match = True
    if has_positive and not positive_match:
        return False
    return True


def _split_kind_and_options(body: str) -> tuple[str, list[str], str] | None:
    if not body:
        return None
    parts = body.split(None, 1)
    if not parts:
        return None
    kind = parts[0].strip()
    rest = parts[1].strip() if len(parts) > 1 else ""
    opts: list[str] = []
    while rest.startswith("-"):
        seg = rest.split(None, 1)
        opts.append(seg[0])
        rest = seg[1].strip() if len(seg) > 1 else ""
    return kind, opts, rest


def _split_ordinal_and_body(line: str) -> tuple[int | None, str] | None:
    if not line:
        return None
    if line.startswith("@"):
        return None, line[1:].strip()
    match = re.match(r"^(\d+)\s+(.*)$", line)
    if match:
        return int(match.group(1)), match.group(2).strip()
    return None


def _find_matching_paren(s: str, start_idx: int) -> int:
    depth = 0
    for i in range(start_idx, len(s)):
        ch = s[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _count_args(args: str) -> int:
    args = args.strip()
    if not args or args.lower() == "void":
        return 0
    if "," in args:
        return len([a for a in args.split(",") if a.strip()])
    # Wine .spec signatures commonly encode argument kinds as whitespace-separated
    # tokens, e.g. "(long long ptr)".
    return len([a for a in args.split() if a.strip()])


def _parse_export_fields(
    kind: str, rest: str
) -> tuple[str, str | None, bool, int, str | None] | None:
    kind_l = kind.lower()
    if not rest:
        return None

    if kind_l == "stub":
        toks = rest.split()
        if not toks:
            return None
        return toks[0], None, False, 0, None

    if kind_l == "extern":
        toks = rest.split()
        if not toks:
            return None
        name = toks[0]
        impl_name = None
        forward = toks[1] if len(toks) > 1 and "." in toks[1] else None
        if len(toks) > 1 and "." not in toks[1]:
            impl_name = toks[1]
        return name, forward, True, 0, impl_name

    lpar = rest.find("(")
    arg_count = 0
    if lpar < 0:
        toks = rest.split()
        if not toks:
            return None
        name = toks[0]
        tail = " ".join(toks[1:])
    else:
        name = rest[:lpar].strip()
        rpar = _find_matching_paren(rest, lpar)
        if rpar < 0:
            return None
        arg_count = _count_args(rest[lpar + 1 : rpar])
        tail = rest[rpar + 1 :].strip()

    if not name:
        return None
    forward = None
    impl_name = None
    if tail:
        tok = tail.split()[0]
        if "." in tok:
            forward = tok
        else:
            impl_name = tok
    return name, forward, False, arg_count, impl_name


def parse_spec(spec_path: Path) -> list[SpecExport]:
    lines = spec_path.read_text(encoding="utf-8", errors="replace").splitlines()
    out: list[SpecExport] = []
    seen_names: set[str] = set()
    used_ordinals: set[int] = set()
    next_auto_ordinal = 1

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        ordinal_body = _split_ordinal_and_body(line)
        if ordinal_body is None:
            continue
        explicit_ordinal, body = ordinal_body
        if not body or body.startswith("#"):
            continue

        parsed = _split_kind_and_options(body)
        if parsed is None:
            continue
        kind, opts, rest = parsed

        arch_opts = [o for o in opts if o.startswith("-arch=")]
        if arch_opts:
            allowed = True
            for o in arch_opts:
                val = o.split("=", 1)[1].strip() if "=" in o else ""
                if not _arch_option_allows(val):
                    allowed = False
                    break
            if not allowed:
                continue

        fields = _parse_export_fields(kind, rest)
        if fields is None:
            continue
        name, forward, is_data, arg_count, impl_name = fields
        noname = "-noname" in opts or name == "@"
        public_name = None if noname else name
        if explicit_ordinal is not None:
            ordinal = explicit_ordinal
        else:
            ordinal = next_auto_ordinal
            while ordinal in used_ordinals:
                ordinal += 1
        dedup_key = public_name if public_name is not None else f"@{ordinal}"
        if dedup_key in seen_names:
            continue
        seen_names.add(dedup_key)
        used_ordinals.add(ordinal)
        next_auto_ordinal = max(next_auto_ordinal, ordinal + 1)
        impl_symbol = impl_name or (name if name != "@" else f"ordinal_{ordinal}")

        out.append(
            SpecExport(
                ordinal=ordinal,
                name=impl_symbol,
                public_name=public_name,
                is_data=is_data,
                is_syscall=("-syscall" in opts),
                forward=forward,
                impl_name=impl_name,
                arg_count=arg_count,
                noname=noname,
            )
        )

    syscall_idx = 0
    for e in out:
        if e.is_syscall:
            e.syscall_nr = 0x1000 + syscall_idx
            syscall_idx += 1

    return out


def _sanitize_ident(name: str) -> str:
    out = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not out:
        out = "sym"
    if out[0].isdigit():
        out = "_" + out
    return out


def emit_c(
    path: Path,
    dll_name: str,
    entries: Iterable[SpecExport],
    stub_return: int,
    emit_dllmain: bool = True,
) -> None:
    entries = list(entries)
    syscall_entries = [e for e in entries if e.is_syscall and not e.is_data and e.forward is None]

    lines: list[str] = []
    lines.append("/* Auto-generated by scripts/spec_codegen.py. */")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append("typedef void* HANDLE;")
    lines.append("typedef uint32_t ULONG;")
    lines.append("")
    lines.append("#ifdef _MSC_VER")
    lines.append("#define DLL_EXPORT __declspec(dllexport)")
    lines.append("#else")
    lines.append("#define DLL_EXPORT __attribute__((visibility(\"default\")))")
    lines.append("#endif")
    lines.append("")
    lines.append("__attribute__((used, visibility(\"hidden\")))")
    lines.append("uint64_t winemu_stub_export(void) {")
    lines.append(f"    return 0x{stub_return:08x}ull;")
    lines.append("}")
    lines.append("")
    lines.append("__attribute__((used, visibility(\"hidden\")))")
    lines.append("uint64_t winemu_data_export = 0;")
    lines.append("")

    for e in syscall_entries:
        assert e.syscall_nr is not None
        sym = f"{dll_name}_syscall_{e.ordinal:04d}"
        lo = e.syscall_nr & 0xFFFF
        hi = (e.syscall_nr >> 16) & 0xFFFF
        lines.append("__attribute__((naked, used, visibility(\"hidden\")))")
        lines.append(f"void {sym}(void) {{")
        if hi:
            lines.append(
                "    asm volatile(\"movz x8, #%d\\nmovk x8, #%d, lsl #16\\nsvc #0\\nret\\n\" :: \"i\"(%d), \"i\"(%d));"
                % (lo, hi, lo, hi)
            )
        else:
            lines.append(
                "    asm volatile(\"movz x8, #%d\\nsvc #0\\nret\\n\" :: \"i\"(%d));"
                % (lo, lo)
            )
        lines.append("}")
        lines.append("")

    if emit_dllmain:
        lines.append("DLL_EXPORT int DllMain(HANDLE inst, ULONG reason, void* reserved) {")
        lines.append("    (void)inst;")
        lines.append("    (void)reason;")
        lines.append("    (void)reserved;")
        lines.append("    return 1;")
        lines.append("}")
        lines.append("")
    else:
        lines.append("extern int DllMain(HANDLE inst, ULONG reason, void* reserved);")
        lines.append("")
    lines.append("DLL_EXPORT int DllMainCRTStartup(HANDLE inst, ULONG reason, void* reserved) {")
    lines.append("    return DllMain(inst, reason, reserved);")
    lines.append("}")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def emit_def(
    path: Path,
    dll_name: str,
    entries: Iterable[SpecExport],
    passthrough_exports: set[str] | None = None,
) -> None:
    entries = list(entries)
    passthrough_exports = passthrough_exports or set()
    lines: list[str] = []
    lines.append(f"LIBRARY {dll_name}")
    lines.append("EXPORTS")
    for e in entries:
        export_key = e.public_name if e.public_name is not None else e.name
        if export_key in passthrough_exports and not e.forward:
            passthrough_target = e.name
            if e.noname:
                if e.is_data:
                    line = f"    {passthrough_target} @{e.ordinal} NONAME DATA"
                else:
                    line = f"    {passthrough_target} @{e.ordinal} NONAME"
            elif e.is_data:
                line = f"    {e.public_name}={passthrough_target} @{e.ordinal} DATA"
            else:
                line = f"    {e.public_name}={passthrough_target} @{e.ordinal}"
        elif e.forward:
            target = e.forward
            if e.noname:
                line = f"    {target} @{e.ordinal} NONAME"
            else:
                line = f"    {e.public_name}={target} @{e.ordinal}"
        elif e.is_data:
            if e.noname:
                line = f"    winemu_data_export @{e.ordinal} NONAME DATA"
            else:
                line = f"    {e.public_name}=winemu_data_export @{e.ordinal} DATA"
        elif e.is_syscall:
            if e.noname:
                line = f"    {dll_name}_syscall_{e.ordinal:04d} @{e.ordinal} NONAME"
            else:
                line = f"    {e.public_name}={dll_name}_syscall_{e.ordinal:04d} @{e.ordinal}"
        else:
            if e.noname:
                line = f"    winemu_stub_export @{e.ordinal} NONAME"
            else:
                line = f"    {e.public_name}=winemu_stub_export @{e.ordinal}"
        lines.append(line)
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def emit_win32k_sysno_header(path: Path, entries: Iterable[SpecExport]) -> None:
    entries = list(entries)
    lines: list[str] = []
    lines.append("/* Auto-generated from win32u.spec. */")
    lines.append("#pragma once")
    lines.append("")
    lines.append("/* win32k/syscall table = 1, encoded in x8 (0x1000 + id). */")
    lines.append("")
    used: set[str] = set()
    for e in entries:
        if not e.is_syscall or e.syscall_nr is None:
            continue
        export_name = e.public_name if e.public_name is not None else e.name
        macro = f"WIN32K_SYSCALL_{_sanitize_ident(export_name)}"
        if macro in used:
            continue
        used.add(macro)
        lines.append(f"#define {macro} 0x{e.syscall_nr:04x}")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def emit_win32k_sysno_rust(path: Path, entries: Iterable[SpecExport]) -> None:
    entries = list(entries)
    lines: list[str] = []
    lines.append("// Auto-generated from win32u.spec. Do not edit manually.")
    lines.append("")
    lines.append("// win32k/syscall table = 1, encoded in x8 (0x1000 + id).")
    lines.append("pub const TABLE_ID: u8 = 1;")
    lines.append("")
    used: set[str] = set()
    for e in entries:
        if not e.is_syscall or e.syscall_nr is None:
            continue
        export_name = e.public_name if e.public_name is not None else e.name
        name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", export_name)
        name = _sanitize_ident(name).upper()
        if not name:
            continue
        if name in used:
            continue
        used.add(name)
        lines.append(f"pub const {name}: u16 = 0x{(e.syscall_nr & 0x0FFF):03x};")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def emit_win32syscalls_header(path: Path, entries: Iterable[SpecExport]) -> None:
    entries = [e for e in entries if e.is_syscall and e.syscall_nr is not None]
    lines: list[str] = []
    lines.append("/* Auto-generated from win32u.spec. */")
    lines.append("#pragma once")
    lines.append("")
    lines.append("#define ALL_SYSCALLS64 \\")
    for idx, e in enumerate(entries):
        suffix = " \\" if idx != len(entries) - 1 else ""
        export_name = e.public_name if e.public_name is not None else e.name
        lines.append(
            f"    SYSCALL_ENTRY(0x{(e.syscall_nr & 0x0FFF):03x}, {export_name}, {e.arg_count}){suffix}"
        )
    if not entries:
        lines.append("    /* no syscalls */")
    lines.append("")
    lines.append("#define ALL_SYSCALLS32 ALL_SYSCALLS64")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
