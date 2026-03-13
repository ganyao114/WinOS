#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from spec_codegen import emit_c, emit_def, parse_spec


def load_passthrough_exports(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    names: set[str] = set()
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        names.add(line)
    return names


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate PE exports/stubs from a Wine .spec file")
    ap.add_argument("--module", required=True, help="DLL module name without .dll suffix")
    ap.add_argument("--spec", required=True, help="Path to .spec file")
    ap.add_argument("--out-c", required=True, help="Generated C source output")
    ap.add_argument("--out-def", required=True, help="Generated DEF output")
    ap.add_argument("--passthrough", help="Optional file listing exports mapped to real objects")
    ap.add_argument(
        "--stub-return",
        default="0x00000000",
        help="Stub return value used by generated fallback exports",
    )
    ap.add_argument(
        "--no-dllmain",
        action="store_true",
        help="Do not emit a generated DllMain body; declare it extern instead",
    )
    args = ap.parse_args()

    spec_path = Path(args.spec)
    if not spec_path.exists():
        raise SystemExit(f"spec not found: {spec_path}")

    out_c = Path(args.out_c)
    out_def = Path(args.out_def)
    out_c.parent.mkdir(parents=True, exist_ok=True)
    out_def.parent.mkdir(parents=True, exist_ok=True)

    entries = parse_spec(spec_path)
    passthrough = load_passthrough_exports(Path(args.passthrough) if args.passthrough else None)
    stub_return = int(args.stub_return, 0)

    emit_c(
        out_c,
        args.module,
        entries,
        stub_return=stub_return,
        emit_dllmain=not args.no_dllmain,
    )
    emit_def(out_def, args.module, entries, passthrough_exports=passthrough)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
