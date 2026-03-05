#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from spec_codegen import emit_c, emit_def, parse_spec


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


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate msvcrt exports/stubs from msvcrt.spec")
    ap.add_argument("--spec", required=True, help="Path to msvcrt.spec")
    ap.add_argument("--out-c", required=True, help="Generated C source output")
    ap.add_argument("--out-def", required=True, help="Generated DEF output")
    ap.add_argument("--passthrough", help="Optional file listing exports that map to real object symbols")
    args = ap.parse_args()

    spec_path = Path(args.spec)
    if not spec_path.exists():
        raise SystemExit(f"spec not found: {spec_path}")

    entries = parse_spec(spec_path)
    out_c = Path(args.out_c)
    out_def = Path(args.out_def)
    out_c.parent.mkdir(parents=True, exist_ok=True)
    out_def.parent.mkdir(parents=True, exist_ok=True)
    passthrough = load_passthrough_exports(Path(args.passthrough) if args.passthrough else None)

    emit_c(out_c, "msvcrt", entries, stub_return=0x00000000)
    emit_def(out_def, "msvcrt", entries, passthrough_exports=passthrough)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
