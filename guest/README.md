# Guest Runtime Artifacts

`guest/sysroot/` contains generated guest binaries (for example `ntdll.dll`, `ntdll.lib`, guest test EXEs).

Layout:
- `guest/ntdll/`: ntdll implementation and build scripts.
- `guest/win32u/`: win32u shim DLL and win32k syscall trampolines.
- `guest/kernelbase/`: kernelbase scaffold for future compatibility exports.
- `tests/guest/*`: C guest test programs (migrated out of `guest/`).

Policy:
- Do not commit generated binaries from `guest/sysroot/`.
- Keep only `guest/sysroot/.gitkeep` in Git.
- Rebuild artifacts locally when needed.

Build commands:

```bash
make -C guest
make -C tests/guest
```
