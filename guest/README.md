# Guest Runtime Artifacts

`guest/sysroot/` contains generated guest binaries (for example `ntdll.dll`, `ntdll.lib`, test EXEs).

Policy:
- Do not commit generated binaries from `guest/sysroot/`.
- Keep only `guest/sysroot/.gitkeep` in Git.
- Rebuild artifacts locally when needed.

Build command:

```bash
make -C guest
```
