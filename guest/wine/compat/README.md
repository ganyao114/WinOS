# Wine Compat Layer

This directory is reserved for WinEmu-specific compatibility shims that are
shared by all guest DLL ports.

Rules:

1. Prefer `guest/wine/include` (synced from Wine) first.
2. Only add files here when upstream Wine headers cannot be used directly.
3. Keep shims minimal and generic; do not create per-DLL private copies.
