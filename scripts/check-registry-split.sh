#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[check] cargo build -p winemu-vmm"
cargo build -p winemu-vmm

echo "[check] cargo build --release (tests/registry_test)"
(
  cd tests/registry_test
  cargo build --release
)

echo "[ok] registry split regression checks passed"
