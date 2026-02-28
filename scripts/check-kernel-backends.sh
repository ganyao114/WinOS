#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_MANIFEST="$ROOT_DIR/winemu-kernel/Cargo.toml"

check_target() {
  local target="$1"
  echo "[check] winemu-kernel --target $target"
  cargo check --manifest-path "$KERNEL_MANIFEST" --target "$target"
}

check_with_fallback() {
  local primary="$1"
  local fallback="$2"
  if rustup target list --installed | grep -qx "$primary"; then
    check_target "$primary"
    return
  fi
  echo "[warn] target $primary is not installed, trying rustup target add"
  if rustup target add "$primary"; then
    check_target "$primary"
    return
  fi
  if rustup target list --installed | grep -qx "$fallback"; then
    echo "[warn] fallback to installed target $fallback"
    check_target "$fallback"
    return
  fi
  if [[ "${CI:-}" == "true" ]]; then
    echo "[error] neither $primary nor $fallback is available in CI"
    return 1
  fi
  echo "[warn] skip x86_64 backend check (no available x86_64 target in local toolchain)"
}

check_target "aarch64-unknown-none"
check_with_fallback "x86_64-unknown-none" "x86_64-unknown-linux-gnu"

echo "[ok] kernel backend checks passed"
