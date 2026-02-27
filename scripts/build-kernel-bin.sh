#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_DIR="$ROOT_DIR/winemu-kernel"
TARGET_TRIPLE="aarch64-unknown-none"
KERNEL_ELF="$KERNEL_DIR/target/$TARGET_TRIPLE/release/winemu-kernel"
KERNEL_BIN="$ROOT_DIR/winemu-kernel.bin"

if command -v rust-objcopy >/dev/null 2>&1; then
  OBJCOPY_BIN="rust-objcopy"
elif command -v llvm-objcopy >/dev/null 2>&1; then
  OBJCOPY_BIN="llvm-objcopy"
elif command -v objcopy >/dev/null 2>&1; then
  OBJCOPY_BIN="objcopy"
else
  echo "[error] rust-objcopy/llvm-objcopy/objcopy not found"
  echo "Install one of them first (recommended: rust-objcopy)."
  exit 1
fi

echo "[build] cargo build --release --target $TARGET_TRIPLE (winemu-kernel)"
(
  cd "$KERNEL_DIR"
  cargo build --release --target "$TARGET_TRIPLE"
)

if [[ ! -f "$KERNEL_ELF" ]]; then
  echo "[error] kernel ELF not found: $KERNEL_ELF"
  exit 1
fi

echo "[build] $OBJCOPY_BIN --binary-architecture=aarch64 --strip-all -O binary"
"$OBJCOPY_BIN" --binary-architecture=aarch64 "$KERNEL_ELF" --strip-all -O binary "$KERNEL_BIN"

BIN_SIZE="$(wc -c <"$KERNEL_BIN" | tr -d '[:space:]')"
echo "[ok] generated: $KERNEL_BIN (${BIN_SIZE} bytes)"
