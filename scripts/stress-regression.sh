#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROUNDS="${1:-50}"
SUITE="${2:-core}"
WINEMU_BIN="$ROOT_DIR/target/debug/winemu"

if ! [[ "$ROUNDS" =~ ^[0-9]+$ ]] || [[ "$ROUNDS" -lt 1 ]]; then
  echo "[error] rounds must be a positive integer (got: $ROUNDS)"
  exit 1
fi
if [[ "$SUITE" != "core" && "$SUITE" != "full" ]]; then
  echo "[error] suite must be one of: core, full (got: $SUITE)"
  exit 1
fi

build_all() {
  echo "[build] kernel binary"
  "$ROOT_DIR/scripts/build-kernel-bin.sh"

  echo "[build] host winemu"
  (cd "$ROOT_DIR" && cargo build)

  echo "[build] guest C tests"
  (cd "$ROOT_DIR/guest" && make)

  echo "[build] guest Rust tests"
  (cd "$ROOT_DIR/tests/thread_test" && cargo build --release --target aarch64-pc-windows-msvc)
  (cd "$ROOT_DIR/tests/full_test" && cargo build --release --target aarch64-pc-windows-msvc)
  (cd "$ROOT_DIR/tests/registry_test" && cargo build --release --target aarch64-pc-windows-msvc)
  (cd "$ROOT_DIR/tests/hello_win" && cargo build --release --target aarch64-pc-windows-msvc)

  echo "[build] codesign winemu"
  (cd "$ROOT_DIR" && codesign --force --entitlements entitlements.plist -s - target/debug/winemu)
}

run_case() {
  local label="$1"
  local exe_path="$2"
  if [[ ! -f "$exe_path" ]]; then
    echo "[error] missing test binary: $exe_path"
    exit 1
  fi
  echo "[run] $label"
  "$WINEMU_BIN" run "$exe_path"
}

build_all

PROCESS_TEST="$ROOT_DIR/guest/sysroot/process_test.exe"
THREAD_TEST="$ROOT_DIR/tests/thread_test/target/aarch64-pc-windows-msvc/release/thread_test.exe"
FULL_TEST="$ROOT_DIR/tests/full_test/target/aarch64-pc-windows-msvc/release/full_test.exe"
REGISTRY_TEST="$ROOT_DIR/tests/registry_test/target/aarch64-pc-windows-msvc/release/registry_test.exe"
HELLO_TEST="$ROOT_DIR/tests/hello_win/target/aarch64-pc-windows-msvc/release/hello_win.exe"

echo "[info] starting stress regression, rounds=$ROUNDS"
for ((round = 1; round <= ROUNDS; round++)); do
  echo "[round $round/$ROUNDS] ========================================"
  run_case "process_test" "$PROCESS_TEST"
  run_case "thread_test" "$THREAD_TEST"
  if [[ "$SUITE" == "full" ]]; then
    run_case "full_test" "$FULL_TEST"
    run_case "registry_test" "$REGISTRY_TEST"
    run_case "hello_win" "$HELLO_TEST"
  fi
done

echo "[ok] stress regression finished: rounds=$ROUNDS suite=$SUITE"
