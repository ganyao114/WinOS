#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WINEMU_BIN="$ROOT_DIR/target/debug/winemu"
VCPU_COUNT="${WINEMU_VCPU_COUNT:-1}"
RUST_LOG_LEVEL="${RUST_LOG:-info}"

PROCESS_TEST="$ROOT_DIR/guest/sysroot/process_test.exe"
THREAD_TEST="$ROOT_DIR/tests/thread_test/target/aarch64-pc-windows-msvc/release/thread_test.exe"
FULL_TEST="$ROOT_DIR/tests/full_test/target/aarch64-pc-windows-msvc/release/full_test.exe"
REGISTRY_TEST="$ROOT_DIR/tests/registry_test/target/aarch64-pc-windows-msvc/release/registry_test.exe"
HELLO_TEST="$ROOT_DIR/tests/hello_win/target/aarch64-pc-windows-msvc/release/hello_win.exe"
KMALLOC_DIRECT_TEST="$ROOT_DIR/tests/kmalloc_direct_test/target/aarch64-pc-windows-msvc/release/kmalloc_direct_test.exe"

build_all() {
  echo "[build] kernel binary"
  "$ROOT_DIR/scripts/build-kernel-bin.sh"

  echo "[build] host winemu"
  (cd "$ROOT_DIR" && cargo build)

  echo "[build] guest runtime"
  (
    cd "$ROOT_DIR/guest" && \
    make ntdll win32u msvcrt shell32 fastprox winspool.drv wined3d runtime-data
  )

  echo "[build] guest C process_test"
  (
    cd "$ROOT_DIR/tests/guest/process_test" && \
    make SYSROOT="$ROOT_DIR/guest/sysroot"
  )

  echo "[build] guest Rust tests"
  (cd "$ROOT_DIR/tests/thread_test" && cargo build --release --target aarch64-pc-windows-msvc)
  (cd "$ROOT_DIR/tests/full_test" && cargo build --release --target aarch64-pc-windows-msvc)
  (cd "$ROOT_DIR/tests/registry_test" && cargo build --release --target aarch64-pc-windows-msvc)
  (cd "$ROOT_DIR/tests/hello_win" && cargo build --release --target aarch64-pc-windows-msvc)
  (cd "$ROOT_DIR/tests/kmalloc_direct_test" && cargo build --release --target aarch64-pc-windows-msvc)

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
  echo "[run] $label (vcpu_count=$VCPU_COUNT)"
  WINEMU_VCPU_COUNT="$VCPU_COUNT" RUST_LOG="$RUST_LOG_LEVEL" \
    "$WINEMU_BIN" run "$exe_path"
}

run_stress_regression() {
  local rounds="$1"
  local suite="$2"

  if ! [[ "$rounds" =~ ^[0-9]+$ ]] || [[ "$rounds" -lt 1 ]]; then
    echo "[error] rounds must be a positive integer (got: $rounds)"
    exit 1
  fi
  if [[ "$suite" != "core" && "$suite" != "full" ]]; then
    echo "[error] suite must be one of: core, full (got: $suite)"
    exit 1
  fi

  build_all

  echo "[info] starting stress regression, rounds=$rounds suite=$suite vcpu_count=$VCPU_COUNT"
  for ((round = 1; round <= rounds; round++)); do
    echo "[round $round/$rounds] ========================================"
    run_case "process_test" "$PROCESS_TEST"
    run_case "thread_test" "$THREAD_TEST"
    if [[ "$suite" == "full" ]]; then
      run_case "full_test" "$FULL_TEST"
      run_case "registry_test" "$REGISTRY_TEST"
      run_case "hello_win" "$HELLO_TEST"
      run_case "kmalloc_direct_test" "$KMALLOC_DIRECT_TEST"
    fi
  done

  echo "[ok] stress regression finished: rounds=$rounds suite=$suite vcpu_count=$VCPU_COUNT"
}

main() {
  local rounds="${1:-50}"
  local suite="${2:-core}"
  run_stress_regression "$rounds" "$suite"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
