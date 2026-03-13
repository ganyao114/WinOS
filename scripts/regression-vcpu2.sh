#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export WINEMU_VCPU_COUNT="${WINEMU_VCPU_COUNT:-2}"
export RUST_LOG="${RUST_LOG:-info}"

# Reuse the shared WinEmu build/run helpers from stress-regression.sh.
# shellcheck source=./stress-regression.sh
source "$ROOT_DIR/scripts/stress-regression.sh"

run_vcpu2_matrix() {
  build_all

  echo "[info] starting fixed regression matrix (vcpu_count=$WINEMU_VCPU_COUNT)"
  run_case "thread_test" "$THREAD_TEST"
  run_case "full_test" "$FULL_TEST"
  run_case "process_test" "$PROCESS_TEST"
  run_case "registry_test" "$REGISTRY_TEST"
  run_case "hello_win" "$HELLO_TEST"
  run_case "kmalloc_direct_test" "$KMALLOC_DIRECT_TEST"
  echo "[ok] fixed regression matrix passed (vcpu_count=$WINEMU_VCPU_COUNT)"
}

run_vcpu2_matrix "$@"
