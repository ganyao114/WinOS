#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_WINE="${1:-${WINE_SRC:-/Users/swift/wine-proton-macos}}"
DST_WIN32U="$ROOT_DIR/guest/win32u"
DST_MSVCRT="$ROOT_DIR/guest/msvcrt"
DST_SHELL32="$ROOT_DIR/guest/shell32"
DST_NLS="$ROOT_DIR/guest/nls"
DST_WINE_INCLUDE="$ROOT_DIR/guest/wine/include"

if [[ ! -d "$SRC_WINE" ]]; then
  echo "wine source not found: $SRC_WINE" >&2
  exit 1
fi

sync_tree() {
  local src="$1"
  local dst="$2"
  if [[ ! -d "$src" ]]; then
    echo "missing source dir: $src" >&2
    exit 1
  fi
  mkdir -p "$dst"
  if ! command -v rsync >/dev/null 2>&1; then
    echo "rsync is required for source sync" >&2
    exit 1
  fi
  rsync -a --delete \
    --exclude 'tests/' \
    --exclude 'Makefile' \
    --exclude 'generated/' \
    --exclude 'passthrough_exports.txt' \
    --exclude 'winemu_*.c' \
    --exclude 'winemu_*.h' \
    "$src/" "$dst/"
}

sync_tree "$SRC_WINE/dlls/win32u" "$DST_WIN32U"
sync_tree "$SRC_WINE/dlls/msvcrt" "$DST_MSVCRT"
sync_tree "$SRC_WINE/dlls/shell32" "$DST_SHELL32"
sync_tree "$SRC_WINE/include" "$DST_WINE_INCLUDE"
mkdir -p "$DST_NLS"
rsync -a --delete \
  --include '*/' \
  --include '*.nls' \
  --exclude '*' \
  "$SRC_WINE/nls/" "$DST_NLS/"

if [[ -d "$SRC_WINE/.git" ]]; then
  REV="$(git -C "$SRC_WINE" rev-parse HEAD 2>/dev/null || true)"
else
  REV=""
fi

write_version() {
  local dst="$1"
  {
    echo "source_path=$SRC_WINE"
    if [[ -n "$REV" ]]; then
      echo "source_git_rev=$REV"
    fi
    echo "synced_at_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  } > "$dst/SOURCE_VERSION.txt"
}

write_version "$DST_WIN32U"
write_version "$DST_MSVCRT"
write_version "$DST_SHELL32"
write_version "$DST_NLS"
write_version "$ROOT_DIR/guest/wine"

{
  echo "source_path=$SRC_WINE"
  if [[ -n "$REV" ]]; then
    echo "source_git_rev=$REV"
  fi
  echo "synced_at_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} > "$ROOT_DIR/guest/WINE_SOURCE_VERSION.txt"

echo "Synced Wine win32u sources into $DST_WIN32U"
echo "Synced Wine msvcrt sources into $DST_MSVCRT"
echo "Synced Wine shell32 sources into $DST_SHELL32"
echo "Synced Wine NLS data into $DST_NLS"
echo "Synced Wine shared headers into $DST_WINE_INCLUDE"
