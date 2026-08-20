#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="${SONGSTERX_VMNET_HELPER_SOURCE:-$ROOT_DIR/vendor/vmnet-helper}"
BUILD_DIR="${SONGSTERX_VMNET_HELPER_BUILD_DIR:-$ROOT_DIR/src-tauri/target/vmnet-helper-build}"
OUTPUT="$ROOT_DIR/src-tauri/resources/vmnet-helper"

if [[ -d "$SOURCE_DIR" ]]; then
  command -v meson >/dev/null || { echo "meson is required to build bundled vmnet-helper" >&2; exit 1; }
  if [[ -f "$BUILD_DIR/build.ninja" ]]; then
    meson setup --reconfigure "$BUILD_DIR" "$SOURCE_DIR" --buildtype=release
  else
    meson setup "$BUILD_DIR" "$SOURCE_DIR" --buildtype=release
  fi
  meson compile -C "$BUILD_DIR"
  install -m 755 "$BUILD_DIR/programs/vmnet-helper" "$OUTPUT"
elif [[ ! -x "$OUTPUT" ]]; then
  echo "bundled vmnet-helper source and resource are both missing" >&2
  echo "expected source: $SOURCE_DIR" >&2
  exit 1
fi

# vmnet-helper upstream uses this entitlement to allow the helper to create
# vmnet interfaces without requiring the SongsterX app to own vmnet access.
SIGNING_IDENTITY="${SONGSTERX_VMNET_HELPER_SIGNING_IDENTITY:-${SONGSTERX_CODESIGN_IDENTITY:--}}"
codesign --force --sign "$SIGNING_IDENTITY" \
  --entitlements "$SOURCE_DIR/building/entitlements.plist" \
  "$OUTPUT"
chmod 755 "$OUTPUT"
echo "Bundled vmnet-helper: $OUTPUT (identity: $SIGNING_IDENTITY)"
