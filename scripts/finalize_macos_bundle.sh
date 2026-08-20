#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_PATH="${1:-$ROOT_DIR/src-tauri/target/release/bundle/macos/SongsterX.app}"
IDENTITY="${SONGSTERX_CODESIGN_IDENTITY:--}"

if [ ! -d "$APP_PATH" ]; then
  echo "missing app bundle: $APP_PATH" >&2
  exit 1
fi
codesign --force --sign "$IDENTITY" \
  --entitlements "$ROOT_DIR/src-tauri/entitlements.plist" \
  "$APP_PATH"
for nested in \
  "$APP_PATH/Contents/Resources/vmnet-helper" \
  "$APP_PATH/Contents/Resources/vfkit"; do
  if [ ! -x "$nested" ]; then
    echo "missing executable nested resource: $nested" >&2
    exit 1
  fi
done
codesign --verify --strict --verbose=4 \
  "$APP_PATH/Contents/Resources/vmnet-helper"
codesign -dv --verbose=4 \
  "$APP_PATH/Contents/Resources/vmnet-helper" 2>&1
codesign -d --entitlements :- \
  "$APP_PATH/Contents/Resources/vmnet-helper"
codesign --verify --strict --verbose=4 \
  "$APP_PATH/Contents/Resources/vfkit"
codesign --verify --deep --strict --verbose=4 "$APP_PATH"
echo "finalized macOS application bundle: $APP_PATH"
