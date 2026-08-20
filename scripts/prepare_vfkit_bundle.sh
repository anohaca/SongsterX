#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="$ROOT_DIR/src-tauri/resources/vfkit"
SOURCE="${SONGSTERX_VFKIT_BIN:-}"

if [[ -z "$SOURCE" ]]; then
    SOURCE="$(command -v vfkit || true)"
fi
if [[ -z "$SOURCE" || ! -f "$SOURCE" ]]; then
    printf '%s\n' 'vfkit executable not found; set SONGSTERX_VFKIT_BIN or install vfkit' >&2
    exit 1
fi
if [[ ! -x "$SOURCE" ]]; then
    printf 'vfkit is not executable: %s\n' "$SOURCE" >&2
    exit 1
fi

FILE_KIND="$(file -b "$SOURCE")"
if [[ "$FILE_KIND" != *'Mach-O 64-bit executable arm64'* ]]; then
    printf 'vfkit must be an Apple Silicon arm64 executable, got: %s\n' "$FILE_KIND" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"
install -m 755 "$SOURCE" "$OUTPUT"
printf '%s\n' "Bundled vfkit: $OUTPUT"
