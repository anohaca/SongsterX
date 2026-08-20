#!/usr/bin/env bash
set -euo pipefail

# Build the Linux guest in a temporary directory, then copy only the runtime
# files into the Tauri resource tree. Cargo/download state never enters the
# repository or the final application bundle.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/src-tauri/resources/gateway-guest"
STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/songsterx-gateway-bundle.XXXXXX")"

cleanup() {
    rm -rf "$STAGING_DIR"
}
trap cleanup EXIT

BUILD_ARGS=(--output "$STAGING_DIR")
if [[ -n "${SONGSTERX_ALPINE_VERSION:-}" ]]; then
    BUILD_ARGS+=(--alpine-version "$SONGSTERX_ALPINE_VERSION")
fi
if [[ -n "${SONGSTERX_SING_BOX_VERSION:-}" ]]; then
    BUILD_ARGS+=(--sing-box-version "$SONGSTERX_SING_BOX_VERSION")
fi

bash "$ROOT_DIR/scripts/build_gateway_guest.sh" "${BUILD_ARGS[@]}"

required_files=(
    kernel
    initrd
    gateway-agent
    sing-box-linux-arm64
    agent.token
    manifest.json
)
for name in "${required_files[@]}"; do
    if [[ ! -f "$STAGING_DIR/$name" ]]; then
        printf 'gateway guest builder did not produce %s\n' "$name" >&2
        exit 1
    fi
done

# This directory is generated output owned by this script. kernel.config is
# intentionally left out of the app: it is useful for development diagnostics
# but is not required to boot or control the guest.
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
for name in "${required_files[@]}"; do
    install -m 644 "$STAGING_DIR/$name" "$OUTPUT_DIR/$name"
done
chmod 755 "$OUTPUT_DIR/gateway-agent" "$OUTPUT_DIR/sing-box-linux-arm64"
chmod 600 "$OUTPUT_DIR/agent.token" "$OUTPUT_DIR/manifest.json"

printf '%s\n' "Bundled Linux Gateway guest: $OUTPUT_DIR"
du -h "$OUTPUT_DIR"/*
