#!/usr/bin/env bash
set -euo pipefail

# Build a small arm64 Linux initrd for the vfkit Gateway. Downloads and
# compiler output are temporary; only final artifacts remain in --output.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR=""
ALPINE_VERSION="${SONGSTERX_ALPINE_VERSION:-3.24.1}"
SING_BOX_VERSION="${SONGSTERX_SING_BOX_VERSION:-1.13.14}"
INPUTS_MANIFEST="${SONGSTERX_GATEWAY_INPUTS_MANIFEST:-$ROOT_DIR/config/gateway-guest-inputs.json}"

usage() {
    cat <<'EOF'
Usage: scripts/build_gateway_guest.sh --output PATH [options]

Options:
  --output PATH              Directory for final guest artifacts (required)
  --alpine-version VERSION   Alpine release, default 3.24.1
  --sing-box-version VERSION Linux arm64 sing-box release, default 1.13.14
  --help                     Show this help

The output directory receives kernel, initrd, gateway-agent, sing-box,
agent.token, and manifest.json. Inputs are locked by
config/gateway-guest-inputs.json; update that manifest when upgrading Alpine
or sing-box. Set SONGSTERX_GATEWAY_AGENT_TOKEN_FILE to the generated
agent.token before starting the app.
EOF
}

while (($# > 0)); do
    case "$1" in
        --output)
            (($# >= 2)) || { usage >&2; exit 2; }
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --alpine-version)
            (($# >= 2)) || { usage >&2; exit 2; }
            ALPINE_VERSION="$2"
            shift 2
            ;;
        --sing-box-version)
            (($# >= 2)) || { usage >&2; exit 2; }
            SING_BOX_VERSION="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

[ -n "$OUTPUT_DIR" ] || { usage >&2; exit 2; }
case "$OUTPUT_DIR" in
    /|.|..|*/..|*/../*)
        printf '%s\n' "refusing ambiguous output directory: $OUTPUT_DIR" >&2
        exit 2
        ;;
esac

for command_name in curl tar gzip cpio unsquashfs cargo rustup shasum file find perl jq; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'missing required command: %s\n' "$command_name" >&2
        exit 1
    }
done
[ "$(uname -m)" = "arm64" ] || {
    printf '%s\n' 'the guest builder currently requires an arm64 macOS host' >&2
    exit 1
}
[ -f "$INPUTS_MANIFEST" ] || {
    printf 'missing Gateway guest input lock manifest: %s\n' "$INPUTS_MANIFEST" >&2
    exit 1
}

LOCKED_ALPINE_VERSION="$(jq -er '.alpine.version' "$INPUTS_MANIFEST")"
LOCKED_ALPINE_BRANCH="$(jq -er '.alpine.branch' "$INPUTS_MANIFEST")"
LOCKED_SING_BOX_VERSION="$(jq -er '.singBox.version' "$INPUTS_MANIFEST")"
[ "$ALPINE_VERSION" = "$LOCKED_ALPINE_VERSION" ] || {
    printf 'Alpine %s is not locked; expected %s in %s\n' \
        "$ALPINE_VERSION" "$LOCKED_ALPINE_VERSION" "$INPUTS_MANIFEST" >&2
    exit 1
}
[ "$SING_BOX_VERSION" = "$LOCKED_SING_BOX_VERSION" ] || {
    printf 'sing-box %s is not locked; expected %s in %s\n' \
        "$SING_BOX_VERSION" "$LOCKED_SING_BOX_VERSION" "$INPUTS_MANIFEST" >&2
    exit 1
}
[ "$LOCKED_ALPINE_BRANCH" = "${ALPINE_VERSION%.*}" ] || {
    printf 'Alpine lock branch does not match version: %s vs %s\n' \
        "$LOCKED_ALPINE_BRANCH" "$ALPINE_VERSION" >&2
    exit 1
}

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/songsterx-gateway-build.XXXXXX")"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

DOWNLOAD_DIR="$WORK_DIR/downloads"
ROOTFS_DIR="$WORK_DIR/rootfs"
BOOTFS_DIR="$WORK_DIR/bootfs"
MODLOOP_DIR="$WORK_DIR/modloop"
INDEX_DIR="$WORK_DIR/index"
CARGO_TARGET_DIR="$WORK_DIR/cargo-target"
mkdir -p "$DOWNLOAD_DIR" "$ROOTFS_DIR" "$BOOTFS_DIR" "$MODLOOP_DIR" "$INDEX_DIR" "$CARGO_TARGET_DIR"

download() {
    local url="$1"
    local destination="$2"
    curl -fL --retry 3 --retry-delay 1 --connect-timeout 15 --max-time 600 \
        -o "$destination" "$url"
}

verify_sha256() {
    local file_path="$1"
    local expected="$2"
    local actual
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || {
        printf 'invalid SHA-256 in Gateway guest input lock for %s\n' "$file_path" >&2
        exit 1
    }
    actual="$(shasum -a 256 "$file_path" | awk '{print $1}')"
    [ "$actual" = "$expected" ] || {
        printf 'SHA-256 mismatch for %s: expected %s, got %s\n' \
            "$file_path" "$expected" "$actual" >&2
        exit 1
    }
}

download_locked() {
    local expected="$1"
    local url="$2"
    local destination="$3"
    download "$url" "$destination"
    verify_sha256 "$destination" "$expected"
}

locked_alpine_file_sha256() {
    jq -er --arg name "$1" '.alpine.files[$name].sha256' "$INPUTS_MANIFEST"
}

locked_alpine_file_name() {
    jq -er --arg name "$1" '.alpine.files[$name].name' "$INPUTS_MANIFEST"
}

ALPINE_BRANCH="$LOCKED_ALPINE_BRANCH"
ALPINE_BASE="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_BRANCH}"
ALPINE_AARCH64="$ALPINE_BASE/releases/aarch64"
ALPINE_NETBOOT="$ALPINE_AARCH64/netboot"
ALPINE_MAIN="$ALPINE_BASE/main/aarch64"

printf '%s\n' 'Downloading Alpine arm64 kernel and base rootfs...'
KERNEL_CONFIG_NAME="$(jq -er '.alpine.kernelConfig.name' "$INPUTS_MANIFEST")"
KERNEL_CONFIG_PATH="$(jq -er '.alpine.kernelConfig.path' "$INPUTS_MANIFEST")"
KERNEL_CONFIG_SHA256="$(jq -er '.alpine.kernelConfig.sha256' "$INPUTS_MANIFEST")"
[ "$KERNEL_CONFIG_NAME" = "$(basename "$KERNEL_CONFIG_PATH")" ] || {
    printf 'Alpine kernel config lock has inconsistent name/path\n' >&2
    exit 1
}
download_locked "$(locked_alpine_file_sha256 vmlinuz-virt)" \
    "$ALPINE_NETBOOT/$(locked_alpine_file_name vmlinuz-virt)" \
    "$DOWNLOAD_DIR/vmlinuz-virt"
download_locked "$(locked_alpine_file_sha256 initramfs-virt)" \
    "$ALPINE_NETBOOT/$(locked_alpine_file_name initramfs-virt)" \
    "$DOWNLOAD_DIR/initramfs-virt"
download_locked "$(locked_alpine_file_sha256 modloop-virt)" \
    "$ALPINE_NETBOOT/$(locked_alpine_file_name modloop-virt)" \
    "$DOWNLOAD_DIR/modloop-virt"
download_locked "$KERNEL_CONFIG_SHA256" "$ALPINE_NETBOOT/$KERNEL_CONFIG_PATH" \
    "$DOWNLOAD_DIR/kernel.config"
MINIROOTFS_NAME="$(jq -er '.alpine.minirootfs.name' "$INPUTS_MANIFEST")"
MINIROOTFS_SHA256="$(jq -er '.alpine.minirootfs.sha256' "$INPUTS_MANIFEST")"
download_locked "$MINIROOTFS_SHA256" "$ALPINE_AARCH64/$MINIROOTFS_NAME" \
    "$DOWNLOAD_DIR/minirootfs.tar.gz"

printf '%s\n' 'Extracting the uncompressed arm64 kernel Image for vfkit...'
VMLINUX_TEXT="$WORK_DIR/vmlinuz.text"
KERNEL_IMAGE="$WORK_DIR/kernel.Image"
dd if="$DOWNLOAD_DIR/vmlinuz-virt" of="$VMLINUX_TEXT" bs=4096 skip=1 2>/dev/null
GZIP_OFFSET="$(perl -0777 -ne '
    my $offset = index($_, "\x1f\x8b\x08");
    print "$offset\n" if $offset >= 0;
' "$VMLINUX_TEXT" | head -n 1)"
[ -n "$GZIP_OFFSET" ] && [ "$GZIP_OFFSET" -ge 0 ] || {
    printf '%s\n' 'could not locate the compressed Linux Image in vmlinuz-virt' >&2
    exit 1
}
dd if="$VMLINUX_TEXT" bs=1 skip="$GZIP_OFFSET" 2>/dev/null | gzip -dc 2>/dev/null > "$KERNEL_IMAGE" || true
file "$KERNEL_IMAGE" | grep -q 'Linux kernel ARM64 boot executable' || {
    printf '%s\n' 'extracted kernel is not an arm64 Linux Image' >&2
    exit 1
}

printf '%s\n' 'Downloading Alpine runtime packages...'
MAIN_INDEX="$INDEX_DIR/main.tgz"
APKINDEX_NAME="$(jq -er '.alpine.apkIndex.name' "$INPUTS_MANIFEST")"
APKINDEX_SHA256="$(jq -er '.alpine.apkIndex.sha256' "$INPUTS_MANIFEST")"
download_locked "$APKINDEX_SHA256" "$ALPINE_MAIN/$APKINDEX_NAME" "$MAIN_INDEX"

download_apk() {
    local package_name="$1"
    local package_version package_file package_sha256
    package_version="$(jq -er --arg package "$package_name" \
        '.alpine.packages[$package].version' "$INPUTS_MANIFEST")"
    package_file="$(jq -er --arg package "$package_name" \
        '.alpine.packages[$package].file' "$INPUTS_MANIFEST")"
    package_sha256="$(jq -er --arg package "$package_name" \
        '.alpine.packages[$package].sha256' "$INPUTS_MANIFEST")"
    [ "$package_file" = "${package_name}-${package_version}.apk" ] || {
        printf 'Alpine package lock has inconsistent file/version for %s\n' \
            "$package_name" >&2
        exit 1
    }
    download_locked "$package_sha256" "$ALPINE_MAIN/$package_file" \
        "$DOWNLOAD_DIR/${package_name}.apk"
}

RUNTIME_PACKAGES=(iproute2-minimal libcap2 libelf libmnl libnftnl libxtables iptables zstd-libs)

# iproute2-minimal supplies a real ip(8); iptables supplies NAT and forwarding.
# Keep their musl runtime dependencies in the initrd as well. In particular,
# libelf loads zstd-libs at runtime even though the package manager is absent
# from this minimal rootfs.
for package_name in musl-dev "${RUNTIME_PACKAGES[@]}"; do
    download_apk "$package_name"
done

printf '%s\n' 'Downloading Linux arm64 sing-box...'
SING_BOX_ARCHIVE="$DOWNLOAD_DIR/sing-box.tar.gz"
SING_BOX_ARCHIVE_NAME="$(jq -er '.singBox.archive.name' "$INPUTS_MANIFEST")"
SING_BOX_ARCHIVE_SHA256="$(jq -er '.singBox.archive.sha256' "$INPUTS_MANIFEST")"
download_locked "$SING_BOX_ARCHIVE_SHA256" \
    "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/$SING_BOX_ARCHIVE_NAME" \
    "$SING_BOX_ARCHIVE"

printf '%s\n' 'Preparing Alpine initrd rootfs...'
tar -xzf "$DOWNLOAD_DIR/minirootfs.tar.gz" -C "$ROOTFS_DIR"
gzip -dc "$DOWNLOAD_DIR/initramfs-virt" | (cd "$BOOTFS_DIR" && cpio -idm --quiet)
mkdir -p "$ROOTFS_DIR/lib"
cp -a "$BOOTFS_DIR/lib/modules" "$ROOTFS_DIR/lib/"
if [ -d "$BOOTFS_DIR/lib/firmware" ]; then
    cp -a "$BOOTFS_DIR/lib/firmware" "$ROOTFS_DIR/lib/"
fi
if [ -d "$BOOTFS_DIR/etc/modprobe.d" ]; then
    mkdir -p "$ROOTFS_DIR/etc/modprobe.d"
    cp -a "$BOOTFS_DIR/etc/modprobe.d/." "$ROOTFS_DIR/etc/modprobe.d/"
fi
unsquashfs -force -quiet -d "$MODLOOP_DIR" "$DOWNLOAD_DIR/modloop-virt"
MODULES_DIR="$(find "$MODLOOP_DIR/modules" -mindepth 1 -maxdepth 1 -type d -name '*-virt' | head -n 1)"
[ -n "$MODULES_DIR" ] || {
    printf '%s\n' 'Alpine modloop does not contain virt kernel modules' >&2
    exit 1
}
MODULES_VERSION="$(basename "$MODULES_DIR")"
mkdir -p "$ROOTFS_DIR/lib/modules/$MODULES_VERSION"
cp -a "$MODULES_DIR/." "$ROOTFS_DIR/lib/modules/$MODULES_VERSION/"
tar -xzf "$DOWNLOAD_DIR/musl-dev.apk" -C "$ROOTFS_DIR"
for package_name in "${RUNTIME_PACKAGES[@]}"; do
    tar -xzf "$DOWNLOAD_DIR/${package_name}.apk" -C "$ROOTFS_DIR"
done

# The guest has no apk database or package manager at boot. Validate the
# shared-library closure needed by iproute2/iptables before producing an
# initrd, so a missing Alpine runtime package cannot surface as an init panic.
require_rootfs_library() {
    local library_name="$1"
    local library_path
    library_path="$(find "$ROOTFS_DIR" \( -type f -o -type l \) -name "$library_name" -print -quit)"
    [ -n "$library_path" ] || {
        printf 'required guest runtime library is missing: %s\n' "$library_name" >&2
        exit 1
    }
}

for library_name in \
    ld-musl-aarch64.so.1 \
    libcap.so.2 \
    libelf.so.1 \
    libz.so.1 \
    libmnl.so.0 \
    libnftnl.so.11 \
    libxtables.so.12 \
    libzstd.so.1; do
    require_rootfs_library "$library_name"
done

SING_BOX_SOURCE="$(tar -tzf "$SING_BOX_ARCHIVE" | awk -F/ '$NF == "sing-box" { print; exit }')"
[ -n "$SING_BOX_SOURCE" ] || {
    printf '%s\n' 'sing-box archive does not contain an executable named sing-box' >&2
    exit 1
}
tar -xzf "$SING_BOX_ARCHIVE" -C "$WORK_DIR" "$SING_BOX_SOURCE"
SING_BOX_BINARY="$WORK_DIR/$SING_BOX_SOURCE"

if ! rustup target list --installed | awk '$1 == "aarch64-unknown-linux-musl" { found = 1 } END { exit found ? 0 : 1 }'; then
    printf '%s\n' 'installing Rust aarch64-unknown-linux-musl target...'
    rustup target add aarch64-unknown-linux-musl
fi

# musl-dev provides crt objects and the musl dynamic loader. clang/lld can
# link the pure-Rust agent without installing a full cross compiler.
MUSL_CLANG="$WORK_DIR/aarch64-linux-musl-clang"
RUST_SYSROOT="$(rustc --print sysroot)"
RUST_LLD="$RUST_SYSROOT/lib/rustlib/aarch64-apple-darwin/bin/rust-lld"
RUST_LLD_WRAPPER="$WORK_DIR/rust-ld.lld"
[ -x "$RUST_LLD" ] || {
    printf '%s\n' "Rust bundled linker not found: $RUST_LLD" >&2
    exit 1
}
cat > "$RUST_LLD_WRAPPER" <<EOF
#!/bin/sh
exec "$RUST_LLD" -flavor gnu "\$@"
EOF
chmod 755 "$RUST_LLD_WRAPPER"
cat > "$MUSL_CLANG" <<EOF
#!/bin/sh
exec clang --target=aarch64-linux-musl --sysroot="$ROOTFS_DIR" -fuse-ld="$RUST_LLD_WRAPPER" "\$@"
EOF
chmod 755 "$MUSL_CLANG"

printf '%s\n' 'Building the Linux arm64 guest-agent...'
(
    cd "$ROOT_DIR"
    CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
        CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$MUSL_CLANG" \
        cargo build --manifest-path src-tauri/guest-agent/Cargo.toml \
            --target aarch64-unknown-linux-musl --release --locked
)
AGENT_BINARY="$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/songsterx-gateway-agent"
[ -x "$AGENT_BINARY" ] || {
    printf '%s\n' 'guest-agent build did not produce an executable' >&2
    exit 1
}

printf '%s\n' 'Installing guest runtime files...'
install -d "$ROOTFS_DIR/usr/lib/songsterx" "$ROOTFS_DIR/usr/bin" \
    "$ROOTFS_DIR/var/lib/songsterx/versions/$SING_BOX_VERSION" \
    "$ROOTFS_DIR/etc/songsterx" "$ROOTFS_DIR/run/songsterx"
install -m 755 "$SING_BOX_BINARY" \
    "$ROOTFS_DIR/var/lib/songsterx/versions/$SING_BOX_VERSION/sing-box"
install -m 755 "$AGENT_BINARY" "$ROOTFS_DIR/usr/bin/songsterx-gateway-agent"
install -m 755 "$ROOT_DIR/guest-runtime/init" "$ROOTFS_DIR/init"
install -m 755 "$ROOT_DIR/guest-runtime/songsterx-gateway-net.sh" \
    "$ROOTFS_DIR/usr/lib/songsterx/songsterx-gateway-net.sh"
printf '%s\n' "$SING_BOX_VERSION" > "$ROOTFS_DIR/var/lib/songsterx/active"

command -v openssl >/dev/null 2>&1 || {
    printf '%s\n' 'openssl is required to generate a random guest agent token' >&2
    exit 1
}
openssl rand -hex 32 > "$ROOTFS_DIR/var/lib/songsterx/agent.token"
chmod 600 "$ROOTFS_DIR/var/lib/songsterx/agent.token"
install -m 600 "$ROOTFS_DIR/var/lib/songsterx/agent.token" "$OUTPUT_DIR/agent.token"

# Development files are only needed as the linker sysroot and do not belong
# in the final initrd.
rm -rf "$ROOTFS_DIR/usr/include" "$ROOTFS_DIR/usr/share/man" \
    "$ROOTFS_DIR/usr/share/doc" "$ROOTFS_DIR/usr/lib/pkgconfig"
find "$ROOTFS_DIR" -type f -name '*.a' -delete

printf '%s\n' 'Creating compressed initrd...'
(cd "$ROOTFS_DIR" && find . -print | LC_ALL=C sort | cpio -o -H newc --quiet | gzip -9) \
    > "$OUTPUT_DIR/initrd"
install -m 644 "$KERNEL_IMAGE" "$OUTPUT_DIR/kernel"
install -m 755 "$AGENT_BINARY" "$OUTPUT_DIR/gateway-agent"
install -m 755 "$SING_BOX_BINARY" "$OUTPUT_DIR/sing-box-linux-arm64"

KERNEL_SHA256="$(shasum -a 256 "$OUTPUT_DIR/kernel" | awk '{print $1}')"
INITRD_SHA256="$(shasum -a 256 "$OUTPUT_DIR/initrd" | awk '{print $1}')"
AGENT_SHA256="$(shasum -a 256 "$OUTPUT_DIR/gateway-agent" | awk '{print $1}')"
SING_BOX_SHA256="$(shasum -a 256 "$OUTPUT_DIR/sing-box-linux-arm64" | awk '{print $1}')"
cat > "$OUTPUT_DIR/manifest.json" <<EOF
{
  "architecture": "aarch64",
  "alpineVersion": "$ALPINE_VERSION",
  "singBoxVersion": "$SING_BOX_VERSION",
  "kernel": {"path": "kernel", "sha256": "$KERNEL_SHA256"},
  "initrd": {"path": "initrd", "sha256": "$INITRD_SHA256"},
  "gatewayAgent": {"path": "gateway-agent", "sha256": "$AGENT_SHA256"},
  "singBox": {"path": "sing-box-linux-arm64", "sha256": "$SING_BOX_SHA256"},
  "tokenFile": "agent.token"
}
EOF
chmod 600 "$OUTPUT_DIR/manifest.json"

printf '\n%s\n' 'Gateway guest artifacts ready:'
du -h "$OUTPUT_DIR/kernel" "$OUTPUT_DIR/initrd" "$OUTPUT_DIR/gateway-agent" "$OUTPUT_DIR/sing-box-linux-arm64"
printf '%s\n' "kernel: $OUTPUT_DIR/kernel"
printf '%s\n' "initrd: $OUTPUT_DIR/initrd"
printf '%s\n' "token:  $OUTPUT_DIR/agent.token"
printf '%s\n' 'Set SONGSTERX_GATEWAY_AGENT_TOKEN_FILE to the token path before starting the app.'
