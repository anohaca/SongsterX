#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

command -v sing-box >/dev/null
command -v jq >/dev/null
command -v shasum >/dev/null

sing-box version
sing-box check -c config/sing-box.gateway-minimal.json
sing-box format -c config/sing-box.gateway-minimal.json >/dev/null
jq empty config/sing-box.gateway-minimal.json
test -f config/songsterx.gateway-minimal.conf
test -f src-tauri/src/vfkit.rs
test -f src-tauri/src/gateway_runtime.rs
rg -q 'build_runtime_plan' src-tauri/src/vfkit.rs
rg -q 'guest_agent::query_status' src-tauri/src/lib.rs
rg -q 'guest_agent::query_connections' src-tauri/src/lib.rs
rg -q '"connections" => respond' src-tauri/guest-agent/main.rs
rg -q 'GUEST_CLASH_API_ADDR.*127\.0\.0\.1:9090' src-tauri/guest-agent/main.rs
rg -q 'GATEWAY_GUEST_PACKET_PATH_RELEASE_GATE' src-tauri/src/lib.rs
rg -q 'const GATEWAY_GUEST_PACKET_PATH_RELEASE_GATE: bool = true;' src-tauri/src/lib.rs
rg -q 'fn gateway_runtime_release_gate_is_open_and_not_a_prelaunch_readiness_probe' src-tauri/src/lib.rs
rg -q 'pub\(crate\) fn runtime_blockers' src-tauri/src/packet_path.rs
rg -q 'pub\(crate\) fn runtime_ready' src-tauri/src/packet_path.rs
rg -q 'default_readiness_is_not_a_valid_prelaunch_runtime_gate' src-tauri/src/packet_path.rs
rg -q 'manual_packet_path_acceptance_is_separate_from_runtime_readiness' src-tauri/src/packet_path.rs
rg -q 'guest_agent_status_diagnostic' src-tauri/src/lib.rs
rg -q 'status_is_bootstrap_ready' src-tauri/src/lib.rs src-tauri/src/guest_agent.rs
rg -q 'status_is_ready' src-tauri/src/lib.rs src-tauri/src/guest_agent.rs
rg -q 'mark_guest_packet_path_not_ready' src-tauri/src/lib.rs
rg -q 'Guest packet path 已验收' src-tauri/src/lib.rs
rg -q '等待验收' src-tauri/src/lib.rs
rg -q 'LAN 与 tun0' src-tauri/src/lib.rs
test -x src-tauri/resources/vmnet-helper
test -x scripts/prepare_vmnet_helper.sh
test -x scripts/build_gateway_guest.sh
test -f src-tauri/guest-agent/Cargo.toml
test -f src-tauri/guest-agent/Cargo.lock
test -f vendor/vmnet-helper/SOURCE.txt
! test -e docs/Default.conf
! rg -n 'BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY|\[Keystore\].*base64\s*=\s*[A-Za-z0-9+/]{128,}|password\s*=\s*[^<[:space:]]|psk\s*=\s*[^<[:space:]]' docs config
! test -e src-tauri/gatewaykit
! test -e native/root-controller
! test -e scripts/prepare_gatewaykit.sh
! test -e scripts/prepare_root_controller.sh
! test -e src-tauri/resources/songsterx-gatewaykit
! test -e src-tauri/resources/songsterx-root-controller
! test -e src-tauri/resources/Libbox.framework
! rg -n 'gateway_child|root_controller|root-controller|packet_relay|packet-relay|utun100|NetworkExtension|network-extension|SongsterXNetwork|songsterx-network-controller' \
    src-tauri/src src-tauri/tauri.conf.json scripts/run_gateway_minimal.sh scripts/finalize_macos_bundle.sh \
    package.json src/App.tsx README.md docs config
jq empty config/module-assets.manifest.json
jq empty config/surge-logic-rules.redacted.json
jq empty config/gateway-guest-inputs.json

python3 - <<'PY'
import configparser
import hashlib
import json
import pathlib
import re
import sys

root = pathlib.Path.cwd()
manifest = json.loads((root / "config/module-assets.manifest.json").read_text())
if manifest["execute_remote_code"] is not False:
    raise SystemExit("remote code execution must remain disabled")

guest_inputs = json.loads((root / "config/gateway-guest-inputs.json").read_text())
if guest_inputs["schema"] != "songsterx-gateway-inputs/v1":
    raise SystemExit("unexpected Gateway guest input lock schema")
alpine = guest_inputs["alpine"]
if alpine["version"] != "3.24.1" or alpine["branch"] != "3.24":
    raise SystemExit("Gateway Alpine version/branch is not the reviewed lock")
hash_re = re.compile(r"^[0-9a-f]{64}$")
for item_name, item in alpine["files"].items():
    if item["name"] != item_name or not hash_re.fullmatch(item["sha256"]):
        raise SystemExit(f"invalid Alpine file lock: {item_name}")
if not hash_re.fullmatch(alpine["kernelConfig"]["sha256"]):
    raise SystemExit("invalid Alpine kernel config lock")
for item_name in ("minirootfs", "apkIndex"):
    if not hash_re.fullmatch(alpine[item_name]["sha256"]):
        raise SystemExit(f"invalid Alpine lock: {item_name}")
expected_packages = {
    "musl-dev", "iproute2-minimal", "libcap2", "libelf", "libmnl",
    "libnftnl", "libxtables", "iptables", "zstd-libs",
}
if set(alpine["packages"]) != expected_packages:
    raise SystemExit("Gateway Alpine package lock does not match the guest runtime")
for package_name, package in alpine["packages"].items():
    if package["file"] != f"{package_name}-{package['version']}.apk":
        raise SystemExit(f"inconsistent APK lock: {package_name}")
    if not hash_re.fullmatch(package["sha256"]):
        raise SystemExit(f"invalid APK hash lock: {package_name}")
sing_box = guest_inputs["singBox"]
if sing_box["version"] != "1.13.14":
    raise SystemExit("sing-box version is not the reviewed lock")
if not hash_re.fullmatch(sing_box["archive"]["sha256"]):
    raise SystemExit("invalid sing-box archive lock")

module_manifest = (root / "config/modules.manifest.yaml").read_text()
module_entries = re.findall(
    r"local_file:\s*(\S+)\s*\n\s+sha256:\s*([0-9a-f]{64})",
    module_manifest,
)
if len(module_entries) != 9:
    raise SystemExit(f"expected 9 module hash entries, got {len(module_entries)}")
for relative, expected in module_entries:
    path = root / relative
    if not path.is_file():
        raise SystemExit(f"missing module: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected:
        raise SystemExit(f"module hash mismatch: {path} ({digest})")

asset_by_source = {asset["source"]: asset for asset in manifest["assets"]}
runtime_urls = {}
module_paths = [root / relative for relative, _ in module_entries]
script_re = re.compile(r'''\bscript-path\s*=\s*["']?(https?://[^,"'\s]+)''', re.I)
data_re = re.compile(r'''\bdata\s*=\s*["'](https?://[^"']+)["']''', re.I)
ruleset_re = re.compile(r'''\bRULE-SET\s*,\s*(https?://[^,\s]+)\s*,''', re.I)
for module_path in module_paths:
    module_text = module_path.read_text(errors="replace")
    urls = set(script_re.findall(module_text))
    urls.update(data_re.findall(module_text))
    urls.update(ruleset_re.findall(module_text))
    runtime_urls[module_path.name] = sorted(urls)

referenced = set().union(*runtime_urls.values()) if runtime_urls else set()
manifest_sources = set(asset_by_source)
if referenced != manifest_sources:
    missing = sorted(referenced - manifest_sources)
    extra = sorted(manifest_sources - referenced)
    raise SystemExit(f"asset closure mismatch: missing={missing}, extra={extra}")
if len(referenced) != 16:
    raise SystemExit(f"expected 16 unique runtime references, got {len(referenced)}")
for module_name, urls in runtime_urls.items():
    for url in urls:
        asset = asset_by_source.get(url)
        if asset is None:
            raise SystemExit(f"runtime dependency missing from manifest: {module_name}: {url}")
        if not (root / asset["local_file"]).is_file():
            raise SystemExit(f"runtime dependency missing locally: {module_name}: {url}")

for asset in manifest["assets"]:
    path = root / asset["local_file"]
    if not path.is_file():
        raise SystemExit(f"missing asset: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != asset["sha256"]:
        raise SystemExit(f"hash mismatch: {path} ({digest})")

gateway_conf = configparser.RawConfigParser()
gateway_conf.read(root / "config/songsterx.gateway-minimal.conf")
gateway = gateway_conf["Gateway"]
general = gateway_conf["General"]
assert gateway["enabled"].lower() == "true"
assert gateway["dhcp"].lower() == "false"
assert gateway["ipv6"].lower() == "false"
assert gateway["client-policy"].lower() == "all"
assert gateway["interface"]
assert gateway["gateway-ip"]
assert gateway["cidr"]
lan_selector = general["gateway-guest-lan-selector"].strip().strip('"')
host_selector = general["gateway-guest-host-selector"].strip().strip('"')
assert lan_selector.startswith(("if:", "mac:"))
assert host_selector.startswith(("if:", "mac:"))
assert general["gateway-upstream-gateway"]
client_value = gateway["clients"].strip()
if len(client_value) >= 2 and client_value[0] == client_value[-1] == '"':
    client_value = client_value[1:-1]
clients = client_value.encode().decode("unicode_escape").splitlines()
assert not clients

logic_manifest = json.loads((root / "config/surge-logic-rules.redacted.json").read_text())
assert logic_manifest["execute_remote_code"] is False
assert logic_manifest["activation"] == "disabled_until_rule_compiler_and_context_runtime"
logic_ids = {item["id"] for item in logic_manifest["rules"]}
for required_id in (
    "source-ad-filter",
    "source-qbittorrent-process",
    "source-emby-mitm-direct",
    "source-geoip-cn-direct",
    "module-ruleset-tieba-ad",
    "module-url-regex",
    "module-ip-cidr-no-resolve",
):
    assert required_id in logic_ids

gateway_config = json.loads((root / "config/sing-box.gateway-minimal.json").read_text())
assert not any(item.get("type") == "dhcp" for item in gateway_config.get("inbounds", []))
guest_tun = gateway_config["inbounds"][0]
assert guest_tun["type"] == "tun"
assert guest_tun["interface_name"] == "tun0"
assert guest_tun["auto_route"] is True
assert guest_tun["strict_route"] is True
assert guest_tun["route_address"] == ["0.0.0.0/1", "128.0.0.0/1"]
assert guest_tun["iproute2_table_index"] == 2022
assert guest_tun["iproute2_rule_index"] == 9000
assert gateway_config["dns"]["servers"][0]["type"] == "fakeip"
assert gateway_config["dns"]["servers"][0]["inet4_range"] == "198.18.0.0/15"
assert gateway_config["dns"]["servers"][0]["inet6_range"] == "fc00::/18"
assert gateway_config["route"]["default_domain_resolver"] == "system-dns"
assert "223.86.225.0/24" in gateway_config["inbounds"][0]["route_exclude_address"]

redacted = (root / "config/surge-default-adapted.redacted.conf").read_text()
for forbidden in ("MII", "-----BEGIN", "eyJ", "p12", "<REDACTED_POLICY_URL>"):
    if forbidden == "<REDACTED_POLICY_URL>":
        continue
    if forbidden in redacted:
        raise SystemExit(f"possible secret material in redacted profile: {forbidden}")

for runtime_file in (
    root / "config/sing-box.gateway-minimal.json",
    root / "config/songsterx.gateway-minimal.conf",
    root / "scripts/run_gateway_minimal.sh",
):
    if re.search(r"\]\(https?://", runtime_file.read_text(errors="replace")):
        raise SystemExit(f"Markdown-form URL found in runtime file: {runtime_file}")

print(f"module assets verified: {len(manifest['assets'])}; guest inputs locked")
PY

python3 -m py_compile scripts/mitm_addon.py scripts/mitm_minimal_addon.py scripts/surge_js_runtime.py
git diff --check
echo "gateway minimal validation: PASS"
