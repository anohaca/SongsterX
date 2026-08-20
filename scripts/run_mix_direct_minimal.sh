#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$ROOT_DIR/config/sing-box.mix-direct-minimal.json"

usage() {
  cat <<'EOF'
Usage:
  scripts/run_mix_direct_minimal.sh --check
  scripts/run_mix_direct_minimal.sh --run

--check  Validate the mixed/direct/system-DNS invariants.
--run    Start the local mixed proxy on 127.0.0.1:2080.

The configuration deliberately has no TUN inbound, no auto_route, no DNS
hijack, no proxy outbound, and no MITM. Applications must explicitly use the
HTTP or SOCKS5 proxy at 127.0.0.1:2080.
EOF
}

case "${1:-}" in
  --check)
    command -v sing-box >/dev/null || { echo "sing-box is required" >&2; exit 1; }
    command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
    sing-box check -c "$CONFIG"
    sing-box format -c "$CONFIG" >/dev/null
    jq -e '
      ([.inbounds[] | select(.type == "mixed")] | length) == 1 and
      ([.inbounds[] | select(.type == "tun")] | length) == 0 and
      ([.. | objects | select(has("auto_route"))] | length) == 0 and
      ([.outbounds[] | select(.type == "direct")] | length) == 1 and
      ([.outbounds[] | select(.type != "direct")] | length) == 0 and
      .dns.final == "system-dns" and
      ([.dns.servers[] | select(.type == "local" and .tag == "system-dns")] | length) == 1 and
      ([.route.rules[]? | select(.action == "hijack-dns")] | length) == 0 and
      .route.final == "direct"
    ' "$CONFIG" >/dev/null
    echo "mix/direct/system-DNS validation: PASS"
    ;;
  --run)
    command -v sing-box >/dev/null || { echo "sing-box is required" >&2; exit 1; }
    exec sing-box run -c "$CONFIG"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
