#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  scripts/run_gateway_minimal.sh --check

--check  Validate the checked-in Gateway contract and fail-closed invariants.

The standalone Gateway runner was removed. The application owns the vfkit,
vmnet-helper, guest-agent, sing-box, and MITM lifecycle as one supervisor.
EOF
}

case "${1:-}" in
  --check)
    exec "$ROOT_DIR/scripts/validate_gateway_minimal.sh"
    ;;
  --help|-h)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
