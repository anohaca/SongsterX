#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

sing-box version
sing-box check -c config/sing-box.example.json
sing-box format -c config/sing-box.example.json >/dev/null
jq empty config/sing-box.example.json
python3 -m py_compile scripts/mitm_addon.py

fence_count="$(awk '/^```/{count++} END{print count + 0}' docs/surge-like-proxy.md)"
if (( fence_count % 2 != 0 )); then
  echo "Markdown code fences are unbalanced" >&2
  exit 1
fi

if rg -n '[[:blank:]]+$' README.md docs/surge-like-proxy.md \
  config/sing-box.example.json scripts/mitm_addon.py scripts/validate_static.sh; then
  echo "Trailing whitespace found" >&2
  exit 1
fi

if rg -n '127\.0\.0\.1:7890|127\.0\.0\.1:1080|"type"[[:space:]]*:[[:space:]]*"block"' \
  config/sing-box.example.json; then
  echo "Legacy loop or unsupported block placeholder found in sample config" >&2
  exit 1
fi

echo "static validation: PASS"
