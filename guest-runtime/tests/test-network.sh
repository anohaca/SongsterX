#!/bin/sh
set -eu

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/songsterx-guest-test.XXXXXX")
trap 'rm -rf "$ROOT"' 0 1 2 3 15

SCRIPT=$(cd "$(dirname "$0")/.." && pwd)/songsterx-gateway-net.sh
SYS="$ROOT/sys/class/net"
PROC="$ROOT/proc/sys/net"
RUN="$ROOT/run"
BIN="$ROOT/bin"
LOG="$ROOT/commands.log"
CMDLINE="$ROOT/cmdline"
ETC="$ROOT/etc"
RESOLV_CONF="$ETC/resolv.conf"

mkdir -p \
    "$SYS/lan0/device" "$SYS/mgmt0/device" \
    "$PROC/ipv4/conf/all" "$PROC/ipv4/conf/lan0" "$PROC/ipv4/conf/mgmt0" \
    "$PROC/ipv6/conf/all" "$PROC/ipv6/conf/default" \
    "$PROC/ipv6/conf/lan0" "$PROC/ipv6/conf/mgmt0" "$BIN" "$ETC"

printf '%s\n' 'nameserver 192.168.1.1' > "$RESOLV_CONF"

printf '02:00:00:00:00:11\n' > "$SYS/lan0/address"
printf '02:00:00:00:00:22\n' > "$SYS/mgmt0/address"
printf 'virtio:d00000001v00001AF4\n' > "$SYS/lan0/device/modalias"
printf 'virtio:d00000001v00001AF4\n' > "$SYS/mgmt0/device/modalias"

for path in \
    "$PROC/ipv4/ip_forward" "$PROC/ipv4/conf/all/rp_filter" \
    "$PROC/ipv4/conf/lan0/rp_filter" "$PROC/ipv4/conf/mgmt0/rp_filter" \
    "$PROC/ipv4/conf/all/send_redirects" "$PROC/ipv4/conf/lan0/send_redirects" \
    "$PROC/ipv4/conf/mgmt0/send_redirects" "$PROC/ipv4/conf/all/accept_redirects" \
    "$PROC/ipv4/conf/lan0/accept_redirects" "$PROC/ipv4/conf/mgmt0/accept_redirects" \
    "$PROC/ipv4/conf/lan0/arp_ignore" "$PROC/ipv4/conf/lan0/arp_announce" \
    "$PROC/ipv4/conf/mgmt0/arp_ignore" "$PROC/ipv4/conf/mgmt0/arp_announce" \
    "$PROC/ipv6/conf/all/accept_ra" "$PROC/ipv6/conf/default/accept_ra" \
    "$PROC/ipv6/conf/lan0/accept_ra" "$PROC/ipv6/conf/mgmt0/accept_ra" \
    "$PROC/ipv6/conf/all/disable_ipv6" "$PROC/ipv6/conf/default/disable_ipv6" \
    "$PROC/ipv6/conf/lan0/disable_ipv6" "$PROC/ipv6/conf/mgmt0/disable_ipv6"; do
    mkdir -p "$(dirname "$path")"
    printf '0\n' > "$path"
done

cat > "$BIN/ip" <<EOF
#!/bin/sh
printf 'ip %s\n' "\$*" >> "$LOG"
if [ "\$1 \$2 \$3" = "route show default" ]; then exit 0; fi
exit 0
EOF
cat > "$BIN/nft" <<EOF
#!/bin/sh
printf 'nft %s\n' "\$*" >> "$LOG"
if [ "\${1:-}" = list ]; then exit 1; fi
if [ "\${1:-}" = -f ]; then cat >> "$LOG"; fi
exit 0
EOF
chmod +x "$BIN/ip" "$BIN/nft"

cat > "$CMDLINE" <<'EOF'
console=hvc0 songsterx.lan_ip=192.168.1.2 songsterx.lan_cidr=192.168.1.0/24 songsterx.host_ip=192.168.250.2 songsterx.host_cidr=192.168.250.0/24 songsterx.upstream_gateway=192.168.1.1 songsterx.dns_server=223.5.5.5 songsterx.agent_port=38291 songsterx.lan_mac=02:00:00:00:00:11 songsterx.host_mac=02:00:00:00:00:22
EOF

run_net() {
    SONGSTERX_CMDLINE_FILE="$CMDLINE" \
    SONGSTERX_SYS_CLASS_NET="$SYS" \
    SONGSTERX_PROC_SYS_NET="$PROC" \
    SONGSTERX_RUN_DIR="$RUN" \
    SONGSTERX_IP_BIN="$BIN/ip" \
    SONGSTERX_NFT_BIN="$BIN/nft" \
    SONGSTERX_FORCE_FIREWALL=nft \
    SONGSTERX_RESOLV_CONF="$RESOLV_CONF" \
    "$SCRIPT" "$@"
}

sh -n "$SCRIPT"
! grep -q 'udhcpc' "$SCRIPT"
run_net setup
[ -f "$RUN/network.ready" ]
[ "$(grep -c '^ip link set dev lo up$' "$LOG")" = 1 ]
[ "$(sed -n 's/^LAN_IF=//p' "$RUN/network.state")" = lan0 ]
[ "$(sed -n 's/^HOST_IF=//p' "$RUN/network.state")" = mgmt0 ]
[ "$(sed -n 's/^DNS_SERVER=//p' "$RUN/network.state")" = 223.5.5.5 ]
[ "$(sed -n 's/^nameserver //p' "$RESOLV_CONF")" = 223.5.5.5 ]
[ "$(grep -c '^options timeout:2 attempts:2$' "$RESOLV_CONF")" = 1 ]
[ "$(cat "$PROC/ipv4/ip_forward")" = 1 ]
grep -q 'type filter hook forward priority 100; policy drop;' "$LOG"
! grep -q 'type filter hook forward priority -50;' "$LOG"

run_net stop-forwarding
[ ! -e "$RUN/network.ready" ]
[ -f "$RUN/network.state" ]
[ "$(cat "$PROC/ipv4/ip_forward")" = 0 ]
run_net stop-forwarding
run_net stop
[ "$(cat "$RESOLV_CONF")" = 'nameserver 192.168.1.1' ]
[ ! -e "$RUN/network.ready" ]
[ ! -e "$RUN/network.state" ]
run_net stop

sed 's/ songsterx.host_mac=[^ ]*//' "$CMDLINE" > "$CMDLINE.missing"
mv "$CMDLINE.missing" "$CMDLINE"
if run_net setup >/dev/null 2>&1; then
    printf '%s\n' 'expected missing host selector to fail' >&2
    exit 1
fi
[ ! -e "$RUN/network.ready" ]

printf '%s\n' 'guest-runtime network simulation: ok'
