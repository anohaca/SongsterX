#!/bin/sh
set -eu

real=0
role=

usage() {
    cat <<'EOF'
usage:
  accept-real-lan.sh [--real-lan] --role host|guest|client

This script never changes routes or the client's default gateway. Configure
the second LAN test device manually before using --real-lan.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --real-lan) real=1; shift ;;
        --role)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            role=$2
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

case "$role" in host|guest|client) ;; *) usage >&2; exit 2 ;; esac

if [ "$real" -ne 1 ]; then
    printf '%s\n' 'DRY RUN ONLY.' "Requested role: $role" \
        'No network state was changed.' \
        "Run explicitly with: $0 --real-lan --role $role"
    exit 0
fi

case "$role" in
    host)
        ps ax | grep '[v]mnet-helper' >/dev/null || { printf '%s\n' 'vmnet-helper not observed' >&2; exit 1; }
        ps ax | grep '[v]fkit' >/dev/null || { printf '%s\n' 'vfkit not observed' >&2; exit 1; }
        printf '%s\n' 'Host process presence observed; this does not prove forwarding.'
        ;;
    guest)
        /usr/lib/songsterx/songsterx-gateway-net.sh status
        ip -4 addr
        ip -4 route
        test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1
        test -f /run/songsterx/network.ready
        test -f /var/lib/songsterx/ready
        if command -v nft >/dev/null 2>&1; then
            nft list table inet songsterx_gateway
        elif command -v iptables >/dev/null 2>&1; then
            iptables -S SONGSTERX_GW_FWD
            iptables -t nat -S SONGSTERX_GW_NAT
        else
            printf '%s\n' 'No nft/iptables found' >&2
            exit 1
        fi
        printf '%s\n' 'Guest local state passed; a second LAN client path is still unproven.'
        ;;
    client)
        : "${GATEWAY_IP:?set GATEWAY_IP to the SongsterX guest LAN address}"
        ping -c 3 "$GATEWAY_IP"
        if [ -n "${TEST_TCP_HOST:-}" ] && [ -n "${TEST_TCP_PORT:-}" ] && command -v nc >/dev/null 2>&1; then
            nc -vz "$TEST_TCP_HOST" "$TEST_TCP_PORT"
        fi
        if [ -n "${TEST_DNS_NAME:-}" ] && [ -n "${TEST_DNS_SERVER:-}" ] && command -v nslookup >/dev/null 2>&1; then
            nslookup "$TEST_DNS_NAME" "$TEST_DNS_SERVER"
        fi
        printf '%s\n' 'Record packet captures/counters separately before claiming TCP/UDP/DNS acceptance.'
        printf '%s\n' 'MITM is not tested or implied by this script.'
        ;;
esac
