#!/bin/sh
set -eu
umask 077

# This controller is intended for a small BusyBox initramfs. It owns only the
# addresses, route, firewall table/chains, and readiness files recorded below.
CMDLINE_FILE=${SONGSTERX_CMDLINE_FILE:-/proc/cmdline}
SYS_CLASS_NET=${SONGSTERX_SYS_CLASS_NET:-/sys/class/net}
PROC_SYS_NET=${SONGSTERX_PROC_SYS_NET:-/proc/sys/net}
RUN_DIR=${SONGSTERX_RUN_DIR:-/run/songsterx}
STATE_FILE="$RUN_DIR/network.state"
READY_FILE="$RUN_DIR/network.ready"
RESOLV_CONF=${SONGSTERX_RESOLV_CONF:-/etc/resolv.conf}
RESOLV_BACKUP="$RUN_DIR/resolv.conf.previous"

IP_BIN=${SONGSTERX_IP_BIN:-ip}
NFT_BIN=${SONGSTERX_NFT_BIN:-nft}
IPTABLES_BIN=${SONGSTERX_IPTABLES_BIN:-iptables}
FORCE_FIREWALL=${SONGSTERX_FORCE_FIREWALL:-}
NFT_TABLE=songsterx_gateway
IPT_FORWARD_CHAIN=SONGSTERX_GW_FWD
IPT_NAT_CHAIN=SONGSTERX_GW_NAT

log() { printf '%s\n' "songsterx-gateway-net: $*" >&2; }
die() { log "$*"; exit 1; }
have_command() { command -v "$1" >/dev/null 2>&1; }

cmdline_value() {
    key=$1
    found=
    count=0
    [ -r "$CMDLINE_FILE" ] || die "kernel cmdline 不可读：$CMDLINE_FILE"
    set -f
    for token in $(cat "$CMDLINE_FILE"); do
        case "$token" in
            "$key"=*) count=$((count + 1)); found=${token#*=} ;;
        esac
    done
    set +f
    [ "$count" -le 1 ] || die "kernel cmdline 参数重复：$key"
    printf '%s\n' "$found"
}

required_cmdline_value() {
    value=$(cmdline_value "$1")
    [ -n "$value" ] || die "kernel cmdline 缺少 $1"
    printf '%s\n' "$value"
}

valid_ipv4() {
    value=$1
    old_ifs=$IFS
    IFS=.
    set -- $value
    IFS=$old_ifs
    [ "$#" -eq 4 ] || return 1
    for octet in "$@"; do
        case "$octet" in ''|*[!0-9]*) return 1 ;; esac
        [ "$octet" -le 255 ] 2>/dev/null || return 1
    done
}

validate_cidr() {
    value=$1
    case "$value" in */*) ;; *) return 1 ;; esac
    address=${value%/*}
    prefix=${value##*/}
    valid_ipv4 "$address" || return 1
    case "$prefix" in ''|*[!0-9]*) return 1 ;; esac
    [ "$prefix" -ge 1 ] 2>/dev/null && [ "$prefix" -le 30 ] 2>/dev/null
}

cidr_prefix() { printf '%s\n' "${1##*/}"; }

validate_ifname() {
    value=$1
    [ -n "$value" ] && [ "${#value}" -le 15 ] || return 1
    case "$value" in *[!A-Za-z0-9_.:-]*) return 1 ;; esac
    [ "$value" != "lo" ]
}

normalize_mac() { printf '%s' "$1" | tr 'A-F' 'a-f'; }

validate_mac() {
    value=$(normalize_mac "$1")
    old_ifs=$IFS
    IFS=:
    set -- $value
    IFS=$old_ifs
    [ "$#" -eq 6 ] || return 1
    for part in "$@"; do
        [ "${#part}" -eq 2 ] || return 1
        case "$part" in *[!0-9a-f]*) return 1 ;; esac
    done
}

is_virtio_interface() {
    iface=$1
    modalias="$SYS_CLASS_NET/$iface/device/modalias"
    uevent="$SYS_CLASS_NET/$iface/device/uevent"
    if [ -r "$modalias" ]; then
        case "$(cat "$modalias")" in virtio:*) return 0 ;; esac
    fi
    if [ -r "$uevent" ] && grep -q '^DRIVER=virtio_net$' "$uevent" 2>/dev/null; then
        return 0
    fi
    return 1
}

resolve_interface() {
    role=$1
    requested_if=$2
    requested_mac=$3
    [ -n "$requested_if" ] || [ -n "$requested_mac" ] ||
        die "$role 接口绑定缺失：必须提供 *_if 或 *_mac"
    by_name=
    by_mac=
    if [ -n "$requested_if" ]; then
        validate_ifname "$requested_if" || die "$role 接口名无效：$requested_if"
        [ -d "$SYS_CLASS_NET/$requested_if" ] || die "$role 接口不存在：$requested_if"
        by_name=$requested_if
    fi
    if [ -n "$requested_mac" ]; then
        validate_mac "$requested_mac" || die "$role MAC 无效：$requested_mac"
        wanted=$(normalize_mac "$requested_mac")
        matches=0
        for path in "$SYS_CLASS_NET"/*; do
            [ -d "$path" ] || continue
            iface=${path##*/}
            [ "$iface" != "lo" ] || continue
            [ -r "$path/address" ] || continue
            actual=$(normalize_mac "$(cat "$path/address")")
            if [ "$actual" = "$wanted" ]; then
                matches=$((matches + 1))
                by_mac=$iface
            fi
        done
        [ "$matches" -eq 1 ] || die "$role MAC 必须唯一匹配一张网卡：$requested_mac"
    fi
    if [ -n "$by_name" ] && [ -n "$by_mac" ] && [ "$by_name" != "$by_mac" ]; then
        die "$role 接口名与 MAC 指向不同网卡"
    fi
    resolved=${by_name:-$by_mac}
    is_virtio_interface "$resolved" || die "$role 接口不是可确认的 virtio-net：$resolved"
    printf '%s\n' "$resolved"
}

write_required_sysctl() {
    path=$1
    value=$2
    [ -w "$path" ] || die "必要 sysctl 不可写：$path"
    printf '%s\n' "$value" > "$path"
}

write_optional_sysctl() {
    path=$1
    value=$2
    if [ -e "$path" ]; then
        [ -w "$path" ] || die "sysctl 不可写：$path"
        printf '%s\n' "$value" > "$path"
    fi
}

state_value() {
    key=$1
    [ -r "$STATE_FILE" ] || return 1
    found=
    count=0
    while IFS='=' read -r name value; do
        if [ "$name" = "$key" ]; then found=$value; count=$((count + 1)); fi
    done < "$STATE_FILE"
    [ "$count" -eq 1 ] || return 1
    printf '%s\n' "$found"
}

load_state() {
    LAN_IF=$(state_value LAN_IF) || return 1
    HOST_IF=$(state_value HOST_IF) || return 1
    LAN_ADDR=$(state_value LAN_ADDR) || return 1
    HOST_ADDR=$(state_value HOST_ADDR) || return 1
    LAN_CIDR=$(state_value LAN_CIDR) || return 1
    UPSTREAM_GATEWAY=$(state_value UPSTREAM_GATEWAY) || return 1
    AGENT_PORT=$(state_value AGENT_PORT) || return 1
    FIREWALL_BACKEND=$(state_value FIREWALL_BACKEND) || return 1
    ADDR_LAN=$(state_value ADDR_LAN) || return 1
    ADDR_HOST=$(state_value ADDR_HOST) || return 1
    ROUTE_ADDED=$(state_value ROUTE_ADDED) || return 1
    FIREWALL_ADDED=$(state_value FIREWALL_ADDED) || return 1
    IP_FORWARD_OLD=$(state_value IP_FORWARD_OLD) || return 1
    DNS_SERVER=$(state_value DNS_SERVER) || return 1
    RESOLV_BACKED_UP=$(state_value RESOLV_BACKED_UP) || return 1
    validate_ifname "$LAN_IF" && validate_ifname "$HOST_IF" || return 1
    validate_cidr "$LAN_ADDR" && validate_cidr "$HOST_ADDR" && validate_cidr "$LAN_CIDR" || return 1
    valid_ipv4 "$UPSTREAM_GATEWAY" || return 1
    case "$DNS_SERVER" in
        ''|*[!A-Za-z0-9:._-]*) return 1 ;;
    esac
    case "$AGENT_PORT" in ''|*[!0-9]*) return 1 ;; esac
    [ "$AGENT_PORT" -ge 1 ] 2>/dev/null && [ "$AGENT_PORT" -le 65535 ] 2>/dev/null || return 1
    case "$FIREWALL_BACKEND" in nft|iptables) ;; *) return 1 ;; esac
    case "$ADDR_LAN$ADDR_HOST$ROUTE_ADDED$FIREWALL_ADDED" in *[!01]*) return 1 ;; esac
    case "$IP_FORWARD_OLD" in 0|1) ;; *) return 1 ;; esac
    case "$RESOLV_BACKED_UP" in 0|1) ;; *) return 1 ;; esac
}

write_state() {
    tmp="$STATE_FILE.tmp.$$"
    mkdir -p "$RUN_DIR"
    {
        printf 'VERSION=2\n'
        printf 'LAN_IF=%s\n' "$LAN_IF"
        printf 'HOST_IF=%s\n' "$HOST_IF"
        printf 'LAN_ADDR=%s\n' "$LAN_ADDR"
        printf 'HOST_ADDR=%s\n' "$HOST_ADDR"
        printf 'LAN_CIDR=%s\n' "$LAN_CIDR"
        printf 'UPSTREAM_GATEWAY=%s\n' "$UPSTREAM_GATEWAY"
        printf 'AGENT_PORT=%s\n' "$AGENT_PORT"
        printf 'FIREWALL_BACKEND=%s\n' "$FIREWALL_BACKEND"
        printf 'ADDR_LAN=%s\n' "$ADDR_LAN"
        printf 'ADDR_HOST=%s\n' "$ADDR_HOST"
        printf 'ROUTE_ADDED=%s\n' "$ROUTE_ADDED"
        printf 'FIREWALL_ADDED=%s\n' "$FIREWALL_ADDED"
        printf 'IP_FORWARD_OLD=%s\n' "$IP_FORWARD_OLD"
        printf 'DNS_SERVER=%s\n' "$DNS_SERVER"
        printf 'RESOLV_BACKED_UP=%s\n' "$RESOLV_BACKED_UP"
    } > "$tmp"
    mv "$tmp" "$STATE_FILE"
}

write_resolv_conf() {
    tmp="$RESOLV_CONF.tmp.$$"
    {
        printf '# Managed by SongsterX Gateway\n'
        printf 'nameserver %s\n' "$DNS_SERVER"
        printf 'options timeout:2 attempts:2\n'
    } > "$tmp"
    mv "$tmp" "$RESOLV_CONF"
}

restore_resolv_conf() {
    if [ "$RESOLV_BACKED_UP" = 1 ]; then
        rm -f "$RESOLV_CONF"
        mv "$RESOLV_BACKUP" "$RESOLV_CONF"
    else
        rm -f "$RESOLV_CONF"
    fi
}

choose_firewall_backend() {
    case "$FORCE_FIREWALL" in
        nft) have_command "$NFT_BIN" || die "指定 nft，但找不到 $NFT_BIN"; printf '%s\n' nft ;;
        iptables) have_command "$IPTABLES_BIN" || die "指定 iptables，但找不到 $IPTABLES_BIN"; printf '%s\n' iptables ;;
        '')
            if have_command "$NFT_BIN"; then printf '%s\n' nft
            elif have_command "$IPTABLES_BIN"; then printf '%s\n' iptables
            else die "guest 缺少 nft 和 iptables，拒绝开启 forwarding"; fi ;;
        *) die "SONGSTERX_FORCE_FIREWALL 只能是 nft 或 iptables" ;;
    esac
}

setup_nft() {
    "$NFT_BIN" list table inet "$NFT_TABLE" >/dev/null 2>&1 &&
        die "nft table inet $NFT_TABLE 已存在，拒绝覆盖非本次状态"
    "$NFT_BIN" -f - <<EOF
table inet $NFT_TABLE {
    chain forward {
        # Run after sing-box auto_redirect/policy-route processing. Packets
        # redirected to tun0 are accepted here; unredirected LAN forwarding
        # remains fail-closed below.
        type filter hook forward priority 100; policy drop;
        ct state established,related accept
        iifname "$LAN_IF" oifname "tun0" accept
        iifname "tun0" oifname "$LAN_IF" accept
        iifname "$LAN_IF" drop
        oifname "$LAN_IF" drop
        iifname "$HOST_IF" drop
        oifname "$HOST_IF" drop
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr $LAN_CIDR oifname "$LAN_IF" masquerade
    }
}
EOF
}

setup_iptables() {
    "$IPTABLES_BIN" -S "$IPT_FORWARD_CHAIN" >/dev/null 2>&1 && die "iptables chain $IPT_FORWARD_CHAIN 已存在"
    "$IPTABLES_BIN" -t nat -S "$IPT_NAT_CHAIN" >/dev/null 2>&1 && die "iptables chain $IPT_NAT_CHAIN 已存在"
    "$IPTABLES_BIN" -N "$IPT_FORWARD_CHAIN"
    "$IPTABLES_BIN" -A "$IPT_FORWARD_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    "$IPTABLES_BIN" -A "$IPT_FORWARD_CHAIN" -i "$LAN_IF" -o tun0 -j ACCEPT
    "$IPTABLES_BIN" -A "$IPT_FORWARD_CHAIN" -i tun0 -o "$LAN_IF" -j ACCEPT
    "$IPTABLES_BIN" -A "$IPT_FORWARD_CHAIN" -j DROP
    "$IPTABLES_BIN" -I FORWARD 1 -j "$IPT_FORWARD_CHAIN"
    "$IPTABLES_BIN" -t nat -N "$IPT_NAT_CHAIN"
    "$IPTABLES_BIN" -t nat -A "$IPT_NAT_CHAIN" -s "$LAN_CIDR" -o "$LAN_IF" -j MASQUERADE
    "$IPTABLES_BIN" -t nat -I POSTROUTING 1 -j "$IPT_NAT_CHAIN"
}

cleanup_firewall() {
    case "$FIREWALL_BACKEND" in
        nft) "$NFT_BIN" delete table inet "$NFT_TABLE" >/dev/null 2>&1 || true ;;
        iptables)
            "$IPTABLES_BIN" -C FORWARD -j "$IPT_FORWARD_CHAIN" >/dev/null 2>&1 &&
                "$IPTABLES_BIN" -D FORWARD -j "$IPT_FORWARD_CHAIN" >/dev/null 2>&1 || true
            "$IPTABLES_BIN" -F "$IPT_FORWARD_CHAIN" >/dev/null 2>&1 || true
            "$IPTABLES_BIN" -X "$IPT_FORWARD_CHAIN" >/dev/null 2>&1 || true
            "$IPTABLES_BIN" -t nat -C POSTROUTING -j "$IPT_NAT_CHAIN" >/dev/null 2>&1 &&
                "$IPTABLES_BIN" -t nat -D POSTROUTING -j "$IPT_NAT_CHAIN" >/dev/null 2>&1 || true
            "$IPTABLES_BIN" -t nat -F "$IPT_NAT_CHAIN" >/dev/null 2>&1 || true
            "$IPTABLES_BIN" -t nat -X "$IPT_NAT_CHAIN" >/dev/null 2>&1 || true
            ;;
    esac
}

restore_forwarding() {
    if [ -w "$PROC_SYS_NET/ipv4/ip_forward" ]; then
        printf '%s\n' "$IP_FORWARD_OLD" > "$PROC_SYS_NET/ipv4/ip_forward"
    fi
}

stop_forwarding() {
    rm -f "$READY_FILE"
    [ -f "$STATE_FILE" ] || return 0
    load_state || die "network.state 无效，拒绝按不可信状态清理"
    [ "$FIREWALL_ADDED" = 1 ] && cleanup_firewall || true
    FIREWALL_ADDED=0
    restore_forwarding
    write_state
}

stop_all() {
    rm -f "$READY_FILE"
    [ -f "$STATE_FILE" ] || return 0
    load_state || die "network.state 无效，拒绝按不可信状态清理"
    [ "$FIREWALL_ADDED" = 1 ] && cleanup_firewall || true
    restore_forwarding
    [ "$ROUTE_ADDED" = 1 ] && "$IP_BIN" route del default via "$UPSTREAM_GATEWAY" dev "$LAN_IF" >/dev/null 2>&1 || true
    [ "$ADDR_LAN" = 1 ] && "$IP_BIN" addr del "$LAN_ADDR" dev "$LAN_IF" >/dev/null 2>&1 || true
    [ "$ADDR_HOST" = 1 ] && "$IP_BIN" addr del "$HOST_ADDR" dev "$HOST_IF" >/dev/null 2>&1 || true
    restore_resolv_conf
    rm -f "$STATE_FILE" "$STATE_FILE.tmp.$$" "$RESOLV_BACKUP"
}

setup() {
    rm -f "$READY_FILE"
    [ ! -e "$STATE_FILE" ] || die "已有 network.state；先显式执行 stop，拒绝覆盖可能仍在使用的状态"
    have_command "$IP_BIN" || die "找不到 ip 命令：$IP_BIN"
    LAN_IP=$(required_cmdline_value songsterx.lan_ip)
    LAN_CIDR=$(required_cmdline_value songsterx.lan_cidr)
    HOST_IP=$(required_cmdline_value songsterx.host_ip)
    HOST_CIDR=$(required_cmdline_value songsterx.host_cidr)
    UPSTREAM_GATEWAY=$(required_cmdline_value songsterx.upstream_gateway)
    DNS_SERVER=$(required_cmdline_value songsterx.dns_server)
    AGENT_PORT=$(required_cmdline_value songsterx.agent_port)
    LAN_IF_REQUEST=$(cmdline_value songsterx.lan_if)
    LAN_MAC_REQUEST=$(cmdline_value songsterx.lan_mac)
    HOST_IF_REQUEST=$(cmdline_value songsterx.host_if)
    HOST_MAC_REQUEST=$(cmdline_value songsterx.host_mac)
    valid_ipv4 "$LAN_IP" || die "songsterx.lan_ip 不是有效 IPv4"
    validate_cidr "$LAN_CIDR" || die "songsterx.lan_cidr 不是 IPv4 CIDR"
    valid_ipv4 "$HOST_IP" || die "songsterx.host_ip 不是有效 IPv4"
    validate_cidr "$HOST_CIDR" || die "songsterx.host_cidr 不是 IPv4 CIDR"
    valid_ipv4 "$UPSTREAM_GATEWAY" || die "songsterx.upstream_gateway 不是有效 IPv4"
    case "$DNS_SERVER" in
        ''|*[!A-Za-z0-9:._-]*) die "songsterx.dns_server 无效" ;;
    esac
    case "$AGENT_PORT" in ''|*[!0-9]*) die "songsterx.agent_port 无效" ;; esac
    [ "$AGENT_PORT" -ge 1 ] 2>/dev/null && [ "$AGENT_PORT" -le 65535 ] 2>/dev/null ||
        die "songsterx.agent_port 必须在 1-65535"
    LAN_IF=$(resolve_interface LAN "$LAN_IF_REQUEST" "$LAN_MAC_REQUEST")
    HOST_IF=$(resolve_interface host-only "$HOST_IF_REQUEST" "$HOST_MAC_REQUEST")
    [ "$LAN_IF" != "$HOST_IF" ] || die "LAN 与 host-only 不能绑定同一张 guest 网卡"
    LAN_ADDR="$LAN_IP/$(cidr_prefix "$LAN_CIDR")"
    HOST_ADDR="$HOST_IP/$(cidr_prefix "$HOST_CIDR")"
    FIREWALL_BACKEND=$(choose_firewall_backend)
    ADDR_LAN=0
    ADDR_HOST=0
    ROUTE_ADDED=0
    FIREWALL_ADDED=0
    IP_FORWARD_OLD=$(cat "$PROC_SYS_NET/ipv4/ip_forward" 2>/dev/null || printf '0')
    case "$IP_FORWARD_OLD" in 0|1) ;; *) die "ip_forward 状态无效" ;; esac
    mkdir -p "$RUN_DIR"
    RESOLV_BACKED_UP=0
    if [ -e "$RESOLV_CONF" ] || [ -L "$RESOLV_CONF" ]; then
        cp -p "$RESOLV_CONF" "$RESOLV_BACKUP"
        RESOLV_BACKED_UP=1
    fi
    write_state
    cleanup_on_error=1
    trap 'if [ "${cleanup_on_error:-1}" -ne 0 ]; then stop_all || true; fi' 0
    "$IP_BIN" link set dev lo up
    "$IP_BIN" link set dev "$LAN_IF" up
    "$IP_BIN" link set dev "$HOST_IF" up
    "$IP_BIN" addr add "$LAN_ADDR" dev "$LAN_IF"
    ADDR_LAN=1
    write_state
    "$IP_BIN" addr add "$HOST_ADDR" dev "$HOST_IF"
    ADDR_HOST=1
    write_state
    if "$IP_BIN" route show default | grep -q .; then die "guest 已存在默认路由，拒绝覆盖非本次路由"; fi
    "$IP_BIN" route add default via "$UPSTREAM_GATEWAY" dev "$LAN_IF"
    ROUTE_ADDED=1
    write_state
    write_resolv_conf
    write_required_sysctl "$PROC_SYS_NET/ipv4/ip_forward" 1
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/all/rp_filter" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/$LAN_IF/rp_filter" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/$HOST_IF/rp_filter" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/all/send_redirects" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/$LAN_IF/send_redirects" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/$HOST_IF/send_redirects" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/all/accept_redirects" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/$LAN_IF/accept_redirects" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/$HOST_IF/accept_redirects" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/$LAN_IF/arp_ignore" 1
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/$LAN_IF/arp_announce" 2
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/$HOST_IF/arp_ignore" 1
    write_optional_sysctl "$PROC_SYS_NET/ipv4/conf/$HOST_IF/arp_announce" 2
    write_optional_sysctl "$PROC_SYS_NET/ipv6/conf/all/accept_ra" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv6/conf/default/accept_ra" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv6/conf/$LAN_IF/accept_ra" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv6/conf/$HOST_IF/accept_ra" 0
    write_optional_sysctl "$PROC_SYS_NET/ipv6/conf/all/disable_ipv6" 1
    write_optional_sysctl "$PROC_SYS_NET/ipv6/conf/default/disable_ipv6" 1
    write_optional_sysctl "$PROC_SYS_NET/ipv6/conf/$LAN_IF/disable_ipv6" 1
    write_optional_sysctl "$PROC_SYS_NET/ipv6/conf/$HOST_IF/disable_ipv6" 1
    case "$FIREWALL_BACKEND" in
        nft) setup_nft ;;
        iptables) setup_iptables ;;
    esac
    FIREWALL_ADDED=1
    write_state
    : > "$READY_FILE"
    cleanup_on_error=0
    trap - 0
    log "network ready: LAN=$LAN_IF $LAN_ADDR, host-only=$HOST_IF $HOST_ADDR, upstream=$UPSTREAM_GATEWAY, firewall=$FIREWALL_BACKEND"
}

case "${1:-}" in
    setup) setup ;;
    stop-forwarding) stop_forwarding ;;
    stop) stop_all ;;
    status)
        if [ -f "$READY_FILE" ] && [ -f "$STATE_FILE" ] && load_state; then
            printf 'ready lan_if=%s host_if=%s upstream=%s\n' "$LAN_IF" "$HOST_IF" "$UPSTREAM_GATEWAY"
        else
            exit 1
        fi
        ;;
    *) printf 'usage: %s {setup|stop-forwarding|stop|status}\n' "$0" >&2; exit 2 ;;
esac
