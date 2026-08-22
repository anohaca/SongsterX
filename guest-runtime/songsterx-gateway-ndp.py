#!/usr/bin/env python3
"""Keep the bridged LAN guest IPv6 neighbor entry discoverable.

Some macOS vmnet bridged paths do not reliably deliver IPv6 multicast NDP to
the virtio guest.  The responder sends unsolicited advertisements and also
answers any solicitation that does reach the guest.  It only advertises the
single address passed by the init script and never changes routes or forwards
traffic.
"""

import argparse
import ipaddress
import signal
import socket
import struct
import time


ETH_P_IPV6 = 0x86DD
ICMPV6_NEIGHBOR_SOLICITATION = 135
ICMPV6_NEIGHBOR_ADVERTISEMENT = 136
ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY = 129
ALL_NODES = ipaddress.IPv6Address("ff02::1").packed
ALL_NODES_MAC = bytes.fromhex("333300000001")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_advertisement(
    address: ipaddress.IPv6Address,
    mac: bytes,
    destination: ipaddress.IPv6Address,
    destination_mac: bytes,
    solicited: bool,
) -> bytes:
    source = address.packed
    target = address.packed
    # SongsterX is the LAN router, so set the Router flag as well as Override.
    flags = 0xA0000000 | (0x40000000 if solicited else 0)
    icmp = struct.pack("!BBH", ICMPV6_NEIGHBOR_ADVERTISEMENT, 0, 0)
    icmp += struct.pack("!I", flags) + target
    icmp += bytes((2, 1)) + mac
    pseudo = source + destination.packed
    pseudo += struct.pack("!I", len(icmp)) + b"\0" * 3 + bytes((58,))
    icmp = icmp[:2] + struct.pack("!H", checksum(pseudo + icmp)) + icmp[4:]
    ipv6 = struct.pack("!IHBB", 6 << 28, len(icmp), 58, 255)
    ipv6 += source + destination.packed
    return destination_mac + mac + struct.pack("!H", ETH_P_IPV6) + ipv6 + icmp


def parse_mac(value: str) -> bytes:
    parts = value.split(":")
    if len(parts) != 6:
        raise ValueError("MAC 地址格式无效")
    try:
        mac = bytes(int(part, 16) for part in parts)
    except ValueError as error:
        raise ValueError("MAC 地址格式无效") from error
    if len(mac) != 6:
        raise ValueError("MAC 地址格式无效")
    return mac


def solicitation_target(frame: bytes, address: bytes):
    if len(frame) < 86 or frame[12:14] != struct.pack("!H", ETH_P_IPV6):
        return None
    ipv6 = frame[14:]
    if ipv6[6] != 58 or ipv6[40] != ICMPV6_NEIGHBOR_SOLICITATION:
        return None
    target = ipv6[48:64]
    if target != address:
        return None
    source = ipaddress.IPv6Address(ipv6[8:24])
    if source.is_unspecified:
        return None
    # An NS is sent to the solicited-node multicast MAC.  The NA response
    # must be unicast to the requester, whose source MAC is bytes 6..11.
    return source, frame[6:12]


def build_echo_reply(
    address: ipaddress.IPv6Address,
    mac: bytes,
    destination: ipaddress.IPv6Address,
    destination_mac: bytes,
    request: bytes,
) -> bytes:
    icmp = bytearray(request)
    icmp[0] = ICMPV6_ECHO_REPLY
    icmp[2:4] = b"\0\0"
    source = address.packed
    pseudo = source + destination.packed
    pseudo += struct.pack("!I", len(icmp)) + b"\0" * 3 + bytes((58,))
    icmp[2:4] = struct.pack("!H", checksum(pseudo + icmp))
    ipv6 = struct.pack("!IHBB", 6 << 28, len(icmp), 58, 64)
    ipv6 += source + destination.packed
    return destination_mac + mac + struct.pack("!H", ETH_P_IPV6) + ipv6 + icmp


def echo_request_target(frame: bytes, address: bytes):
    if len(frame) < 62 or frame[12:14] != struct.pack("!H", ETH_P_IPV6):
        return None
    ipv6 = frame[14:]
    payload_length = struct.unpack("!H", ipv6[4:6])[0]
    if len(ipv6) < 40 + payload_length or ipv6[6] != 58:
        return None
    if ipv6[24:40] != address or len(ipv6) < 48:
        return None
    icmp = ipv6[40 : 40 + payload_length]
    if len(icmp) < 8 or icmp[0] != ICMPV6_ECHO_REQUEST or icmp[1] != 0:
        return None
    source = ipaddress.IPv6Address(ipv6[8:24])
    if source.is_unspecified:
        return None
    return source, frame[6:12], icmp


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--mac", required=True)
    args = parser.parse_args()
    address = ipaddress.IPv6Address(args.address.split("/", 1)[0])
    mac = parse_mac(args.mac)
    tail = address.packed[-3:].hex()
    solicited_node = ipaddress.IPv6Address(f"ff02::1:ff{tail[:2]}:{tail[2:]}")
    solicited_node_mac = bytes.fromhex("3333ff" + tail)
    stopped = False

    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IPV6)) as raw:
        raw.bind((args.interface, 0))
        raw.settimeout(0.2)
        next_announcement = 0.0
        burst_remaining = 5
        while not stopped:
            now = time.monotonic()
            if now >= next_announcement:
                for destination, destination_mac in (
                    (ipaddress.IPv6Address(ALL_NODES), ALL_NODES_MAC),
                    (solicited_node, solicited_node_mac),
                ):
                    raw.send(
                        build_advertisement(
                            address, mac, destination, destination_mac, solicited=False
                        )
                    )
                if burst_remaining:
                    burst_remaining -= 1
                    next_announcement = now + 0.2
                else:
                    next_announcement = now + 2.0
            try:
                frame = raw.recv(2048)
            except socket.timeout:
                continue
            echo = echo_request_target(frame, address.packed)
            if echo is not None:
                source, source_mac, request = echo
                raw.send(build_echo_reply(address, mac, source, source_mac, request))
                continue
            request = solicitation_target(frame, address.packed)
            if request is None:
                continue
            source, source_mac = request
            raw.send(
                build_advertisement(
                    address, mac, source, source_mac, solicited=True
                )
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
