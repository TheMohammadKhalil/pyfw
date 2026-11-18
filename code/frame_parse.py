from __future__ import annotations

import struct
from typing import NamedTuple

TPID_8021Q = 0x8100
TPID_8021AD = 0x88A8
ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD
PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}


class IPv4Info(NamedTuple):
    src: int
    dst: int
    proto: int
    src_port: int
    dst_port: int


class FrameInfo(NamedTuple):
    dst_mac: bytes
    src_mac: bytes
    ethertype: int
    vlan_id: int | None
    l3_offset: int
    ipv4: IPv4Info | None


def mac_to_bytes(mac: str) -> bytes:
    raw = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(raw) != 6:
        raise ValueError(f"not a MAC address: {mac!r}")
    return raw


def mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def ip_to_int(ip: str) -> int:
    parts = [int(p) for p in ip.split(".")]
    if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
        raise ValueError(f"not an IPv4 address: {ip!r}")
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def int_to_ip(value: int) -> str:
    return ".".join(str((value >> s) & 0xFF) for s in (24, 16, 8, 0))


def parse_ipv4(frame: bytes, off: int) -> IPv4Info | None:
    if len(frame) < off + 20 or frame[off] >> 4 != 4:
        return None
    ihl = (frame[off] & 0x0F) * 4
    proto = frame[off + 9]
    src, dst = struct.unpack_from("!II", frame, off + 12)
    frag_offset = struct.unpack_from("!H", frame, off + 6)[0] & 0x1FFF
    l4 = off + ihl
    if proto in (6, 17) and frag_offset == 0 and len(frame) >= l4 + 4:
        sport, dport = struct.unpack_from("!HH", frame, l4)
        return IPv4Info(src, dst, proto, sport, dport)
    return IPv4Info(src, dst, proto, -1, -1)


def parse_frame(frame: bytes) -> FrameInfo:
    if len(frame) < 14:
        raise ValueError("frame shorter than 14 bytes")
    et = struct.unpack_from("!H", frame, 12)[0]
    vid: int | None = None
    l3 = 14
    if et in (TPID_8021Q, TPID_8021AD):
        if len(frame) < 18:
            raise ValueError("VLAN frame shorter than 18 bytes")
        tci, et = struct.unpack_from("!HH", frame, 14)
        vid = tci & 0x0FFF
        l3 = 18
    ip = parse_ipv4(frame, l3) if et == ETH_IPV4 else None
    return FrameInfo(frame[0:6], frame[6:12], et, vid, l3, ip)


def ip_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 128) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, ttl, proto, 0,
                      ip_to_int(src).to_bytes(4, "big"), ip_to_int(dst).to_bytes(4, "big"))
    return hdr[:10] + ip_checksum(hdr).to_bytes(2, "big") + hdr[12:] + payload


def build_icmp_echo(ident: int = 1, seq: int = 1, data: bytes = b"pyfw ping") -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + data
    return body[:2] + ip_checksum(body).to_bytes(2, "big") + body[4:]


def build_tcp_syn(sport: int, dport: int) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x02, 64240, 0, 0)


def build_frame(dst: str, src: str, ethertype: int, payload: bytes, vlan_id: int | None = None) -> bytes:
    tag = b"" if vlan_id is None else struct.pack("!HH", TPID_8021Q, vlan_id & 0x0FFF)
    frame = mac_to_bytes(dst) + mac_to_bytes(src) + tag + struct.pack("!H", ethertype) + payload
    return frame + bytes(max(0, 60 - len(frame)))


def describe(frame: bytes) -> str:
    f = parse_frame(frame)
    text = f"{mac_to_str(f.src_mac)} > {mac_to_str(f.dst_mac)}"
    if f.vlan_id is not None:
        text += f" vlan {f.vlan_id}"
    text += f" ethertype 0x{f.ethertype:04x} length {len(frame)}"
    if f.ipv4:
        ip = f.ipv4
        text += f": {int_to_ip(ip.src)} > {int_to_ip(ip.dst)} {PROTO_NAMES.get(ip.proto, ip.proto)}"
        if ip.dst_port >= 0:
            text += f" {ip.src_port} > {ip.dst_port}"
    return text


if __name__ == "__main__":

    LAPTOP_A, LAPTOP_B = "40:c2:ba:50:b1:b7", "e4:54:e8:2d:8f:ca"
    ping = build_frame(LAPTOP_B, LAPTOP_A, ETH_IPV4,
                       build_ipv4("192.168.10.135", "192.168.10.136", 1, build_icmp_echo()))
    print(describe(ping))
    print(parse_frame(ping))
    syn = build_frame(LAPTOP_B, LAPTOP_A, ETH_IPV4,
                      build_ipv4("192.168.10.135", "192.168.10.136", 6, build_tcp_syn(50000, 5201)), vlan_id=10)
    print(describe(syn))
