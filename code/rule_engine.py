from __future__ import annotations

import time
from dataclasses import dataclass, field

from fcs_check import fcs_ok
from frame_parse import ETH_IPV4, mac_to_bytes, parse_frame
from token_bucket import TokenBucket, parse_rate

PORTS = ("p25", "p1")
PROTOS = {"icmp": 1, "tcp": 6, "udp": 17}
FORWARD, DROP = "forward", "drop"


@dataclass(frozen=True)
class Net:
    addr: int
    mask: int
    text: str

    @classmethod
    def parse(cls, text: str) -> Net:
        ip, _, plen = text.partition("/")
        bits = int(plen) if plen else 32
        if not 0 <= bits <= 32:
            raise ValueError(f"bad prefix length in {text!r}")
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
            raise ValueError(f"not an IPv4 address: {text!r}")
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        value = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        return cls(value & mask, mask, text)

    def contains(self, ip: int) -> bool:
        return ip & self.mask == self.addr


@dataclass
class Rule:
    id: str
    action: str
    priority: int = 100
    in_port: str = "any"
    src_mac: str | None = None
    dst_mac: str | None = None
    ethertype: int | None = None
    min_len: int | None = None
    max_len: int | None = None
    src_ip: Net | None = None
    dst_ip: Net | None = None
    proto: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    rate: str | None = None
    bucket: TokenBucket | None = field(default=None, repr=False, compare=False)

    @property
    def uses_ip(self) -> bool:
        return any(v is not None for v in (self.src_ip, self.dst_ip, self.proto, self.src_port, self.dst_port))

    def matches(self, in_port: str, src: bytes, dst: bytes, ethertype: int, wire_len: int,
                ip: tuple[int, int, int, int, int] | None) -> bool:
        if self.in_port != "any" and self.in_port != in_port:
            return False
        if self.src_mac is not None and mac_to_bytes(self.src_mac) != src:
            return False
        if self.dst_mac is not None and mac_to_bytes(self.dst_mac) != dst:
            return False
        if self.ethertype is not None and self.ethertype != ethertype:
            return False
        if self.min_len is not None and wire_len < self.min_len:
            return False
        if self.max_len is not None and wire_len > self.max_len:
            return False
        if self.uses_ip:
            if ip is None:
                return False
            s, d, proto, sport, dport = ip
            if self.src_ip is not None and not self.src_ip.contains(s):
                return False
            if self.dst_ip is not None and not self.dst_ip.contains(d):
                return False
            if self.proto is not None and PROTOS[self.proto] != proto:
                return False
            if self.src_port is not None and self.src_port != sport:
                return False
            if self.dst_port is not None and self.dst_port != dport:
                return False
        return True


def parse_rule(text: str, auto_id: str = "r1") -> Rule:
    words = text.split()
    if not words or words[0] not in ("allow", "deny", "limit"):
        raise ValueError("a rule starts with allow, deny or limit")
    if len(words) % 2 == 0:
        raise ValueError(f"every field needs a value: {text!r}")
    r = Rule(id=auto_id, action=words[0])
    for key, value in zip(words[1::2], words[2::2]):
        if key == "id":
            r.id = value
        elif key == "priority":
            r.priority = int(value)
        elif key == "in-port":
            if value not in (*PORTS, "any"):
                raise ValueError("in-port is p25, p1 or any")
            r.in_port = value
        elif key in ("src-mac", "dst-mac"):
            mac_to_bytes(value)
            setattr(r, key.replace("-", "_"), value.lower().replace("-", ":"))
        elif key == "ethertype":
            r.ethertype = int(value, 16) if value.lower().startswith("0x") else int(value)
        elif key in ("min-len", "max-len"):
            setattr(r, key.replace("-", "_"), int(value))
        elif key in ("src-ip", "dst-ip"):
            setattr(r, key.replace("-", "_"), Net.parse(value))
        elif key == "proto":
            if value not in PROTOS:
                raise ValueError("proto is icmp, tcp or udp")
            r.proto = value
        elif key in ("src-port", "dst-port"):
            port = int(value)
            if not 1 <= port <= 65535:
                raise ValueError("ports are 1-65535")
            setattr(r, key.replace("-", "_"), port)
        elif key == "rate":
            r.rate = value
        else:
            raise ValueError(f"unknown field {key!r}")
    if (r.src_port or r.dst_port) and r.proto not in ("tcp", "udp"):
        raise ValueError("src-port / dst-port need proto tcp or udp")
    if (r.action == "limit") != (r.rate is not None):
        raise ValueError("rate goes with limit, and limit needs a rate")
    if r.rate is not None:
        r.bucket = TokenBucket(parse_rate(r.rate), now_ns=time.perf_counter_ns())
    return r


class RuleTable:
    def __init__(self, rules: list[Rule], default_policy: str = "allow") -> None:
        if default_policy not in ("allow", "deny"):
            raise ValueError("default policy is allow or deny")
        ids = [r.id for r in rules]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate rule ids")
        self.rules = sorted(rules, key=lambda r: r.priority)
        self.default_policy = default_policy
        self.hits: dict[str, int] = {}

    def decide(self, frame: bytes, in_port: str, *, has_fcs: bool = False, now_ns: int = 0) -> tuple[str, str | None, str]:
        n = len(frame)
        wire_len = n if has_fcs else n + 4
        if wire_len < 64:
            return DROP, "size", "-"
        info = parse_frame(frame)
        if wire_len > (1522 if info.vlan_id is not None else 1518):
            return DROP, "size", "-"
        ip = tuple(info.ipv4) if info.ethertype == ETH_IPV4 and info.ipv4 else None
        rule = next((r for r in self.rules if r.matches(in_port, info.src_mac, info.dst_mac,
                                                        info.ethertype, wire_len, ip)), None)
        rid = rule.id if rule else "default"
        self.hits[rid] = self.hits.get(rid, 0) + 1
        if rule is not None and rule.action == "deny":
            return DROP, "rule", rid
        if has_fcs and not fcs_ok(frame):
            return DROP, "crc", rid
        if rule is None and self.default_policy == "deny":
            return DROP, "rule", rid
        if rule is not None and rule.bucket is not None:
            if not rule.bucket.allow(n, now_ns or time.perf_counter_ns()):
                return DROP, "rate", rid
        return FORWARD, None, rid


if __name__ == "__main__":
    from frame_parse import build_frame, build_icmp_echo, build_ipv4, build_tcp_syn

    A_MAC, B_MAC = "40:c2:ba:50:b1:b7", "e4:54:e8:2d:8f:ca"
    A_IP, B_IP = "192.168.10.135", "192.168.10.136"
    ping_a_to_b = build_frame(B_MAC, A_MAC, ETH_IPV4, build_ipv4(A_IP, B_IP, 1, build_icmp_echo()))
    reply_b_to_a = build_frame(A_MAC, B_MAC, ETH_IPV4, build_ipv4(B_IP, A_IP, 1, build_icmp_echo()))
    iperf_syn = build_frame(B_MAC, A_MAC, ETH_IPV4, build_ipv4(A_IP, B_IP, 6, build_tcp_syn(50000, 5201)))

    def show(title: str, table: RuleTable) -> None:
        print(f"\n{title}")
        for name, frame, port in (("A -> B ping   (in p25)", ping_a_to_b, "p25"),
                                  ("B -> A reply  (in p1) ", reply_b_to_a, "p1"),
                                  ("A -> B iperf3 (in p25)", iperf_syn, "p25")):
            print(f"  {name}: {table.decide(frame, port)}")

    show("Block ping to B, from the E3200 side only",
         RuleTable([parse_rule(f"deny proto icmp dst-ip {B_IP} in-port p25 priority 5 id no-ping-b")]))
    show("Stateless trap: deny ICMP from B, no in-port. A's ping reaches B, but B's reply is dropped,\n"
         "so A's ping fails too (a rule cannot tell a request from a reply)",
         RuleTable([parse_rule(f"deny proto icmp src-ip {B_IP} priority 5 id no-icmp-from-b")]))
    show("Block TCP port 5201 to B",
         RuleTable([parse_rule(f"deny proto tcp dst-port 5201 dst-ip {B_IP} priority 5 id no-iperf")]))
    show("Default deny: allow IPv4 and ARP",
         RuleTable([parse_rule("allow ethertype 0x0800 priority 10 id allow-ipv4"),
                    parse_rule("allow ethertype 0x0806 priority 11 id allow-arp")], "deny"))
