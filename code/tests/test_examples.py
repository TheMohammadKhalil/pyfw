from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fcs_check import append_fcs, fcs_ok, strip_fcs
from frame_parse import (
    ETH_ARP, ETH_IPV4, build_frame, build_icmp_echo, build_ipv4, build_tcp_syn, describe, int_to_ip,
    ip_checksum, ip_to_int, mac_to_bytes, parse_frame,
)
from mini_bridge import PACKET_AUXDATA, SOL_PACKET, reinsert_vlan
from router_nft import build_router_script, main as router_main
from rule_engine import DROP, FORWARD, Net, RuleTable, parse_rule
from token_bucket import TokenBucket, parse_rate, simulate

A_MAC, B_MAC = "40:c2:ba:50:b1:b7", "e4:54:e8:2d:8f:ca"
A_IP, B_IP = "192.168.10.135", "192.168.10.136"


def ping(src_mac: str = A_MAC, dst_mac: str = B_MAC, src: str = A_IP, dst: str = B_IP, vlan: int | None = None) -> bytes:
    return build_frame(dst_mac, src_mac, ETH_IPV4, build_ipv4(src, dst, 1, build_icmp_echo()), vlan_id=vlan)


def syn(dport: int, dst: str = B_IP) -> bytes:
    return build_frame(B_MAC, A_MAC, ETH_IPV4, build_ipv4(A_IP, dst, 6, build_tcp_syn(50000, dport)))


def test_parse_untagged_ping() -> None:
    f = parse_frame(ping())
    assert f.dst_mac == mac_to_bytes(B_MAC) and f.src_mac == mac_to_bytes(A_MAC)
    assert f.ethertype == ETH_IPV4 and f.vlan_id is None and f.l3_offset == 14
    assert f.ipv4 is not None
    assert (int_to_ip(f.ipv4.src), int_to_ip(f.ipv4.dst), f.ipv4.proto) == (A_IP, B_IP, 1)
    assert (f.ipv4.src_port, f.ipv4.dst_port) == (-1, -1)


def test_parse_vlan_tcp_ports() -> None:
    frame = build_frame(B_MAC, A_MAC, ETH_IPV4, build_ipv4(A_IP, B_IP, 6, build_tcp_syn(50000, 5201)), vlan_id=10)
    f = parse_frame(frame)
    assert f.vlan_id == 10 and f.ethertype == ETH_IPV4 and f.l3_offset == 18
    assert f.ipv4 is not None and (f.ipv4.src_port, f.ipv4.dst_port) == (50000, 5201)
    assert "vlan 10" in describe(frame) and "50000 > 5201" in describe(frame)


def test_ipv4_header_checksum_is_valid() -> None:
    hdr = build_ipv4(A_IP, B_IP, 1, b"")[:20]
    assert ip_checksum(hdr) == 0


def test_frames_are_padded_and_short_frames_rejected() -> None:
    assert len(build_frame(B_MAC, A_MAC, ETH_ARP, b"")) == 60
    with pytest.raises(ValueError):
        parse_frame(b"\x00" * 13)
    with pytest.raises(ValueError):
        mac_to_bytes("40:c2:ba")
    assert int_to_ip(ip_to_int("192.168.10.1")) == "192.168.10.1"


def test_fcs_good_and_bad() -> None:
    good = append_fcs(ping())
    assert fcs_ok(good) and strip_fcs(good) == ping()
    bad = bytearray(good)
    bad[30] ^= 0x80
    assert not fcs_ok(bytes(bad))
    assert not fcs_ok(b"\x00\x01")


def test_parse_rate_needs_unit() -> None:
    assert parse_rate("300mbit") == 300_000_000
    assert parse_rate("1.5gbit") == 1_500_000_000
    with pytest.raises(ValueError):
        parse_rate("900")


def test_token_bucket_refuses_then_refills() -> None:
    b = TokenBucket(parse_rate("1mbit"), now_ns=0)
    assert b.allow(1522, 0)
    assert not b.allow(1522, 0)
    assert b.allow(1522, 13_000_000)


@pytest.mark.parametrize(("offered", "expected"), [(50, 50), (500, 100), (900, 100)])
def test_token_bucket_rate_within_2_percent(offered: float, expected: float) -> None:
    assert simulate("100mbit", offered) == pytest.approx(expected, rel=0.02)


def test_parse_rule_fields() -> None:
    r = parse_rule(f"deny proto tcp dst-port 5201 dst-ip {B_IP} src-ip 192.168.10.0/24 in-port p25 priority 5 id no-iperf")
    assert (r.id, r.action, r.priority, r.in_port, r.proto, r.dst_port) == ("no-iperf", "deny", 5, "p25", "tcp", 5201)
    assert r.dst_ip == Net.parse(B_IP) and r.src_ip is not None and r.src_ip.contains(ip_to_int(A_IP))


@pytest.mark.parametrize("bad", [
    "drop src-mac 40:c2:ba:50:b1:b7",
    "deny dst-port 22",
    "deny proto gre",
    "limit in-port p25",
    "deny rate 10mbit",
    "deny in-port p3",
    "deny src-ip 192.168.10.0/33",
    "deny src-mac",
])
def test_parse_rule_refuses(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_rule(bad)


def test_t10_deny_ping_to_b_from_p25_only() -> None:
    t = RuleTable([parse_rule(f"deny proto icmp dst-ip {B_IP} in-port p25 priority 5 id no-ping-b")])
    assert t.decide(ping(), "p25") == (DROP, "rule", "no-ping-b")
    assert t.decide(ping(B_MAC, A_MAC, B_IP, A_IP), "p1")[0] == FORWARD
    assert t.decide(ping(B_MAC, "58:6d:8f:6a:a3:6f", B_IP, "192.168.10.1"), "p1")[0] == FORWARD
    assert t.hits == {"no-ping-b": 1, "default": 2}


def test_rules_are_stateless() -> None:
    t = RuleTable([parse_rule(f"deny proto icmp dst-ip {B_IP} id no-icmp-to-b")])
    assert t.decide(ping(A_MAC, B_MAC, A_IP, B_IP), "p25")[0] == DROP

    assert t.decide(ping(B_MAC, A_MAC, B_IP, A_IP), "p1")[0] == FORWARD
    assert t.decide(ping(A_MAC, B_MAC, A_IP, B_IP), "p25")[0] == DROP


def test_t11_deny_tcp_port() -> None:
    t = RuleTable([parse_rule(f"deny proto tcp dst-port 5201 dst-ip {B_IP} priority 5 id no-iperf")])
    assert t.decide(syn(5201), "p25") == (DROP, "rule", "no-iperf")
    assert t.decide(syn(22), "p25")[0] == FORWARD
    assert t.decide(ping(), "p25")[0] == FORWARD


def test_mac_rule_and_priority_order() -> None:
    t = RuleTable([
        parse_rule(f"deny src-mac {A_MAC} priority 20 id block-a"),
        parse_rule(f"allow src-mac {A_MAC} proto icmp priority 10 id allow-a-ping"),
    ])
    assert t.decide(ping(), "p25") == (FORWARD, None, "allow-a-ping")
    assert t.decide(syn(80), "p25") == (DROP, "rule", "block-a")


def test_default_deny_profile() -> None:
    t = RuleTable([parse_rule("allow ethertype 0x0800 priority 10 id allow-ipv4"),
                   parse_rule("allow ethertype 0x0806 priority 11 id allow-arp")], "deny")
    assert t.decide(ping(), "p25")[0] == FORWARD
    assert t.decide(build_frame(B_MAC, A_MAC, ETH_ARP, b""), "p25")[0] == FORWARD
    assert t.decide(build_frame(B_MAC, A_MAC, 0x86DD, b""), "p25") == (DROP, "rule", "default")


def test_ip_rule_ignores_non_ipv4_frames() -> None:
    t = RuleTable([parse_rule("deny proto icmp id no-icmp")])
    assert t.decide(build_frame(B_MAC, A_MAC, ETH_ARP, b""), "p25")[0] == FORWARD


def test_vlan_frame_matches_inner_type() -> None:
    t = RuleTable([parse_rule(f"deny proto icmp dst-ip {B_IP} id no-ping-b")])
    assert t.decide(ping(vlan=10), "p25") == (DROP, "rule", "no-ping-b")


@pytest.mark.parametrize(("size", "has_fcs", "tagged", "ok"), [
    (59, False, False, False), (60, False, False, True), (1514, False, False, True), (1515, False, False, False),
    (63, True, False, False), (64, True, False, True), (1518, True, False, True), (1519, True, False, False),
    (1518, False, True, True), (1519, False, True, False), (1522, True, True, True), (1523, True, True, False),
])
def test_size_limits(size: int, has_fcs: bool, tagged: bool, ok: bool) -> None:
    base = build_frame(B_MAC, A_MAC, 0x88B5, b"", vlan_id=10 if tagged else None)
    body = size - 4 if has_fcs else size
    frame = (base + bytes(body))[:body] if body >= 14 else base[:body]
    if has_fcs:
        frame = append_fcs(frame)
    assert len(frame) == size
    verdict = RuleTable([]).decide(frame, "p25", has_fcs=has_fcs)
    assert (verdict[0] == FORWARD) is ok
    if not ok:
        assert verdict[1] == "size"


def test_bad_fcs_dropped_after_rules() -> None:
    t = RuleTable([])
    good = append_fcs(ping())
    bad = bytearray(good)
    bad[-1] ^= 0xFF
    assert t.decide(good, "p25", has_fcs=True)[0] == FORWARD
    assert t.decide(bytes(bad), "p25", has_fcs=True) == (DROP, "crc", "default")


def test_limit_rule_drops_with_reason_rate() -> None:
    t = RuleTable([parse_rule("limit in-port p25 rate 1mbit id cap-in")])
    frame = ping()
    assert t.decide(frame, "p25", now_ns=1)[0] == FORWARD
    results = [t.decide(frame, "p25", now_ns=1) for _ in range(100)]
    assert (DROP, "rate", "cap-in") in results
    assert t.decide(frame, "p1", now_ns=1)[0] == FORWARD


def test_duplicate_ids_and_bad_policy() -> None:
    with pytest.raises(ValueError):
        RuleTable([parse_rule("deny id x"), parse_rule("allow id x")])
    with pytest.raises(ValueError):
        RuleTable([], "reject")


def test_reinsert_vlan_from_auxdata() -> None:
    import struct
    untagged = ping()
    aux = struct.pack("IIIHHHH", 0x10 | 0x40, 0, 0, 0, 0, 10, 0x8100)
    tagged = reinsert_vlan(untagged, [(SOL_PACKET, PACKET_AUXDATA, aux)])
    assert parse_frame(tagged).vlan_id == 10 and len(tagged) == len(untagged) + 4
    assert reinsert_vlan(untagged, [(SOL_PACKET, PACKET_AUXDATA, struct.pack("IIIHHHH", 0, 0, 0, 0, 0, 0, 0))]) == untagged
    aux_no_tpid = struct.pack("IIIHHHH", 0x10, 0, 0, 0, 0, 10, 0)
    assert reinsert_vlan(untagged, [(SOL_PACKET, PACKET_AUXDATA, aux_no_tpid)])[12:14] == b"\x81\x00"


def test_mini_bridge_refuses_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    import mini_bridge
    monkeypatch.setattr(mini_bridge.sys, "platform", "win32")
    assert mini_bridge.main(["--p25", "x", "--p1", "y", "--rule", "deny proto icmp id t"]) == 2


def test_router_script_structure() -> None:
    rules = [
        parse_rule("deny dst-ip 192.168.2.20 proto tcp dst-port 22 in-port p25 priority 5 id no-ssh-to-b"),
        parse_rule("limit in-port p25 rate 300mbit priority 6 id cap-wan"),
        parse_rule("deny proto icmp priority 7 id no-icmp"),
    ]
    s = build_router_script("enp45s0", "enp46s0", rules, "allow")
    lines = [ln.strip() for ln in s.splitlines()]
    assert lines[:3] == ["table inet pyfw1 {}", "delete table inet pyfw1", "table inet pyfw1 {"]
    assert "type filter hook forward priority 0; policy drop;" in lines
    assert 'iifname != { "enp45s0", "enp46s0" } drop' in lines
    assert 'iifname "enp45s0" ip daddr 192.168.2.20 tcp dport 22 counter drop comment "no-ssh-to-b"' in lines
    assert ('iifname "enp45s0" limit rate over 37500000 bytes/second burst 375000 bytes '
            'counter drop comment "cap-wan rate"') in lines

    assert sum('comment "no-icmp"' in ln for ln in lines) == 2

    order = [i for i, ln in enumerate(lines) if "comment" in ln]
    assert [lines[i].split('comment "')[1].rstrip('"') for i in order] == [
        "no-ssh-to-b", "cap-wan rate", "cap-wan", "no-icmp", "no-icmp", "default p25", "default p1"]
    assert 'iifname { "enp45s0", "enp46s0" } meta l4proto icmp accept' in lines


def test_router_script_default_deny(capsys: pytest.CaptureFixture[str]) -> None:
    assert router_main(["--wan", "w0", "--lan", "l0", "--policy", "deny"]) == 0
    out = capsys.readouterr().out
    assert 'iifname "w0" counter drop comment "default p25"' in out
    assert 'iifname "l0" counter drop comment "default p1"' in out
