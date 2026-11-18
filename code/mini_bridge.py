from __future__ import annotations

import argparse
import errno
import select
import socket
import struct
import sys
from collections.abc import Iterable

from rule_engine import FORWARD, RuleTable, parse_rule

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_AUXDATA = 8
PACKET_IGNORE_OUTGOING = 23
PACKET_OUTGOING = 4
TP_STATUS_VLAN_VALID = 0x10
TP_STATUS_VLAN_TPID_VALID = 0x40
AUXDATA = struct.Struct("IIIHHHH")
LINK_ERRNOS = {errno.ENETDOWN, errno.ENXIO, errno.ENODEV}


def reinsert_vlan(data: bytes, ancdata: Iterable[tuple[int, int, bytes]]) -> bytes:
    for level, kind, cdata in ancdata:
        if level == SOL_PACKET and kind == PACKET_AUXDATA and len(cdata) >= AUXDATA.size:
            status, _len, _snap, _mac, _net, tci, tpid = AUXDATA.unpack_from(cdata)
            if status & TP_STATUS_VLAN_VALID:
                if not status & TP_STATUS_VLAN_TPID_VALID:
                    tpid = 0x8100
                return data[:12] + struct.pack("!HH", tpid, tci) + data[12:]
    return data


def open_port(iface: str) -> socket.socket:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    s.bind((iface, ETH_P_ALL))
    ifindex = socket.if_nametoindex(iface)
    s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, struct.pack("iHH8s", ifindex, PACKET_MR_PROMISC, 0, b""))
    s.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    try:
        s.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)
    except OSError:
        pass
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    s.setblocking(False)
    return s


def run(ifaces: dict[str, str], table: RuleTable) -> dict[str, dict[str, int]]:
    socks = {port: open_port(iface) for port, iface in ifaces.items()}
    other = {"p25": "p1", "p1": "p25"}
    by_fd = {s.fileno(): port for port, s in socks.items()}
    anc_size = socket.CMSG_SPACE(AUXDATA.size)
    counts = {port: {"rx": 0, "forwarded": 0, "dropped": 0, "link_down": 0} for port in socks}
    print(f"bridging {ifaces['p25']} (p25) <-> {ifaces['p1']} (p1); Ctrl+C stops", flush=True)
    try:
        while True:
            ready, _, _ = select.select(list(socks.values()), [], [], 1.0)
            for s in ready:
                in_port = by_fd[s.fileno()]
                while True:
                    try:
                        data, anc, _flags, addr = s.recvmsg(2048, anc_size)
                    except (BlockingIOError, InterruptedError):
                        break
                    except OSError as e:
                        if e.errno in LINK_ERRNOS:
                            break
                        raise
                    if addr[2] == PACKET_OUTGOING:
                        continue
                    if anc:
                        data = reinsert_vlan(data, anc)
                    c = counts[in_port]
                    c["rx"] += 1
                    action, _reason, _rid = table.decide(data, in_port, has_fcs=False)
                    if action != FORWARD:
                        c["dropped"] += 1
                        continue
                    try:
                        socks[other[in_port]].send(data)
                        c["forwarded"] += 1
                    except OSError as e:
                        if e.errno not in LINK_ERRNOS:
                            raise
                        c["link_down"] += 1
    except KeyboardInterrupt:
        pass
    finally:
        for s in socks.values():
            s.close()
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Minimal two-port L2 firewall (Linux, root).")
    ap.add_argument("--p25", required=True, help="interface on the E3200 side, e.g. enp45s0")
    ap.add_argument("--p1", required=True, help="interface on Laptop B's side, e.g. enp46s0")
    ap.add_argument("--rule", action="append", default=[], help='e.g. "deny src-mac 40:c2:ba:50:b1:b7 id block-a"')
    ap.add_argument("--policy", choices=("allow", "deny"), default="allow", help="default policy")
    a = ap.parse_args(argv)
    table = RuleTable([parse_rule(text, f"r{i + 1}") for i, text in enumerate(a.rule)], a.policy)
    if sys.platform != "linux":
        print("mini_bridge needs Linux (AF_PACKET raw sockets)", file=sys.stderr)
        return 2
    counts = run({"p25": a.p25, "p1": a.p1}, table)
    for port, c in counts.items():
        print(f"in {port}: {c}")
    print(f"rule hits: {table.hits}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
