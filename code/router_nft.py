from __future__ import annotations

import argparse

from rule_engine import Rule, parse_rule
from token_bucket import BURST_S, MIN_BURST_BYTES, parse_rate

TABLE = "pyfw1"


def match_text(rule: Rule, iface: str) -> str:
    m = [f'iifname "{iface}"']
    if rule.src_mac:
        m.append(f"ether saddr {rule.src_mac}")
    if rule.dst_mac:
        m.append(f"ether daddr {rule.dst_mac}")
    if rule.src_ip:
        m.append(f"ip saddr {rule.src_ip.text}")
    if rule.dst_ip:
        m.append(f"ip daddr {rule.dst_ip.text}")
    if rule.proto and (rule.src_port or rule.dst_port):
        if rule.src_port:
            m.append(f"{rule.proto} sport {rule.src_port}")
        if rule.dst_port:
            m.append(f"{rule.proto} dport {rule.dst_port}")
    elif rule.proto:
        m.append(f"meta l4proto {rule.proto}")
    if rule.ethertype is not None:
        m.append(f"meta protocol 0x{rule.ethertype:04x}")
    if rule.min_len is not None or rule.max_len is not None:

        lo = max(0, (rule.min_len or 0) - 18)
        hi = (rule.max_len or 1522) - 18
        m.append(f"meta length {lo}-{hi}")
    return " ".join(m)


def limit_text(rate: str) -> str:
    bytes_per_s = parse_rate(rate) // 8
    burst = max(int(bytes_per_s * BURST_S), MIN_BURST_BYTES)
    return f"limit rate over {bytes_per_s} bytes/second burst {burst} bytes"


def build_router_script(wan: str, lan: str, rules: list[Rule], policy: str = "allow") -> str:
    ifaces = {"p25": wan, "p1": lan}
    both = f'{{ "{wan}", "{lan}" }}'
    fwd = [f"iifname != {both} drop", f"oifname != {both} drop"]
    for r in sorted(rules, key=lambda r: r.priority):
        ports = list(ifaces) if r.in_port == "any" else [r.in_port]
        for port in ports:
            m = match_text(r, ifaces[port])
            if r.action == "deny":
                fwd.append(f'{m} counter drop comment "{r.id}"')
            elif r.action == "allow":
                fwd.append(f'{m} counter accept comment "{r.id}"')
            else:
                assert r.rate is not None
                fwd.append(f'{m} {limit_text(r.rate)} counter drop comment "{r.id} rate"')
                fwd.append(f'{m} counter accept comment "{r.id}"')
    verdict = "accept" if policy == "allow" else "drop"
    for port, iface in ifaces.items():
        fwd.append(f'iifname "{iface}" counter {verdict} comment "default {port}"')
    inp = [
        f"iifname {both} meta l4proto icmp accept",
        f"iifname {both} ct state established,related accept",
        f"iifname {both} counter drop",
    ]
    lines = [
        f"table inet {TABLE} {{}}",
        f"delete table inet {TABLE}",
        f"table inet {TABLE} {{",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
        *(f"    {s}" for s in fwd),
        "  }",
        "  chain input {",
        "    type filter hook input priority 0; policy accept;",
        *(f"    {s}" for s in inp),
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Print the router-mode nftables script.")
    ap.add_argument("--wan", default="enp45s0", help="p25, towards the E3200")
    ap.add_argument("--lan", default="enp46s0", help="p1, towards Laptop B")
    ap.add_argument("--rule", action="append", default=[])
    ap.add_argument("--policy", choices=("allow", "deny"), default="allow")
    a = ap.parse_args(argv)
    rules = [parse_rule(text, f"r{i + 1}") for i, text in enumerate(a.rule)]
    print(build_router_script(a.wan, a.lan, rules, a.policy), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
