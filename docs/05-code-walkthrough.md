# 5 · How the code works

## Frame processing

```text
Receive frame → Check size → Read headers → Match rule → Check FCS if supplied → Apply rate limit → Forward or drop
```

[frame_parse.py](../code/frame_parse.py) reads the Ethernet header, an optional VLAN tag, and IPv4 information. For TCP and UDP packets, it also reads the source and destination ports.

[rule_engine.py](../code/rule_engine.py) checks rules in priority order. Lower numbers run first, and the first matching rule decides the action. When no rule matches, the table's default policy applies.

## Rules

Rules begin with `allow`, `deny`, or `limit`, followed by field-value pairs:

```text
deny proto icmp dst-ip 192.168.10.136 in-port p25 id block-ping
deny proto tcp dst-port 5201 priority 5 id block-port
limit in-port p25 rate 100mbit id cap-traffic
allow ethertype 0x0806 id allow-arp
```

Fields that are left out match any value. Rules can match MAC addresses, IPv4 addresses or subnets, protocols, TCP/UDP ports, EtherType, frame size, and input port.

Rules are stateless. Each frame is evaluated independently, so a rule can affect both requests and replies. Use `in-port` when a rule should apply in only one direction.

## Integrity and rate limiting

[fcs_check.py](../code/fcs_check.py) calculates and validates the Ethernet frame check sequence using CRC-32. The rule engine can use it when the supplied frame includes an FCS. The live bridge receives frames without the FCS and relies on the network card's validation.

[token_bucket.py](../code/token_bucket.py) limits traffic by keeping a byte allowance that refills over time. Frames exceeding the available allowance are dropped. The bucket allows a short burst of traffic rather than queuing frames.

## Live forwarding

[mini_bridge.py](../code/mini_bridge.py) opens a raw socket on each interface and waits for incoming frames. It restores a VLAN tag when Linux supplies it separately, runs the rule engine, and forwards accepted frames through the other interface. It prints traffic counters when stopped.

[router_nft.py](../code/router_nft.py) converts rules into an nftables script. [router_setup.sh](../code/router_setup.sh) assigns interface addresses, enables IPv4 forwarding, and loads that script.
