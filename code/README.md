# Firewall modules

Run these commands from the repository root with Python 3.11 or later.

| File | Purpose |
|---|---|
| [frame_parse.py](frame_parse.py) | Read and build Ethernet, VLAN, and IPv4 frames |
| [fcs_check.py](fcs_check.py) | Calculate and validate Ethernet CRC-32 checksums |
| [token_bucket.py](token_bucket.py) | Limit traffic using a token bucket |
| [rule_engine.py](rule_engine.py) | Parse rules and decide whether to forward or drop a frame |
| [mini_bridge.py](mini_bridge.py) | Forward traffic between two Linux Ethernet interfaces |
| [router_nft.py](router_nft.py) | Generate an nftables ruleset |
| [router_setup.sh](router_setup.sh) | Configure or remove the router setup |

```bash
python code/rule_engine.py
```

The example uses sample frames and prints the rule decisions. The frame parser, checksum module, and rate limiter also run independently.

For live traffic, follow the [setup instructions](../docs/03-setup.md). The bridge and router script need Linux and administrator privileges.
