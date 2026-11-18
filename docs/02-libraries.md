# 2 · Libraries and tools

## Python

The firewall modules require Python 3.11 or later and use the standard library.

| Module | Purpose |
|---|---|
| `socket` | Receive and send Ethernet frames through Linux raw sockets |
| `struct` | Read packet headers and encode socket options |
| `select` | Wait for traffic on the bridge interfaces |
| `zlib` | Calculate CRC-32 checksums |
| `time` | Measure elapsed time for rate limiting |
| `dataclasses` | Store frame information and firewall rules |
| `argparse` | Read command-line arguments |

The documentation builder also uses standard-library modules for file handling and HTML formatting. The automated tests use `pytest`, listed in `requirements-dev.txt`.

## Linux tools

| Tool | Purpose |
|---|---|
| `ip` | Configure interface addresses and link state |
| `ethtool` | Configure network-card offloads and FCS handling |
| `sysctl` | Enable or disable IPv4 forwarding |
| `nft` | Load the router firewall rules |
| `bash` | Run the router setup script |

The examples that print results can run on Windows, macOS, or Linux. Live Ethernet bridging and router configuration require Linux.
