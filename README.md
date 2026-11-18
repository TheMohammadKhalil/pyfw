# pyfw

### A Python firewall for a small network lab

pyfw explores how a firewall reads network traffic and decides what to allow, block, or rate-limit. The project includes a two-port Ethernet bridge, a rule engine, and a router setup using Linux nftables.

## What it does

- Reads Ethernet frames, VLAN tags, IPv4 addresses, and TCP/UDP ports.
- Applies rules by MAC address, IP address, protocol, port, and frame size.
- Supports **allow**, **deny**, and **rate-limit** actions.
- Checks frame integrity with CRC-32 when an FCS is supplied to the rule engine.
- Forwards traffic between two Ethernet ports on Linux.
- Generates nftables rules for routing between two networks.

## Network layout

```text
Laptop A ── Router ── [ p25 | pyfw mini PC | p1 ] ── Laptop B
```

In **bridge mode**, both laptops share one network. The mini PC filters Ethernet traffic between them without acting as their gateway.

In **router mode**, the mini PC connects two networks and uses nftables to filter routed traffic.

## Quick start

Use **Python 3.11 or later**. The Python examples use only the standard library.

```bash
git clone https://github.com/TheMohammadKhalil/pyfw.git
cd pyfw
python code/rule_engine.py
```

This example prints the decisions made by several firewall rules without changing your network. You can also run:

```bash
python code/frame_parse.py
python code/fcs_check.py
python code/token_bucket.py
python code/router_nft.py
```

The live bridge and router setup require **Linux**, administrator privileges, and two Ethernet ports. See the [setup instructions](docs/03-setup.md) before running them.

## Project structure

| Folder | Contents |
|---|---|
| [code/](code/README.md) | Firewall modules, runnable examples, and automated tests |
| [docs/](docs/01-topology.md) | Network layout, requirements, setup, and implementation notes |
| [html/](html/index.html) | Offline HTML copy of the documentation |
| [tools/](tools/build_html.py) | Documentation builder |

## Documentation

- [Network layout](docs/01-topology.md)
- [Libraries and tools](docs/02-libraries.md)
- [Setup](docs/03-setup.md)
- [Bridge and router modes](docs/04-gateway-and-router.md)
- [How the code works](docs/05-code-walkthrough.md)

To read the documentation offline, open `html/index.html` in a browser. After editing the source or Markdown, refresh the HTML with `python tools/build_html.py`.

## Project scope

This is a lab prototype. The bridge uses stateless rules: each frame is evaluated separately. Its live forwarding path relies on the network card for FCS validation. The repository contains the command-line modules shown above; it does not include a dashboard or a background service.
