# 1 · Network layout

The lab uses two laptops, a Linksys E3200 router, and a mini PC with two Ethernet ports.

```text
Laptop A ── E3200 LAN port ── p25 [ pyfw mini PC ] p1 ── Laptop B
```

## Connections

| Connection | Purpose |
|---|---|
| Laptop A to an E3200 LAN port | Connect the first laptop to the network |
| E3200 LAN port to mini PC `p25` | Carry traffic into the firewall |
| Mini PC `p1` to Laptop B | Carry filtered traffic to the second laptop |
| Mini PC Wi-Fi | Separate management connection |

The lab does not need an internet connection. The E3200's Internet port stays disconnected. Disable laptop Wi-Fi when using this layout so traffic follows the Ethernet path.

## Bridge addresses

| Device | Example address | Gateway |
|---|---|---|
| Laptop A | `192.168.10.135/24` | `192.168.10.1` |
| E3200 | `192.168.10.1/24` | — |
| Mini PC Ethernet ports | No IP addresses | — |
| Laptop B | `192.168.10.136/24` | `192.168.10.1` |

Both laptops receive their addresses from the E3200's DHCP server. The mini PC forwards or drops frames without changing their source and destination addresses.

## Interface names

The lab mini PC uses `enp45s0` for `p25` and `enp46s0` for `p1`. Replace these names with the interfaces on your machine. The rule field `in-port p25` matches traffic arriving from the router; `in-port p1` matches traffic arriving from Laptop B.

See [bridge and router modes](04-gateway-and-router.md) for the alternative two-network layout.
