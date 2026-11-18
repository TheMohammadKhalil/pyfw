# 3 · Setup

## Get the project

```bash
git clone https://github.com/TheMohammadKhalil/pyfw.git
cd pyfw
python3 code/rule_engine.py
```

Use Python 3.11 or later. No Python packages are needed to run the firewall modules.

## Prepare the mini PC

Use a Linux machine with two Ethernet ports and a separate management connection, such as Wi-Fi. On Ubuntu, install the network tools:

```bash
sudo apt install python3 iproute2 ethtool nftables
ip -br link
```

The commands below use `enp45s0` and `enp46s0`. Replace them with your Ethernet interface names. Keep these interfaces dedicated to the lab, and stop any other bridge or service using them. Configure the network manager to leave them unmanaged so it does not restore addresses during operation.

## Bridge mode

Connect the devices as shown in the [network layout](01-topology.md). Enable DHCP on the E3200 and both laptops.

Remove addresses from the two firewall ports and disable offloads that can change the frames delivered to the program. These commands change the selected interfaces, so use the separate management connection.

```bash
sudo ip addr flush dev enp45s0
sudo ip addr flush dev enp46s0
sudo sysctl -w net.ipv6.conf.enp45s0.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.enp46s0.disable_ipv6=1
sudo ip link set dev enp45s0 up
sudo ip link set dev enp46s0 up
sudo ethtool -K enp45s0 gro off gso off tso off lro off rxvlan off
sudo ethtool -K enp46s0 gro off gso off tso off lro off rxvlan off
sudo ethtool -K enp45s0 rx-fcs off rx-all off
sudo ethtool -K enp46s0 rx-fcs off rx-all off
```

Some adapters do not support every offload setting. Inspect their settings with `ethtool -k`. The bridge expects frames without an FCS; the network card handles CRC validation.

Start the bridge with a rule that blocks ICMP traffic to Laptop B from the router side:

```bash
sudo python3 code/mini_bridge.py --p25 enp45s0 --p1 enp46s0 --rule "deny proto icmp dst-ip 192.168.10.136 in-port p25 id block-ping"
```

Change the destination address to match Laptop B. Unmatched traffic is allowed by default. Press Ctrl+C to stop forwarding and print the counters. The interface settings remain in place until you restore them through your network configuration.

## Router mode

Stop the bridge before switching modes. Use these example addresses:

| Device or interface | Address | Gateway |
|---|---|---|
| E3200 | `192.168.10.1/24` | — |
| Laptop A | `192.168.10.135/24` | `192.168.10.1` |
| Mini PC `p25` | `192.168.10.10/24` | — |
| Mini PC `p1` | `192.168.2.1/24` | — |
| Laptop B | `192.168.2.20/24` | `192.168.2.1` |

Keep the management connection on a different subnet. Add a static route on the E3200 for `192.168.2.0/24` through `192.168.10.10`.

Start routing:

```bash
sudo bash code/router_setup.sh up enp45s0 enp46s0
```

The script assigns the two mini PC addresses, enables IPv4 forwarding, and loads the `inet pyfw1` nftables table. Its default rules allow forwarding between the two Ethernet ports. To apply a custom rule:

```bash
python3 code/router_nft.py --wan enp45s0 --lan enp46s0 --rule "deny proto tcp dst-port 22 dst-ip 192.168.2.20 in-port p25 id block-ssh" | sudo nft -f -
```

Remove the router setup:

```bash
sudo bash code/router_setup.sh down enp45s0 enp46s0
```

This removes the added addresses and firewall table and disables IPv4 forwarding. It does not restore earlier interface or forwarding settings.
