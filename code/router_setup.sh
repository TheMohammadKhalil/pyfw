#!/usr/bin/env bash
set -euo pipefail

CMD=${1:-}
WAN=${2:-enp45s0}
LAN=${3:-enp46s0}
WAN_CIDR=${4:-192.168.10.10/24}
LAN_CIDR=${5:-192.168.2.1/24}
HERE=$(cd "$(dirname "$0")" && pwd)

case "$CMD" in
up)
  for net in "$WAN_CIDR" "$LAN_CIDR"; do
    prefix=${net%.*}.
    if ip -4 -o addr show | grep -v -e " $WAN " -e " $LAN " | grep -q " inet ${prefix}"; then
      echo "router_setup: another interface is already in ${prefix}x; pick other networks" >&2
      exit 1
    fi
  done
  sysctl -qw net.ipv4.ip_forward=1
  for IF in "$WAN" "$LAN"; do
    ethtool -K "$IF" rx-fcs off rx-all off 2>/dev/null || true
    ip link set dev "$IF" up
  done
  ip addr replace "$WAN_CIDR" dev "$WAN"
  ip addr replace "$LAN_CIDR" dev "$LAN"
  python3 "$HERE/router_nft.py" --wan "$WAN" --lan "$LAN" | nft -f -
  echo "router_setup: up. $WAN=$WAN_CIDR  $LAN=$LAN_CIDR"
  ip -br addr show dev "$WAN"; ip -br addr show dev "$LAN"
  ;;
down)
  nft delete table inet pyfw1 2>/dev/null || true
  ip addr del "$WAN_CIDR" dev "$WAN" 2>/dev/null || true
  ip addr del "$LAN_CIDR" dev "$LAN" 2>/dev/null || true
  sysctl -qw net.ipv4.ip_forward=0
  echo "router_setup: down (table removed, addresses removed, forwarding off)"
  ;;
*)
  echo "Usage: $0 {up|down} [WAN_IF] [LAN_IF] [WAN_CIDR] [LAN_CIDR]" >&2
  exit 2
  ;;
esac
