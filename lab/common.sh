#!/usr/bin/env bash
# Shared helpers for the Pierce NAT lab. Source this file; do not run it.
set -euo pipefail

# Topology (everything lives in network namespaces; the host network is never touched):
#
#   peerA 10.0.1.2 -- natA 10.0.1.1 | 192.0.32.1 --+
#                                                   |  bridge "br0" inside netns pierce-inet
#   peerB 10.0.2.2 -- natB 10.0.2.1 | 192.0.32.2 --+
#                                                   |
#                    obs 192.0.32.10, 192.0.32.11 +  (two "public servers": STUN, NAT self-check)
#
# Why 192.0.32.0/24 and not a documentation range like 203.0.113.0/24: miniupnpd (the port
# mapping daemon run with PORTMAP) refuses to hand out mappings on a reserved external address.
# The namespaces have no route to the real internet, so nothing is ever sent to these addresses.
#
# Why the bridge is in its own netns: Docker loads br_netfilter, which sends bridged traffic on the
# host through Docker's iptables FORWARD chain (policy DROP). A fresh netns has none of that.
NS_PEER_A=pierce-peerA
NS_PEER_B=pierce-peerB
NS_NAT_A=pierce-natA
NS_NAT_B=pierce-natB
NS_INET=pierce-inet
NS_OBS=pierce-obs
ALL_NS=("$NS_PEER_A" "$NS_PEER_B" "$NS_NAT_A" "$NS_NAT_B" "$NS_OBS" "$NS_INET")

PEER_A_IP=10.0.1.2
PEER_B_IP=10.0.2.2
NAT_A_LAN_IP=10.0.1.1
NAT_B_LAN_IP=10.0.2.1
NAT_A_WAN_IP=192.0.32.1
NAT_B_WAN_IP=192.0.32.2
OBS_IP1=192.0.32.10
OBS_IP2=192.0.32.11

# IPv6 (setup.sh with IPV6=A|B|AB): no NAT, as with most IPv6 deployments; the routers only
# filter (stateful: replies to what the LAN sent). Documentation prefix 2001:db8::/32.
PEER_A_IP6=2001:db8:1::2
PEER_B_IP6=2001:db8:2::2
NAT_A_LAN_IP6=2001:db8:1::1
NAT_B_LAN_IP6=2001:db8:2::1
NAT_A_WAN_IP6=2001:db8:100::1
NAT_B_WAN_IP6=2001:db8:100::2
OBS_IP6=2001:db8:100::10

NAT_TYPES=(full restricted port-restricted symmetric-random symmetric-sequential)

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "run as root (sudo)" >&2
    exit 1
  fi
}

need_tools() {
  for t in ip nft ping python3; do
    command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }
  done
}

ns_exec() { ip netns exec "$1" "${@:2}"; }

ns_add() { ip netns add "$1"; ns_exec "$1" ip link set lo up; }

lab_exists() { ip netns list | grep -qw "$NS_INET"; }

# veth_pair <if_a> <ns_a> <addr_a> <if_b> <ns_b> <addr_b>
# Creates a virtual cable and plugs each end into a namespace. An empty addr leaves that end unaddressed.
veth_pair() {
  local a=$1 ns_a=$2 addr_a=$3 b=$4 ns_b=$5 addr_b=$6
  ip link add "$a" netns "$ns_a" type veth peer name "$b" netns "$ns_b"
  [[ -n $addr_a ]] && ns_exec "$ns_a" ip addr add "$addr_a" dev "$a"
  [[ -n $addr_b ]] && ns_exec "$ns_b" ip addr add "$addr_b" dev "$b"
  ns_exec "$ns_a" ip link set "$a" up
  ns_exec "$ns_b" ip link set "$b" up
}

# to_inet <if_in_ns> <ns> <addr>: cable from a namespace to the bridge in pierce-inet.
to_inet() {
  local inner=$1 ns=$2 addr=$3 outer="br-${1}"
  veth_pair "$inner" "$ns" "$addr" "$outer" "$NS_INET" ""
  ns_exec "$NS_INET" ip link set "$outer" master br0
}

enable_forward() { ns_exec "$1" sysctl -qw net.ipv4.ip_forward=1; }
