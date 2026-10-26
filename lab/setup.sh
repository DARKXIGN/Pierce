#!/usr/bin/env bash
# Usage: sudo ./lab/setup.sh <natA-type> <natB-type>
# Types: full | restricted | port-restricted | symmetric-random | symmetric-sequential
#
# NAT behavior per RFC 4787 terms (mapping = which public port you get, filtering = who may send in):
#   type                  mapping                                   inbound filtering
#   full                  endpoint-independent                      none (anyone may send to the mapped port)
#   restricted            endpoint-independent                      only remote IPs this internal endpoint has sent to
#   port-restricted       endpoint-independent                      only remote IP:port pairs this endpoint has sent to
#   symmetric-random      endpoint-dependent, random port           only remote IP:port pairs
#   symmetric-sequential  endpoint-dependent, next port in sequence only remote IP:port pairs
#                         (the C++ userspace NAT in lab/usernat/; build it first with cmake)
#
# Environment: USERNAT_LIFETIME (mapping lifetime in s, default 120), USERNAT_STEP (port step,
# default 1), PIERCE_BUILD (build directory holding the usernat binary, default ./build).
set -Eeuo pipefail  # -E: the ERR trap also fires inside functions
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$here/common.sh"
need_root; need_tools

TYPE_A=${1:-full}
TYPE_B=${2:-full}
for t in "$TYPE_A" "$TYPE_B"; do
  [[ " ${NAT_TYPES[*]} " == *" $t "* ]] || { echo "unknown NAT type: $t (use: ${NAT_TYPES[*]})" >&2; exit 2; }
done
USERNAT=${PIERCE_BUILD:-"$here/../build"}/usernat
if [[ " $TYPE_A $TYPE_B " == *" symmetric-sequential "* && ! -x $USERNAT ]]; then
  # nftables cannot hand out ports in sequence, so this type needs the C++ userspace NAT.
  echo "symmetric-sequential needs $USERNAT: run cmake -B build && cmake --build build" >&2
  exit 3
fi

if lab_exists; then
  echo "lab already up; run: sudo ./lab/teardown.sh" >&2
  exit 1
fi
# If anything below fails, remove whatever was half-built.
trap '"$here/teardown.sh" >/dev/null 2>&1' ERR

for ns in "${ALL_NS[@]}"; do ns_add "$ns"; done

# "Internet": a plain bridge inside pierce-inet
ns_exec "$NS_INET" ip link add br0 type bridge
ns_exec "$NS_INET" ip link set br0 up

# LAN links
veth_pair pA-lan "$NS_PEER_A" "$PEER_A_IP/24" nA-lan "$NS_NAT_A" "$NAT_A_LAN_IP/24"
veth_pair pB-lan "$NS_PEER_B" "$PEER_B_IP/24" nB-lan "$NS_NAT_B" "$NAT_B_LAN_IP/24"

# WAN links to the bridge
to_inet nA-wan "$NS_NAT_A" "$NAT_A_WAN_IP/24"
to_inet nB-wan "$NS_NAT_B" "$NAT_B_WAN_IP/24"
to_inet obs0 "$NS_OBS" "$OBS_IP1/24"
ns_exec "$NS_OBS" ip addr add "$OBS_IP2/24" dev obs0

# Routes
ns_exec "$NS_PEER_A" ip route add default via "$NAT_A_LAN_IP"
ns_exec "$NS_PEER_B" ip route add default via "$NAT_B_LAN_IP"
enable_forward "$NS_NAT_A"
enable_forward "$NS_NAT_B"

# start_usernat <ns> <lan_if> <wan_if> <public_ip>
# The kernel keeps NATing everything except UDP (so ping still works); UDP is left entirely to
# usernat, which reads it from packet sockets and sends the rewritten packets from a raw socket.
start_usernat() {
  local ns=$1 lan=$2 wan=$3 pub=$4
  ns_exec "$ns" nft -f - <<NFT
table ip raw {
  # No conntrack for UDP: the kernel must neither NAT it nor remember it.
  chain prerouting { type filter hook prerouting priority -300; meta l4proto udp notrack; }
  chain output { type filter hook output priority -300; meta l4proto udp notrack; }
}
table ip nat {
  chain postrouting { type nat hook postrouting priority 100; oifname "$wan" meta l4proto != udp masquerade; }
}
table ip filter {
  # usernat already got its copy of these from its packet sockets; the kernel drops the originals.
  # (Dropping inbound UDP in "input" also stops the kernel answering with ICMP port unreachable.)
  chain input { type filter hook input priority 0; iifname "$wan" meta l4proto udp drop; }
  chain forward {
    type filter hook forward priority 0; policy drop;
    meta l4proto udp drop
    ct state established,related accept
    iifname "$lan" oifname "$wan" accept
  }
}
NFT
  # Started with ip netns exec directly so teardown.sh finds it via "ip netns pids" and stops it.
  ip netns exec "$ns" "$USERNAT" --lan "$lan" --wan "$wan" --public-ip "$pub" \
    --lifetime "${USERNAT_LIFETIME:-120}" --step "${USERNAT_STEP:-1}" \
    >"/tmp/pierce-usernat-$ns.log" 2>&1 &
  local pid=$!
  sleep 0.2
  kill -0 "$pid" 2>/dev/null || { echo "usernat failed in $ns:" >&2; cat "/tmp/pierce-usernat-$ns.log" >&2; return 1; }
  echo "$ns: symmetric-sequential NAT on $wan (usernat pid $pid, log /tmp/pierce-usernat-$ns.log)"
}

# apply_nat <ns> <type> <lan_if> <wan_if> <lan_host_ip> <public_ip>
apply_nat() {
  local ns=$1 type=$2 lan=$3 wan=$4 host=$5 pub=$6
  local snat="masquerade" dnat="" inbound=""
  if [[ $type == symmetric-sequential ]]; then
    start_usernat "$ns" "$lan" "$wan" "$pub"
    return
  fi

  # Linux masquerade keeps the source port when it is free, so one internal ip:port gets the same
  # public port for every destination (endpoint-independent mapping). "random" picks a fresh port
  # per connection, i.e. per destination: that is the random-port symmetric NAT.
  [[ $type == symmetric-random ]] && snat="masquerade random"

  # Cone types with open-ish filtering need unsolicited inbound UDP to reach the host at all, so we
  # forward every inbound UDP port to the single LAN host. Because masquerade preserved the port,
  # public port == internal port and no port rewrite is needed. (Valid for a one-host LAN, which is
  # exactly what the lab has.)
  if [[ $type == full || $type == restricted ]]; then
    dnat="iifname \"$wan\" udp dport 1024-65535 dnat to $host;"
  fi

  case "$type" in
    full)
      inbound="iifname \"$wan\" ip protocol udp accept" ;;
    restricted)
      # Accept a new inbound flow only if this internal ip:port has sent to that remote IP before.
      inbound="iifname \"$wan\" ip protocol udp ip daddr . udp dport . ip saddr @contacted accept" ;;
    port-restricted|symmetric-random)
      # Only replies to flows we started: that is exactly conntrack's "established".
      inbound="" ;;
  esac

  ns_exec "$ns" nft -f - <<NFT
table ip nat {
  chain prerouting { type nat hook prerouting priority -100; ${dnat} }
  chain postrouting { type nat hook postrouting priority 100; oifname "$wan" ${snat}; }
}
table ip filter {
  # Remembers (internal ip, internal port, remote ip) for every outbound UDP packet. Used by "restricted".
  set contacted {
    type ipv4_addr . inet_service . ipv4_addr
    flags dynamic, timeout
    timeout 120s
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    iifname "$lan" oifname "$wan" ip protocol udp update @contacted { ip saddr . udp sport . ip daddr }
    ct state established,related accept
    iifname "$lan" oifname "$wan" accept
    ${inbound}
  }
}
NFT
  echo "$ns: $type NAT on $wan"
}

apply_nat "$NS_NAT_A" "$TYPE_A" nA-lan nA-wan "$PEER_A_IP" "$NAT_A_WAN_IP"
apply_nat "$NS_NAT_B" "$TYPE_B" nB-lan nB-wan "$PEER_B_IP" "$NAT_B_WAN_IP"

trap - ERR
echo "lab up: natA=$TYPE_A natB=$TYPE_B"
