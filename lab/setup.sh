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
# default 1), PIERCE_BUILD (build directory holding the usernat binary, default ./build),
# PORTMAP (A, B or AB: which routers also do UPnP / NAT-PMP / PCP port mapping with miniupnpd;
# needs ./lab/get_miniupnpd.sh first; nftables NAT types only).
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

PORTMAP_A=0 PORTMAP_B=0
[[ ${PORTMAP:-} == *A* ]] && PORTMAP_A=1
[[ ${PORTMAP:-} == *B* ]] && PORTMAP_B=1
MINIUPNPD=${PIERCE_BUILD:-"$here/../build"}/miniupnpd/usr/sbin/miniupnpd
if [[ $PORTMAP_A$PORTMAP_B != 00 ]]; then
  [[ -x $MINIUPNPD ]] || { echo "PORTMAP needs $MINIUPNPD: run ./lab/get_miniupnpd.sh" >&2; exit 3; }
  if [[ ($PORTMAP_A == 1 && $TYPE_A == symmetric-sequential) || ($PORTMAP_B == 1 && $TYPE_B == symmetric-sequential) ]]; then
    # miniupnpd programs nftables; the userspace NAT does not read nftables rules.
    echo "PORTMAP is not available for symmetric-sequential (userspace NAT)" >&2; exit 3
  fi
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
# The lab runs connection attempts several times a second, which no real host does. Linux allows
# a host about 6 ICMP errors in a burst, then one per second, so with the default the agent's
# probes for port mapping services (answered with ICMP port unreachable when absent) would start
# timing out: an artifact of the measurement loop, not of the NAT. Lab routers do not rate-limit.
for ns in "$NS_NAT_A" "$NS_NAT_B"; do ns_exec "$ns" sysctl -qw net.ipv4.icmp_ratelimit=0; done

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

# apply_nat <ns> <type> <lan_if> <wan_if> <lan_host_ip> <public_ip> <portmap 0|1>
apply_nat() {
  local ns=$1 type=$2 lan=$3 wan=$4 host=$5 pub=$6 portmap=${7:-0}
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
    dnat="iifname \"$wan\" udp dport 1024-65535 dnat ip to $host;"
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

  # inet tables (not ip) so that miniupnpd, whose nftables backend only knows inet, can share them:
  # every base chain first jumps into a chain of miniupnpd's, empty unless PORTMAP runs it. Port
  # mappings it adds there come before the NAT type's own rules, as on a real router.
  ns_exec "$ns" nft -f - <<NFT
table inet nat {
  chain prerouting_miniupnpd {}
  chain postrouting_miniupnpd {}
  chain prerouting { type nat hook prerouting priority -100; jump prerouting_miniupnpd; ${dnat} }
  chain postrouting { type nat hook postrouting priority 100; jump postrouting_miniupnpd; oifname "$wan" ${snat}; }
}
table inet filter {
  # Remembers (internal ip, internal port, remote ip) for every outbound UDP packet. Used by "restricted".
  set contacted {
    type ipv4_addr . inet_service . ipv4_addr
    flags dynamic, timeout
    timeout 120s
  }
  chain miniupnpd {}
  # Unsolicited UDP to the router's own WAN address (nothing listens there) must be dropped here.
  # Otherwise the kernel delivers it locally, answers with ICMP port unreachable, and confirms a
  # conntrack entry for (remote -> our public ip:port). If the LAN host then sends to that remote,
  # masquerade sees the clash and picks a different public port: an early probe from the peer
  # would silently turn this endpoint-independent NAT into an endpoint-dependent one.
  chain input { type filter hook input priority 0; iifname "$wan" meta l4proto udp ct state new drop; }
  chain forward {
    type filter hook forward priority 0; policy drop;
    jump miniupnpd
    iifname "$lan" oifname "$wan" ip protocol udp update @contacted { ip saddr . udp sport . ip daddr }
    ct state established,related accept
    iifname "$lan" oifname "$wan" accept
    ${inbound}
  }
}
NFT
  echo "$ns: $type NAT on $wan"
  if [[ $portmap == 1 ]]; then start_miniupnpd "$ns" "$lan" "$wan" "$pub"; fi
}

# start_miniupnpd <ns> <lan_if> <wan_if> <public_ip>: the router also answers UPnP IGD, NAT-PMP and
# PCP port mapping requests from its LAN (miniupnpd, as on many home routers).
start_miniupnpd() {
  local ns=$1 lan=$2 wan=$3 pub=$4 conf="/tmp/pierce-miniupnpd-$1.conf"
  cat > "$conf" <<CONF
ext_ifname=$wan
listening_ip=$lan
enable_upnp=yes
enable_natpmp=yes
# Only map ports to the host that asks, and only unprivileged ports.
secure_mode=yes
allow 1024-65535 0.0.0.0/0 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
system_uptime=yes
uuid=$(cat /proc/sys/kernel/random/uuid)
upnp_table_name=filter
upnp_nat_table_name=nat
upnp_forward_chain=miniupnpd
upnp_nat_chain=prerouting_miniupnpd
upnp_nat_postrouting_chain=postrouting_miniupnpd
CONF
  # -d: stay in the foreground (teardown.sh stops it with the namespace); -P: own pid file.
  ip netns exec "$ns" "$MINIUPNPD" -d -f "$conf" -P "/tmp/pierce-miniupnpd-$ns.pid" \
    >"/tmp/pierce-miniupnpd-$ns.log" 2>&1 &
  local pid=$!
  for _ in $(seq 20); do
    grep -q "Listening for NAT-PMP" "/tmp/pierce-miniupnpd-$ns.log" && break
    sleep 0.1
  done
  kill -0 "$pid" 2>/dev/null || { echo "miniupnpd failed in $ns:" >&2; cat "/tmp/pierce-miniupnpd-$ns.log" >&2; return 1; }
  echo "$ns: port mapping (UPnP IGD, NAT-PMP, PCP) by miniupnpd pid $pid, log /tmp/pierce-miniupnpd-$ns.log"
}

apply_nat "$NS_NAT_A" "$TYPE_A" nA-lan nA-wan "$PEER_A_IP" "$NAT_A_WAN_IP" "$PORTMAP_A"
apply_nat "$NS_NAT_B" "$TYPE_B" nB-lan nB-wan "$PEER_B_IP" "$NAT_B_WAN_IP" "$PORTMAP_B"

trap - ERR
echo "lab up: natA=$TYPE_A natB=$TYPE_B"
