#!/usr/bin/env bash
# Stage 4 in the lab: real traffic through the WireGuard tunnel, over a direct and a relayed path.
#   sudo ./lab/run_stage4.sh [results_dir]                 -> results/stage4_lab.csv
# Environment: RUNS (per pair, default 5), PAIRS (natA:natB list). The default covers each way a
#   connection can come about: port-restricted x2 (plain hole punching), symmetric-random x
#   port-restricted (birthday probing, so direct or relayed), symmetric-sequential x2 (port
#   prediction through the userspace NAT) and symmetric-random x2 (always relayed).
#   UDP_BLOCKED_PAIRS (default port-restricted:port-restricted) then run the same with all of
#   peerA's UDP dropped at its NAT, like a network that only lets TCP out: no STUN, no direct
#   path, no UDP relay, so the agents must meet on the relay over TCP/TLS (path relay-tls).
#
# Per run: both agents connect with the stage 3 techniques and then carry traffic between TUN
# devices (peerA 10.99.0.1, peerB 10.99.0.2). Measured from peerA: 50 pings (100 ms apart) and
# a 5 s iperf3 TCP transfer. One CSV row per run:
#   natA,natB,run,path,ping_avg_ms,ping_loss_pct,iperf_mbps
# On relayed runs, tcpdump also checks the relay hop: the pings carry a marker, which must be
# visible on peerA's TUN device (plaintext) and never in the packets to and from the relay.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$here/common.sh"
need_root
for t in iperf3 tcpdump; do command -v $t >/dev/null || { echo "missing $t (apt install $t)" >&2; exit 1; }; done

results=${1:-"$here/../results"}
build=${PIERCE_BUILD:-"$here/../build"}
runs=${RUNS:-5}
for bin in stun_server pierce-coord pierce-agent pierce-relay pierce-wgkey usernat; do
  [[ -x $build/$bin ]] || { echo "missing $build/$bin (needs cargo for BoringTun): cmake -B build && cmake --build build" >&2; exit 1; }
done
mkdir -p "$results"
out=$results/stage4_lab.csv
echo "natA,natB,run,path,ping_avg_ms,ping_loss_pct,iperf_mbps" > "$out"
tmp=$(mktemp -d)
MARKER=5069657263652d706c61696e  # "Pierce-plain" as hex, the ping payload pattern
secret=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')

# The relay's TLS certificate: self-signed, made per run. Agents do not check it (see
# agent/tls_relay.hpp); it only has to exist for TLS.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/relay.key" -out "$tmp/relay.crt" \
  -days 1 -subj /CN=pierce-relay >/dev/null 2>&1

# Keys are made once and exchanged "in advance" (here: through files), never via the coordinator.
"$build/pierce-wgkey" genkey > "$tmp/a.key"; "$build/pierce-wgkey" pubkey < "$tmp/a.key" > "$tmp/a.pub"
"$build/pierce-wgkey" genkey > "$tmp/b.key"; "$build/pierce-wgkey" pubkey < "$tmp/b.key" > "$tmp/b.pub"

start_servers() {
  ip netns exec "$NS_OBS" "$build/stun_server" --ip "$OBS_IP1" --alt-ip "$OBS_IP2" >/dev/null 2>&1 &
  servers="$!"
  ip netns exec "$NS_OBS" "$build/pierce-relay" --listen "$OBS_IP1:3480" --secret "$secret" \
    --tls-listen "$OBS_IP1:3443" --tls-cert "$tmp/relay.crt" --tls-key "$tmp/relay.key" >/dev/null 2>&1 &
  servers+=" $!"
  ip netns exec "$NS_OBS" "$build/pierce-coord" --listen "$OBS_IP1:50051" \
    --relay "$OBS_IP1:3480" --relay-secret "$secret" --relay-tls-port 3443 >/dev/null 2>&1 &
  servers+=" $!"
  sleep 0.3
}
stop_servers() { kill $servers 2>/dev/null; wait $servers 2>/dev/null || true; }

# tun_up <ns> <addr>: a persistent TUN device the agent attaches to. MTU 1420 leaves room for
# WireGuard's 60 bytes of overhead inside a 1500-byte link.
tun_up() {
  ns_exec "$1" ip tuntap add dev pierce0 mode tun
  ns_exec "$1" ip addr add "$2/24" dev pierce0
  ns_exec "$1" ip link set pierce0 mtu 1420 up
}

# found <hex> <pcap>: does the capture contain these bytes anywhere?
found() { python3 -c "import sys; sys.exit(0 if bytes.fromhex('$1') in open('$2','rb').read() else 1)"; }

one_run() {
  local a=$1 b=$2 i=$3 label_a=${4:-$1}
  : > "$tmp/a.err"; : > "$tmp/b.err"  # exist before the wait loop below greps them
  local args=(--coord "$OBS_IP1:50051" --stun "$OBS_IP1:3478" --stun-alt-ip "$OBS_IP2"
              --tun pierce0 --hold 30)
  ns_exec "$NS_PEER_A" "$build/pierce-agent" "${args[@]}" --id A --peer B \
    --wg-key "$(cat "$tmp/a.key")" --wg-peer "$(cat "$tmp/b.pub")" >"$tmp/a.out" 2>"$tmp/a.err" &
  local pa=$!
  ns_exec "$NS_PEER_B" "$build/pierce-agent" "${args[@]}" --id B --peer A \
    --wg-key "$(cat "$tmp/b.key")" --wg-peer "$(cat "$tmp/a.pub")" >"$tmp/b.out" 2>"$tmp/b.err" &
  local pb=$!
  local _
  for _ in $(seq 150); do  # up to 15 s: the TLS fallback comes after the UDP relay timed out
    grep -q "dataplane up" "$tmp/a.err" && grep -q "dataplane up" "$tmp/b.err" && break
    sleep 0.1
  done
  local path; path=$(cut -d, -f4 "$tmp/a.out")
  # The WireGuard handshake happens in the first few hundred ms; wait for the first reply.
  for _ in $(seq 20); do ns_exec "$NS_PEER_A" ping -c 1 -W 1 10.99.0.2 >/dev/null 2>&1 && break; done

  local cap_relay="$tmp/relay.pcap" cap_tun="$tmp/tun.pcap" tcpd=""
  if [[ $path == relay* ]]; then
    ip netns exec "$NS_OBS" tcpdump -i obs0 -U -w "$cap_relay" udp port 3480 or tcp port 3443 >/dev/null 2>&1 &
    tcpd="$!"
    ip netns exec "$NS_PEER_A" tcpdump -i pierce0 -U -w "$cap_tun" icmp >/dev/null 2>&1 &
    tcpd+=" $!"
    sleep 0.5
  fi
  local ping_out
  ping_out=$(ns_exec "$NS_PEER_A" ping -c 50 -i 0.1 -p "$MARKER" 10.99.0.2 2>&1)
  local loss avg
  loss=$(sed -n 's/.* \([0-9.]*\)% packet loss.*/\1/p' <<<"$ping_out")
  avg=$(sed -n 's|^rtt [^=]*= [0-9.]*/\([0-9.]*\)/.*|\1|p' <<<"$ping_out")
  if [[ -n $tcpd ]]; then
    sleep 0.5; kill $tcpd 2>/dev/null; wait $tcpd 2>/dev/null || true
    if found "$MARKER" "$cap_tun" && ! found "$MARKER" "$cap_relay"; then
      echo "  relay hop: no plaintext (marker on pierce0, not in $(stat -c %s "$cap_relay") bytes at the relay)"
    else
      echo "  relay hop: PLAINTEXT CHECK FAILED"; relay_check=1
    fi
    cp "$cap_relay" "$results/stage4_relay_hop.pcap" 2>/dev/null
  fi
  ns_exec "$NS_PEER_B" iperf3 -s -1 >/dev/null 2>&1 &
  local srv=$!
  sleep 0.3
  local mbps
  mbps=$(ns_exec "$NS_PEER_A" iperf3 -c 10.99.0.2 -t 5 -J 2>/dev/null |
         python3 -c "import json,sys; print(round(json.load(sys.stdin)['end']['sum_received']['bits_per_second']/1e6, 1))" 2>/dev/null)
  wait "$srv" 2>/dev/null || true
  kill "$pa" "$pb" 2>/dev/null; wait "$pa" "$pb" 2>/dev/null || true
  echo "$label_a,$b,$i,${path:-none},$avg,$loss,$mbps" >> "$out"
  printf '%-21s %-21s run %d: path=%-9s ping avg=%s ms loss=%s%% iperf3=%s Mbit/s\n' \
    "$label_a" "$b" "$i" "${path:-none}" "${avg:-?}" "${loss:-?}" "${mbps:-?}"
}

relay_check=0
default_pairs="port-restricted:port-restricted symmetric-random:port-restricted"
default_pairs+=" symmetric-sequential:symmetric-sequential symmetric-random:symmetric-random"
for pair in ${PAIRS:-$default_pairs}; do
  a=${pair%%:*} b=${pair##*:}
  for ((i = 1; i <= runs; i++)); do
    "$here/teardown.sh" >/dev/null 2>&1
    "$here/setup.sh" "$a" "$b" >/dev/null 2>&1 || { echo "setup failed: $a $b" >&2; continue; }
    tun_up "$NS_PEER_A" 10.99.0.1
    tun_up "$NS_PEER_B" 10.99.0.2
    start_servers
    one_run "$a" "$b" "$i"
    stop_servers
  done
done
for pair in ${UDP_BLOCKED_PAIRS-port-restricted:port-restricted}; do
  a=${pair%%:*} b=${pair##*:}
  for ((i = 1; i <= runs; i++)); do
    "$here/teardown.sh" >/dev/null 2>&1
    "$here/setup.sh" "$a" "$b" >/dev/null 2>&1 || { echo "setup failed: $a $b" >&2; continue; }
    # peerA's network lets no UDP through at all, in either direction.
    ns_exec "$NS_NAT_A" nft insert rule inet filter forward meta l4proto udp drop
    tun_up "$NS_PEER_A" 10.99.0.1
    tun_up "$NS_PEER_B" 10.99.0.2
    start_servers
    one_run "$a" "$b" "$i" "$a+udp-blocked"
    stop_servers
  done
done
"$here/teardown.sh" >/dev/null 2>&1
rm -rf "$tmp"
echo "wrote $out"
exit $relay_check
