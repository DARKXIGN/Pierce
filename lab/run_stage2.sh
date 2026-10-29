#!/usr/bin/env bash
# Stage 2: direct connection attempts (STUN + signaling + simultaneous probes, no relay yet).
#
#   sudo ./lab/run_stage2.sh baseline [results_dir]   # all 5×5 combinations -> stage2_baseline.csv
#   sudo ./lab/run_stage2.sh delay    [results_dir]   # extra delay on one side -> stage2_delay.csv
#   sudo ./lab/run_stage2.sh stage3   [results_dir]   # with stage 3 techniques -> stage3_improved.csv
#   sudo ./lab/run_stage2.sh upgrade  [results_dir]   # relay -> direct upgrades -> stage3_upgrade.csv
#   sudo ./lab/run_stage2.sh portmap  [results_dir]   # router A does port mapping -> stage3_portmap.csv
#
# baseline and delay run plain stage 2 hole punching. stage3 runs the same 5×5 matrix with the
# stage 3 techniques switched on: NAT mapping characterization, port prediction, birthday
# probing, and the relay fallback after the 3 s direct attempt (two relays in obs; the
# coordination server picks the one with the lowest RTT_A + RTT_B).
# portmap is stage3 with natA also running miniupnpd (UPnP IGD / NAT-PMP / PCP; needs
# ./lab/get_miniupnpd.sh): rows "<type>+portmap" for every nftables NAT type (the userspace NAT
# has no port mapping), then one row per protocol on its own, "symmetric-random+pcp" etc., against
# symmetric-random.
# upgrade holds each connection for UPGRADE_HOLD seconds (default 16) and lets a relayed
# connection retry the direct path every UPGRADE_RETRY_MS (default 5000; 30000 in production,
# shortened so the experiment fits in minutes), recording how long until it upgraded.
#
# Environment: ATTEMPTS (per combination, default 100), ONLY_A (limit NAT A types, baseline),
#   DELAYS (delay mode, ms on natA's WAN link, default "0 50 100 200"),
#   DELAY_PAIRS (delay mode, natA:natB, default "full:full port-restricted:port-restricted
#   symmetric-random:restricted"), PIERCE_BUILD (build directory, default ./build).
#
# One attempt = both agents start at the same time; success = both got an authenticated probe
# response directly within 3 s. path is "direct", "relay" (both fell back to the relay and
# reached each other through it; success stays 0, because the headline is the direct rate) or
# "none". time_to_connect_ms is the slower side's over the path that won, empty for "none";
# probes_sent is the sum of both sides.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$here/common.sh"
need_root

mode=${1:-baseline}
results=${2:-"$here/../results"}
build=${PIERCE_BUILD:-"$here/../build"}
attempts=${ATTEMPTS:-100}
for bin in stun_server pierce-coord pierce-agent pierce-relay usernat; do
  [[ -x $build/$bin ]] || { echo "missing $build/$bin: cmake -B build && cmake --build build" >&2; exit 1; }
done
mkdir -p "$results"
COORD="$OBS_IP1:50051"
STUN="$OBS_IP1:3478"
RELAYS=("$OBS_IP1:3480" "$OBS_IP2:3480")
RELAY_SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')  # fresh per run, never stored

# start_servers: STUN + coordination server (+ relays in stage3/upgrade) in obs. Sets $servers.
start_servers() {
  ip netns exec "$NS_OBS" "$build/stun_server" --ip "$OBS_IP1" --alt-ip "$OBS_IP2" >/dev/null 2>&1 &
  servers="$!"
  local coord_args=(--listen "$COORD")
  if [[ $use_relays == 1 ]]; then
    local r
    for r in "${RELAYS[@]}"; do
      ip netns exec "$NS_OBS" "$build/pierce-relay" --listen "$r" --secret "$RELAY_SECRET" >/dev/null 2>&1 &
      servers+=" $!"
      coord_args+=(--relay "$r")
    done
    coord_args+=(--relay-secret "$RELAY_SECRET")
  fi
  ip netns exec "$NS_OBS" "$build/pierce-coord" "${coord_args[@]}" >/dev/null 2>&1 &
  servers+=" $!"
  sleep 0.3
}
# common.sh enables set -e; wait returns the killed server's status (143), which is expected.
stop_servers() { kill $servers 2>/dev/null; wait $servers 2>/dev/null || true; }

# attempt <prefix>: one connection attempt; appends "<prefix>,success,ms,probes,path" to $out.
attempt() {
  local prefix=$1 ra rb
  ra=$(mktemp); rb=$(mktemp)
  local args=(--coord "$COORD" --stun "$STUN" "${agent_extra[@]}")
  ns_exec "$NS_PEER_A" "$build/pierce-agent" "${args[@]}" --id A --peer B >"$ra" 2>/dev/null &
  local pa=$!
  ns_exec "$NS_PEER_B" "$build/pierce-agent" "${args[@]}" --id B --peer A >"$rb" 2>/dev/null
  wait "$pa" || true  # a crashed agent still printed a failure line
  # Each agent printed "direct,time_ms,probes,path,remote".
  paste -d, "$ra" "$rb" | awk -F, -v p="$prefix" '{
      ok = ($1 == 1 && $6 == 1)
      # Both reached each other through the relay; "relay-tls" if either side went over TCP/TLS.
      rel = ($4 ~ /^relay/ && $9 ~ /^relay/)
      path = ok ? "direct" : (rel ? (($4 == "relay-tls" || $9 == "relay-tls") ? "relay-tls" : "relay") : "none")
      ms = (path == "none") ? "" : (($2 > $7) ? $2 : $7)
      print p "," ok "," ms "," ($3 + $8) "," path }' >> "$out"
  rm -f "$ra" "$rb"
}

# run_combo <a> <b> [delay]: fresh lab, then $attempts attempts. NAT A is written to the CSV as
# $label_a when that is set (e.g. "full+portmap").
run_combo() {
  local a=$1 b=$2 delay=${3:-} la=${label_a:-$1}
  "$here/teardown.sh" >/dev/null 2>&1
  if ! "$here/setup.sh" "$a" "$b" >/dev/null 2>&1; then
    printf '%-21s %-21s SETUP FAILED\n' "$a" "$b"; return
  fi
  if [[ -n $delay && $delay != 0 ]]; then
    # One side only: everything natA sends to the internet is delayed (signaling and probes).
    ns_exec "$NS_NAT_A" tc qdisc add dev nA-wan root netem delay "${delay}ms"
  fi
  start_servers
  local i
  for ((i = 1; i <= attempts; i++)); do
    if [[ -n $delay ]]; then attempt "$la,$b,$delay,$i"; else attempt "$la,$b,$i"; fi
  done
  stop_servers
  local ok relayed
  ok=$(awk -F, -v a="$la" -v b="$b" -v d="$delay" \
    '$1==a && $2==b && (d=="" || $3==d) && $(NF-3)==1' "$out" | wc -l)
  relayed=$(awk -F, -v a="$la" -v b="$b" -v d="$delay" \
    '$1==a && $2==b && (d=="" || $3==d) && $NF ~ /^relay/' "$out" | wc -l)
  printf '%-28s %-21s %s%s/%s direct%s\n' "$la" "$b" "${delay:+delay=${delay}ms }" "$ok" "$attempts" \
    "$([[ $use_relays == 1 ]] && echo ", $relayed relay")"
}

# upgrade_attempt <a> <b> <i>: one held connection; appends "a,b,i,initial_path,upgrade_ms".
upgrade_attempt() {
  local a=$1 b=$2 i=$3 ea eb oa
  ea=$(mktemp); eb=$(mktemp); oa=$(mktemp)
  local args=(--coord "$COORD" --stun "$STUN" "${agent_extra[@]}" --hold "${UPGRADE_HOLD:-16}"
              --keepalive-ms 1000 --retry-direct-ms "${UPGRADE_RETRY_MS:-5000}")
  ns_exec "$NS_PEER_A" "$build/pierce-agent" "${args[@]}" --id A --peer B >"$oa" 2>"$ea" &
  local pa=$!
  ns_exec "$NS_PEER_B" "$build/pierce-agent" "${args[@]}" --id B --peer A >/dev/null 2>"$eb"
  wait "$pa" || true
  # Both sides must have upgraded; the slower one counts.
  local path ua ub up=""
  path=$(cut -d, -f4 "$oa")
  ua=$(sed -n 's/^upgrade_ms=//p' "$ea"); ub=$(sed -n 's/^upgrade_ms=//p' "$eb")
  if [[ -n $ua && -n $ub ]]; then up=$(( ua > ub ? ua : ub )); fi
  echo "$a,$b,$i,${path:-none},$up" >> "$out"
  rm -f "$ea" "$eb" "$oa"
}

agent_extra=()
use_relays=0
label_a=""
case $mode in
  portmap)
    [[ -x $build/miniupnpd/usr/sbin/miniupnpd ]] || { echo "run ./lab/get_miniupnpd.sh first" >&2; exit 1; }
    use_relays=1
    out=$results/stage3_portmap.csv
    echo "natA,natB,attempt,success,time_to_connect_ms,probes_sent,path" > "$out"
    export PORTMAP=A
    for a in full restricted port-restricted symmetric-random; do
      agent_extra=(--stun-alt-ip "$OBS_IP2" --stun-alt-port 3479)
      label_a="$a+portmap"
      for b in "${NAT_TYPES[@]}"; do run_combo "$a" "$b"; done
    done
    for proto in pcp natpmp upnp; do
      agent_extra=(--stun-alt-ip "$OBS_IP2" --stun-alt-port 3479 --portmap "$proto")
      label_a="symmetric-random+$proto"
      run_combo symmetric-random symmetric-random
    done ;;
  upgrade)
    agent_extra=(--stun-alt-ip "$OBS_IP2" --stun-alt-port 3479)
    use_relays=1
    out=$results/stage3_upgrade.csv
    echo "natA,natB,attempt,initial_path,upgrade_ms" > "$out"
    for pair in ${UPGRADE_PAIRS:-symmetric-random:port-restricted port-restricted:symmetric-random}; do
      a=${pair%%:*} b=${pair##*:}
      "$here/teardown.sh" >/dev/null 2>&1
      "$here/setup.sh" "$a" "$b" >/dev/null 2>&1 || { echo "setup failed: $a $b" >&2; continue; }
      start_servers
      for ((i = 1; i <= ${ATTEMPTS:-20}; i++)); do upgrade_attempt "$a" "$b" "$i"; done
      stop_servers
      awk -F, -v a="$a" -v b="$b" '$1==a && $2==b {n++; if ($4=="relay") r++; if ($5!="") u++}
        END {printf "%-21s %-21s %d attempts, %d started on the relay, %d of those upgraded\n", a, b, n, r, u}' "$out"
    done ;;
  stage3)
    agent_extra=(--stun-alt-ip "$OBS_IP2" --stun-alt-port 3479)
    use_relays=1
    out=$results/stage3_improved.csv
    echo "natA,natB,attempt,success,time_to_connect_ms,probes_sent,path" > "$out"
    for a in ${ONLY_A:-"${NAT_TYPES[@]}"}; do
      for b in "${NAT_TYPES[@]}"; do run_combo "$a" "$b"; done
    done ;;
  baseline)
    out=$results/stage2_baseline.csv
    echo "natA,natB,attempt,success,time_to_connect_ms,probes_sent,path" > "$out"
    for a in ${ONLY_A:-"${NAT_TYPES[@]}"}; do
      for b in "${NAT_TYPES[@]}"; do run_combo "$a" "$b"; done
    done ;;
  delay)
    command -v tc >/dev/null || { echo "missing tc (apt install iproute2)" >&2; exit 1; }
    # netem lives in a kernel module that minimal kernels leave out.
    ip netns add pierce-netem-check
    if ! ip netns exec pierce-netem-check tc qdisc add dev lo root netem delay 1ms 2>/dev/null; then
      ip netns del pierce-netem-check
      echo "tc netem not available: sudo modprobe sch_netem" \
        "(on Ubuntu: sudo apt install linux-modules-extra-\$(uname -r))" >&2
      exit 1
    fi
    ip netns del pierce-netem-check
    out=$results/stage2_delay.csv
    echo "natA,natB,delay_ms,attempt,success,time_to_connect_ms,probes_sent,path" > "$out"
    for pair in ${DELAY_PAIRS:-full:full port-restricted:port-restricted symmetric-random:restricted}; do
      for d in ${DELAYS:-0 50 100 200}; do run_combo "${pair%%:*}" "${pair##*:}" "$d"; done
    done ;;
  *) echo "usage: $0 baseline|delay|stage3|upgrade [results_dir]" >&2; exit 2 ;;
esac
"$here/teardown.sh" >/dev/null 2>&1
echo "wrote $out"
