#!/usr/bin/env bash
# Stage 2: direct connection attempts (STUN + signaling + simultaneous probes, no relay yet).
#
#   sudo ./lab/run_stage2.sh baseline [results_dir]   # all 5×5 combinations -> stage2_baseline.csv
#   sudo ./lab/run_stage2.sh delay    [results_dir]   # extra delay on one side -> stage2_delay.csv
#   sudo ./lab/run_stage2.sh stage3   [results_dir]   # with stage 3 techniques -> stage3_improved.csv
#
# baseline and delay run plain stage 2 hole punching. stage3 runs the same 5×5 matrix with the
# stage 3 techniques switched on (so far: NAT mapping characterization + port prediction).
#
# Environment: ATTEMPTS (per combination, default 100), ONLY_A (limit NAT A types, baseline),
#   DELAYS (delay mode, ms on natA's WAN link, default "0 50 100 200"),
#   DELAY_PAIRS (delay mode, natA:natB, default "full:full port-restricted:port-restricted
#   symmetric-random:restricted"), PIERCE_BUILD (build directory, default ./build).
#
# One attempt = both agents start at the same time; success = both got an authenticated probe
# response within 3 s. time_to_connect_ms is the slower side's, probes_sent the sum of both sides,
# path "direct" on success and "none" on failure (there is no relay until stage 3).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$here/common.sh"
need_root

mode=${1:-baseline}
results=${2:-"$here/../results"}
build=${PIERCE_BUILD:-"$here/../build"}
attempts=${ATTEMPTS:-100}
for bin in stun_server pierce-coord pierce-agent usernat; do
  [[ -x $build/$bin ]] || { echo "missing $build/$bin: cmake -B build && cmake --build build" >&2; exit 1; }
done
mkdir -p "$results"
COORD="$OBS_IP1:50051"
STUN="$OBS_IP1:3478"

# start_servers: STUN + coordination server in the obs namespace. Sets $servers (pids).
start_servers() {
  ip netns exec "$NS_OBS" "$build/stun_server" --ip "$OBS_IP1" --alt-ip "$OBS_IP2" >/dev/null 2>&1 &
  local s=$!
  ip netns exec "$NS_OBS" "$build/pierce-coord" --listen "$COORD" >/dev/null 2>&1 &
  servers="$s $!"
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
  # Each agent printed "success,time_ms,probes,path,remote".
  paste -d, "$ra" "$rb" | awk -F, -v p="$prefix" '{
      ok = ($1 == 1 && $6 == 1); ms = ""
      if (ok) ms = ($2 > $7) ? $2 : $7
      print p "," ok "," ms "," ($3 + $8) "," (ok ? "direct" : "none") }' >> "$out"
  rm -f "$ra" "$rb"
}

# run_combo <a> <b> <prefix-template>: fresh lab, then $attempts attempts.
run_combo() {
  local a=$1 b=$2 delay=${3:-}
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
    if [[ -n $delay ]]; then attempt "$a,$b,$delay,$i"; else attempt "$a,$b,$i"; fi
  done
  stop_servers
  local ok
  ok=$(awk -F, -v a="$a" -v b="$b" -v d="$delay" \
    '$1==a && $2==b && (d=="" || $3==d) && $(NF-3)==1' "$out" | wc -l)
  printf '%-21s %-21s %s%s/%s direct\n' "$a" "$b" "${delay:+delay=${delay}ms }" "$ok" "$attempts"
}

agent_extra=()
case $mode in
  stage3)
    agent_extra=(--stun-alt-ip "$OBS_IP2" --stun-alt-port 3479)
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
  *) echo "usage: $0 baseline|delay|stage3 [results_dir]" >&2; exit 2 ;;
esac
"$here/teardown.sh" >/dev/null 2>&1
echo "wrote $out"
