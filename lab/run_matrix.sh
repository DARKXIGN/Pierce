#!/usr/bin/env bash
# Bring the lab up for every NAT A × NAT B combination (5×5) and measure each one.
# Usage: sudo ./lab/run_matrix.sh [results_dir]       (default: results/)
# Environment: ATTEMPTS (detector runs per combination, default 100), ONLY_A (limit NAT A types),
#              PIERCE_BUILD (build directory, default ./build).
#
# Per combination:
#   1. self-check with the Python tester (natcheck.py)     -> lab_selfcheck.csv
#   2. ATTEMPTS runs of the C++ NAT type detector per side -> stage1_nat_detect.csv
#      one row per attempt: success = both sides classified as configured
# Later stages plug the real experiment (hole punching) into run_one().
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$here/common.sh"
need_root

results=${1:-"$here/../results"}
build=${PIERCE_BUILD:-"$here/../build"}
attempts=${ATTEMPTS:-100}
for bin in stun_server nat_detect usernat; do
  [[ -x $build/$bin ]] || { echo "missing $build/$bin: cmake -B build && cmake --build build" >&2; exit 1; }
done
mkdir -p "$results"
selfcheck=$results/lab_selfcheck.csv
detect=$results/stage1_nat_detect.csv
echo "nat_a,nat_b,ping_ok,detected_a,detected_b,match" > "$selfcheck"
echo "natA,natB,attempt,success,detected_a,detected_b,detect_ms" > "$detect"

# detect_runs <a> <b>: run the detector in both peers at once, append one CSV row per attempt.
detect_runs() {
  local a=$1 b=$2 tmp
  tmp=$(mktemp -d)
  # The self-check server used the same ports a moment ago; retry until our server binds.
  local srv tries=0
  while :; do
    ip netns exec "$NS_OBS" "$build/stun_server" --ip "$OBS_IP1" --alt-ip "$OBS_IP2" >/dev/null 2>&1 &
    srv=$!
    sleep 0.2
    kill -0 "$srv" 2>/dev/null && break
    (( ++tries < 10 )) || { echo "stun_server did not start" >&2; break; }
  done
  # Lab links never lose packets, so short timeouts are safe and keep 100 runs quick.
  local args=(--server "$OBS_IP1:3478" --alt-ip "$OBS_IP2" --timeout-ms 100 --tries 2 --repeat "$attempts")
  ns_exec "$NS_PEER_A" "$build/nat_detect" "${args[@]}" > "$tmp/a" &
  local det_a=$!
  ns_exec "$NS_PEER_B" "$build/nat_detect" "${args[@]}" > "$tmp/b"
  wait "$det_a"
  kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null
  # Line i of each file is attempt i: "<type>,<ms>". The slower side sets the attempt's time.
  paste -d, "$tmp/a" "$tmp/b" | awk -F, -v a="$a" -v b="$b" '{
      ok = ($1 == a && $3 == b) ? 1 : 0; ms = ($2 > $4) ? $2 : $4
      print a "," b "," NR "," ok "," $1 "," $3 "," ms }' >> "$detect"
  local ok
  ok=$(awk -F, -v a="$a" -v b="$b" '$1==a && $2==b && $4==1' "$detect" | wc -l)
  rm -rf "$tmp"
  echo "$ok/$attempts"
}

run_one() {
  local a=$1 b=$2 ping=0 det match=0
  "$here/teardown.sh" >/dev/null 2>&1
  local rc=0
  "$here/setup.sh" "$a" "$b" >/dev/null 2>&1 || rc=$?
  if [[ $rc != 0 ]]; then
    echo "$a,$b,0,setup-failed,setup-failed,0" >> "$selfcheck"
    printf '%-21s %-21s SETUP FAILED (exit %s)\n' "$a" "$b" "$rc"
    return
  fi
  "$here/check_ping.sh" >/dev/null && ping=1
  det=$("$here/check_nat.sh" "$a" "$b" 2>/dev/null) && match=1
  local da db
  da=$(sed -n 's/^natA: //p' <<<"$det"); db=$(sed -n 's/^natB: //p' <<<"$det")
  echo "$a,$b,$ping,$da,$db,$match" >> "$selfcheck"
  # Rebuild the lab so the detector starts from empty NAT state. Otherwise the kernel can hand the
  # detector a local port the self-check just closed, whose conntrack entry (e.g. toward the
  # server's other port) is still alive and lets a "should be filtered" reply through.
  "$here/teardown.sh" >/dev/null 2>&1
  "$here/setup.sh" "$a" "$b" >/dev/null 2>&1 || { printf '%-21s %-21s SETUP FAILED (detector)\n' "$a" "$b"; return; }
  local detected
  detected=$(detect_runs "$a" "$b")
  printf '%-21s %-21s ping=%s  self-check=%-8s detector=%s\n' "$a" "$b" "$ping" \
    "$([[ $match == 1 ]] && echo OK || echo MISMATCH)" "$detected"
}

for a in ${ONLY_A:-"${NAT_TYPES[@]}"}; do
  for b in "${NAT_TYPES[@]}"; do run_one "$a" "$b"; done
done
"$here/teardown.sh" >/dev/null 2>&1
echo "wrote $selfcheck $detect"
