#!/usr/bin/env bash
# Bring the lab up for every NAT A × NAT B combination (4×4) and self-check each one.
# Usage: sudo ./lab/run_matrix.sh [out.csv]     (default: results/lab_selfcheck.csv)
# Later stages plug the real experiment (STUN detector, hole punching) into run_one().
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$here/common.sh"
need_root

out=${1:-"$here/../results/lab_selfcheck.csv"}
mkdir -p "$(dirname "$out")"
echo "nat_a,nat_b,ping_ok,detected_a,detected_b,match" > "$out"

run_one() {
  local a=$1 b=$2 ping=0 det match=0
  "$here/teardown.sh" >/dev/null 2>&1
  "$here/setup.sh" "$a" "$b" >/dev/null || { echo "$a,$b,0,setup-failed,setup-failed,0" >> "$out"; return; }
  "$here/check_ping.sh" >/dev/null && ping=1
  det=$("$here/check_nat.sh" "$a" "$b" 2>/dev/null) && match=1
  local da db
  da=$(sed -n 's/^natA: //p' <<<"$det"); db=$(sed -n 's/^natB: //p' <<<"$det")
  echo "$a,$b,$ping,$da,$db,$match" >> "$out"
  printf '%-16s %-16s ping=%s  A=%-16s B=%-16s %s\n' "$a" "$b" "$ping" "$da" "$db" \
    "$([[ $match == 1 ]] && echo OK || echo MISMATCH)"
}

for a in ${ONLY_A:-"${NAT_TYPES[@]}"}; do
  for b in "${NAT_TYPES[@]}"; do run_one "$a" "$b"; done
done
"$here/teardown.sh" >/dev/null 2>&1
echo "wrote $out"
