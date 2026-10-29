#!/usr/bin/env bash
# Reduced lab matrix as a regression guard (GitHub Actions, or by hand on OCI).
#   sudo ./lab/ci.sh [out_dir]          (default: a fresh temp dir)
# Runs stage 1 detection and stage 3 connections for all 5×5 combinations with CI_ATTEMPTS
# (default 10) attempts each, plus the coordination-outage test for a direct and a relayed path,
# and compares the results with the committed full measurements in results/ (lab/ci_check.py).
# Writes Markdown tables of the run to $GITHUB_STEP_SUMMARY when that is set.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$here/common.sh"
need_root
out=${1:-$(mktemp -d)}
mkdir -p "$out"
export ATTEMPTS=${CI_ATTEMPTS:-10}
rc=0

step() { echo; echo "== $*"; }

step "stage 1: NAT type detection, $ATTEMPTS attempts per combination"
"$here/run_matrix.sh" "$out" || rc=1
step "stage 3: connections, $ATTEMPTS attempts per combination"
"$here/run_stage2.sh" stage3 "$out" || rc=1
step "coordination server outage"
"$here/check_coord_outage.sh" port-restricted port-restricted || rc=1
"$here/check_coord_outage.sh" symmetric-random symmetric-random || rc=1

step "compare with the committed measurements"
python3 "$here/ci_check.py" \
  "$here/../results/stage1_nat_detect.csv" "$out/stage1_nat_detect.csv" \
  "$here/../results/stage3_improved.csv" "$out/stage3_improved.csv" || rc=1
# The self-check must match exactly: the lab itself is deterministic.
if awk -F, 'NR > 1 && $6 != 1' "$out/lab_selfcheck.csv" | grep -q .; then
  echo "FAIL lab self-check:"; awk -F, 'NR > 1 && $6 != 1' "$out/lab_selfcheck.csv"; rc=1
fi

if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
  {
    echo "## Lab regression run ($ATTEMPTS attempts per combination)"
    echo "### Stage 1: NAT type detection"
    python3 "$here/report.py" "$out/stage1_nat_detect.csv" --time-col detect_ms --time-label "Detection time"
    echo "### Stage 3: direct connection with prediction, birthday probing, relay"
    python3 "$here/report.py" "$out/stage3_improved.csv"
  } >> "$GITHUB_STEP_SUMMARY"
fi
echo
[[ $rc == 0 ]] && echo "CI lab run: PASS" || echo "CI lab run: FAIL"
exit $rc
