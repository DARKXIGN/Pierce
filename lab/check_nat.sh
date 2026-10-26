#!/usr/bin/env bash
# Check that both lab NATs behave like the type they were set up as.
# Usage: sudo ./lab/check_nat.sh [expected-natA] [expected-natB]
# Prints the detected type for each side; exits non-zero if an expectation does not match.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$here/common.sh"
need_root

# Start ip netns exec directly (not via the ns_exec function) so $! is the server itself and kill works.
ip netns exec "$NS_OBS" python3 "$here/natcheck.py" server >/dev/null 2>&1 &
srv=$!
trap 'kill $srv 2>/dev/null || true' EXIT
sleep 0.3

got_a=$(ns_exec "$NS_PEER_A" python3 "$here/natcheck.py" client)
got_b=$(ns_exec "$NS_PEER_B" python3 "$here/natcheck.py" client)
echo "natA: $got_a"
echo "natB: $got_b"

rc=0
[[ -z ${1:-} || $got_a == "$1" ]] || { echo "MISMATCH natA: expected $1" >&2; rc=1; }
[[ -z ${2:-} || $got_b == "$2" ]] || { echo "MISMATCH natB: expected $2" >&2; rc=1; }
exit $rc
