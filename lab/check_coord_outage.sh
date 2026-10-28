#!/usr/bin/env bash
# Coordination server outage: once the peers are connected, killing the server must not matter.
#   sudo ./lab/check_coord_outage.sh [natA] [natB]        (default: port-restricted port-restricted)
# Connects A and B, kills the coordination and STUN servers, then lets both agents send a
# keepalive every 500 ms for 10 s. PASS if both still get (nearly) every keepalive answered.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$here/common.sh"
need_root
build=${PIERCE_BUILD:-"$here/../build"}
a=${1:-port-restricted} b=${2:-port-restricted}

"$here/teardown.sh" >/dev/null 2>&1
"$here/setup.sh" "$a" "$b" >/dev/null || exit 1
tmp=$(mktemp -d)
cleanup() { "$here/teardown.sh" >/dev/null 2>&1; rm -rf "$tmp"; }
trap cleanup EXIT

ip netns exec "$NS_OBS" "$build/stun_server" --ip "$OBS_IP1" --alt-ip "$OBS_IP2" >/dev/null 2>&1 &
stun_pid=$!
ip netns exec "$NS_OBS" "$build/pierce-coord" --listen "$OBS_IP1:50051" >/dev/null 2>&1 &
coord_pid=$!
sleep 0.3

args=(--coord "$OBS_IP1:50051" --stun "$OBS_IP1:3478" --hold 10 --keepalive-ms 500)
ip netns exec "$NS_PEER_A" "$build/pierce-agent" "${args[@]}" --id A --peer B >"$tmp/a.out" 2>"$tmp/a.err" &
pa=$!
ip netns exec "$NS_PEER_B" "$build/pierce-agent" "${args[@]}" --id B --peer A >"$tmp/b.out" 2>"$tmp/b.err" &
pb=$!

# Wait until both say "connected", then pull the plug on the servers.
for _ in $(seq 50); do
  grep -q connected "$tmp/a.err" && grep -q connected "$tmp/b.err" && break
  sleep 0.1
done
if ! grep -q connected "$tmp/a.err" || ! grep -q connected "$tmp/b.err"; then
  echo "FAIL  peers did not connect ($a x $b)"; exit 1
fi
kill "$coord_pid" "$stun_pid"
wait "$coord_pid" "$stun_pid" 2>/dev/null || true  # 143 = killed, as intended (common.sh sets -e)
kill -0 "$coord_pid" 2>/dev/null && { echo "FAIL  coordination server still running"; exit 1; }
echo "coordination server killed after connect; holding for 10 s"

wait "$pa" "$pb" || true
rc=0
for side in a b; do
  line=$(grep keepalive "$tmp/$side.err")
  sent=$(sed -n 's/.*sent=\([0-9]*\).*/\1/p' <<<"$line")
  answered=$(sed -n 's/.*answered=\([0-9]*\).*/\1/p' <<<"$line")
  # The very last keepalive can still be in flight when the hold ends.
  if [[ -n $sent && $sent -ge 15 && $answered -ge $((sent - 1)) ]]; then
    echo "PASS  peer ${side^^}: $line"
  else
    echo "FAIL  peer ${side^^}: ${line:-no keepalive report}"; rc=1
  fi
done
exit $rc
