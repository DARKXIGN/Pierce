#!/usr/bin/env bash
# Verify basic reachability inside the lab. Run after setup.sh (root).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$here/common.sh"
need_root

ok=0; fail=0
check() {
  local ns=$1 target=$2 label=$3
  if ns_exec "$ns" ping -c 2 -W 1 "$target" >/dev/null 2>&1; then
    echo "PASS  $label"; ok=$((ok+1))
  else
    echo "FAIL  $label"; fail=$((fail+1))
  fi
}

check "$NS_PEER_A" "$NAT_A_LAN_IP" "peerA -> natA (LAN gateway)"
check "$NS_PEER_B" "$NAT_B_LAN_IP" "peerB -> natB (LAN gateway)"
check "$NS_NAT_A"  "$NAT_B_WAN_IP" "natA -> natB (WAN)"
check "$NS_PEER_A" "$NAT_B_WAN_IP" "peerA -> natB WAN (through natA)"
check "$NS_PEER_B" "$NAT_A_WAN_IP" "peerB -> natA WAN (through natB)"
check "$NS_PEER_A" "$OBS_IP1"      "peerA -> obs #1 (through natA)"
check "$NS_PEER_B" "$OBS_IP2"      "peerB -> obs #2 (through natB)"

echo "ok=$ok fail=$fail"
[[ $fail -eq 0 ]]
