#!/usr/bin/env bash
# Remove everything setup.sh created. Safe to run repeatedly.
# Deleting a namespace also deletes its veth ends, bridge and nftables rules, so nothing is left behind.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
source "$here/common.sh"
need_root

for ns in "${ALL_NS[@]}"; do
  # Stop anything still running inside the lab namespace (e.g. a test server) before deleting it.
  pids=$(ip netns pids "$ns" 2>/dev/null || true)
  [[ -n $pids ]] && kill $pids 2>/dev/null
  ip netns del "$ns" 2>/dev/null && echo "deleted $ns"
done
echo "lab down"
